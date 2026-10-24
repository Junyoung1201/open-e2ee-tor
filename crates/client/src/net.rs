//! HTTP over Tor (or, in debug builds only, over a local Unix socket).
//!
//! The onion address authenticates the server at the Tor layer, so there
//! is no TLS. Every response is size-capped before it is parsed, and every
//! error message from the server is sanitised before it is shown.

use std::convert::Infallible;
use std::path::Path;
#[cfg(debug_assertions)]
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use o2ee_protocol::api::{ErrorBody, MAX_ERROR_CHARS, MAX_JSON_BODY};
use o2ee_protocol::text::sanitize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;
use tor_rtcompat::PreferredRuntime;

use crate::Error;

/// A watched request fails when no body bytes have gone out and no reply
/// has come back for this long. A Tor stream can die without closing.
pub const STALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Request bodies are handed to the connection in pieces of this size, so
/// the bytes sent so far can be counted.
const BODY_PIECE: usize = 64 * 1024;

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone)]
enum Transport {
    Tor(Arc<TorClient<PreferredRuntime>>),
    #[cfg(debug_assertions)]
    Direct(PathBuf),
}

/// A connection factory for the pinned server.
#[derive(Clone)]
pub struct Net {
    transport: Transport,
    server: String,
}

impl std::fmt::Debug for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Net").field("server", &self.server).finish()
    }
}

impl Net {
    /// Bootstraps an embedded Tor client. Its state and cache live under
    /// `tor_dir`; nothing else is configured or logged.
    pub async fn tor(server: &str, tor_dir: &Path) -> Result<Self, Error> {
        #[cfg(debug_assertions)]
        if let Some(socket) = std::env::var_os("O2EE_INSECURE_DIRECT") {
            return Ok(Self {
                transport: Transport::Direct(PathBuf::from(socket)),
                server: server.to_owned(),
            });
        }
        crate::paths::private_dir(tor_dir)?;
        // Tor's TLS links use rustls; pick its crypto backend explicitly
        // (an error only means one is installed already).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config: TorClientConfig =
            TorClientConfigBuilder::from_directories(tor_dir.join("state"), tor_dir.join("cache"))
                .build()
                .map_err(|e| Error::Network(format!("Tor configuration: {e}")))?;
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| Error::Network(format!("Cannot connect to Tor: {e}")))?;
        Ok(Self {
            transport: Transport::Tor(client),
            server: server.to_owned(),
        })
    }

    /// Debug builds only: talk to a server's Unix socket directly, without
    /// Tor. Used by tests; release builds do not contain this.
    #[cfg(debug_assertions)]
    pub fn direct(socket: &Path, server: &str) -> Self {
        Self {
            transport: Transport::Direct(socket.to_owned()),
            server: server.to_owned(),
        }
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn is_tor(&self) -> bool {
        matches!(self.transport, Transport::Tor(_))
    }

    async fn connect(&self) -> Result<Box<dyn Io>, Error> {
        match &self.transport {
            Transport::Tor(client) => {
                let stream = client
                    .connect((self.server.as_str(), 80))
                    .await
                    .map_err(|e| Error::Network(format!("Cannot reach server: {e}")))?;
                Ok(Box::new(stream))
            }
            #[cfg(debug_assertions)]
            Transport::Direct(path) => {
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(|e| Error::Network(format!("Cannot reach server: {e}")))?;
                Ok(Box::new(stream))
            }
        }
    }

    /// Sends one request on a fresh stream.
    pub fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, String)],
        body: Bytes,
    ) -> impl Future<Output = Result<Response<Incoming>, Error>> + Send {
        // Not an `async fn`: an extra layer here makes the CLI's future too
        // deep for the compiler.
        self.send_body(method, path, token, headers, Full::new(body))
    }

    /// Sends one request and reads a small reply, reporting the body bytes
    /// sent so far to `on_sent`. Fails with [`Error::Network`] if nothing
    /// moves for [`STALL_TIMEOUT`].
    pub async fn send_watched(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, String)],
        body: Bytes,
        on_sent: impl FnMut(u64),
    ) -> Result<(StatusCode, Bytes), Error> {
        self.send_watched_with(method, path, token, headers, body, on_sent, STALL_TIMEOUT)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_watched_with(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, String)],
        body: Bytes,
        mut on_sent: impl FnMut(u64),
        stall: Duration,
    ) -> Result<(StatusCode, Bytes), Error> {
        let sent = Arc::new(AtomicU64::new(0));
        let body = Counted {
            data: body,
            handed: 0,
            sent: Arc::clone(&sent),
        };
        let request = async {
            let res = self.send_body(method, path, token, headers, body).await?;
            read_small(res).await
        };
        tokio::pin!(request);
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        let mut last = 0;
        let mut moved = Instant::now();
        loop {
            tokio::select! {
                outcome = &mut request => return outcome,
                _ = tick.tick() => {
                    let now = sent.load(Ordering::Relaxed);
                    if now != last {
                        last = now;
                        moved = Instant::now();
                        on_sent(now);
                    } else if moved.elapsed() >= stall {
                        return Err(Error::Network("Server stopped responding".into()));
                    }
                }
            }
        }
    }

    async fn send_body<B>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, String)],
        body: B,
    ) -> Result<Response<Incoming>, Error>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // Tor circuits fail now and then. Retrying is safe only before any
        // request bytes have left, so only opening the stream is retried.
        let mut attempt = 0;
        let io = loop {
            match self.connect().await {
                Ok(io) => break io,
                Err(_) if attempt < 3 => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_secs(2 << attempt)).await;
                }
                Err(e) => return Err(e),
            }
        };
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .map_err(|e| Error::Network(format!("Connection failed: {e}")))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, &self.server)
            .body(body)
            .map_err(|_| Error::Protocol("Bad request".into()))?;
        let h = req.headers_mut();
        if let Some(token) = token {
            let value = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| Error::Protocol("Bad token".into()))?;
            h.insert(header::AUTHORIZATION, value);
        }
        for (name, value) in headers {
            let name = header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| Error::Protocol("Bad header".into()))?;
            let value =
                HeaderValue::from_str(value).map_err(|_| Error::Protocol("Bad header".into()))?;
            h.insert(name, value);
        }
        sender
            .send_request(req)
            .await
            .map_err(|e| Error::Network(format!("Request failed: {e}")))
    }

    /// Sends JSON (or nothing) and parses a JSON reply. Non-2xx replies
    /// become [`Error::Server`] with the server's sanitised message.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&impl Serialize>,
    ) -> Result<T, Error> {
        let bytes = match body {
            Some(b) => Bytes::from(
                serde_json::to_vec(b).map_err(|_| Error::Protocol("Bad request".into()))?,
            ),
            None => Bytes::new(),
        };
        let headers = if body.is_some() {
            vec![("content-type", "application/json".to_owned())]
        } else {
            Vec::new()
        };
        let res = self.send(method, path, token, &headers, bytes).await?;
        let (status, body) = read_small(res).await?;
        if !status.is_success() {
            return Err(server_error(status, &body));
        }
        let body = if body.is_empty() {
            Bytes::from_static(b"null")
        } else {
            body
        };
        serde_json::from_slice(&body).map_err(|_| Error::Protocol("Unexpected server reply".into()))
    }
}

/// A request body that records how much of it the connection has taken.
/// A piece counts as sent once the next one is asked for.
struct Counted {
    data: Bytes,
    handed: u64,
    sent: Arc<AtomicU64>,
}

impl Body for Counted {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        this.sent.store(this.handed, Ordering::Relaxed);
        if this.data.is_empty() {
            return Poll::Ready(None);
        }
        let piece = this.data.split_to(this.data.len().min(BODY_PIECE));
        this.handed += piece.len() as u64;
        Poll::Ready(Some(Ok(Frame::data(piece))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.len() as u64)
    }
}

/// Reads a whole response body of at most [`MAX_JSON_BODY`] bytes.
pub async fn read_small(res: Response<Incoming>) -> Result<(StatusCode, Bytes), Error> {
    let status = res.status();
    let body = Limited::new(res.into_body(), MAX_JSON_BODY)
        .collect()
        .await
        .map_err(|_| Error::Protocol("Server reply is too large".into()))?
        .to_bytes();
    Ok((status, body))
}

pub fn server_error(status: StatusCode, body: &[u8]) -> Error {
    let message = serde_json::from_slice::<ErrorBody>(body)
        .map(|b| sanitize(&b.error, MAX_ERROR_CHARS))
        .unwrap_or_else(|_| format!("HTTP {}", status.as_u16()));
    Error::Server {
        status: status.as_u16(),
        message,
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tokio::io::AsyncReadExt;

    use super::*;

    /// A server that takes the whole body and never answers, like a Tor
    /// stream that died without closing.
    #[tokio::test]
    async fn stalled_request_fails_and_reports_progress() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("s.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            while stream.read(&mut buf).await.unwrap_or(0) > 0 {}
        });
        let net = Net::direct(&socket, "test.onion");
        let total = 4 * BODY_PIECE;
        let mut seen = Vec::new();
        let result = net
            .send_watched_with(
                Method::PUT,
                "/",
                None,
                &[],
                Bytes::from(vec![0u8; total]),
                |n| seen.push(n),
                Duration::from_secs(1),
            )
            .await;
        assert!(matches!(result, Err(Error::Network(_))), "{result:?}");
        assert!(seen.windows(2).all(|w| w[0] < w[1]), "{seen:?}");
        assert!(
            seen.last().is_some_and(|n| *n > 0 && *n <= total as u64),
            "{seen:?}"
        );
    }
}
