//! HTTP over Tor (or, in debug builds only, over a local Unix socket).
//!
//! The onion address authenticates the server at the Tor layer, so there
//! is no TLS. Every response is size-capped before it is parsed, and every
//! error message from the server is sanitised before it is shown.

use std::path::Path;
#[cfg(debug_assertions)]
use std::path::PathBuf;
use std::sync::Arc;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use o2ee_protocol::api::{ErrorBody, MAX_ERROR_CHARS, MAX_JSON_BODY};
use o2ee_protocol::text::sanitize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};
use tor_rtcompat::PreferredRuntime;

use crate::Error;

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
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, String)],
        body: Bytes,
    ) -> Result<Response<Incoming>, Error> {
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
            .body(Full::new(body))
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
