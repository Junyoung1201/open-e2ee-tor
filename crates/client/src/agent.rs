//! The login agent: a background process that holds the session token,
//! the unlocked private keys and the Tor client in memory, and serves the
//! other commands over a Unix socket only this user can open.
//!
//! It exits on `logout`, when the session expires, when the server ends
//! the session, or on reboot. Nothing it holds is written to disk.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use age::secrecy::SecretString;
use o2ee_protocol::Username;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Notify, mpsc};
use zeroize::Zeroize;

use crate::Error;
use crate::net::Net;
use crate::ops::{self, Phase, Progress, Session, Source};
use crate::paths::{Paths, private_dir};

const MAX_LINE: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Login {
        id: String,
        password: String,
    },
    Status,
    Logout,
    Lookup {
        username: String,
    },
    Trust {
        username: String,
        fingerprint: String,
    },
    Send {
        target: String,
        path: PathBuf,
        dir: bool,
    },
    Inbox,
    Peek {
        id: String,
    },
    Download {
        id: String,
        output: PathBuf,
    },
}

impl Drop for Request {
    fn drop(&mut self) {
        if let Self::Login { password, .. } = self {
            password.zeroize();
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Progress(Progress),
    Done { value: Value },
    Error { message: String, login: bool },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    pub username: String,
    pub expires_in: u64,
    pub fingerprint: String,
    pub tor: bool,
}

// ----------------------------------------------------------- client side

/// A connection to a running agent.
pub struct Client {
    stream: BufReader<UnixStream>,
}

impl Client {
    /// Connects to the agent, if one is running.
    pub async fn connect(paths: &Paths) -> Option<Self> {
        UnixStream::connect(paths.agent_socket())
            .await
            .ok()
            .map(|s| Self {
                stream: BufReader::new(s),
            })
    }

    /// Sends one request and returns its final value. Progress events go
    /// to `on_progress`.
    pub async fn request(
        mut self,
        req: &Request,
        mut on_progress: impl FnMut(&Progress),
    ) -> Result<Value, AgentError> {
        let mut line = serde_json::to_vec(req).map_err(|_| AgentError::Lost)?;
        line.push(b'\n');
        self.stream
            .get_mut()
            .write_all(&line)
            .await
            .map_err(|_| AgentError::Lost)?;
        line.zeroize();
        loop {
            let mut buf = String::new();
            let n = (&mut self.stream)
                .take(MAX_LINE as u64)
                .read_line(&mut buf)
                .await
                .map_err(|_| AgentError::Lost)?;
            if n == 0 {
                return Err(AgentError::Lost);
            }
            match serde_json::from_str::<Event>(&buf).map_err(|_| AgentError::Lost)? {
                Event::Progress(p) => on_progress(&p),
                Event::Done { value } => return Ok(value),
                Event::Error { message, login } => {
                    return Err(AgentError::Failed { message, login });
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum AgentError {
    Lost,
    Failed { message: String, login: bool },
}

/// Starts a detached agent process (`o2ee agent`) and waits for its
/// socket.
pub async fn spawn(paths: &Paths) -> Result<Client, Error> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().map_err(|e| Error::Local(e.to_string()))?;
    std::process::Command::new(exe)
        .arg("agent")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        // Own process group: closing the terminal does not take it down.
        .process_group(0)
        .spawn()
        .map_err(|e| Error::Local(format!("Cannot start agent: {e}")))?;
    for _ in 0..100 {
        if let Some(c) = Client::connect(paths).await {
            return Ok(c);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(Error::Local("Agent did not start".into()))
}

// ------------------------------------------------------------ agent side

/// Makes this process harder to inspect: no core dumps, and on Linux not
/// ptrace-able or readable through /proc by other processes of the user.
fn harden() {
    let _ = rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );
    #[cfg(target_os = "linux")]
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);
}

fn bind(path: &Path) -> Result<UnixListener, Error> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        private_dir(dir)?;
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .map_err(|e| Error::Local(format!("Cannot open agent socket: {e}")))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::Local(e.to_string()))?;
    Ok(listener)
}

async fn accept_own(listener: &UnixListener) -> Option<UnixStream> {
    let uid = rustix::process::getuid().as_raw();
    loop {
        let (stream, _) = listener.accept().await.ok()?;
        if stream.peer_cred().is_ok_and(|c| c.uid() == uid) {
            return Some(stream);
        }
    }
}

async fn read_request(stream: &mut BufReader<UnixStream>) -> Option<Request> {
    let mut buf = String::new();
    let n = (&mut *stream)
        .take(MAX_LINE as u64)
        .read_line(&mut buf)
        .await
        .ok()?;
    let req = (n > 0).then(|| serde_json::from_str(&buf).ok()).flatten();
    buf.zeroize();
    req
}

async fn reply(stream: &mut BufReader<UnixStream>, event: &Event) {
    if let Ok(mut line) = serde_json::to_vec(event) {
        line.push(b'\n');
        let _ = stream.get_mut().write_all(&line).await;
    }
}

fn failure(e: &Error) -> Event {
    Event::Error {
        message: e.to_string(),
        login: matches!(e, Error::Server { status: 401, .. }),
    }
}

/// Entry point of `o2ee agent`.
pub async fn run(paths: Paths) -> Result<(), Error> {
    harden();
    let socket = paths.agent_socket();
    let listener = bind(&socket)?;
    let result = serve(&paths, &listener).await;
    let _ = std::fs::remove_file(&socket);
    result
}

async fn serve(paths: &Paths, listener: &UnixListener) -> Result<(), Error> {
    // The first request must be the login, within a minute.
    let Ok(Some(stream)) =
        tokio::time::timeout(Duration::from_secs(60), accept_own(listener)).await
    else {
        return Ok(());
    };
    let mut stream = BufReader::new(stream);
    let Some(first) = read_request(&mut stream).await else {
        return Ok(());
    };
    let Request::Login { id, password } = &first else {
        return Ok(());
    };
    let session = match login(paths, id, password, &mut stream).await {
        Ok(s) => s,
        Err(e) => {
            reply(&mut stream, &failure(&e)).await;
            return Ok(());
        }
    };
    reply(
        &mut stream,
        &Event::Done {
            value: serde_json::json!({ "username": session.user.as_str() }),
        },
    )
    .await;
    drop(stream);
    drop(first);

    let deadline = session.expires;
    let session = Arc::new(session);
    let stop = Arc::new(Notify::new());
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        tokio::select! {
            _ = tokio::time::sleep(left) => return Ok(()),
            _ = stop.notified() => return Ok(()),
            conn = accept_own(listener) => {
                let Some(conn) = conn else { return Ok(()) };
                let (session, stop) = (session.clone(), stop.clone());
                tokio::spawn(async move { handle(session, BufReader::new(conn), stop).await });
            }
        }
    }
}

async fn login(
    paths: &Paths,
    id: &str,
    password: &str,
    stream: &mut BufReader<UnixStream>,
) -> Result<Session, Error> {
    let user = Username::parse(id).map_err(|e| Error::Local(e.to_string()))?;
    let (server, _) = paths.server()?;
    reply(
        stream,
        &Event::Progress(Progress {
            phase: Phase::Connecting,
            done: 0,
            total: 0,
        }),
    )
    .await;
    let net = Net::tor(&server, &paths.tor()).await?;
    let password = SecretString::from(password.to_owned());
    ops::login(net, paths.clone(), &user, &password).await
}

async fn handle(session: Arc<Session>, mut stream: BufReader<UnixStream>, stop: Arc<Notify>) {
    let Some(req) = read_request(&mut stream).await else {
        return;
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Progress>();
    let work = run_request(&session, &req, tx, &stop);
    tokio::pin!(work);
    let result = loop {
        tokio::select! {
            r = &mut work => break r,
            Some(p) = rx.recv() => reply(&mut stream, &Event::Progress(p)).await,
        }
    };
    while let Ok(p) = rx.try_recv() {
        reply(&mut stream, &Event::Progress(p)).await;
    }
    let event = match result {
        Ok(value) => Event::Done { value },
        Err(e) => failure(&e),
    };
    // The server ended the session (expired, suspended, or ended by the
    // admin): there is nothing left to serve.
    if matches!(event, Event::Error { login: true, .. }) {
        stop.notify_one();
    }
    reply(&mut stream, &event).await;
}

fn user(name: &str) -> Result<Username, Error> {
    Username::parse(name).map_err(|e| Error::Local(format!("Invalid ID: {e}")))
}

fn to_value<T: Serialize>(v: &T) -> Result<Value, Error> {
    serde_json::to_value(v).map_err(|_| Error::Local("Internal error".into()))
}

async fn run_request(
    s: &Session,
    req: &Request,
    tx: mpsc::UnboundedSender<Progress>,
    stop: &Notify,
) -> Result<Value, Error> {
    match req {
        Request::Login { .. } => Err(Error::Local(format!(
            "Already logged in as {}. Run o2ee logout first.",
            s.user
        ))),
        Request::Status => {
            let me = s.me().await?;
            to_value(&Status {
                username: me.username,
                expires_in: s
                    .expires
                    .saturating_duration_since(Instant::now())
                    .as_secs(),
                fingerprint: s.fingerprint(),
                tor: s.net.is_tor(),
            })
        }
        Request::Logout => {
            stop.notify_one();
            Ok(Value::Null)
        }
        Request::Lookup { username } => {
            let (fingerprint, trust) = s.lookup(&user(username)?).await?;
            Ok(serde_json::json!({ "fingerprint": fingerprint, "trust": trust }))
        }
        Request::Trust {
            username,
            fingerprint,
        } => {
            s.trust(&user(username)?, fingerprint).await?;
            Ok(Value::Null)
        }
        Request::Send { target, path, dir } => {
            let source = if *dir { Source::Dir } else { Source::File };
            let id = s.send(&user(target)?, path, source, Some(tx)).await?;
            Ok(Value::String(id))
        }
        Request::Inbox => to_value(&s.inbox().await?),
        Request::Peek { id } => to_value(&s.peek(id).await?),
        Request::Download { id, output } => {
            let path = s.download(id, output, Some(tx)).await?;
            Ok(Value::String(path.display().to_string()))
        }
    }
}
