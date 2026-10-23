//! o2ee: command-line client for open-e2ee-share-tor.
//!
//! There is deliberately no option or environment variable that carries a
//! password; passwords are only ever read from the terminal.

mod cli;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use age::secrecy::ExposeSecret;
use clap::Parser;
use o2ee::agent::{self, AgentError, Request, Status};
use o2ee::net::Net;
use o2ee::ops::{self, InboxItem, Peek, Trust};
use o2ee::paths::Paths;
use o2ee::tty::{self, ProgressLine};
use o2ee_protocol::Username;
use serde::Deserialize;
use serde_json::Value;

use cli::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            tty::err(&format!("Cannot start: {e}"));
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli.command)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            tty::err(&message);
            ExitCode::FAILURE
        }
    }
}

fn parse_id(id: &str, what: &str) -> Result<Username, String> {
    Username::parse(id).map_err(|e| format!("Invalid {what}: {e}"))
}

async fn run(command: Command) -> Result<(), String> {
    let paths = Paths::discover().map_err(|e| e.to_string())?;
    match command {
        Command::Agent => agent::run(paths).await.map_err(|e| e.to_string()),
        Command::Signup { id } => signup(&paths, &id).await,
        Command::Login { id } => login(&paths, &id).await,
        Command::Logout => match agent::Client::connect(&paths).await {
            Some(c) => {
                let _ = c.request(&Request::Logout, |_| {}).await;
                tty::out("Logged out");
                Ok(())
            }
            None => {
                tty::out("Not logged in");
                Ok(())
            }
        },
        Command::Status => status(&paths).await,
        Command::Send { target, file, dir } => {
            let target = parse_id(&target, "target")?;
            let (path, is_dir) = match (file, dir) {
                (Some(f), None) => (f, false),
                (None, Some(d)) => (d, true),
                _ => return Err("Use exactly one of --file or --dir".into()),
            };
            send(&paths, &target, &path, is_dir).await
        }
        Command::Download { transfer, output } => download(&paths, &transfer, output).await,
        Command::Inbox => inbox(&paths).await,
        Command::Update => update(&paths).await,
    }
}

/// Runs a request on the agent, drawing progress.
async fn ask(paths: &Paths, req: &Request) -> Result<Value, String> {
    let client = agent::Client::connect(paths)
        .await
        .ok_or("Not logged in. Run o2ee login first.")?;
    let mut line = ProgressLine::default();
    let result = client.request(req, |p| line.update(p)).await;
    line.finish();
    match result {
        Ok(v) => Ok(v),
        Err(AgentError::Lost) => Err("Lost connection to the login agent".into()),
        Err(AgentError::Failed {
            message,
            login: true,
        }) => Err(format!("{message}. Session ended; run o2ee login again.")),
        Err(AgentError::Failed { message, .. }) => Err(message),
    }
}

fn decode<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T, String> {
    serde_json::from_value(v).map_err(|_| "Unexpected reply from the login agent".to_owned())
}

async fn signup(paths: &Paths, id: &str) -> Result<(), String> {
    let user = parse_id(id, "ID")?;
    let (server, warning) = paths.server().map_err(|e| e.to_string())?;
    if let Some(w) = warning {
        tty::err(&w);
    }
    let password = tty::password("password: ").map_err(|e| e.to_string())?;
    ops::check_password_strength(password.expose_secret(), &user).map_err(|e| e.to_string())?;
    let again = tty::password("re-enter password: ").map_err(|e| e.to_string())?;
    if password.expose_secret() != again.expose_secret() {
        return Err("Passwords do not match".into());
    }
    drop(again);
    let mut line = ProgressLine::default();
    line.update(&ops::Progress {
        phase: ops::Phase::Connecting,
        done: 0,
        total: 0,
    });
    let net = Net::tor(&server, &paths.tor()).await;
    line.finish();
    let net = net.map_err(|e| format!("Signup failed: \"{e}\""))?;
    let fingerprint = ops::signup(&net, paths, &user, &password)
        .await
        .map_err(|e| format!("Signup failed: \"{e}\""))?;
    tty::out("Signup requested. Waiting for approval.");
    tty::out(&format!("Fingerprint: {fingerprint}"));
    Ok(())
}

async fn login(paths: &Paths, id: &str) -> Result<(), String> {
    let user = parse_id(id, "ID")?;
    if let Some(c) = agent::Client::connect(paths).await {
        return match c.request(&Request::Status, |_| {}).await {
            Ok(v) => {
                let s: Status = decode(v)?;
                if s.username == user.as_str() {
                    tty::out(&format!("Logged in as {}", s.username));
                    Ok(())
                } else {
                    Err(format!(
                        "Already logged in as {}. Run o2ee logout first.",
                        s.username
                    ))
                }
            }
            Err(_) => Err("A login agent is running but not responding. Run o2ee logout.".into()),
        };
    }
    let (_, warning) = paths.server().map_err(|e| e.to_string())?;
    if let Some(w) = warning {
        tty::err(&w);
    }
    let password = tty::password("password: ").map_err(|e| e.to_string())?;
    let client = agent::spawn(paths).await.map_err(|e| e.to_string())?;
    let req = Request::Login {
        id: user.to_string(),
        password: password.expose_secret().to_owned(),
    };
    drop(password);
    let mut line = ProgressLine::default();
    let result = client.request(&req, |p| line.update(p)).await;
    drop(req);
    line.finish();
    match result {
        Ok(_) => {
            tty::out(&format!("Logged in as {user}"));
            Ok(())
        }
        Err(AgentError::Failed { message, .. }) => Err(format!("Login failed: \"{message}\"")),
        Err(AgentError::Lost) => Err("Login failed: \"Login agent stopped\"".into()),
    }
}

async fn status(paths: &Paths) -> Result<(), String> {
    let Some(c) = agent::Client::connect(paths).await else {
        tty::out("Not logged in");
        return Ok(());
    };
    match c.request(&Request::Status, |_| {}).await {
        Ok(v) => {
            let s: Status = decode(v)?;
            let (h, m) = (s.expires_in / 3600, s.expires_in % 3600 / 60);
            tty::out(&format!(
                "Logged in as {} (expires in {h}h {m}m)",
                s.username
            ));
            tty::out(&format!("Fingerprint: {}", s.fingerprint));
            tty::out(if s.tor {
                "Tor: connected"
            } else {
                "Tor: not used (debug direct connection)"
            });
            Ok(())
        }
        Err(AgentError::Failed { login: true, .. }) | Err(AgentError::Lost) => {
            tty::out("Not logged in");
            Ok(())
        }
        Err(AgentError::Failed { message, .. }) => Err(message),
    }
}

#[derive(Deserialize)]
struct Lookup {
    fingerprint: String,
    trust: Trust,
}

/// Makes sure `user`'s keys are pinned, asking the user to compare the
/// fingerprint the first time.
async fn ensure_trusted(
    paths: &Paths,
    user: &str,
    fingerprint: &str,
    trust: &Trust,
) -> Result<(), String> {
    match trust {
        Trust::Known => Ok(()),
        Trust::Changed => Err(format!(
            "Keys of {user} changed since you verified them. Refused."
        )),
        Trust::New => {
            let question = format!("Verify {user} fingerprint: {fingerprint}");
            if !tty::confirm(&question).map_err(|e| e.to_string())? {
                return Err("Cancelled".into());
            }
            ask(
                paths,
                &Request::Trust {
                    username: user.to_owned(),
                    fingerprint: fingerprint.to_owned(),
                },
            )
            .await
            .map(|_| ())
        }
    }
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    std::path::absolute(path).map_err(|e| format!("{}: {e}", path.display()))
}

async fn send(paths: &Paths, target: &Username, path: &Path, is_dir: bool) -> Result<(), String> {
    let path = absolute(path)?;
    let meta = std::fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if is_dir && !meta.is_dir() {
        return Err(format!("Not a folder: {}", path.display()));
    }
    if !is_dir && !meta.is_file() {
        return Err(format!("Not a file: {}", path.display()));
    }
    let lookup: Lookup = decode(
        ask(
            paths,
            &Request::Lookup {
                username: target.to_string(),
            },
        )
        .await?,
    )?;
    ensure_trusted(paths, target.as_str(), &lookup.fingerprint, &lookup.trust).await?;
    let id: String = decode(
        ask(
            paths,
            &Request::Send {
                target: target.to_string(),
                path,
                dir: is_dir,
            },
        )
        .await?,
    )?;
    tty::out(&format!("Sent to {target}. Transfer ID: {id}"));
    Ok(())
}

fn default_downloads() -> Result<PathBuf, String> {
    let dir = dirs::download_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
        .ok_or("Cannot find your Downloads folder; use --output")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir)
}

async fn download(paths: &Paths, id: &str, output: Option<PathBuf>) -> Result<(), String> {
    let id = id.trim().to_ascii_lowercase();
    if !o2ee_protocol::container::valid_transfer_id(&id) {
        return Err("Invalid transfer ID".into());
    }
    let output = match output {
        Some(dir) => {
            let dir = absolute(&dir)?;
            if !dir.is_dir() {
                return Err(format!("Output folder does not exist: {}", dir.display()));
            }
            dir
        }
        None => default_downloads()?,
    };
    let peek: Peek = decode(ask(paths, &Request::Peek { id: id.clone() }).await?)?;
    ensure_trusted(paths, &peek.sender, &peek.fingerprint, &peek.trust).await?;
    let saved: String = decode(ask(paths, &Request::Download { id, output }).await?)?;
    tty::out(&format!("Saved to {saved}"));
    Ok(())
}

fn size(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_000_000.0)
}

async fn inbox(paths: &Paths) -> Result<(), String> {
    let items: Vec<InboxItem> = decode(ask(paths, &Request::Inbox).await?)?;
    if items.is_empty() {
        tty::out("No transfers");
        return Ok(());
    }
    tty::out(&format!(
        "{:<32}  {:<20}  {:>10}  {:>7}  NAME",
        "ID", "FROM", "SIZE", "EXPIRES"
    ));
    for item in items {
        let expires = format!("{}h", item.expires_in.div_ceil(3600));
        let (from, size_text, name) = match &item.peek {
            Some(p) => {
                let from = match p.trust {
                    Trust::Known => p.sender.clone(),
                    Trust::New => format!("{} (new)", p.sender),
                    Trust::Changed => format!("{} (KEY CHANGED)", p.sender),
                };
                (from, size(p.size), p.name.clone())
            }
            None => (
                "unverified".to_owned(),
                format!("~{}", size(item.ciphertext_size)),
                "-".to_owned(),
            ),
        };
        tty::out(&format!(
            "{:<32}  {:<20}  {:>10}  {:>7}  {name}",
            item.id, from, size_text, expires
        ));
    }
    Ok(())
}

async fn update(paths: &Paths) -> Result<(), String> {
    use o2ee::update::{Outcome, RELEASE_PUBKEY};
    let key = RELEASE_PUBKEY.ok_or("Updates are disabled in this build (no release key)")?;
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| format!("Cannot find the o2ee executable: {e}"))?;
    let (server, warning) = paths.server().map_err(|e| e.to_string())?;
    if let Some(w) = warning {
        tty::err(&w);
    }
    tty::err("Checking for updates...");
    let mut line = ProgressLine::default();
    line.update(&ops::Progress {
        phase: ops::Phase::Connecting,
        done: 0,
        total: 0,
    });
    let net = Net::tor(&server, &paths.tor()).await;
    line.finish();
    let net = net.map_err(|e| format!("Update failed: \"{e}\""))?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let current = env!("CARGO_PKG_VERSION");
    let work = o2ee::update::update(&net, key, current, &exe, Some(tx));
    tokio::pin!(work);
    let result = loop {
        tokio::select! {
            r = &mut work => break r,
            Some(p) = rx.recv() => line.update(&p),
        }
    };
    line.finish();
    match result.map_err(|e| format!("Update failed: \"{e}\""))? {
        Outcome::UpToDate(v) => tty::out(&format!("Already up to date (v{v})")),
        Outcome::Updated(v) => {
            // The running agent is the old binary; end it.
            if let Some(c) = agent::Client::connect(paths).await {
                let _ = c.request(&Request::Logout, |_| {}).await;
                tty::out(&format!("Updated to v{v}. Log in again."));
            } else {
                tty::out(&format!("Updated to v{v}"));
            }
        }
    }
    Ok(())
}
