//! o2ee-server command line.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use o2ee_server::admin::{MIN_ADMIN_PASSWORD_CHARS, set_admin_password};
use o2ee_server::{App, bind_public, serve};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "o2ee-server",
    version,
    about = "open-e2ee-share-tor relay server"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the onion API and the local admin page
    Run {
        #[arg(long, value_name = "DIR")]
        data_dir: PathBuf,
        /// Unix socket that torrc's HiddenServicePort points to
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
        /// Tor's hostname file for this onion service
        #[arg(long, value_name = "FILE", conflicts_with = "onion")]
        onion_hostname_file: Option<PathBuf>,
        /// Onion address, if not read from the hostname file
        #[arg(long, value_name = "ADDRESS")]
        onion: Option<String>,
        /// Admin page port on 127.0.0.1
        #[arg(long, default_value_t = 8788)]
        admin_port: u16,
    },
    /// Set the admin page password (asked twice on the terminal)
    SetAdminPassword {
        #[arg(long, value_name = "DIR")]
        data_dir: PathBuf,
    },
    /// Publish a signed client release (made by deploy/make-release.sh)
    PublishRelease {
        #[arg(long, value_name = "DIR")]
        data_dir: PathBuf,
        /// Folder with manifest.json, its .minisig, minisign.pub and binaries
        #[arg(long, value_name = "DIR")]
        from: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "{message}");
            ExitCode::FAILURE
        }
    }
}

fn valid_onion(name: &str) -> bool {
    name.strip_suffix(".onion").is_some_and(|base| {
        base.len() == 56 && base.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    })
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::PublishRelease { data_dir, from } => {
            let version = o2ee_server::release::publish(&data_dir, &from)?;
            let _ = writeln!(std::io::stderr(), "Published release {version}");
            Ok(())
        }
        Command::SetAdminPassword { data_dir } => {
            let first = Zeroizing::new(
                rpassword::prompt_password("New admin password: ")
                    .map_err(|_| "Password input requires a terminal".to_owned())?,
            );
            if first.chars().count() < MIN_ADMIN_PASSWORD_CHARS {
                return Err(format!(
                    "Password must be at least {MIN_ADMIN_PASSWORD_CHARS} characters"
                ));
            }
            let second = Zeroizing::new(
                rpassword::prompt_password("Re-enter password: ")
                    .map_err(|_| "Password input requires a terminal".to_owned())?,
            );
            if *first != *second {
                return Err("Passwords do not match".into());
            }
            set_admin_password(&data_dir, &first).map_err(|e| format!("Cannot save: {e}"))?;
            let _ = writeln!(std::io::stderr(), "Admin password set");
            Ok(())
        }
        Command::Run {
            data_dir,
            socket,
            onion_hostname_file,
            onion,
            admin_port,
        } => {
            let name = match (onion, onion_hostname_file) {
                (Some(name), _) => name,
                (None, Some(file)) => std::fs::read_to_string(&file)
                    .map_err(|e| format!("Cannot read {}: {e}", file.display()))?
                    .trim()
                    .to_owned(),
                (None, None) => return Err("Give --onion-hostname-file or --onion".into()),
            };
            if !valid_onion(&name) {
                return Err(format!("Not a v3 onion address: {name}"));
            }
            let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            runtime.block_on(async {
                let app = App::open(&data_dir, &name, o2ee_protocol::crypto::pow::DIFFICULTY)
                    .map_err(|e| format!("Cannot open data dir: {e}"))?;
                let public =
                    bind_public(&socket).map_err(|e| format!("Cannot bind socket: {e}"))?;
                let admin = tokio::net::TcpListener::bind(("127.0.0.1", admin_port))
                    .await
                    .map_err(|e| format!("Cannot bind admin port: {e}"))?;
                let _ = writeln!(
                    std::io::stderr(),
                    "o2ee-server running for {name}; admin page http://127.0.0.1:{admin_port}/"
                );
                serve(app, public, admin).await.map_err(|e| e.to_string())
            })
        }
    }
}
