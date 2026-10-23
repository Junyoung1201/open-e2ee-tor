use std::path::PathBuf;

use clap::{ArgGroup, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "o2ee",
    version,
    about = "End-to-end encrypted file sharing over Tor"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Request a new account (an admin must approve it)
    Signup {
        #[arg(long, value_name = "ID")]
        id: String,
    },
    /// Log in and keep the session until logout or expiry
    Login {
        #[arg(long, value_name = "ID")]
        id: String,
    },
    /// End the session and forget the unlocked keys
    Logout,
    /// Show login, key fingerprint and Tor status
    Status,
    /// Send a file or a zipped folder to another account
    #[command(group(ArgGroup::new("source").required(true).args(["file", "dir"])))]
    Send {
        #[arg(long, value_name = "ID")]
        target: String,
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
    },
    /// Download a received transfer
    Download {
        #[arg(value_name = "TRANSFER_ID")]
        transfer: String,
        /// Folder to save into (default: your Downloads folder)
        #[arg(long, value_name = "DIR")]
        output: Option<PathBuf>,
    },
    /// List received transfers
    Inbox,
    /// Install a newer signed release of o2ee
    Update,
    /// Background process started by `login` (internal)
    #[command(hide = true)]
    Agent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use clap::error::ErrorKind;

    fn parse(args: &[&str]) -> Result<Command, ErrorKind> {
        Cli::try_parse_from(std::iter::once("o2ee").chain(args.iter().copied()))
            .map(|cli| cli.command)
            .map_err(|e| e.kind())
    }

    #[test]
    fn definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn send_needs_exactly_one_source() {
        assert!(matches!(
            parse(&["send", "--target", "bob", "--file", "a.txt"]),
            Ok(Command::Send {
                file: Some(_),
                dir: None,
                ..
            })
        ));
        assert!(matches!(
            parse(&["send", "--target", "bob", "--dir", "photos"]),
            Ok(Command::Send {
                file: None,
                dir: Some(_),
                ..
            })
        ));
        assert_eq!(
            parse(&["send", "--target", "bob", "--file", "a", "--dir", "b"]).err(),
            Some(ErrorKind::ArgumentConflict)
        );
        assert_eq!(
            parse(&["send", "--target", "bob"]).err(),
            Some(ErrorKind::MissingRequiredArgument)
        );
    }

    #[test]
    fn passwords_are_never_arguments() {
        for flag in ["--pw", "-pw", "--password"] {
            assert_eq!(
                parse(&["login", "--id", "alice", flag, "secret"]).err(),
                Some(ErrorKind::UnknownArgument),
                "{flag}"
            );
            assert_eq!(
                parse(&["signup", "--id", "alice", flag, "secret"]).err(),
                Some(ErrorKind::UnknownArgument),
                "{flag}"
            );
        }
    }

    #[test]
    fn download_output_is_optional() {
        assert!(matches!(
            parse(&["download", "abc"]),
            Ok(Command::Download { output: None, .. })
        ));
        assert!(matches!(
            parse(&["download", "abc", "--output", "/tmp/x"]),
            Ok(Command::Download {
                output: Some(_),
                ..
            })
        ));
    }
}
