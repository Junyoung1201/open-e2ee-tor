//! o2ee client library: everything behind the `o2ee` command.

#[cfg(not(unix))]
compile_error!("o2ee currently supports Unix-like systems (Linux, macOS) only");

pub mod agent;
pub mod net;
pub mod ops;
pub mod paths;
pub mod tty;
pub mod update;

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Problem on this device (files, input, policy).
    Local(String),
    /// Tor or connection failure; usually worth retrying.
    Network(String),
    /// The server refused; `message` is already sanitised.
    Server { status: u16, message: String },
    /// The server replied with something that does not follow the protocol.
    Protocol(String),
    /// A signature, key or ciphertext check failed.
    Verify(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(m)
            | Self::Network(m)
            | Self::Protocol(m)
            | Self::Server { message: m, .. } => f.write_str(m),
            Self::Verify(m) => write!(f, "Verification failed: {m}"),
        }
    }
}

impl std::error::Error for Error {}
