//! Terminal input and output.
//!
//! Passwords and confirmations are read from the controlling terminal
//! itself, never from stdin, arguments or the environment. Results go to
//! stdout; progress and errors go to stderr.

use std::io::{BufRead, IsTerminal, Write};

use age::secrecy::SecretString;

use crate::Error;
use crate::ops::{Phase, Progress};

fn no_terminal() -> Error {
    Error::Local("Password input requires a terminal".into())
}

/// Reads a password with echo off. rpassword opens `/dev/tty` directly and
/// restores the terminal even when interrupted.
pub fn password(prompt: &str) -> Result<SecretString, Error> {
    let text = rpassword::prompt_password(prompt).map_err(|_| no_terminal())?;
    Ok(SecretString::from(text))
}

/// Asks a yes/no question on the terminal; anything but "y"/"yes" is no.
pub fn confirm(question: &str) -> Result<bool, Error> {
    let fail = || Error::Local("Confirmation requires a terminal".into());
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| fail())?;
    let mut out = &tty;
    write!(out, "{question} [y/N] ").map_err(|_| fail())?;
    out.flush().map_err(|_| fail())?;
    let mut answer = String::new();
    std::io::BufReader::new(&tty)
        .read_line(&mut answer)
        .map_err(|_| fail())?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

pub fn out(line: &str) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

pub fn err(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

fn mb(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / 1_000_000.0)
}

/// Single-line progress on stderr, redrawn in place; silent when stderr is
/// not a terminal.
#[derive(Default)]
pub struct ProgressLine {
    shown: bool,
}

impl ProgressLine {
    pub fn update(&mut self, p: &Progress) {
        let stderr = std::io::stderr();
        if !stderr.is_terminal() {
            return;
        }
        let label = match p.phase {
            Phase::Connecting => {
                let mut e = stderr.lock();
                let _ = write!(e, "\r\x1b[2KConnecting to Tor...");
                let _ = e.flush();
                self.shown = true;
                return;
            }
            Phase::Preparing => "Preparing",
            Phase::Uploading => "Uploading",
            Phase::Downloading => "Downloading",
            Phase::Verifying => "Verifying",
        };
        let pct = if p.total == 0 {
            100.0
        } else {
            p.done as f64 * 100.0 / p.total as f64
        };
        let (done, total) = if p.phase == Phase::Preparing {
            // Preparing hashes then encrypts, so it counts each byte twice.
            (p.done / 2, p.total / 2)
        } else {
            (p.done, p.total)
        };
        let mut e = stderr.lock();
        let _ = write!(
            e,
            "\r\x1b[2K{label} ({}/{} MB, {pct:.1}%)",
            mb(done),
            mb(total)
        );
        let _ = e.flush();
        self.shown = true;
    }

    pub fn finish(&mut self) {
        if self.shown {
            let _ = writeln!(std::io::stderr());
            self.shown = false;
        }
    }
}
