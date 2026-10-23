//! The real `o2ee` binary: passwords typed into a pseudo-terminal (via
//! util-linux `script`), the background agent, progress and messages.

// The direct (non-Tor) test transport exists only in debug builds.
#![cfg(debug_assertions)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::*;

const BIN: &str = env!("CARGO_BIN_EXE_o2ee");

fn env(cmd: &mut Command, home: &Path, server: &TestServer) {
    cmd.env("O2EE_HOME", home)
        .env("O2EE_SERVER", SERVER)
        .env("O2EE_INSECURE_DIRECT", &server.socket);
}

/// Runs `o2ee <args>` without a terminal.
fn plain(home: &Path, server: &TestServer, args: &[&str]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args).stdin(Stdio::null());
    env(&mut cmd, home, server);
    cmd.output().unwrap()
}

/// Runs `o2ee <args>` on a pseudo-terminal. Each line of `input` is typed
/// only after the next prompt (`password: `, `[y/N] `) appeared, like a
/// person would, so echo is already off when a password is typed.
fn typed(home: &Path, server: &TestServer, args: &[&str], input: &str) -> (bool, String) {
    use std::io::Read;
    use std::sync::mpsc;
    let line = std::iter::once(BIN)
        .chain(args.iter().copied())
        .map(|a| format!("'{a}'"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut cmd = Command::new("script");
    cmd.args(["-qec", &line, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    env(&mut cmd, home, server);
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = out.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut text = Vec::new();
    let mut prompts_seen = 0;
    let mut lines = input.lines();
    while let Ok(chunk) = rx.recv_timeout(std::time::Duration::from_secs(60)) {
        text.extend_from_slice(&chunk);
        let shown = String::from_utf8_lossy(&text);
        let prompts = shown.matches("password: ").count() + shown.matches("[y/N] ").count();
        while prompts_seen < prompts {
            prompts_seen += 1;
            if let Some(l) = lines.next() {
                // Give the program a moment to switch echo off after
                // printing the prompt, as a human would.
                std::thread::sleep(std::time::Duration::from_millis(50));
                stdin.write_all(format!("{l}\n").as_bytes()).unwrap();
                stdin.flush().unwrap();
            }
        }
    }
    drop(stdin);
    let status = child.wait().unwrap();
    let _ = reader.join();
    (
        status.success(),
        String::from_utf8_lossy(&text).replace('\r', ""),
    )
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn pw_line() -> String {
    format!("{PASSWORD}\n")
}

#[tokio::test(flavor = "multi_thread")]
async fn full_cli_session() {
    let server = start().await;
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    // signup asks twice; a mismatch stops before anything is created.
    let (ok, out) = typed(
        alice.path(),
        &server,
        &["signup", "--id", "alice"],
        &format!("{PASSWORD}\nsomething else entirely\n"),
    );
    assert!(!ok);
    assert!(out.contains("Passwords do not match"), "{out}");
    // The password is never echoed.
    assert!(!out.contains(PASSWORD));

    let input = format!("{PASSWORD}\n{PASSWORD}\n");
    let (ok, out) = typed(alice.path(), &server, &["signup", "--id", "alice"], &input);
    assert!(ok, "{out}");
    assert!(out.contains("password: "));
    assert!(out.contains("re-enter password: "));
    assert!(
        out.contains("Signup requested. Waiting for approval."),
        "{out}"
    );
    let fp_line = out
        .lines()
        .find(|l| l.starts_with("Fingerprint: "))
        .unwrap();
    assert_eq!(
        fp_line.trim_start_matches("Fingerprint: "),
        server.app.store.persist().accounts["alice"].fingerprint
    );
    assert!(!out.contains(PASSWORD));
    let (ok, _) = typed(bob.path(), &server, &["signup", "--id", "bob"], &input);
    assert!(ok);

    // Not approved yet.
    let (ok, out) = typed(
        alice.path(),
        &server,
        &["login", "--id", "alice"],
        &pw_line(),
    );
    assert!(!ok);
    assert!(
        out.contains("Login failed: \"Account is waiting for approval\""),
        "{out}"
    );
    server.approve("alice");
    server.approve("bob");

    let (ok, out) = typed(
        alice.path(),
        &server,
        &["login", "--id", "alice"],
        "wrong password here\n",
    );
    assert!(!ok);
    assert!(
        out.contains("Login failed: \"Invalid ID or password\""),
        "{out}"
    );

    let (ok, out) = typed(
        alice.path(),
        &server,
        &["login", "--id", "alice"],
        &pw_line(),
    );
    assert!(ok, "{out}");
    assert!(out.contains("Logged in as alice"));
    // The agent outlived the terminal it was started from.
    let s = plain(alice.path(), &server, &["status"]);
    let text = stdout(&s);
    assert!(
        text.contains("Logged in as alice (expires in 11h 5"),
        "{text}"
    );
    assert!(text.contains(&format!("{fp_line}\n")));
    // Logging in again as the same account is a no-op; as another is not.
    let (ok, out) = typed(alice.path(), &server, &["login", "--id", "alice"], "");
    assert!(ok && out.contains("Logged in as alice"), "{out}");
    let (ok, out) = typed(alice.path(), &server, &["login", "--id", "bob"], "");
    assert!(!ok && out.contains("Already logged in as alice"), "{out}");

    let (ok, _) = typed(bob.path(), &server, &["login", "--id", "bob"], &pw_line());
    assert!(ok);

    // send: first time asks to verify bob's fingerprint; "n" cancels.
    let work = tempfile::tempdir().unwrap();
    let (file, data) = random_file(work.path(), "notes.txt", 1_500_000);
    let file = file.to_str().unwrap().to_owned();
    let (ok, out) = typed(
        alice.path(),
        &server,
        &["send", "--target", "bob", "--file", &file],
        "n\n",
    );
    assert!(!ok);
    assert!(out.contains("Verify bob fingerprint: "), "{out}");
    assert!(out.contains("Cancelled"));
    let (ok, out) = typed(
        alice.path(),
        &server,
        &["send", "--target", "bob", "--file", &file],
        "y\n",
    );
    assert!(ok, "{out}");
    assert!(out.contains("Uploading ("), "{out}");
    assert!(out.contains("MB, 100.0%)"), "{out}");
    let id = out
        .lines()
        .find_map(|l| l.strip_prefix("Sent to bob. Transfer ID: "))
        .unwrap()
        .trim()
        .to_owned();
    assert_eq!(id.len(), 32);

    // Without a terminal there is no progress line, and pinned contacts
    // are not asked about again.
    let o = plain(
        alice.path(),
        &server,
        &["send", "--target", "bob", "--file", &file],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(!stderr(&o).contains("Uploading"));

    let o = plain(bob.path(), &server, &["inbox"]);
    let text = stdout(&o);
    assert!(text.starts_with("ID "), "{text}");
    assert!(text.contains(&id));
    assert!(text.contains("alice (new)"));
    assert!(text.contains("notes.txt"));
    assert!(text.contains("1.5 MB"));

    let out_dir = tempfile::tempdir().unwrap();
    let (ok, out) = typed(
        bob.path(),
        &server,
        &[
            "download",
            &id,
            "--output",
            out_dir.path().to_str().unwrap(),
        ],
        "y\n",
    );
    assert!(ok, "{out}");
    assert!(out.contains("Verify alice fingerprint: "));
    assert!(out.contains("Downloading ("));
    let saved = out_dir.path().join("notes.txt");
    assert!(
        out.contains(&format!("Saved to {}", saved.display())),
        "{out}"
    );
    assert_eq!(std::fs::read(&saved).unwrap(), data);

    // Second transfer is still waiting; sender now shows as verified.
    let text = stdout(&plain(bob.path(), &server, &["inbox"]));
    assert!(text.contains("alice ") && !text.contains("(new)"), "{text}");

    // --output must exist.
    let o = plain(
        bob.path(),
        &server,
        &["download", &id, "--output", "/nonexistent/x"],
    );
    assert!(!o.status.success());
    assert!(stderr(&o).contains("Output folder does not exist"));

    // Folders go as zip.
    let folder = work.path().join("album");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("1.txt"), "one").unwrap();
    let o = plain(
        alice.path(),
        &server,
        &["send", "--target", "bob", "--dir", folder.to_str().unwrap()],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let o = plain(
        alice.path(),
        &server,
        &["send", "--target", "bob", "--dir", &file],
    );
    assert!(stderr(&o).contains("Not a folder"));

    for home in [alice.path(), bob.path()] {
        let o = plain(home, &server, &["logout"]);
        assert_eq!(stdout(&o), "Logged out\n");
        let o = plain(home, &server, &["status"]);
        assert_eq!(stdout(&o), "Not logged in\n");
    }
    let o = plain(alice.path(), &server, &["inbox"]);
    assert!(stderr(&o).contains("Not logged in. Run o2ee login first."));
}

#[tokio::test(flavor = "multi_thread")]
async fn passwords_only_from_a_terminal() {
    let server = start().await;
    let home = tempfile::tempdir().unwrap();
    // stdin carries a password, but there is no terminal: refused.
    // setsid: no controlling terminal even when the test runner has one.
    let mut cmd = {
        let mut c = Command::new("setsid");
        c.arg("-w").arg(BIN).args(["signup", "--id", "alice"]);
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        env(&mut c, home.path(), &server);
        c
    };
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n{PASSWORD}\n").as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("Password input requires a terminal"),
        "{}",
        stderr(&o)
    );
    assert!(server.app.store.persist().accounts.is_empty());

    for flag in ["--pw", "-pw", "--password"] {
        let o = plain(home.path(), &server, &["login", "--id", "alice", flag, "x"]);
        assert!(!o.status.success());
        assert!(stderr(&o).contains("unexpected argument"), "{flag}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn weak_passwords_are_refused_locally() {
    let server = start().await;
    let home = tempfile::tempdir().unwrap();
    let (ok, out) = typed(
        home.path(),
        &server,
        &["signup", "--id", "alice"],
        "short\n",
    );
    assert!(!ok);
    assert!(
        out.contains("Password must be at least 10 characters"),
        "{out}"
    );
    let (ok, out) = typed(
        home.path(),
        &server,
        &["signup", "--id", "alice"],
        "alicealicealice\n",
    );
    assert!(!ok);
    assert!(out.contains("Password is too easy to guess"), "{out}");
    assert!(server.app.store.persist().accounts.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_ending_the_session_stops_the_agent() {
    let server = start().await;
    let home = tempfile::tempdir().unwrap();
    let input = format!("{PASSWORD}\n{PASSWORD}\n");
    assert!(typed(home.path(), &server, &["signup", "--id", "alice"], &input).0);
    server.approve("alice");
    assert!(
        typed(
            home.path(),
            &server,
            &["login", "--id", "alice"],
            &pw_line()
        )
        .0
    );
    server.app.store.end_sessions("alice");
    let o = plain(home.path(), &server, &["inbox"]);
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("Session ended; run o2ee login again."),
        "{}",
        stderr(&o)
    );
    // The agent is gone.
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(
        stdout(&plain(home.path(), &server, &["status"])),
        "Not logged in\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn update_needs_a_built_in_release_key() {
    let server = start().await;
    let home = tempfile::tempdir().unwrap();
    // Test builds carry no release key, so update must refuse to run.
    let o = plain(home.path(), &server, &["update"]);
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("Updates are disabled in this build (no release key)"),
        "{}",
        stderr(&o)
    );
}
