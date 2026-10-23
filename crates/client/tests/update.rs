//! `o2ee update` against a real server: only a correctly signed, newer
//! release for this server and platform may replace the executable.

// The direct (non-Tor) test transport exists only in debug builds.
#![cfg(debug_assertions)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::*;
use o2ee::Error;
use o2ee::update::{Outcome, update};
use o2ee_protocol::release::{Manifest, ReleaseFile, current_target};
use sha2::Digest;

struct Fixture {
    server: TestServer,
    key: minisign::KeyPair,
    exe_dir: tempfile::TempDir,
    exe: PathBuf,
}

async fn fixture() -> Fixture {
    let server = start().await;
    let exe_dir = tempfile::tempdir().unwrap();
    let exe = exe_dir.path().join("o2ee");
    std::fs::write(&exe, b"old binary").unwrap();
    Fixture {
        server,
        key: minisign::KeyPair::generate_unencrypted_keypair().unwrap(),
        exe_dir,
        exe,
    }
}

fn make_release(
    dir: &Path,
    kp: &minisign::KeyPair,
    version: &str,
    server: &str,
    target: &str,
    binary: &[u8],
) {
    std::fs::create_dir_all(dir).unwrap();
    let name = format!("o2ee-{target}");
    std::fs::write(dir.join(&name), binary).unwrap();
    let manifest = serde_json::to_string(&Manifest {
        product: "o2ee".into(),
        version: version.into(),
        server: server.into(),
        files: vec![ReleaseFile {
            target: target.into(),
            name,
            size: binary.len() as u64,
            sha256: hex::encode(sha2::Sha256::digest(binary)),
        }],
    })
    .unwrap();
    std::fs::write(dir.join("manifest.json"), &manifest).unwrap();
    let sig = minisign::sign(Some(&kp.pk), &kp.sk, manifest.as_bytes(), None, None).unwrap();
    std::fs::write(dir.join("manifest.json.minisig"), sig.into_string()).unwrap();
    std::fs::write(
        dir.join("minisign.pub"),
        kp.pk.to_box().unwrap().to_string(),
    )
    .unwrap();
}

impl Fixture {
    fn publish(&self, kp: &minisign::KeyPair, version: &str, server: &str, binary: &[u8]) {
        let dir = self.exe_dir.path().join(format!("rel-{version}"));
        make_release(&dir, kp, version, server, &current_target(), binary);
        o2ee_server::release::publish(self.server.app.store.dir(), &dir).unwrap();
    }

    async fn run(&self, current: &str) -> Result<Outcome, Error> {
        update(
            &self.server.net(),
            &self.key.pk.to_base64(),
            current,
            &self.exe,
            None,
        )
        .await
    }

    fn exe_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.exe).unwrap()
    }

    fn leftovers(&self) -> usize {
        std::fs::read_dir(self.exe_dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".o2ee-update-")
            })
            .count()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn installs_a_newer_signed_release() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture().await;
    // Nothing published yet.
    assert_eq!(
        f.run("0.1.0").await.unwrap(),
        Outcome::UpToDate("0.1.0".into())
    );

    f.publish(&f.key, "0.2.0", SERVER, b"new binary");
    assert_eq!(
        f.run("0.1.0").await.unwrap(),
        Outcome::Updated("0.2.0".into())
    );
    assert_eq!(f.exe_bytes(), b"new binary");
    let mode = std::fs::metadata(&f.exe).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
    assert_eq!(f.leftovers(), 0);

    // Same or newer local version: nothing to do (no downgrades).
    assert_eq!(
        f.run("0.2.0").await.unwrap(),
        Outcome::UpToDate("0.2.0".into())
    );
    assert_eq!(
        f.run("1.0.0").await.unwrap(),
        Outcome::UpToDate("1.0.0".into())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_releases_signed_with_another_key() {
    let f = fixture().await;
    let attacker = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    // A compromised server publishes its own release with its own key.
    f.publish(&attacker, "9.0.0", SERVER, b"malware");
    assert!(matches!(f.run("0.1.0").await, Err(Error::Verify(_))));
    assert_eq!(f.exe_bytes(), b"old binary");
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_a_swapped_binary() {
    let f = fixture().await;
    f.publish(&f.key, "0.2.0", SERVER, b"new binary");
    // The server swaps the binary after publishing; size kept the same.
    let live = f
        .server
        .app
        .store
        .dir()
        .join("release")
        .join(format!("o2ee-{}", current_target()));
    std::fs::write(&live, b"bad binary").unwrap();
    match f.run("0.1.0").await {
        Err(Error::Verify(m)) => assert!(m.contains("does not match"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(f.exe_bytes(), b"old binary");
    assert_eq!(f.leftovers(), 0);
    // Longer than signed.
    std::fs::write(&live, b"much longer binary").unwrap();
    assert!(f.run("0.1.0").await.is_err());
    assert_eq!(f.exe_bytes(), b"old binary");
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_releases_for_another_server_or_platform() {
    let f = fixture().await;
    let other = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.onion";
    f.publish(&f.key, "0.2.0", other, b"elsewhere");
    assert!(matches!(f.run("0.1.0").await, Err(Error::Verify(_))));

    let dir = f.exe_dir.path().join("rel-other-platform");
    make_release(&dir, &f.key, "0.3.0", SERVER, "sparc-plan9", b"x");
    o2ee_server::release::publish(f.server.app.store.dir(), &dir).unwrap();
    match f.run("0.1.0").await {
        Err(Error::Local(m)) => assert!(m.contains("No release for this platform"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(f.exe_bytes(), b"old binary");
}
