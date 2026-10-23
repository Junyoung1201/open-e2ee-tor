//! End-to-end tests: real server code and real client code talking over a
//! Unix socket (the Tor hop is the only thing left out), including a
//! server that misbehaves on purpose.

// The direct (non-Tor) test transport exists only in debug builds.
#![cfg(debug_assertions)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use o2ee::Error;
use o2ee::ops::{Source, Trust};
use o2ee_protocol::Username;
use o2ee_server::store::Status;

fn name(n: &str) -> Username {
    Username::parse(n).unwrap()
}

fn files_on_server(server: &TestServer) -> usize {
    std::fs::read_dir(server.app.store.files_dir())
        .unwrap()
        .filter(|e| {
            o2ee_server::storage::is_transfer_file(
                &e.as_ref().unwrap().file_name().to_string_lossy(),
            )
        })
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_needs_approval_then_send_and_receive() {
    let server = start().await;
    let (alice, alice_fp) = signup(&server, "alice").await;
    let (bob, _) = signup(&server, "bob").await;

    // Admin sees the same fingerprint the applicant was shown.
    assert_eq!(
        server.app.store.persist().accounts["alice"].fingerprint,
        alice_fp
    );
    match login(&server, &alice).await {
        Err(Error::Server { message, .. }) => {
            assert_eq!(message, "Account is waiting for approval")
        }
        other => panic!("{other:?}"),
    }
    server.approve("alice");
    server.approve("bob");
    let a = login(&server, &alice).await.unwrap();
    let b = login(&server, &bob).await.unwrap();
    assert_eq!(a.fingerprint(), alice_fp);
    assert_eq!(a.me().await.unwrap().username, "alice");

    // Sending needs the recipient pinned first.
    let (fp_bob, trust) = a.lookup(&name("bob")).await.unwrap();
    assert_eq!(trust, Trust::New);
    let dir = tempfile::tempdir().unwrap();
    let (file, data) = random_file(dir.path(), "report.bin", 2_500_000);
    assert!(
        a.send(&name("bob"), &file, Source::File, None)
            .await
            .is_err()
    );
    a.trust(&name("bob"), &fp_bob).await.unwrap();
    assert_eq!(a.lookup(&name("bob")).await.unwrap().1, Trust::Known);

    let id = a
        .send(&name("bob"), &file, Source::File, None)
        .await
        .unwrap();
    // Nothing of the plaintext is left in the sender's work folder.
    assert_eq!(
        std::fs::read_dir(alice.paths.outgoing()).unwrap().count(),
        0
    );

    let inbox = b.inbox().await.unwrap();
    assert_eq!(inbox.len(), 1);
    let peek = inbox[0].peek.clone().unwrap();
    assert_eq!(
        (
            peek.id.as_str(),
            peek.sender.as_str(),
            peek.name.as_str(),
            peek.size
        ),
        (id.as_str(), "alice", "report.bin", data.len() as u64)
    );
    assert_eq!(peek.trust, Trust::New);
    // The server only sees whole MiB plus small overhead, not the size.
    assert!(inbox[0].ciphertext_size >= 3 * 1024 * 1024);

    // Downloading also needs the sender pinned.
    let out = tempfile::tempdir().unwrap();
    assert!(b.download(&id, out.path(), None).await.is_err());
    b.trust(&name("alice"), &peek.fingerprint).await.unwrap();
    let saved = b.download(&id, out.path(), None).await.unwrap();
    assert_eq!(saved, out.path().join("report.bin"));
    assert_eq!(std::fs::read(&saved).unwrap(), data);

    // Delivered transfers are gone from the server.
    assert!(b.inbox().await.unwrap().is_empty());
    assert_eq!(files_on_server(&server), 0);

    // A second file with the same name never overwrites the first.
    let id2 = a
        .send(&name("bob"), &file, Source::File, None)
        .await
        .unwrap();
    let saved2 = b.download(&id2, out.path(), None).await.unwrap();
    assert_eq!(saved2, out.path().join("report (1).bin"));
}

#[tokio::test(flavor = "multi_thread")]
async fn folders_arrive_as_zip() {
    let server = start().await;
    let (_, a) = active_user(&server, "alice").await;
    let (_, b) = active_user(&server, "bob").await;
    let fp = a.lookup(&name("bob")).await.unwrap().0;
    a.trust(&name("bob"), &fp).await.unwrap();
    let fp = b.lookup(&name("alice")).await.unwrap().0;
    b.trust(&name("alice"), &fp).await.unwrap();

    let src = tempfile::tempdir().unwrap();
    let folder = src.path().join("photos");
    std::fs::create_dir_all(folder.join("2026")).unwrap();
    std::fs::write(folder.join("a.txt"), "first").unwrap();
    std::fs::write(folder.join("2026/b.txt"), "second").unwrap();
    let id = a
        .send(&name("bob"), &folder, Source::Dir, None)
        .await
        .unwrap();

    let out = tempfile::tempdir().unwrap();
    let saved = b.download(&id, out.path(), None).await.unwrap();
    assert_eq!(saved, out.path().join("photos.zip"));
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&saved).unwrap()).unwrap();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut zip.by_name("2026/b.txt").unwrap(), &mut text).unwrap();
    assert_eq!(text, "second");
    // Not extracted automatically.
    assert!(!out.path().join("a.txt").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_and_lockout() {
    let server = start().await;
    let (alice, _) = signup(&server, "alice").await;
    server.approve("alice");
    let wrong = age::secrecy::SecretString::from("not the password at all".to_owned());
    for _ in 0..5 {
        match o2ee::ops::login(server.net(), alice.paths.clone(), &alice.user, &wrong).await {
            Err(Error::Server { message, .. }) => assert_eq!(message, "Invalid ID or password"),
            other => panic!("{other:?}"),
        }
    }
    // Now even the right password is refused for a while.
    match login(&server, &alice).await {
        Err(Error::Server { message, .. }) => {
            assert_eq!(message, "Too many failed logins. Try again later.")
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_account_looks_like_wrong_password() {
    let server = start().await;
    let (alice, _) = signup(&server, "alice").await;
    server.approve("alice");
    let mut ghost = alice.paths.clone();
    // Same key file, different account name that does not exist.
    let ghost_user = name("ghost");
    std::fs::create_dir_all(ghost.base.join("accounts")).unwrap();
    std::fs::rename(
        alice.paths.account(&alice.user),
        alice.paths.account(&ghost_user),
    )
    .unwrap();
    ghost.base = alice.paths.base.clone();
    match o2ee::ops::login(server.net(), ghost, &ghost_user, &password()).await {
        Err(Error::Server { message, .. }) => assert_eq!(message, "Invalid ID or password"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_signup_is_refused() {
    let server = start().await;
    signup(&server, "alice").await;
    let home = tempfile::tempdir().unwrap();
    let paths = o2ee::paths::Paths {
        base: home.path().to_owned(),
    };
    match o2ee::ops::signup(&server.net(), &paths, &name("alice"), &password()).await {
        Err(Error::Server { message, .. }) => assert_eq!(message, "ID is already taken"),
        other => panic!("{other:?}"),
    }
    // The failed attempt leaves no keys behind.
    assert!(!paths.identity_file(&name("alice")).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn suspended_or_deleted_accounts_lose_access() {
    let server = start().await;
    let (_, a) = active_user(&server, "alice").await;
    let (bob, b) = active_user(&server, "bob").await;
    server.set_status("alice", Status::Suspended);
    server.app.store.end_sessions("alice");
    assert!(matches!(
        a.me().await,
        Err(Error::Server { status: 401, .. })
    ));
    // Others cannot look the suspended account up or send to it.
    assert!(matches!(
        b.lookup(&name("alice")).await,
        Err(Error::Server { status: 404, .. })
    ));
    {
        let mut p = server.app.store.persist();
        server.app.store.delete_account(&mut p, "bob");
        server.app.store.save(&p).unwrap();
    }
    assert!(b.me().await.is_err());
    assert!(login(&server, &bob).await.is_err());
}

async fn pinned_pair(server: &TestServer) -> (o2ee::ops::Session, o2ee::ops::Session) {
    let (_, a) = active_user(server, "alice").await;
    let (_, b) = active_user(server, "bob").await;
    let fp = a.lookup(&name("bob")).await.unwrap().0;
    a.trust(&name("bob"), &fp).await.unwrap();
    let fp = b.lookup(&name("alice")).await.unwrap().0;
    b.trust(&name("alice"), &fp).await.unwrap();
    (a, b)
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_ciphertext_is_rejected_and_nothing_is_saved() {
    let server = start().await;
    let (a, b) = pinned_pair(&server).await;
    let dir = tempfile::tempdir().unwrap();
    let (file, _) = random_file(dir.path(), "data.bin", 300_000);
    let id = a
        .send(&name("bob"), &file, Source::File, None)
        .await
        .unwrap();

    let stored = server.app.store.file_path(&id);
    let mut bytes = std::fs::read(&stored).unwrap();
    let pos = bytes.len() / 2;
    bytes[pos] ^= 1;
    std::fs::write(&stored, &bytes).unwrap();

    let out = tempfile::tempdir().unwrap();
    match b.download(&id, out.path(), None).await {
        Err(Error::Verify(_)) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    // Not acknowledged: still on the server for the record.
    assert_eq!(b.inbox().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn server_cannot_swap_keys() {
    let server = start().await;
    let (a, _b) = pinned_pair(&server).await;
    let (_, mallory_fp) = signup(&server, "mallory").await;
    // A malicious server serves mallory's keys as bob's. They are signed
    // for "mallory", so they fail verification for "bob".
    {
        let mut p = server.app.store.persist();
        let fake = p.accounts["mallory"].bundle.clone();
        p.accounts.get_mut("bob").unwrap().bundle = fake;
    }
    assert!(matches!(
        a.lookup(&name("bob")).await,
        Err(Error::Protocol(_))
    ));
    // Or bob re-registers new keys (or the server makes a valid new bundle
    // for "bob" from keys it controls): the pinned key no longer matches.
    let evil = o2ee_protocol::crypto::Identity::generate();
    {
        let mut p = server.app.store.persist();
        p.accounts.get_mut("bob").unwrap().bundle = evil.public_bundle(&name("bob"), SERVER);
    }
    let (fp, trust) = a.lookup(&name("bob")).await.unwrap();
    assert_eq!(trust, Trust::Changed);
    assert_ne!(fp, mallory_fp);
    let dir = tempfile::tempdir().unwrap();
    let (file, _) = random_file(dir.path(), "x", 10);
    match a.send(&name("bob"), &file, Source::File, None).await {
        Err(Error::Verify(m)) => assert!(m.contains("changed")),
        other => panic!("{other:?}"),
    }
    // Trusting it anyway through the API is refused too.
    assert!(a.trust(&name("bob"), &fp).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_transfer_is_rejected() {
    let server = start().await;
    let (a, b) = pinned_pair(&server).await;
    let dir = tempfile::tempdir().unwrap();
    let (file, _) = random_file(dir.path(), "once.bin", 1000);
    let id = a
        .send(&name("bob"), &file, Source::File, None)
        .await
        .unwrap();
    // The server re-delivers the same ciphertext under a new id.
    let replay = o2ee_protocol::container::new_transfer_id();
    {
        let mut p = server.app.store.persist();
        let t = p.transfers[&id].clone();
        p.transfers.insert(replay.clone(), t);
    }
    std::fs::copy(
        server.app.store.file_path(&id),
        server.app.store.file_path(&replay),
    )
    .unwrap();
    match b.peek(&replay).await {
        Err(Error::Verify(m)) => assert!(m.contains("not sent for this transfer"), "{m}"),
        other => panic!("{other:?}"),
    }
    let out = tempfile::tempdir().unwrap();
    assert!(b.download(&replay, out.path(), None).await.is_err());
    assert!(b.download(&id, out.path(), None).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn transfers_are_private_to_the_recipient() {
    let server = start().await;
    let (a, b) = pinned_pair(&server).await;
    let (_, eve) = active_user(&server, "eve").await;
    let dir = tempfile::tempdir().unwrap();
    let (file, _) = random_file(dir.path(), "x", 1000);
    let id = a
        .send(&name("bob"), &file, Source::File, None)
        .await
        .unwrap();
    assert!(eve.inbox().await.unwrap().is_empty());
    assert!(matches!(
        eve.peek(&id).await,
        Err(Error::Server { status: 404, .. })
    ));
    // Even with the ciphertext, eve cannot decrypt it.
    {
        let mut p = server.app.store.persist();
        p.transfers.get_mut(&id).unwrap().recipient = "eve".into();
    }
    assert!(matches!(eve.peek(&id).await, Err(Error::Verify(_))));
    drop(b);
}

#[tokio::test(flavor = "multi_thread")]
async fn interrupted_download_resumes() {
    let server = start().await;
    let (a, b) = pinned_pair(&server).await;
    let dir = tempfile::tempdir().unwrap();
    let (file, data) = random_file(dir.path(), "big.bin", 5_000_000);
    let id = a
        .send(&name("bob"), &file, Source::File, None)
        .await
        .unwrap();
    // Pretend an earlier download stopped half-way.
    let stored = std::fs::read(server.app.store.file_path(&id)).unwrap();
    let part = b.paths.incoming().join(format!("{id}.part"));
    std::fs::create_dir_all(b.paths.incoming()).unwrap();
    std::fs::write(&part, &stored[..stored.len() / 2]).unwrap();

    let out = tempfile::tempdir().unwrap();
    let saved = b.download(&id, out.path(), None).await.unwrap();
    assert_eq!(std::fs::read(saved).unwrap(), data);
    assert!(!part.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_transfers_and_requests_are_swept() {
    let server = start().await;
    let (a, b) = pinned_pair(&server).await;
    signup(&server, "carol").await;
    let dir = tempfile::tempdir().unwrap();
    let (file, _) = random_file(dir.path(), "x", 1000);
    let id = a
        .send(&name("bob"), &file, Source::File, None)
        .await
        .unwrap();
    {
        let mut p = server.app.store.persist();
        p.transfers.get_mut(&id).unwrap().expires_at = 1;
        p.accounts.get_mut("carol").unwrap().requested_at = 1;
    }
    server.app.store.sweep().unwrap();
    assert!(b.inbox().await.unwrap().is_empty());
    assert_eq!(files_on_server(&server), 0);
    assert!(!server.app.store.persist().accounts.contains_key("carol"));
}

#[tokio::test(flavor = "multi_thread")]
async fn state_survives_restart_but_sessions_do_not() {
    let server = start().await;
    let (alice, a) = active_user(&server, "alice").await;
    drop(a);
    let data = server.data_dir();
    let app2 = o2ee_server::App::open(&data, SERVER, 8).unwrap();
    assert_eq!(
        app2.store.persist().accounts["alice"].status,
        Status::Active
    );
    assert!(app2.store.memory().sessions.is_empty());
    // The OPAQUE setup persisted, so the same password still works.
    drop(server.app.store.persist());
    assert!(login(&server, &alice).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_signature_in_bundle_is_rejected() {
    let server = start().await;
    let (a, _b) = pinned_pair(&server).await;
    {
        let mut p = server.app.store.persist();
        let bundle = &mut p.accounts.get_mut("bob").unwrap().bundle;
        bundle.signature = o2ee_protocol::text::b64e([0u8; 64]);
    }
    assert!(matches!(
        a.lookup(&name("bob")).await,
        Err(Error::Protocol(_))
    ));
}
