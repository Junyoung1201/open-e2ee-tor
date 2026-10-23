//! Whole system over the real Tor network (ignored by default, takes a few
//! minutes): the test server is published as a fresh onion service through
//! Arti, and two clients with their own embedded Tor clients sign up, log
//! in, pin keys, send and receive a file.
//!
//! In production the onion service is run by C tor instead (see deploy/);
//! the server only ever sees its Unix socket either way.
//!
//! ```text
//! cargo test -p o2ee --test tor_full -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::time::{Duration, Instant};

use arti_client::TorClient;
use arti_client::config::TorClientConfigBuilder;
use futures::StreamExt;
use hyper::Method;
use o2ee::net::Net;
use o2ee::ops::{self, Source};
use o2ee::paths::Paths;
use o2ee_protocol::Username;
use o2ee_server::store::Status;
use o2ee_server::{App, bind_public, serve};
use safelog::DisplayRedacted;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Tor network; takes minutes"]
async fn full_stack_over_real_tor() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir().unwrap();

    // Publish an onion service with Arti.
    let host_cfg = TorClientConfigBuilder::from_directories(
        root.path().join("host/state"),
        root.path().join("host/cache"),
    )
    .build()
    .unwrap();
    let host = TorClient::create_bootstrapped(host_cfg).await.unwrap();
    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname("o2eetest".parse().unwrap())
        .build()
        .unwrap();
    let (service, requests) = host.launch_onion_service(svc_cfg).unwrap().unwrap();
    let onion = service
        .onion_address()
        .unwrap()
        .display_unredacted()
        .to_string();
    println!("onion service: {onion}");

    // The o2ee server behind it, exactly as with C tor: a Unix socket.
    let app = App::open(&root.path().join("data"), &onion, 8).unwrap();
    let socket = root.path().join("public.sock");
    let public = bind_public(&socket).unwrap();
    let admin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve(app.clone(), public, admin));
    let proxy_socket = socket.clone();
    tokio::spawn(async move {
        let mut streams = Box::pin(tor_hsservice::handle_rend_requests(requests));
        while let Some(req) = streams.next().await {
            let socket = proxy_socket.clone();
            tokio::spawn(async move {
                let Ok(mut tor) = req.accept(Connected::new_empty()).await else {
                    return;
                };
                let Ok(mut local) = tokio::net::UnixStream::connect(&socket).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tor, &mut local).await;
            });
        }
    });

    // Two independent clients, each with its own embedded Tor.
    let alice_home = tempfile::tempdir().unwrap();
    let bob_home = tempfile::tempdir().unwrap();
    let alice_paths = Paths {
        base: alice_home.path().to_owned(),
    };
    let bob_paths = Paths {
        base: bob_home.path().to_owned(),
    };
    let alice_net = Net::tor(&onion, &alice_paths.tor()).await.unwrap();
    let bob_net = Net::tor(&onion, &bob_paths.tor()).await.unwrap();
    assert!(alice_net.is_tor() && bob_net.is_tor());

    // Wait until the descriptor is published and reachable.
    let started = Instant::now();
    loop {
        let r: Result<o2ee_protocol::api::Challenge, _> = alice_net
            .call(Method::GET, "/v1/signup/challenge", None, None::<&()>)
            .await;
        match r {
            Ok(_) => break,
            Err(e) if started.elapsed() < Duration::from_secs(600) => {
                println!("waiting for onion service: {e}");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Err(e) => panic!("onion service unreachable: {e}"),
        }
    }
    println!("reachable after {:?}", started.elapsed());

    let pw = age::secrecy::SecretString::from("tangerine rocket 42".to_owned());
    let alice = Username::parse("alice").unwrap();
    let bob = Username::parse("bob").unwrap();
    let fp_alice = ops::signup(&alice_net, &alice_paths, &alice, &pw)
        .await
        .unwrap();
    ops::signup(&bob_net, &bob_paths, &bob, &pw).await.unwrap();
    {
        let mut p = app.store.persist();
        for u in ["alice", "bob"] {
            p.accounts.get_mut(u).unwrap().status = Status::Active;
        }
        app.store.save(&p).unwrap();
    }
    let a = ops::login(alice_net, alice_paths, &alice, &pw)
        .await
        .unwrap();
    let b = ops::login(bob_net, bob_paths, &bob, &pw).await.unwrap();
    assert_eq!(a.fingerprint(), fp_alice);

    let (fp, _) = a.lookup(&bob).await.unwrap();
    a.trust(&bob, &fp).await.unwrap();
    let (fp, _) = b.lookup(&alice).await.unwrap();
    b.trust(&alice, &fp).await.unwrap();

    let work = tempfile::tempdir().unwrap();
    let data: Vec<u8> = (0..1_200_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let file = work.path().join("over-tor.bin");
    std::fs::write(&file, &data).unwrap();
    let t = Instant::now();
    let id = a.send(&bob, &file, Source::File, None).await.unwrap();
    println!("sent in {:?}", t.elapsed());

    let out = tempfile::tempdir().unwrap();
    let t = Instant::now();
    let saved = b.download(&id, out.path(), None).await.unwrap();
    println!("received in {:?}", t.elapsed());
    assert_eq!(std::fs::read(saved).unwrap(), data);
    assert!(b.inbox().await.unwrap().is_empty());
    drop(service);
}
