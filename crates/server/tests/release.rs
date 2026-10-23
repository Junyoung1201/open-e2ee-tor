//! Release publishing, the install guide and downloads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use o2ee_protocol::release::{Manifest, Release, ReleaseFile};
use o2ee_server::release::publish;
use o2ee_server::{App, bind_public, serve};
use sha2::Digest;

const SERVER: &str = "o2eetestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";

fn write_release(dir: &Path, kp: &minisign::KeyPair, version: &str, binary: &[u8]) {
    std::fs::create_dir_all(dir).unwrap();
    let name = "o2ee-x86_64-linux";
    std::fs::write(dir.join(name), binary).unwrap();
    let manifest = serde_json::to_string(&Manifest {
        product: "o2ee".into(),
        version: version.into(),
        server: SERVER.into(),
        files: vec![ReleaseFile {
            target: "x86_64-linux".into(),
            name: name.into(),
            size: binary.len() as u64,
            sha256: hex::encode(sha2::Sha256::digest(binary)),
        }],
    })
    .unwrap();
    std::fs::write(dir.join("manifest.json"), &manifest).unwrap();
    let sig = minisign::sign(Some(&kp.pk), &kp.sk, manifest.as_bytes(), None, None).unwrap();
    std::fs::write(dir.join("manifest.json.minisig"), sig.into_string()).unwrap();
    let bin_sig = minisign::sign(Some(&kp.pk), &kp.sk, binary, None, None).unwrap();
    std::fs::write(dir.join(format!("{name}.minisig")), bin_sig.into_string()).unwrap();
    std::fs::write(
        dir.join("minisign.pub"),
        kp.pk.to_box().unwrap().to_string(),
    )
    .unwrap();
}

struct Reply {
    status: StatusCode,
    headers: hyper::HeaderMap,
    body: Bytes,
}

async fn get(socket: &Path, path: &str) -> Reply {
    let io = tokio::net::UnixStream::connect(socket).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri(path)
        .header("host", SERVER)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body,
    }
}

async fn start(dir: &Path) -> (std::sync::Arc<App>, std::path::PathBuf) {
    let app = App::open(&dir.join("data"), SERVER, 4).unwrap();
    let socket = dir.join("s.sock");
    let public = bind_public(&socket).unwrap();
    let admin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve(app.clone(), public, admin));
    (app, socket)
}

#[tokio::test(flavor = "multi_thread")]
async fn guide_and_downloads() {
    let dir = tempfile::tempdir().unwrap();
    let (app, socket) = start(dir.path()).await;

    let r = get(&socket, "/guide").await;
    assert_eq!(r.status, StatusCode::OK);
    let html = String::from_utf8_lossy(&r.body).into_owned();
    assert!(html.contains("No release has been published yet."));
    assert_eq!(
        get(&socket, "/v1/release").await.status,
        StatusCode::NOT_FOUND
    );

    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let rel = dir.path().join("rel");
    write_release(&rel, &kp, "0.2.0", b"new binary");
    assert_eq!(publish(app.store.dir(), &rel).unwrap(), "0.2.0");

    let r = get(&socket, "/guide").await;
    let html = String::from_utf8_lossy(&r.body).into_owned();
    assert!(html.contains("Version 0.2.0"));
    assert!(html.contains("/download/o2ee-x86_64-linux"));
    assert!(html.contains(&kp.pk.to_base64()));
    assert!(html.contains("another channel"));
    // Plain HTML and CSS only.
    assert!(!html.to_lowercase().contains("<script"));
    let csp = r
        .headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("style-src 'self'"));
    let css = get(&socket, "/guide.css").await;
    assert!(String::from_utf8_lossy(&css.body).contains("color-scheme: dark"));

    let r = get(&socket, "/download/o2ee-x86_64-linux").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(&r.body[..], b"new binary");
    assert!(
        r.headers
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("attachment")
    );
    for ok in [
        "/download/o2ee-x86_64-linux.minisig",
        "/download/manifest.json",
        "/download/manifest.json.minisig",
        "/download/minisign.pub",
    ] {
        assert_eq!(get(&socket, ok).await.status, StatusCode::OK, "{ok}");
    }
    // Nothing else from the data folder.
    std::fs::write(app.store.dir().join("release").join("extra"), "x").unwrap();
    for bad in [
        "/download/extra",
        "/download/..%2Fstate.json",
        "/download/.hidden",
        "/download/state.json",
        "/download/opaque_setup.bin",
    ] {
        assert_eq!(
            get(&socket, bad).await.status,
            StatusCode::NOT_FOUND,
            "{bad}"
        );
    }

    let r = get(&socket, "/v1/release").await;
    let release: Release = serde_json::from_slice(&r.body).unwrap();
    let m = o2ee_protocol::release::verify(&release, &kp.pk.to_base64(), SERVER).unwrap();
    assert_eq!(m.version, "0.2.0");
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_checks_everything() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    App::open(&data, SERVER, 4).unwrap();
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();

    // Binary changed after signing.
    let rel = dir.path().join("a");
    write_release(&rel, &kp, "0.2.0", b"signed");
    std::fs::write(rel.join("o2ee-x86_64-linux"), b"swapped").unwrap();
    assert!(publish(&data, &rel).unwrap_err().contains("does not match"));

    // Signed by a different key than the one shipped with it.
    let other = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let rel = dir.path().join("b");
    write_release(&rel, &kp, "0.2.0", b"signed");
    std::fs::write(
        rel.join("minisign.pub"),
        other.pk.to_box().unwrap().to_string(),
    )
    .unwrap();
    assert!(publish(&data, &rel).is_err());

    // Manifest edited after signing.
    let rel = dir.path().join("c");
    write_release(&rel, &kp, "0.2.0", b"signed");
    let text = std::fs::read_to_string(rel.join("manifest.json")).unwrap();
    std::fs::write(rel.join("manifest.json"), text.replace("0.2.0", "0.9.0")).unwrap();
    assert!(publish(&data, &rel).is_err());

    // Good, then no going back.
    let rel = dir.path().join("d");
    write_release(&rel, &kp, "0.3.0", b"v3");
    assert_eq!(publish(&data, &rel).unwrap(), "0.3.0");
    let rel = dir.path().join("e");
    write_release(&rel, &kp, "0.2.0", b"v2");
    assert!(publish(&data, &rel).unwrap_err().contains("not newer"));
    let rel = dir.path().join("f");
    write_release(&rel, &kp, "0.4.0", b"v4");
    assert_eq!(publish(&data, &rel).unwrap(), "0.4.0");
    assert_eq!(
        std::fs::read(data.join("release").join("o2ee-x86_64-linux")).unwrap(),
        b"v4"
    );
}
