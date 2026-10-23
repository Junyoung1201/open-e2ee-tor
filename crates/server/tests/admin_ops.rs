//! Admin page operations: changing the storage folder and restarting the
//! real server binary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use o2ee_server::store::Transfer;
use o2ee_server::{App, bind_public, serve, storage};

const SERVER: &str = "o2eetestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";
const ADMIN_PW: &str = "correct horse admin";
/// A well-formed v3 onion name, which the real binary insists on.
const REAL_ONION: &str = "o2eetestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";

struct Reply {
    status: StatusCode,
    headers: hyper::HeaderMap,
    body: String,
}

async fn admin(port: u16, method: Method, path: &str, cookie: Option<&str>, body: &str) -> Reply {
    let io = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let origin = format!("http://127.0.0.1:{port}");
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("127.0.0.1:{port}"))
        .header("origin", &origin)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    let res = sender
        .send_request(b.body(Full::new(Bytes::from(body.to_owned()))).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// Logs in; returns (cookie, csrf).
async fn login(port: u16) -> (String, String) {
    let r = admin(
        port,
        Method::POST,
        "/login",
        None,
        "password=correct+horse+admin",
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let cookie = r.headers["set-cookie"].to_str().unwrap();
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let html = admin(port, Method::GET, "/", Some(&cookie), "").await.body;
    let at = html.find("name=\"csrf\" value=\"").unwrap() + 19;
    (cookie, html[at..at + 64].to_owned())
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

async fn embedded(dir: &Path) -> (std::sync::Arc<App>, u16) {
    let app = App::open(&dir.join("data"), SERVER, 4).unwrap();
    o2ee_server::admin::set_admin_password(app.store.dir(), ADMIN_PW).unwrap();
    let public = bind_public(&dir.join("s.sock")).unwrap();
    let admin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = admin.local_addr().unwrap().port();
    tokio::spawn(serve(app.clone(), public, admin));
    (app, port)
}

#[tokio::test(flavor = "multi_thread")]
async fn storage_folder_change_applies_on_restart() {
    let root = tempfile::tempdir().unwrap();
    let (app, port) = embedded(root.path()).await;
    let (cookie, csrf) = login(port).await;

    let html = admin(port, Method::GET, "/", Some(&cookie), "").await.body;
    assert!(html.contains("<dt>Storage</dt>"));
    assert!(html.contains(&app.store.files_dir().display().to_string()));
    assert!(html.contains("the next time the server restarts"));
    assert!(html.contains("Restart server"));

    // Refused: relative, inside the data dir, a folder with other files.
    let busy = root.path().join("docs");
    std::fs::create_dir_all(&busy).unwrap();
    std::fs::write(busy.join("thesis.docx"), "mine").unwrap();
    for (path, expect) in [
        ("relative/dir".to_owned(), "absolute path"),
        (
            app.store.dir().join("release").display().to_string(),
            "outside the server data folder",
        ),
        (busy.display().to_string(), "not empty"),
    ] {
        let r = admin(
            port,
            Method::POST,
            "/storage",
            Some(&cookie),
            &format!("csrf={csrf}&path={}", enc(&path)),
        )
        .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER);
        let html = admin(port, Method::GET, "/", Some(&cookie), "").await.body;
        assert!(html.contains(expect), "{path}: {html}");
        assert!(!html.contains("Pending:"));
    }
    // Wrong CSRF token.
    let r = admin(
        port,
        Method::POST,
        "/storage",
        Some(&cookie),
        &format!("csrf=00&path={}", enc("/tmp/x")),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // A waiting transfer, then a valid change.
    let id = o2ee_protocol::container::new_transfer_id();
    std::fs::write(app.store.file_path(&id), b"ciphertext").unwrap();
    {
        let mut p = app.store.persist();
        p.transfers.insert(
            id.clone(),
            Transfer {
                recipient: "bob".into(),
                size: 10,
                ready: true,
                expires_at: u64::MAX / 2,
                upload_key_hash: None,
                received: 10,
            },
        );
        app.store.save(&p).unwrap();
    }
    let new = root.path().join("big-disk").join("o2ee");
    admin(
        port,
        Method::POST,
        "/storage",
        Some(&cookie),
        &format!("csrf={csrf}&path={}", enc(&new.display().to_string())),
    )
    .await;
    let html = admin(port, Method::GET, "/", Some(&cookie), "").await.body;
    assert!(
        html.contains("Restart the server to move the files"),
        "{html}"
    );
    assert!(html.contains("Pending:"));
    // Nothing moves until the restart.
    assert!(app.store.file_path(&id).exists());
    assert!(!new.exists());

    // "Restart": open the same data dir again.
    let data = app.store.dir().to_owned();
    drop(app);
    let app2 = App::open(&data, SERVER, 4).unwrap();
    assert_eq!(app2.store.files_dir(), new.as_path());
    assert_eq!(
        std::fs::read(app2.store.file_path(&id)).unwrap(),
        b"ciphertext"
    );
    assert!(app2.store.persist().transfers[&id].ready);
    assert!(!data.join("files").exists());
    let config = storage::load(&data).unwrap();
    assert_eq!(config.next_storage_dir, None);
    // Other people's files were never touched.
    assert_eq!(
        std::fs::read_to_string(busy.join("thesis.docx")).unwrap(),
        "mine"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn embedded_server_does_not_exec() {
    let root = tempfile::tempdir().unwrap();
    let (_app, port) = embedded(root.path()).await;
    let (cookie, csrf) = login(port).await;
    let r = admin(
        port,
        Method::POST,
        "/restart",
        Some(&cookie),
        &format!("csrf={csrf}"),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let html = admin(port, Method::GET, "/", Some(&cookie), "").await.body;
    assert!(html.contains("Restart is not available"));
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_button_restarts_the_real_server() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    o2ee_server::admin::set_admin_password(&data, ADMIN_PW).unwrap();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_o2ee-server"))
        .args(["run", "--data-dir"])
        .arg(&data)
        .arg("--socket")
        .arg(root.path().join("p.sock"))
        .args(["--onion", REAL_ONION, "--admin-port", &port.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let wait_up = || async {
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    };
    assert!(wait_up().await);
    let (cookie, csrf) = login(port).await;

    // Queue a storage change, then restart from the page.
    let new = root.path().join("moved");
    admin(
        port,
        Method::POST,
        "/storage",
        Some(&cookie),
        &format!("csrf={csrf}&path={}", enc(&new.display().to_string())),
    )
    .await;
    let r = admin(
        port,
        Method::POST,
        "/restart",
        Some(&cookie),
        &format!("csrf={csrf}"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Restarting"));

    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(wait_up().await, "server did not come back");
    // Same process (exec in place), so a service manager keeps tracking it.
    assert!(child.try_wait().unwrap().is_none());
    // Sessions were in memory only.
    let r = admin(port, Method::GET, "/", Some(&cookie), "").await;
    assert_eq!(r.headers["location"], "/login");
    // The storage change was applied by the restart.
    let config = storage::load(&data).unwrap();
    assert_eq!(config.storage_dir.as_deref(), Some(new.as_path()));
    assert!(new.join(".o2ee-storage").exists());
    let _ = child.kill();
    let _ = child.wait();
}
