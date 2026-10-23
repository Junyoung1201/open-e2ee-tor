//! Test harness: an in-process o2ee-server on a temporary Unix socket, and
//! client accounts with their own temporary homes.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use age::secrecy::SecretString;
use o2ee::net::Net;
use o2ee::ops::{self, Session};
use o2ee::paths::Paths;
use o2ee_protocol::Username;
use o2ee_server::store::Status;
use o2ee_server::{App, bind_public, serve};
use tempfile::TempDir;

pub const SERVER: &str = "o2eetestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";
pub const PASSWORD: &str = "tangerine rocket 42";

pub struct TestServer {
    pub app: Arc<App>,
    pub dir: TempDir,
    pub socket: PathBuf,
    pub admin_port: u16,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn start() -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let app = App::open(&dir.path().join("data"), SERVER, 8).unwrap();
    let socket = dir.path().join("run").join("public.sock");
    let public = bind_public(&socket).unwrap();
    let admin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin.local_addr().unwrap().port();
    let task = tokio::spawn(serve(app.clone(), public, admin));
    TestServer {
        app,
        dir,
        socket,
        admin_port,
        task,
    }
}

impl TestServer {
    pub fn net(&self) -> Net {
        Net::direct(&self.socket, SERVER)
    }

    pub fn set_status(&self, user: &str, status: Status) {
        let mut p = self.app.store.persist();
        p.accounts.get_mut(user).unwrap().status = status;
        self.app.store.save(&p).unwrap();
    }

    pub fn approve(&self, user: &str) {
        self.set_status(user, Status::Active);
    }

    pub fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }
}

pub struct TestUser {
    pub home: TempDir,
    pub paths: Paths,
    pub user: Username,
}

pub fn password() -> SecretString {
    SecretString::from(PASSWORD.to_owned())
}

pub async fn signup(server: &TestServer, name: &str) -> (TestUser, String) {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths {
        base: home.path().to_owned(),
    };
    let user = Username::parse(name).unwrap();
    let fp = ops::signup(&server.net(), &paths, &user, &password())
        .await
        .unwrap();
    (TestUser { home, paths, user }, fp)
}

pub async fn active_user(server: &TestServer, name: &str) -> (TestUser, Session) {
    let (u, _) = signup(server, name).await;
    server.approve(name);
    let s = login(server, &u).await.unwrap();
    (u, s)
}

pub async fn login(server: &TestServer, u: &TestUser) -> Result<Session, o2ee::Error> {
    ops::login(server.net(), u.paths.clone(), &u.user, &password()).await
}

pub fn random_file(dir: &Path, name: &str, len: usize) -> (PathBuf, Vec<u8>) {
    let mut data = vec![0u8; len];
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15 ^ len as u64;
    for b in data.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    let path = dir.join(name);
    std::fs::write(&path, &data).unwrap();
    (path, data)
}
