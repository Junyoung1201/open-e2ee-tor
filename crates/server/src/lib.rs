//! o2ee-server: relay for end-to-end encrypted transfers between accounts.
//!
//! Two listeners that never share routes:
//! - the public API on a Unix socket that Tor's onion service forwards to;
//! - the admin page on 127.0.0.1, which is not mapped in torrc.
//!
//! The server keeps no access or request logs.

pub mod admin;
pub mod api;
pub mod release;
pub mod store;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UnixListener};

pub use store::Store;

#[derive(Debug)]
pub struct App {
    pub store: Store,
    /// The onion address clients pin; bundles and OPAQUE logins bind to it.
    pub server_name: String,
    pub pow_difficulty: u8,
}

impl App {
    pub fn open(
        data_dir: &Path,
        server_name: &str,
        pow_difficulty: u8,
    ) -> std::io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            store: Store::open(data_dir)?,
            server_name: server_name.to_owned(),
            pow_difficulty,
        }))
    }
}

/// Binds the public API to a Unix socket readable only by this user.
pub fn bind_public(path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        store::private_dir(parent)?;
    }
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves both listeners and the expiry sweep until either server fails.
pub async fn serve(app: Arc<App>, public: UnixListener, admin: TcpListener) -> std::io::Result<()> {
    let port = admin.local_addr()?.port();
    if !admin.local_addr()?.ip().is_loopback() {
        return Err(std::io::Error::other("admin page must listen on 127.0.0.1"));
    }
    let sweeper = {
        let app = app.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let _ = app.store.sweep();
            }
        })
    };
    let public = axum::serve(public, api::router(app.clone()));
    let admin = axum::serve(admin, admin::router(app, port));
    let result = tokio::select! {
        r = public.into_future() => r,
        r = admin.into_future() => r,
    };
    sweeper.abort();
    result
}
