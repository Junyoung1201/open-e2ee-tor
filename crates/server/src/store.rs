//! Server state: a small JSON file for accounts and transfer metadata, one
//! ciphertext file per transfer, and in-memory-only sessions.
//!
//! Nothing here records who did what or when beyond what the service needs
//! to work (no login history, no access times, no sender of a transfer).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use o2ee_protocol::crypto::{SignedBundle, Suite, random_bytes};
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{ServerLogin, ServerSetup};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    Active,
    Suspended,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub status: Status,
    pub password_file: String,
    pub bundle: SignedBundle,
    pub fingerprint: String,
    pub note: String,
    /// Signup time rounded down to the hour; used only to expire requests.
    pub requested_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transfer {
    pub recipient: String,
    pub size: u64,
    pub ready: bool,
    /// Rounded up to the hour.
    pub expires_at: u64,
    /// SHA-256 of the sender's upload key while the upload is unfinished.
    pub upload_key_hash: Option<String>,
    #[serde(skip)]
    pub received: u64,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Persist {
    pub accounts: BTreeMap<String, Account>,
    pub transfers: BTreeMap<String, Transfer>,
}

#[derive(Debug)]
pub struct Session {
    pub username: String,
    pub expires: Instant,
}

pub struct PendingLogin {
    pub state: ServerLogin<Suite>,
    pub username: String,
    pub expires: Instant,
}

#[derive(Default)]
pub struct Failures {
    pub count: u32,
    pub locked_until: Option<Instant>,
}

impl Failures {
    pub fn locked(&self, now: Instant) -> bool {
        self.locked_until.is_some_and(|t| t > now)
    }

    /// Five unsuccessful attempts in a row are free; after that each one
    /// locks the account's login for 30 s, doubling up to 15 min.
    pub fn record(&mut self, now: Instant) {
        self.count = self.count.saturating_add(1);
        if self.count >= 5 {
            let secs = (30u64 << (self.count - 5).min(5)).min(900);
            self.locked_until = Some(now + Duration::from_secs(secs));
        }
    }
}

pub struct AdminSession {
    pub csrf: String,
    pub expires: Instant,
    /// One-time message for the next dashboard view.
    pub flash: Option<String>,
}

#[derive(Default)]
pub struct Memory {
    pub sessions: HashMap<String, Session>,
    pub logins: HashMap<String, PendingLogin>,
    pub failures: HashMap<String, Failures>,
    pub used_challenges: HashMap<Vec<u8>, u64>,
    pub uploading: HashSet<String>,
    pub admin_sessions: HashMap<String, AdminSession>,
    pub admin_failures: Failures,
}

pub const MAX_PENDING_LOGINS: usize = 1000;
pub const LOGIN_STATE_TTL: Duration = Duration::from_secs(120);

pub struct Store {
    dir: PathBuf,
    files: PathBuf,
    persist: Mutex<Persist>,
    memory: Mutex<Memory>,
    pub setup: ServerSetup<Suite>,
    pub pow_key: [u8; 32],
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn round_up_hour(t: u64) -> u64 {
    t.div_ceil(3600) * 3600
}

pub fn private_dir(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

/// Writes `data` to `path` atomically with mode 600.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}

impl Store {
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        private_dir(dir)?;
        let files = crate::storage::prepare(dir)?;

        let setup_path = dir.join("opaque_setup.bin");
        let setup = match fs::read(&setup_path) {
            Ok(bytes) => ServerSetup::<Suite>::deserialize(&bytes)
                .map_err(|_| std::io::Error::other("opaque_setup.bin is damaged"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let setup = ServerSetup::<Suite>::new(&mut OsRng);
                write_private(&setup_path, &setup.serialize())?;
                setup
            }
            Err(e) => return Err(e),
        };

        let mut persist: Persist = match fs::read(dir.join("state.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| std::io::Error::other("state.json is damaged"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Persist::default(),
            Err(e) => return Err(e),
        };

        // Resume points come from the files themselves; transfer files
        // without a record (e.g. after a crash) are removed. Nothing else in
        // the storage folder is ever touched.
        for (id, t) in persist.transfers.iter_mut() {
            t.received = fs::metadata(files.join(format!("{id}.bin")))
                .map(|m| m.len().min(t.size))
                .unwrap_or(0);
        }
        persist
            .transfers
            .retain(|id, t| !t.ready || files.join(format!("{id}.bin")).exists());
        for entry in fs::read_dir(&files)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let orphan = crate::storage::is_transfer_file(name)
                && name
                    .strip_suffix(".bin")
                    .is_some_and(|id| !persist.transfers.contains_key(id));
            if orphan {
                let _ = fs::remove_file(entry.path());
            }
        }

        let store = Self {
            dir: dir.to_owned(),
            files,
            persist: Mutex::new(persist),
            memory: Mutex::new(Memory::default()),
            setup,
            pow_key: random_bytes::<32>(),
        };
        store.save(&store.persist())?;
        Ok(store)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Folder holding transfer ciphertext (see `storage`).
    pub fn files_dir(&self) -> &Path {
        &self.files
    }

    pub fn file_path(&self, id: &str) -> PathBuf {
        self.files.join(format!("{id}.bin"))
    }

    pub fn persist(&self) -> MutexGuard<'_, Persist> {
        self.persist.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn memory(&self) -> MutexGuard<'_, Memory> {
        self.memory.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn save(&self, p: &Persist) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(p).map_err(std::io::Error::other)?;
        write_private(&self.dir.join("state.json"), &bytes)
    }

    pub fn admin_password_path(&self) -> PathBuf {
        self.dir.join("admin_password")
    }

    /// Removes one transfer and its file.
    pub fn delete_transfer(&self, p: &mut Persist, id: &str) {
        p.transfers.remove(id);
        let _ = fs::remove_file(self.file_path(id));
    }

    /// Deletes an account, its waiting transfers and its sessions.
    pub fn delete_account(&self, p: &mut Persist, username: &str) {
        p.accounts.remove(username);
        let ids: Vec<String> = p
            .transfers
            .iter()
            .filter(|(_, t)| t.recipient == username)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.delete_transfer(p, &id);
        }
        self.end_sessions(username);
    }

    pub fn end_sessions(&self, username: &str) {
        self.memory().sessions.retain(|_, s| s.username != username);
    }

    /// Drops everything whose time has come. Called periodically.
    pub fn sweep(&self) -> std::io::Result<()> {
        let now = now_secs();
        {
            let mut p = self.persist();
            let expired: Vec<String> = p
                .transfers
                .iter()
                .filter(|(_, t)| t.expires_at <= now)
                .map(|(id, _)| id.clone())
                .collect();
            let stale: Vec<String> = p
                .accounts
                .iter()
                .filter(|(_, a)| {
                    a.status == Status::Pending
                        && a.requested_at + o2ee_protocol::SIGNUP_RETENTION_SECS <= now
                })
                .map(|(u, _)| u.clone())
                .collect();
            if !expired.is_empty() || !stale.is_empty() {
                for id in &expired {
                    self.delete_transfer(&mut p, id);
                }
                for u in &stale {
                    self.delete_account(&mut p, u);
                }
                self.save(&p)?;
            }
        }
        let instant = Instant::now();
        let mut m = self.memory();
        m.sessions.retain(|_, s| s.expires > instant);
        m.logins.retain(|_, l| l.expires > instant);
        m.used_challenges.retain(|_, exp| *exp > now);
        m.admin_sessions.retain(|_, s| s.expires > instant);
        Ok(())
    }
}
