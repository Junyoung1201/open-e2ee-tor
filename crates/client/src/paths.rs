//! Where the client keeps things, and which server it talks to.
//!
//! ```text
//! <base>/server                      optional server override (warns)
//! <base>/accounts/<id>/identity.age  private keys, encrypted with the password
//! <base>/accounts/<id>/bundle.json   own signed public keys
//! <base>/accounts/<id>/contacts.json pinned keys of other accounts
//! <base>/outgoing, <base>/incoming   ciphertext of unfinished transfers
//! <base>/tor                         embedded Tor state and cache
//! ```
//! `<base>` is `$O2EE_HOME`, or the platform's local data dir + `/o2ee`.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use o2ee_protocol::Username;

use crate::Error;

/// Onion address compiled into release builds (`O2EE_SERVER_ONION` at
/// build time).
pub const BUILTIN_SERVER: Option<&str> = option_env!("O2EE_SERVER_ONION");

#[derive(Clone, Debug)]
pub struct Paths {
    pub base: PathBuf,
}

impl Paths {
    pub fn discover() -> Result<Self, Error> {
        let base = match std::env::var_os("O2EE_HOME") {
            Some(p) => PathBuf::from(p),
            None => dirs::data_local_dir()
                .ok_or_else(|| Error::Local("Cannot find a data folder".into()))?
                .join("o2ee"),
        };
        private_dir(&base)?;
        Ok(Self { base })
    }

    pub fn account(&self, user: &Username) -> PathBuf {
        self.base.join("accounts").join(user.as_str())
    }

    pub fn identity_file(&self, user: &Username) -> PathBuf {
        self.account(user).join("identity.age")
    }

    pub fn bundle_file(&self, user: &Username) -> PathBuf {
        self.account(user).join("bundle.json")
    }

    pub fn contacts_file(&self, user: &Username) -> PathBuf {
        self.account(user).join("contacts.json")
    }

    pub fn outgoing(&self) -> PathBuf {
        self.base.join("outgoing")
    }

    pub fn incoming(&self) -> PathBuf {
        self.base.join("incoming")
    }

    pub fn tor(&self) -> PathBuf {
        self.base.join("tor")
    }

    /// The agent socket: in the per-user runtime dir when there is one and
    /// no `O2EE_HOME` override, otherwise in `<base>`.
    pub fn agent_socket(&self) -> PathBuf {
        if std::env::var_os("O2EE_HOME").is_none()
            && let Some(run) = dirs::runtime_dir()
        {
            return run.join("o2ee").join("agent.sock");
        }
        self.base.join("agent.sock")
    }

    /// The pinned server, plus a warning when it does not come from the
    /// build itself.
    pub fn server(&self) -> Result<(String, Option<String>), Error> {
        let override_file = self.base.join("server");
        let configured = fs::read_to_string(&override_file)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        #[cfg(debug_assertions)]
        let configured = std::env::var("O2EE_SERVER").ok().or(configured);
        match (BUILTIN_SERVER, configured) {
            (Some(built), Some(other)) if built != other => Ok((
                other.clone(),
                Some(format!(
                    "Warning: using server {other} instead of the built-in one"
                )),
            )),
            (Some(built), _) => Ok((built.to_owned(), None)),
            (None, Some(other)) => Ok((
                other.clone(),
                Some(format!(
                    "Warning: using server {other} from {}",
                    override_file.display()
                )),
            )),
            (None, None) => Err(Error::Local(format!(
                "No server configured. Put its onion address in {}",
                override_file.display()
            ))),
        }
    }
}

pub fn private_dir(path: &Path) -> Result<(), Error> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .and_then(|_| fs::set_permissions(path, fs::Permissions::from_mode(0o700)))
        .map_err(|e| Error::Local(format!("Cannot create {}: {e}", path.display())))
}

/// Atomically writes a file only this user can read.
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), Error> {
    let fail = |e: std::io::Error| Error::Local(format!("Cannot write {}: {e}", path.display()));
    if let Some(dir) = path.parent() {
        private_dir(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(fail)?;
    f.write_all(data).map_err(fail)?;
    f.sync_all().map_err(fail)?;
    fs::rename(&tmp, path).map_err(fail)
}
