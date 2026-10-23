//! Where transfer ciphertext is kept, and moving it when the admin picks a
//! new folder.
//!
//! The folder lives in `<data dir>/config.json`. A change is only recorded
//! as pending; the next start moves every transfer file into the new folder
//! (rolling back if anything fails) and switches over. Accounts, keys and
//! state always stay in the data directory.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::store::{private_dir, write_private};

const CONFIG: &str = "config.json";
/// Marks a folder as o2ee storage, so it may be reused or emptied.
const MARKER: &str = ".o2ee-storage";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Current storage folder; `None` means `<data dir>/files`.
    #[serde(default)]
    pub storage_dir: Option<PathBuf>,
    /// Folder to move to on the next start.
    #[serde(default)]
    pub next_storage_dir: Option<PathBuf>,
    /// Why the last move failed, shown on the admin page.
    #[serde(default)]
    pub storage_error: Option<String>,
}

pub fn default_storage(data_dir: &Path) -> PathBuf {
    data_dir.join("files")
}

pub fn load(data_dir: &Path) -> std::io::Result<Config> {
    match fs::read(data_dir.join(CONFIG)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| std::io::Error::other("config.json is damaged")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e),
    }
}

pub fn save(data_dir: &Path, config: &Config) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(config).map_err(std::io::Error::other)?;
    write_private(&data_dir.join(CONFIG), &bytes)
}

pub fn current(data_dir: &Path, config: &Config) -> PathBuf {
    config
        .storage_dir
        .clone()
        .unwrap_or_else(|| default_storage(data_dir))
}

/// `<32 lowercase hex>.bin`: the only files o2ee ever creates, moves or
/// deletes in a storage folder.
pub fn is_transfer_file(name: &str) -> bool {
    name.strip_suffix(".bin").is_some_and(|id| {
        id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Resolves `..` and symlinks of the deepest existing ancestor.
fn normalize(path: &Path) -> Option<PathBuf> {
    let mut existing = path.to_path_buf();
    let mut rest = Vec::new();
    while !existing.exists() {
        rest.push(existing.file_name()?.to_owned());
        existing = existing.parent()?.to_path_buf();
    }
    let mut out = existing.canonicalize().ok()?;
    for part in rest.into_iter().rev() {
        out.push(part);
    }
    Some(out)
}

/// A folder is usable if it does not exist yet, is empty, or is already
/// o2ee storage. Anything else may hold someone's files.
fn usable(dir: &Path) -> Result<(), String> {
    match fs::read_dir(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Cannot use {}: {e}", dir.display())),
        Ok(mut entries) => {
            if dir.join(MARKER).exists() || entries.next().is_none() {
                Ok(())
            } else {
                Err("The folder is not empty. Choose an empty or new folder.".into())
            }
        }
    }
}

/// Checks a folder entered on the admin page and returns it normalised.
pub fn check_new(input: &str, data_dir: &Path, current: &Path) -> Result<PathBuf, String> {
    let input = input.trim();
    if input.is_empty() || input.len() > 1024 || input.chars().any(char::is_control) {
        return Err("Enter a folder path".into());
    }
    let path = Path::new(input);
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return Err("Use an absolute path without ..".into());
    }
    let path = normalize(path).ok_or("Invalid folder path")?;
    if path.exists() && !path.is_dir() {
        return Err("That path is a file, not a folder".into());
    }
    let data = normalize(data_dir).unwrap_or_else(|| data_dir.to_owned());
    let default = default_storage(&data);
    // Inside the data dir only its own files/ folder is allowed, and never
    // anything that contains the data dir.
    if (path.starts_with(&data) && path != default) || data.starts_with(&path) {
        return Err("Choose a folder outside the server data folder".into());
    }
    if normalize(current).as_deref() == Some(path.as_path()) {
        return Ok(path);
    }
    usable(&path)?;
    Ok(path)
}

fn mark(dir: &Path) -> std::io::Result<()> {
    private_dir(dir)?;
    let path = dir.join(MARKER);
    if !path.exists() {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(b"o2ee transfer storage. Do not put other files here.\n")?;
    }
    Ok(())
}

fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            let tmp = to.with_extension("bin.part");
            let result = (|| {
                let mut src = fs::File::open(from)?;
                let mut dst = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)?;
                std::io::copy(&mut src, &mut dst)?;
                dst.sync_all()?;
                fs::rename(&tmp, to)?;
                fs::remove_file(from)
            })();
            if result.is_err() {
                let _ = fs::remove_file(&tmp);
            }
            result
        }
        Err(e) => Err(e),
    }
}

/// Moves every transfer file from `from` to `to`. On failure, files already
/// moved are put back and the error is returned.
fn move_all(from: &Path, to: &Path) -> Result<(), String> {
    usable(to)?;
    mark(to).map_err(|e| e.to_string())?;
    let mut moved: Vec<PathBuf> = Vec::new();
    let names: Vec<_> = match fs::read_dir(from) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .filter(|n| n.to_str().is_some_and(is_transfer_file))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.to_string()),
    };
    for name in names {
        let (src, dst) = (from.join(&name), to.join(&name));
        if let Err(e) = move_file(&src, &dst) {
            for back in moved.iter().rev() {
                let _ = move_file(&to.join(back), &from.join(back));
            }
            return Err(e.to_string());
        }
        moved.push(PathBuf::from(name));
    }
    // Leave the old folder only if nothing but our marker is left.
    let _ = fs::remove_file(from.join(MARKER));
    let _ = fs::remove_dir(from);
    Ok(())
}

/// Called once at start: applies a pending move and returns the folder to
/// use from now on.
pub fn prepare(data_dir: &Path) -> std::io::Result<PathBuf> {
    let mut config = load(data_dir)?;
    let mut dir = current(data_dir, &config);
    if let Some(next) = config.next_storage_dir.take() {
        if next == dir {
            config.storage_error = None;
        } else {
            match move_all(&dir, &next) {
                Ok(()) => {
                    config.storage_dir = Some(next.clone());
                    config.storage_error = None;
                    dir = next;
                }
                Err(e) => {
                    config.storage_error = Some(format!(
                        "Could not move files to {}: {e}. Still using {}.",
                        next.display(),
                        dir.display()
                    ));
                }
            }
        }
        save(data_dir, &config)?;
    }
    mark(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> String {
        format!("{}.bin", hex::encode([n; 16]))
    }

    #[test]
    fn transfer_file_names() {
        assert!(is_transfer_file(&id(1)));
        for bad in [
            "notes.txt",
            "abc.bin",
            ".o2ee-storage",
            &id(1).to_uppercase(),
        ] {
            assert!(!is_transfer_file(bad), "{bad}");
        }
    }

    #[test]
    fn check_new_rules() {
        let root = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let data = root.path().join("data");
        fs::create_dir_all(&data).unwrap_or_else(|e| panic!("{e}"));
        let cur = default_storage(&data);
        let ok = root.path().join("new-store");
        assert_eq!(
            check_new(ok.to_str().unwrap_or_default(), &data, &cur).ok(),
            ok.canonicalize().ok().or(Some(ok.clone()))
        );
        for bad in ["relative/path", "", "/tmp/../etc"] {
            assert!(check_new(bad, &data, &cur).is_err(), "{bad}");
        }
        // The data dir, something inside it, or a parent of it.
        for bad in [data.clone(), data.join("release"), root.path().to_owned()] {
            assert!(
                check_new(bad.to_str().unwrap_or_default(), &data, &cur).is_err(),
                "{}",
                bad.display()
            );
        }
        // A folder that already holds someone's files.
        let busy = root.path().join("documents");
        fs::create_dir_all(&busy).unwrap_or_else(|e| panic!("{e}"));
        fs::write(busy.join("thesis.docx"), "x").unwrap_or_else(|e| panic!("{e}"));
        let err = check_new(busy.to_str().unwrap_or_default(), &data, &cur)
            .err()
            .unwrap_or_default();
        assert!(err.contains("not empty"), "{err}");
    }

    #[test]
    fn pending_move_happens_on_prepare() {
        let root = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let data = root.path().join("data");
        let old = prepare(&data).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(old, default_storage(&data));
        fs::write(old.join(id(1)), "one").unwrap_or_else(|e| panic!("{e}"));
        fs::write(old.join(id(2)), "two").unwrap_or_else(|e| panic!("{e}"));

        let new = root.path().join("elsewhere").join("store");
        save(
            &data,
            &Config {
                next_storage_dir: Some(new.clone()),
                ..load(&data).unwrap_or_default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(prepare(&data).ok(), Some(new.clone()));
        assert_eq!(
            fs::read_to_string(new.join(id(1))).ok().as_deref(),
            Some("one")
        );
        assert!(new.join(MARKER).exists());
        assert!(!old.exists());
        let c = load(&data).unwrap_or_default();
        assert_eq!(
            (c.storage_dir, c.next_storage_dir, c.storage_error),
            (Some(new), None, None)
        );
    }

    #[test]
    fn failed_move_keeps_old_folder() {
        let root = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let data = root.path().join("data");
        let old = prepare(&data).unwrap_or_else(|e| panic!("{e}"));
        fs::write(old.join(id(1)), "one").unwrap_or_else(|e| panic!("{e}"));
        // Someone put files in the target before the restart.
        let target = root.path().join("target");
        fs::create_dir_all(&target).unwrap_or_else(|e| panic!("{e}"));
        fs::write(target.join("private.txt"), "mine").unwrap_or_else(|e| panic!("{e}"));
        save(
            &data,
            &Config {
                next_storage_dir: Some(target.clone()),
                ..Config::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(prepare(&data).ok(), Some(old.clone()));
        assert!(old.join(id(1)).exists());
        assert_eq!(
            fs::read_to_string(target.join("private.txt"))
                .ok()
                .as_deref(),
            Some("mine")
        );
        let c = load(&data).unwrap_or_default();
        assert!(c.storage_error.unwrap_or_default().contains("Still using"));
        assert_eq!(c.next_storage_dir, None);
    }
}
