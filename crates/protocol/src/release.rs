//! Signed release manifests for `o2ee update` and the download guide.
//!
//! A release is `manifest.json` plus its minisign signature, made offline
//! with the release key. Clients only trust the release public key built
//! into them, never one served by the server, so a compromised server can
//! withhold updates but cannot install anything.

use serde::{Deserialize, Serialize};

pub const MANIFEST: &str = "manifest.json";
pub const MANIFEST_SIG: &str = "manifest.json.minisig";
pub const PUBKEY_FILE: &str = "minisign.pub";
/// Largest manifest or signature either side reads.
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;
/// Largest binary `o2ee update` downloads.
pub const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub product: String,
    pub version: String,
    /// The onion address this release is built for.
    pub server: String,
    pub files: Vec<ReleaseFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFile {
    /// `<arch>-<os>`, e.g. `x86_64-linux`.
    pub target: String,
    pub name: String,
    pub size: u64,
    /// Lowercase hex SHA-256.
    pub sha256: String,
}

/// The served release, exactly as signed.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub manifest: String,
    pub signature: String,
}

/// This build's target in manifest notation.
pub fn current_target() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// File names that may appear in a release and in `/download/<name>`.
pub fn valid_file_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `major.minor.patch`, digits only.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.split('.');
    let mut next = || -> Option<u64> {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    let version = (next()?, next()?, next()?);
    parts.next().is_none().then_some(version)
}

impl Manifest {
    /// Shape checks that do not need the signature.
    pub fn parse(text: &str) -> Result<Self, ReleaseError> {
        if text.len() > MAX_MANIFEST_BYTES {
            return Err(ReleaseError::Malformed);
        }
        let m: Manifest = serde_json::from_str(text).map_err(|_| ReleaseError::Malformed)?;
        let ok = m.product == "o2ee"
            && parse_version(&m.version).is_some()
            && !m.files.is_empty()
            && m.files.len() <= 16
            && m.files.iter().all(|f| {
                valid_file_name(&f.name)
                    && f.name != MANIFEST
                    && !f.name.ends_with(".minisig")
                    && f.name != PUBKEY_FILE
                    && f.size > 0
                    && f.size <= MAX_BINARY_BYTES
                    && f.sha256.len() == 64
                    && f.sha256
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                    && f.target.len() <= 32
            });
        if ok {
            Ok(m)
        } else {
            Err(ReleaseError::Malformed)
        }
    }

    pub fn file_for(&self, target: &str) -> Option<&ReleaseFile> {
        self.files.iter().find(|f| f.target == target)
    }
}

/// Verifies `release` with the pinned `public_key` (minisign base64) and
/// checks that it is meant for `server`.
pub fn verify(release: &Release, public_key: &str, server: &str) -> Result<Manifest, ReleaseError> {
    if release.manifest.len() > MAX_MANIFEST_BYTES || release.signature.len() > MAX_MANIFEST_BYTES {
        return Err(ReleaseError::Malformed);
    }
    let pk = minisign_verify::PublicKey::from_base64(public_key.trim())
        .map_err(|_| ReleaseError::BadKey)?;
    let sig = minisign_verify::Signature::decode(&release.signature)
        .map_err(|_| ReleaseError::BadSignature)?;
    pk.verify(release.manifest.as_bytes(), &sig, false)
        .map_err(|_| ReleaseError::BadSignature)?;
    let m = Manifest::parse(&release.manifest)?;
    if m.server != server {
        return Err(ReleaseError::WrongServer);
    }
    Ok(m)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseError {
    Malformed,
    BadKey,
    BadSignature,
    WrongServer,
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "Release information is malformed",
            Self::BadKey => "Release key in this build is invalid",
            Self::BadSignature => "Release signature is invalid",
            Self::WrongServer => "Release is for a different server",
        })
    }
}

impl std::error::Error for ReleaseError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(server: &str) -> String {
        serde_json::to_string(&Manifest {
            product: "o2ee".into(),
            version: "1.2.3".into(),
            server: server.into(),
            files: vec![ReleaseFile {
                target: "x86_64-linux".into(),
                name: "o2ee-x86_64-linux".into(),
                size: 10,
                sha256: "a".repeat(64),
            }],
        })
        .unwrap_or_default()
    }

    fn sign(text: &str, kp: &minisign::KeyPair) -> String {
        minisign::sign(Some(&kp.pk), &kp.sk, text.as_bytes(), None, None)
            .map(|b| b.into_string())
            .unwrap_or_default()
    }

    #[test]
    fn signed_manifest_verifies_only_with_pinned_key() {
        let kp =
            minisign::KeyPair::generate_unencrypted_keypair().unwrap_or_else(|e| panic!("{e}"));
        let other =
            minisign::KeyPair::generate_unencrypted_keypair().unwrap_or_else(|e| panic!("{e}"));
        let text = manifest("a.onion");
        let release = Release {
            signature: sign(&text, &kp),
            manifest: text.clone(),
        };
        let pk = kp.pk.to_base64();
        assert!(verify(&release, &pk, "a.onion").is_ok());
        assert_eq!(
            verify(&release, &other.pk.to_base64(), "a.onion").err(),
            Some(ReleaseError::BadSignature)
        );
        assert_eq!(
            verify(&release, &pk, "b.onion").err(),
            Some(ReleaseError::WrongServer)
        );
        let tampered = Release {
            manifest: text.replace("1.2.3", "9.9.9"),
            signature: release.signature.clone(),
        };
        assert_eq!(
            verify(&tampered, &pk, "a.onion").err(),
            Some(ReleaseError::BadSignature)
        );
    }

    #[test]
    fn versions_and_names() {
        assert_eq!(parse_version("0.10.2"), Some((0, 10, 2)));
        for bad in ["1.2", "1.2.3.4", "1.2.x", "", "1..2", "+1.2.3", "1.2.3-rc1"] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
        assert!(parse_version("0.2.0") > parse_version("0.1.9"));
        assert!(valid_file_name("o2ee-x86_64-linux"));
        for bad in ["", "../x", ".hidden", "a/b", "a b", "a\\b", &"a".repeat(65)] {
            assert!(!valid_file_name(bad), "{bad}");
        }
    }

    #[test]
    fn manifest_shape() {
        assert!(Manifest::parse(&manifest("a.onion")).is_ok());
        let bad = manifest("a.onion").replace("o2ee-x86_64-linux", "../../state.json");
        assert!(Manifest::parse(&bad).is_err());
        let bad = manifest("a.onion").replace("\"size\":10", "\"size\":0");
        assert!(Manifest::parse(&bad).is_err());
    }
}
