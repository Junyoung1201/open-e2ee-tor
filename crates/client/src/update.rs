//! `o2ee update`: install a newer release signed with the release key that
//! is built into this binary.
//!
//! The server only delivers files. The manifest must carry a valid
//! signature from the pinned key, name this exact onion server, be newer
//! than the running version and list this platform; the binary must match
//! the signed size and SHA-256. Only then is the running executable
//! replaced, in one rename.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Method, StatusCode};
use o2ee_protocol::crypto::random_bytes;
use o2ee_protocol::release::{self, Release, current_target, parse_version};
use sha2::Digest;
use tokio::sync::mpsc::UnboundedSender;

use crate::Error;
use crate::net::{Net, read_small, server_error};
use crate::ops::{Phase, Progress, Reporter};

/// Release public key (minisign, base64) built in with
/// `O2EE_RELEASE_PUBKEY`. Without it this build cannot update itself.
pub const RELEASE_PUBKEY: Option<&str> = option_env!("O2EE_RELEASE_PUBKEY");

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    UpToDate(String),
    Updated(String),
}

pub async fn update(
    net: &Net,
    public_key: &str,
    current_version: &str,
    exe: &Path,
    progress: Option<UnboundedSender<Progress>>,
) -> Result<Outcome, Error> {
    let res = net
        .send(Method::GET, "/v1/release", None, &[], Bytes::new())
        .await?;
    let (status, body) = read_small(res).await?;
    if status == StatusCode::NOT_FOUND {
        return Ok(Outcome::UpToDate(current_version.to_owned()));
    }
    if !status.is_success() {
        return Err(server_error(status, &body));
    }
    let release: Release = serde_json::from_slice(&body)
        .map_err(|_| Error::Protocol("Unexpected server reply".into()))?;
    let manifest = release::verify(&release, public_key, net.server())
        .map_err(|e| Error::Verify(e.to_string()))?;
    let (Some(new), Some(now)) = (
        parse_version(&manifest.version),
        parse_version(current_version),
    ) else {
        return Err(Error::Protocol("Bad version".into()));
    };
    if new <= now {
        return Ok(Outcome::UpToDate(current_version.to_owned()));
    }
    let target = current_target();
    let file = manifest
        .file_for(&target)
        .ok_or_else(|| Error::Local(format!("No release for this platform ({target})")))?
        .clone();

    // Stage next to the executable so the final rename stays on one file
    // system; failing here means we could not replace it anyway.
    let dir = exe
        .parent()
        .ok_or_else(|| Error::Local("Cannot find the o2ee executable".into()))?;
    let tmp = dir.join(format!(".o2ee-update-{}", hex::encode(random_bytes::<8>())));
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&tmp)
        .map_err(|e| Error::Local(format!("Cannot replace {}: {e}", exe.display())))?;
    let result = async {
        let res = net
            .send(
                Method::GET,
                &format!("/download/{}", file.name),
                None,
                &[],
                Bytes::new(),
            )
            .await?;
        if res.status() != StatusCode::OK {
            return Err(Error::Server {
                status: res.status().as_u16(),
                message: "Download failed".into(),
            });
        }
        let mut reporter = Reporter::new(progress, Phase::Downloading, file.size);
        let mut hasher = sha2::Sha256::new();
        let mut got = 0u64;
        let mut body = res.into_body();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| Error::Network(format!("Download interrupted: {e}")))?;
            if let Ok(data) = frame.into_data() {
                got += data.len() as u64;
                if got > file.size {
                    return Err(Error::Verify("Download is larger than signed".into()));
                }
                hasher.update(&data);
                out.write_all(&data)
                    .map_err(|e| Error::Local(format!("{}: {e}", tmp.display())))?;
                reporter.update(got);
            }
        }
        if got != file.size || hex::encode(hasher.finalize()) != file.sha256 {
            return Err(Error::Verify(
                "Download does not match the signed release".into(),
            ));
        }
        out.sync_all()
            .map_err(|e| Error::Local(format!("{}: {e}", tmp.display())))?;
        fs::rename(&tmp, exe)
            .map_err(|e| Error::Local(format!("Cannot replace {}: {e}", exe.display())))
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map(|()| Outcome::Updated(manifest.version))
}
