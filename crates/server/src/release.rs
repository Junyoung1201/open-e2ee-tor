//! Client releases: publishing a signed release into the data folder, and
//! serving the install guide, the downloads and the manifest over the
//! onion service.
//!
//! The server never holds the release signing key. It checks a release
//! against the public key that comes with it before publishing, but clients
//! only trust the key built into them.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use o2ee_protocol::release::{
    MANIFEST, MANIFEST_SIG, MAX_MANIFEST_BYTES, Manifest, PUBKEY_FILE, Release, parse_version,
    valid_file_name,
};
use o2ee_protocol::text::sanitize;

use crate::App;
use crate::store::{private_dir, write_private};

pub fn release_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("release")
}

fn read_small(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > MAX_MANIFEST_BYTES as u64 {
        return None;
    }
    fs::read_to_string(path).ok()
}

/// The published release, if any.
struct Published {
    manifest: Manifest,
    manifest_text: String,
    signature: String,
    public_key: Option<String>,
}

fn load(data_dir: &Path) -> Option<Published> {
    let dir = release_dir(data_dir);
    let manifest_text = read_small(&dir.join(MANIFEST))?;
    let signature = read_small(&dir.join(MANIFEST_SIG))?;
    let manifest = Manifest::parse(&manifest_text).ok()?;
    Some(Published {
        manifest,
        manifest_text,
        signature,
        public_key: read_small(&dir.join(PUBKEY_FILE)),
    })
}

fn sha256_file(path: &Path) -> std::io::Result<(u64, String)> {
    use sha2::Digest;
    let mut f = fs::File::open(path)?;
    let mut h = sha2::Sha256::new();
    let n = std::io::copy(&mut f, &mut h)?;
    Ok((n, hex::encode(h.finalize())))
}

/// Publishes the release in `from` (made by deploy/make-release.sh and
/// signed offline): checks the signature against `from/minisign.pub`, the
/// sizes and hashes of every file, refuses to go back to an older version,
/// then replaces the published release in one rename.
pub fn publish(data_dir: &Path, from: &Path) -> Result<String, String> {
    let text = read_small(&from.join(MANIFEST)).ok_or("manifest.json is missing or too large")?;
    let signature =
        read_small(&from.join(MANIFEST_SIG)).ok_or("manifest.json.minisig is missing")?;
    let public_key = read_small(&from.join(PUBKEY_FILE)).ok_or("minisign.pub is missing")?;
    let key_line = public_key
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .ok_or("minisign.pub is malformed")?;
    let manifest = Manifest::parse(&text).map_err(|e| e.to_string())?;
    let release = Release {
        manifest: text.clone(),
        signature: signature.clone(),
    };
    o2ee_protocol::release::verify(&release, key_line, &manifest.server)
        .map_err(|e| e.to_string())?;
    if let Some(current) = load(data_dir)
        && parse_version(&manifest.version) <= parse_version(&current.manifest.version)
    {
        return Err(format!(
            "Version {} is not newer than the published {}",
            manifest.version, current.manifest.version
        ));
    }

    let staging = data_dir.join("release.new");
    let _ = fs::remove_dir_all(&staging);
    private_dir(&staging).map_err(|e| e.to_string())?;
    let copy = |name: &str| -> Result<(), String> {
        let bytes = fs::read(from.join(name)).map_err(|e| format!("{name}: {e}"))?;
        write_private(&staging.join(name), &bytes).map_err(|e| format!("{name}: {e}"))
    };
    for f in &manifest.files {
        let (size, hash) =
            sha256_file(&from.join(&f.name)).map_err(|e| format!("{}: {e}", f.name))?;
        if size != f.size || hash != f.sha256 {
            return Err(format!("{} does not match manifest.json", f.name));
        }
        copy(&f.name)?;
        let sig = format!("{}.minisig", f.name);
        if from.join(&sig).exists() {
            copy(&sig)?;
        }
    }
    for name in [MANIFEST, MANIFEST_SIG, PUBKEY_FILE] {
        copy(name)?;
    }
    let live = release_dir(data_dir);
    let old = data_dir.join("release.old");
    let _ = fs::remove_dir_all(&old);
    if live.exists() {
        fs::rename(&live, &old).map_err(|e| e.to_string())?;
    }
    fs::rename(&staging, &live).map_err(|e| e.to_string())?;
    let _ = fs::remove_dir_all(&old);
    Ok(manifest.version)
}

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/guide", get(guide))
        .route("/guide.css", get(style))
        .route("/download/{name}", get(download))
        .route("/v1/release", get(release))
}

async fn style() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("guide.css"),
    )
        .into_response()
}

fn esc(s: &str) -> String {
    sanitize(s, 500)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn size(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_000_000.0)
}

async fn guide(State(app): State<Arc<App>>) -> Response {
    let mut body = String::from(
        "<h1>o2ee</h1><p class=\"lead\">End-to-end encrypted file sharing over Tor. \
         Command line only. Your files are encrypted on your device; this server only \
         relays ciphertext.</p>",
    );
    match load(app.store.dir()) {
        None => body.push_str("<p class=\"note\">No release has been published yet.</p>"),
        Some(p) => {
            let m = &p.manifest;
            body.push_str(&format!(
                "<h2>1. Download</h2><p>Version {}</p><table><tr><th>Platform</th><th>File</th><th>Size</th></tr>",
                esc(&m.version)
            ));
            for f in &m.files {
                body.push_str(&format!(
                    "<tr><td>{}</td><td><a href=\"/download/{name}\">{name}</a> \
                     · <a href=\"/download/{name}.minisig\">signature</a></td><td>{}</td></tr>",
                    esc(&f.target),
                    size(f.size),
                    name = esc(&f.name),
                ));
            }
            body.push_str("</table>");
            let first = m.files.first().map(|f| esc(&f.name)).unwrap_or_default();
            let key = p
                .public_key
                .as_deref()
                .and_then(|k| {
                    k.lines()
                        .map(str::trim)
                        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
                        .map(esc)
                })
                .unwrap_or_else(|| "(not published)".into());
            body.push_str(&format!(
                "<h2>2. Verify</h2>\
                 <p class=\"note\">Get the release public key from the administrator through \
                 another channel and check that it matches the one below. This page alone \
                 proves nothing: whoever controls the server controls the page.</p>\
                 <pre>{key}</pre>\
                 <pre>minisign -Vm {first} -P {key}</pre>\
                 <h2>3. Install</h2>\
                 <pre>chmod +x {first}\nmkdir -p ~/.local/bin\nmv {first} ~/.local/bin/o2ee</pre>"
            ));
        }
    }
    body.push_str(
        "<h2>4. Sign up</h2><pre>o2ee signup --id &lt;id&gt;</pre>\
         <p>Send the fingerprint it prints to the administrator through another channel. \
         After approval:</p><pre>o2ee login --id &lt;id&gt;\no2ee send --target &lt;id&gt; --file &lt;path&gt;\no2ee inbox\no2ee download &lt;transfer id&gt;</pre>\
         <h2>Update</h2><pre>o2ee update</pre>\
         <p>Installs only releases signed with the key built into your copy.</p>",
    );
    Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <title>o2ee install guide</title><link rel=\"stylesheet\" href=\"/guide.css\"></head>\
         <body><main>{body}</main></body></html>"
    ))
    .into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not found").into_response()
}

async fn download(State(app): State<Arc<App>>, UrlPath(name): UrlPath<String>) -> Response {
    if !valid_file_name(&name) {
        return not_found();
    }
    let Some(p) = load(app.store.dir()) else {
        return not_found();
    };
    // Only files that belong to the published release.
    let listed = [MANIFEST, MANIFEST_SIG, PUBKEY_FILE].contains(&name.as_str())
        || p.manifest
            .files
            .iter()
            .any(|f| f.name == name || format!("{}.minisig", f.name) == name);
    if !listed {
        return not_found();
    }
    let path = release_dir(app.store.dir()).join(&name);
    let Ok(file) = tokio::fs::File::open(&path).await else {
        return not_found();
    };
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let mut res = Response::new(Body::from_stream(tokio_util::io::ReaderStream::new(file)));
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    res
}

async fn release(State(app): State<Arc<App>>) -> Response {
    match load(app.store.dir()) {
        Some(p) => (
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::to_vec(&Release {
                manifest: p.manifest_text,
                signature: p.signature,
            })
            .unwrap_or_default(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":"No release published"}"#,
        )
            .into_response(),
    }
}
