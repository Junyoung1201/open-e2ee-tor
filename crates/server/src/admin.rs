//! Admin page, served only on 127.0.0.1 and never through the onion
//! service. Plain HTML forms, no scripts.
//!
//! Defences: Host allow-list (blocks DNS rebinding), Origin and
//! Sec-Fetch-Site checks plus a per-session CSRF token on every POST,
//! an Argon2id-hashed password with failure back-off, and an HttpOnly,
//! SameSite=Strict session cookie kept in memory only.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::OsRng as PhOsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use o2ee_protocol::crypto::random_bytes;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::App;
use crate::store::{AdminSession, Status, now_secs, write_private};

const COOKIE: &str = "o2ee_admin";
const SESSION_TTL: Duration = Duration::from_secs(60 * 60);
pub const MIN_ADMIN_PASSWORD_CHARS: usize = 12;

#[derive(Clone)]
struct AdminState {
    app: Arc<App>,
    port: u16,
}

pub fn router(app: Arc<App>, port: u16) -> Router {
    let state = AdminState { app, port };
    Router::new()
        .route("/", get(dashboard))
        .route("/style.css", get(style))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/action", post(action))
        .fallback(|| async { (StatusCode::NOT_FOUND, "Not found") })
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Rejects requests that did not come from a browser on this machine
/// talking to this exact address, and adds strict response headers.
async fn guard(State(s): State<AdminState>, req: Request, next: Next) -> Response {
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| {
            h == format!("127.0.0.1:{}", s.port) || h == format!("localhost:{}", s.port)
        });
    if !host_ok {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    if req.method() == axum::http::Method::POST {
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        let origin_ok = req
            .headers()
            .get(header::ORIGIN)
            .is_none_or(|o| o.to_str().ok() == Some(&format!("http://{host}")));
        let site_ok = req
            .headers()
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v == "same-origin" || v == "none");
        if !origin_ok || !site_ok {
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        // Not "no-referrer": under that policy browsers send `Origin: null`
        // on form posts, which the Origin check above must refuse. Nothing
        // is sent to other sites either way.
        ("referrer-policy", "same-origin"),
        ("cache-control", "no-store"),
    ] {
        h.insert(name, HeaderValue::from_static(value));
    }
    res
}

async fn style() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("admin.css"),
    )
        .into_response()
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{}</title><link rel=\"stylesheet\" href=\"/style.css\"></head>\
         <body><main>{body}</main></body></html>",
        esc(title)
    ))
}

fn cookie_value(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().strip_prefix(&format!("{COOKIE}=")))
        .map(str::to_owned)
        .next()
}

/// Returns the CSRF token of a valid admin session.
fn session(s: &AdminState, headers: &HeaderMap) -> Option<String> {
    let token = cookie_value(headers)?;
    let m = s.app.store.memory();
    m.admin_sessions
        .get(&token)
        .filter(|a| a.expires > Instant::now())
        .map(|a| a.csrf.clone())
}

fn password_hash(s: &AdminState) -> Option<String> {
    std::fs::read_to_string(s.app.store.admin_password_path())
        .ok()
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
}

pub fn hash_admin_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut PhOsRng);
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn set_admin_password(dir: &std::path::Path, password: &str) -> std::io::Result<()> {
    crate::store::private_dir(dir)?;
    let hash = hash_admin_password(password).map_err(std::io::Error::other)?;
    write_private(&dir.join("admin_password"), hash.as_bytes())
}

async fn login_page(State(s): State<AdminState>, headers: HeaderMap) -> Response {
    if session(&s, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    login_form(&s, "").into_response()
}

fn login_form(s: &AdminState, message: &str) -> Html<String> {
    if password_hash(s).is_none() {
        return page(
            "o2ee admin",
            &format!(
                "<h1>o2ee admin</h1><p class=\"warn\">Admin password is not set.</p>\
                 <p>Run on this computer:</p><pre>o2ee-server set-admin-password --data-dir {}</pre>",
                esc(&s.app.store.dir().display().to_string())
            ),
        );
    }
    let msg = if message.is_empty() {
        String::new()
    } else {
        format!("<p class=\"warn\">{}</p>", esc(message))
    };
    page(
        "o2ee admin login",
        &format!(
            "<h1>o2ee admin</h1>{msg}<form method=\"post\" action=\"/login\">\
             <label>Password <input type=\"password\" name=\"password\" autocomplete=\"current-password\" autofocus required></label>\
             <button>Log in</button></form>"
        ),
    )
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

fn parse_form<T: serde::de::DeserializeOwned>(body: &Bytes) -> Option<T> {
    serde_urlencoded::from_bytes(body).ok()
}

async fn login(State(s): State<AdminState>, body: Bytes) -> Response {
    let Some(form) = parse_form::<LoginForm>(&body) else {
        return login_form(&s, "Invalid request").into_response();
    };
    let password = Zeroizing::new(form.password);
    let now = Instant::now();
    if s.app.store.memory().admin_failures.locked(now) {
        return login_form(&s, "Too many failed attempts. Try again later.").into_response();
    }
    let Some(stored) = password_hash(&s) else {
        return login_form(&s, "").into_response();
    };
    let ok = PasswordHash::new(&stored).is_ok_and(|h| {
        argon2::Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    });
    if !ok {
        s.app.store.memory().admin_failures.record(now);
        return login_form(&s, "Wrong password").into_response();
    }
    let token = hex::encode(random_bytes::<32>());
    let mut m = s.app.store.memory();
    m.admin_failures = Default::default();
    m.admin_sessions.insert(
        token.clone(),
        AdminSession {
            csrf: hex::encode(random_bytes::<32>()),
            expires: now + SESSION_TTL,
        },
    );
    let cookie = format!(
        "{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    let mut res = Redirect::to("/").into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    res
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

fn csrf_ok(expected: &str, got: &str) -> bool {
    bool::from(expected.as_bytes().ct_eq(got.as_bytes()))
}

async fn logout(State(s): State<AdminState>, headers: HeaderMap, body: Bytes) -> Response {
    if let (Some(csrf), Some(form)) = (session(&s, &headers), parse_form::<CsrfForm>(&body))
        && csrf_ok(&csrf, &form.csrf)
        && let Some(token) = cookie_value(&headers)
    {
        s.app.store.memory().admin_sessions.remove(&token);
    }
    let mut res = Redirect::to("/login").into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("o2ee_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    res
}

#[derive(Deserialize)]
struct ActionForm {
    csrf: String,
    action: String,
    username: String,
    #[serde(default)]
    confirm: String,
}

async fn action(State(s): State<AdminState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(csrf) = session(&s, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let Some(form) = parse_form::<ActionForm>(&body) else {
        return (StatusCode::BAD_REQUEST, "Invalid request").into_response();
    };
    if !csrf_ok(&csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    let store = &s.app.store;
    let mut p = store.persist();
    let Some(account) = p.accounts.get_mut(&form.username) else {
        return Redirect::to("/").into_response();
    };
    let user = form.username.clone();
    match (form.action.as_str(), account.status) {
        ("approve", Status::Pending) => account.status = Status::Active,
        ("reject", Status::Pending) => {
            p.accounts.remove(&user);
        }
        ("suspend", Status::Active) => {
            account.status = Status::Suspended;
            store.end_sessions(&user);
        }
        ("resume", Status::Suspended) => account.status = Status::Active,
        ("logout", _) => store.end_sessions(&user),
        ("delete", Status::Active | Status::Suspended) if form.confirm == user => {
            store.delete_account(&mut p, &user);
        }
        _ => return (StatusCode::BAD_REQUEST, "Invalid action").into_response(),
    }
    if store.save(&p).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Could not save").into_response();
    }
    Redirect::to("/").into_response()
}

fn mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_000_000.0)
}

fn button(csrf: &str, action: &str, user: &str, label: &str, class: &str) -> String {
    format!(
        "<form method=\"post\" action=\"/action\" class=\"inline\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <input type=\"hidden\" name=\"action\" value=\"{action}\">\
         <input type=\"hidden\" name=\"username\" value=\"{}\">\
         <button class=\"{class}\">{label}</button></form>",
        esc(csrf),
        esc(user)
    )
}

async fn dashboard(State(s): State<AdminState>, headers: HeaderMap) -> Response {
    let Some(csrf) = session(&s, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let store = &s.app.store;
    let now = now_secs();
    let p = store.persist();
    let sessions: Vec<String> = store
        .memory()
        .sessions
        .values()
        .map(|x| x.username.clone())
        .collect();

    let mut body = String::from("<header><h1>o2ee admin</h1>");
    let _ = write!(
        body,
        "<form method=\"post\" action=\"/logout\" class=\"inline\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\"><button>Log out</button></form></header>",
        esc(&csrf)
    );

    let waiting: u64 = p.transfers.values().map(|t| t.size).sum();
    let free = rustix::fs::statvfs(store.dir())
        .map(|v| v.f_bavail.saturating_mul(v.f_frsize))
        .unwrap_or(0);
    let _ = write!(
        body,
        "<section><h2>Server</h2><dl>\
         <dt>Onion address</dt><dd><code>{}</code></dd>\
         <dt>Waiting transfers</dt><dd>{} ({})</dd>\
         <dt>Free disk</dt><dd>{}</dd></dl></section>",
        esc(&s.app.server_name),
        p.transfers.len(),
        mb(waiting),
        mb(free)
    );

    body.push_str("<section><h2>Signup requests</h2>");
    let pending: Vec<_> = p
        .accounts
        .iter()
        .filter(|(_, a)| a.status == Status::Pending)
        .collect();
    if pending.is_empty() {
        body.push_str("<p class=\"muted\">No requests.</p>");
    } else {
        body.push_str(
            "<p class=\"muted\">Approve only after the applicant gave you the same fingerprint through another channel.</p>\
             <table><tr><th>ID</th><th>Fingerprint</th><th>Note</th><th>Expires</th><th></th></tr>",
        );
        for (user, a) in pending {
            let left = (a.requested_at + o2ee_protocol::SIGNUP_RETENTION_SECS).saturating_sub(now);
            let _ = write!(
                body,
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>in {}h</td><td>{}{}</td></tr>",
                esc(user),
                esc(&a.fingerprint),
                esc(&a.note),
                left / 3600,
                button(&csrf, "approve", user, "Approve", "ok"),
                button(&csrf, "reject", user, "Reject", "danger"),
            );
        }
        body.push_str("</table>");
    }
    body.push_str("</section>");

    body.push_str("<section><h2>Accounts</h2>");
    let accounts: Vec<_> = p
        .accounts
        .iter()
        .filter(|(_, a)| a.status != Status::Pending)
        .collect();
    if accounts.is_empty() {
        body.push_str("<p class=\"muted\">No accounts.</p>");
    } else {
        body.push_str(
            "<table><tr><th>ID</th><th>Status</th><th>Fingerprint</th><th>Inbox</th><th>Sessions</th><th></th></tr>",
        );
        for (user, a) in accounts {
            let (count, bytes) = p
                .transfers
                .values()
                .filter(|t| &t.recipient == user)
                .fold((0, 0), |(c, b), t| (c + 1, b + t.size));
            let active = sessions.iter().filter(|u| *u == user).count();
            let (status, toggle) = match a.status {
                Status::Active => ("active", button(&csrf, "suspend", user, "Suspend", "")),
                _ => ("suspended", button(&csrf, "resume", user, "Resume", "ok")),
            };
            let _ = write!(
                body,
                "<tr><td>{}</td><td>{status}</td><td><code>{}</code></td><td>{count} ({})</td><td>{active}</td>\
                 <td>{toggle}{}<form method=\"post\" action=\"/action\" class=\"inline\">\
                 <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                 <input type=\"hidden\" name=\"action\" value=\"delete\">\
                 <input type=\"hidden\" name=\"username\" value=\"{}\">\
                 <input name=\"confirm\" placeholder=\"type ID to delete\" size=\"14\" required>\
                 <button class=\"danger\">Delete</button></form></td></tr>",
                esc(user),
                esc(&a.fingerprint),
                mb(bytes),
                button(&csrf, "logout", user, "End sessions", ""),
                esc(&csrf),
                esc(user),
            );
        }
        body.push_str("</table>");
    }
    body.push_str("</section>");
    page("o2ee admin", &body).into_response()
}
