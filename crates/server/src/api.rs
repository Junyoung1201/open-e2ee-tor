//! Public API served to clients over the onion service.
//!
//! The server trusts no client: every body is size-capped and parsed
//! strictly, every id and name is validated, and every action is checked
//! against the caller's session, account status and quotas.

use std::io::SeekFrom;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use futures_util::StreamExt;
use o2ee_protocol::api::*;
use o2ee_protocol::container::{max_ciphertext_len, valid_transfer_id};
use o2ee_protocol::crypto::{Suite, identifiers, pow, random_bytes, session_token, sha256};
use o2ee_protocol::text::{b64d, b64d_array, b64e};
use o2ee_protocol::{
    MAX_PENDING_BYTES_PER_ACCOUNT, MAX_PENDING_SIGNUPS, MIB, SESSION_LIFETIME_SECS,
    TRANSFER_RETENTION_SECS, Username, validate_signup_note,
};
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::App;
use crate::store::{
    Account, LOGIN_STATE_TTL, MAX_PENDING_LOGINS, PendingLogin, Session, Status, Transfer,
    now_secs, round_up_hour,
};

/// Space kept free on the server's disk no matter what.
const DISK_RESERVE: u64 = 1024 * MIB;
/// An upload request that sends nothing for this long is dropped, so a
/// dead stream does not hold the transfer's upload slot. Shorter than the
/// client's stall timeout, so the slot is free when the client retries.
const UPLOAD_IDLE: Duration = Duration::from_secs(60);
/// Each account's waiting transfers may use this much ciphertext (the
/// plaintext limit plus age overhead).
const PENDING_CIPHERTEXT_LIMIT: u64 = MAX_PENDING_BYTES_PER_ACCOUNT + 4 * MIB;

pub struct ApiError(StatusCode, String);

impl ApiError {
    fn new(status: StatusCode, msg: &str) -> Self {
        Self(status, msg.to_owned())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&ErrorBody { error: self.1 }).unwrap_or_default();
        (self.0, [(header::CONTENT_TYPE, "application/json")], body).into_response()
    }
}

type Result<T> = std::result::Result<T, ApiError>;

fn bad() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "Invalid request")
}

fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Transfer not found")
}

fn internal() -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Server error")
}

fn parse<T: DeserializeOwned>(body: &Bytes) -> Result<T> {
    if body.len() > MAX_JSON_BODY {
        return Err(bad());
    }
    serde_json::from_slice(body).map_err(|_| bad())
}

fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> Response {
    let body = serde_json::to_vec(value).unwrap_or_default();
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// Account names on the wire must already be in canonical form.
fn canonical(name: &str) -> Result<Username> {
    let user = Username::parse(name).map_err(|_| bad())?;
    if user.as_str() == name {
        Ok(user)
    } else {
        Err(bad())
    }
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/v1/signup/challenge", get(challenge))
        .route("/v1/signup/start", post(signup_start))
        .route("/v1/signup/finish", post(signup_finish))
        .route("/v1/login/start", post(login_start))
        .route("/v1/login/finish", post(login_finish))
        .route("/v1/me", get(me))
        .route("/v1/accounts/{username}", get(account))
        .route("/v1/transfers", post(create_transfer))
        .route("/v1/transfers/{id}/upload", get(upload_state))
        .route(
            "/v1/transfers/{id}/data",
            put(upload_data)
                .get(download_data)
                .layer(DefaultBodyLimit::max(MAX_UPLOAD_CHUNK)),
        )
        .route("/v1/transfers/{id}/finish", post(finish_upload))
        .route("/v1/transfers/{id}/ack", post(ack))
        .route("/v1/inbox", get(inbox))
        .merge(crate::release::routes())
        .fallback(|| async { ApiError::new(StatusCode::NOT_FOUND, "Not found") })
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(app)
}

/// Strict headers on every public response. Nothing here runs scripts or
/// loads anything from elsewhere, including the install guide.
async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; style-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("x-frame-options", "DENY"),
    ] {
        h.insert(name, HeaderValue::from_static(value));
    }
    res
}

// ---------------------------------------------------------------- signup

async fn challenge(State(app): State<Arc<App>>) -> Response {
    let challenge = pow::issue(&app.store.pow_key, now_secs() + 600);
    json(
        StatusCode::OK,
        &Challenge {
            challenge: b64e(challenge),
            difficulty: app.pow_difficulty,
        },
    )
}

fn check_pow(app: &App, username: &Username, challenge: &str, nonce: u64) -> Result<Vec<u8>> {
    let c = b64d_array::<{ pow::CHALLENGE_LEN }>(challenge).ok_or_else(bad)?;
    let expires = pow::check_issued(&app.store.pow_key, &c).ok_or_else(bad)?;
    if expires <= now_secs() || app.store.memory().used_challenges.contains_key(&c[..]) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Challenge expired"));
    }
    if !pow::verify(&c, username, nonce, app.pow_difficulty) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Proof of work failed",
        ));
    }
    Ok(c.to_vec())
}

fn check_signup_open(app: &App, username: &Username) -> Result<()> {
    let p = app.store.persist();
    if p.accounts.contains_key(username.as_str()) {
        return Err(ApiError::new(StatusCode::CONFLICT, "ID is already taken"));
    }
    let pending = p
        .accounts
        .values()
        .filter(|a| a.status == Status::Pending)
        .count();
    if pending >= MAX_PENDING_SIGNUPS {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signup is temporarily closed",
        ));
    }
    Ok(())
}

async fn signup_start(State(app): State<Arc<App>>, body: Bytes) -> Result<Response> {
    let req: SignupStart = parse(&body)?;
    let username = canonical(&req.username)?;
    check_pow(&app, &username, &req.challenge, req.nonce)?;
    check_signup_open(&app, &username)?;
    let msg = b64d(&req.registration_request, 1024).ok_or_else(bad)?;
    let msg = RegistrationRequest::<Suite>::deserialize(&msg).map_err(|_| bad())?;
    let start =
        ServerRegistration::<Suite>::start(&app.store.setup, msg, username.as_str().as_bytes())
            .map_err(|_| bad())?;
    Ok(json(
        StatusCode::OK,
        &SignupStartReply {
            registration_response: b64e(start.message.serialize()),
        },
    ))
}

async fn signup_finish(State(app): State<Arc<App>>, body: Bytes) -> Result<Response> {
    let req: SignupFinish = parse(&body)?;
    let username = canonical(&req.username)?;
    let challenge = check_pow(&app, &username, &req.challenge, req.nonce)?;
    validate_signup_note(&req.note).map_err(|_| bad())?;
    let bundle = req
        .bundle
        .verify(&app.server_name, Some(&username))
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid public keys"))?;
    let upload = b64d(&req.registration_upload, 4096).ok_or_else(bad)?;
    let upload = RegistrationUpload::<Suite>::deserialize(&upload).map_err(|_| bad())?;
    let password_file = ServerRegistration::<Suite>::finish(upload);

    check_signup_open(&app, &username)?;
    let mut p = app.store.persist();
    // Re-check under the lock that the name is still free.
    if p.accounts.contains_key(username.as_str()) {
        return Err(ApiError::new(StatusCode::CONFLICT, "ID is already taken"));
    }
    app.store
        .memory()
        .used_challenges
        .insert(challenge, now_secs() + 600);
    p.accounts.insert(
        username.to_string(),
        Account {
            status: Status::Pending,
            password_file: b64e(password_file.serialize()),
            bundle: req.bundle,
            fingerprint: bundle.fingerprint().to_string(),
            note: req.note,
            requested_at: now_secs() / 3600 * 3600,
        },
    );
    app.store.save(&p).map_err(|_| internal())?;
    Ok(StatusCode::ACCEPTED.into_response())
}

// ----------------------------------------------------------------- login

fn login_params<'a>(app: &'a App, username: &'a Username) -> ServerLoginParameters<'a, 'a> {
    ServerLoginParameters {
        context: Some(o2ee_protocol::crypto::OPAQUE_CONTEXT),
        identifiers: identifiers(username, &app.server_name),
    }
}

async fn login_start(State(app): State<Arc<App>>, body: Bytes) -> Result<Response> {
    let req: LoginStart = parse(&body)?;
    let username = canonical(&req.username)?;
    let msg = b64d(&req.credential_request, 1024).ok_or_else(bad)?;
    let msg = CredentialRequest::<Suite>::deserialize(&msg).map_err(|_| bad())?;
    let now = Instant::now();
    {
        let m = app.store.memory();
        if m.failures
            .get(username.as_str())
            .is_some_and(|f| f.locked(now))
        {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many failed logins. Try again later.",
            ));
        }
    }
    // Unknown accounts get a response indistinguishable from a real one.
    let password_file = app
        .store
        .persist()
        .accounts
        .get(username.as_str())
        .and_then(|a| b64d(&a.password_file, 4096))
        .and_then(|b| ServerRegistration::<Suite>::deserialize(&b).ok());
    let exists = password_file.is_some();
    let start = ServerLogin::start(
        &mut OsRng,
        &app.store.setup,
        password_file,
        msg,
        username.as_str().as_bytes(),
        login_params(&app, &username),
    )
    .map_err(|_| bad())?;
    let login_id = hex::encode(random_bytes::<16>());
    let mut m = app.store.memory();
    m.logins.retain(|_, l| l.expires > now);
    if m.logins.len() >= MAX_PENDING_LOGINS {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Server is busy",
        ));
    }
    // Every start is one online password guess: a client learns whether
    // its guess was right locally and need not send the final message. So
    // attempts are counted here and cleared only by a successful finish.
    // Unknown accounts are not tracked (they can never succeed), which
    // keeps this table bounded by the number of accounts.
    if exists {
        m.failures
            .entry(username.to_string())
            .or_default()
            .record(now);
    }
    m.logins.insert(
        login_id.clone(),
        PendingLogin {
            state: start.state,
            username: username.to_string(),
            expires: now + LOGIN_STATE_TTL,
        },
    );
    Ok(json(
        StatusCode::OK,
        &LoginStartReply {
            login_id,
            credential_response: b64e(start.message.serialize()),
        },
    ))
}

async fn login_finish(State(app): State<Arc<App>>, body: Bytes) -> Result<Response> {
    let req: LoginFinish = parse(&body)?;
    let pending = app
        .store
        .memory()
        .logins
        .remove(&req.login_id)
        .filter(|l| l.expires > Instant::now())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Login expired. Try again."))?;
    let username = canonical(&pending.username)?;
    let msg = b64d(&req.credential_finalization, 1024).ok_or_else(bad)?;
    let msg = CredentialFinalization::<Suite>::deserialize(&msg).map_err(|_| bad())?;
    let result = pending.state.finish(msg, login_params(&app, &username));
    let status = app
        .store
        .persist()
        .accounts
        .get(username.as_str())
        .map(|a| a.status);
    let now = Instant::now();
    let (Ok(result), Some(status)) = (result, status) else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid ID or password",
        ));
    };
    let mut m = app.store.memory();
    m.failures.remove(username.as_str());
    match status {
        Status::Pending => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Account is waiting for approval",
        )),
        Status::Suspended => Err(ApiError::new(StatusCode::FORBIDDEN, "Account is suspended")),
        Status::Active => {
            let token = session_token(&result.session_key);
            m.sessions.insert(
                hex::encode(sha256(token.as_bytes())),
                Session {
                    username: username.to_string(),
                    expires: now + Duration::from_secs(SESSION_LIFETIME_SECS),
                },
            );
            Ok(json(
                StatusCode::OK,
                &LoginFinishReply {
                    username: username.to_string(),
                    expires_in: SESSION_LIFETIME_SECS,
                },
            ))
        }
    }
}

/// The logged-in, still active account behind the request's bearer token.
fn auth(app: &App, headers: &HeaderMap) -> Result<(String, u64)> {
    let unauthorized = || ApiError::new(StatusCode::UNAUTHORIZED, "Not logged in");
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| t.len() == 64)
        .ok_or_else(unauthorized)?;
    let key = hex::encode(sha256(token.as_bytes()));
    let now = Instant::now();
    let (username, left) = {
        let m = app.store.memory();
        let s = m
            .sessions
            .get(&key)
            .filter(|s| s.expires > now)
            .ok_or_else(unauthorized)?;
        (s.username.clone(), (s.expires - now).as_secs())
    };
    let active = app
        .store
        .persist()
        .accounts
        .get(&username)
        .is_some_and(|a| a.status == Status::Active);
    if !active {
        app.store.memory().sessions.remove(&key);
        return Err(unauthorized());
    }
    Ok((username, left))
}

async fn me(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response> {
    let (username, expires_in) = auth(&app, &headers)?;
    Ok(json(
        StatusCode::OK,
        &Me {
            username,
            expires_in,
        },
    ))
}

async fn account(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Response> {
    auth(&app, &headers)?;
    let user = canonical(&name)?;
    let p = app.store.persist();
    let account = p
        .accounts
        .get(user.as_str())
        .filter(|a| a.status == Status::Active)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "No such user"))?;
    Ok(json(StatusCode::OK, &account.bundle))
}

// ------------------------------------------------------------- transfers

fn disk_free(app: &App) -> u64 {
    rustix::fs::statvfs(app.store.files_dir())
        .map(|s| s.f_bavail.saturating_mul(s.f_frsize))
        .unwrap_or(0)
}

async fn create_transfer(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    auth(&app, &headers)?;
    let req: CreateTransfer = parse(&body)?;
    let recipient = canonical(&req.recipient)?;
    if !valid_transfer_id(&req.id) {
        return Err(bad());
    }
    if req.size < MIB || req.size > max_ciphertext_len() {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "File is too large",
        ));
    }
    if disk_free(&app) < req.size.saturating_add(DISK_RESERVE) {
        return Err(ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "Server storage is full",
        ));
    }
    let upload_key = hex::encode(random_bytes::<32>());
    let mut p = app.store.persist();
    if !p
        .accounts
        .get(recipient.as_str())
        .is_some_and(|a| a.status == Status::Active)
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "No such user"));
    }
    if p.transfers.contains_key(&req.id) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Transfer already exists",
        ));
    }
    let pending: u64 = p
        .transfers
        .values()
        .filter(|t| t.recipient == recipient.as_str())
        .map(|t| t.size)
        .sum();
    if pending.saturating_add(req.size) > PENDING_CIPHERTEXT_LIMIT {
        return Err(ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "Recipient inbox is full",
        ));
    }
    p.transfers.insert(
        req.id.clone(),
        Transfer {
            recipient: recipient.to_string(),
            size: req.size,
            ready: false,
            expires_at: round_up_hour(now_secs() + TRANSFER_RETENTION_SECS),
            upload_key_hash: Some(hex::encode(sha256(upload_key.as_bytes()))),
            received: 0,
        },
    );
    app.store.save(&p).map_err(|_| internal())?;
    Ok(json(
        StatusCode::CREATED,
        &CreateTransferReply { upload_key },
    ))
}

/// Checks the upload key of an unfinished transfer; returns (received, size).
fn uploader(app: &App, headers: &HeaderMap, id: &str) -> Result<(u64, u64)> {
    auth(app, headers)?;
    if !valid_transfer_id(id) {
        return Err(not_found());
    }
    let key = headers
        .get(UPLOAD_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(not_found)?;
    let hash = hex::encode(sha256(key.as_bytes()));
    let p = app.store.persist();
    let t = p.transfers.get(id).ok_or_else(not_found)?;
    let ok = t
        .upload_key_hash
        .as_deref()
        .is_some_and(|h| bool::from(subtle::ConstantTimeEq::ct_eq(h.as_bytes(), hash.as_bytes())));
    if !ok || t.ready {
        return Err(not_found());
    }
    Ok((t.received, t.size))
}

async fn upload_state(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response> {
    let (received, _) = uploader(&app, &headers, &id)?;
    Ok(json(StatusCode::OK, &UploadState { received }))
}

#[derive(Deserialize)]
struct Offset {
    offset: u64,
}

/// Releases the per-transfer upload lock when the request ends.
struct UploadGuard<'a>(&'a App, String);

impl Drop for UploadGuard<'_> {
    fn drop(&mut self) {
        self.0.store.memory().uploading.remove(&self.1);
    }
}

async fn upload_data(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<Offset>,
    body: Body,
) -> Result<Response> {
    let (received, size) = uploader(&app, &headers, &id)?;
    if q.offset != received {
        return Ok(json(StatusCode::CONFLICT, &UploadState { received }));
    }
    if !app.store.memory().uploading.insert(id.clone()) {
        return Err(ApiError::new(StatusCode::CONFLICT, "Upload in progress"));
    }
    let _guard = UploadGuard(&app, id.clone());

    let path = app.store.file_path(&id);
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .await
        .map_err(|_| internal())?;
    file.seek(SeekFrom::Start(received))
        .await
        .map_err(|_| internal())?;

    let mut stream = body.into_data_stream();
    let mut written = 0u64;
    let mut failed = false;
    while let Some(chunk) = tokio::time::timeout(UPLOAD_IDLE, stream.next())
        .await
        .unwrap_or(Some(Err(axum::Error::new("idle"))))
    {
        let Ok(chunk) = chunk else {
            failed = true;
            break;
        };
        written += chunk.len() as u64;
        if received + written > size || written > MAX_UPLOAD_CHUNK as u64 {
            failed = true;
            break;
        }
        if file.write_all(&chunk).await.is_err() {
            failed = true;
            break;
        }
    }
    // A broken request leaves no partial bytes behind: the resume point is
    // always the end of the last complete request.
    let end = if failed { received } else { received + written };
    file.set_len(end).await.map_err(|_| internal())?;
    file.sync_data().await.map_err(|_| internal())?;
    if let Some(t) = app.store.persist().transfers.get_mut(&id) {
        t.received = end;
    }
    if failed {
        return Err(bad());
    }
    Ok(json(StatusCode::OK, &UploadState { received: end }))
}

async fn finish_upload(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response> {
    let (received, size) = uploader(&app, &headers, &id)?;
    if received != size {
        return Err(ApiError::new(StatusCode::CONFLICT, "Upload incomplete"));
    }
    let mut p = app.store.persist();
    let t = p.transfers.get_mut(&id).ok_or_else(not_found)?;
    t.ready = true;
    t.upload_key_hash = None;
    app.store.save(&p).map_err(|_| internal())?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn inbox(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response> {
    let (username, _) = auth(&app, &headers)?;
    let now = now_secs();
    let p = app.store.persist();
    let mut transfers: Vec<InboxEntry> = p
        .transfers
        .iter()
        .filter(|(_, t)| t.ready && t.recipient == username)
        .map(|(id, t)| InboxEntry {
            id: id.clone(),
            size: t.size,
            expires_in: t.expires_at.saturating_sub(now),
        })
        .collect();
    transfers.sort_by_key(|t| t.expires_in);
    transfers.truncate(MAX_INBOX_ENTRIES);
    Ok(json(StatusCode::OK, &Inbox { transfers }))
}

/// A ready transfer addressed to the caller.
fn delivery(app: &App, headers: &HeaderMap, id: &str) -> Result<u64> {
    let (username, _) = auth(app, headers)?;
    if !valid_transfer_id(id) {
        return Err(not_found());
    }
    let p = app.store.persist();
    p.transfers
        .get(id)
        .filter(|t| t.ready && t.recipient == username)
        .map(|t| t.size)
        .ok_or_else(not_found)
}

fn parse_range(headers: &HeaderMap, size: u64) -> Result<Option<(u64, u64)>> {
    let Some(value) = headers.get(header::RANGE) else {
        return Ok(None);
    };
    let range = value
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("bytes="))
        .ok_or_else(bad)?;
    let (start, end) = range.split_once('-').ok_or_else(bad)?;
    let start: u64 = start.parse().map_err(|_| bad())?;
    let end: u64 = if end.is_empty() {
        size.saturating_sub(1)
    } else {
        end.parse::<u64>()
            .map_err(|_| bad())?
            .min(size.saturating_sub(1))
    };
    if start >= size || end < start {
        return Err(ApiError::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "Invalid range",
        ));
    }
    Ok(Some((start, end)))
}

async fn download_data(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response> {
    let size = delivery(&app, &headers, &id)?;
    let range = parse_range(&headers, size)?;
    let (start, end) = range.unwrap_or((0, size.saturating_sub(1)));
    let mut file = tokio::fs::File::open(app.store.file_path(&id))
        .await
        .map_err(|_| not_found())?;
    file.seek(SeekFrom::Start(start))
        .await
        .map_err(|_| internal())?;
    let len = end - start + 1;
    let stream = tokio_util::io::ReaderStream::new(tokio::io::AsyncReadExt::take(file, len));
    let mut response = Response::new(Body::from_stream(stream));
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if range.is_some() {
        let value = format!("bytes {start}-{end}/{size}");
        h.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&value).map_err(|_| internal())?,
        );
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
    }
    Ok(response)
}

async fn ack(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response> {
    delivery(&app, &headers, &id)?;
    let mut p = app.store.persist();
    app.store.delete_transfer(&mut p, &id);
    app.store.save(&p).map_err(|_| internal())?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
