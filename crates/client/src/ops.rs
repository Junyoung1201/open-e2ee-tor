//! What the client actually does: signup, login and, for a logged-in
//! session, key lookup and pinning, sending, listing and downloading.
//!
//! The client trusts the server for nothing but delivery. Public keys it
//! hands out are pinned on first use and compared afterwards; every
//! received file is decrypted, its sender signature and context checked,
//! and written under its final name only after all of that succeeded.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use age::secrecy::SecretString;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Method, StatusCode};
use o2ee_protocol::api::*;
use o2ee_protocol::container::{self, Header, Kind, new_transfer_id, valid_transfer_id};
use o2ee_protocol::crypto::{
    Identity, OPAQUE_CONTEXT, SignedBundle, Suite, VerifiedBundle, identifiers, pow, session_token,
};
use o2ee_protocol::text::{b64d, b64e, sanitize};
use o2ee_protocol::{MAX_FILE_BYTES, Username};
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;
use zeroize::Zeroizing;

use crate::Error;
use crate::net::{Net, STALL_TIMEOUT, read_small, server_error};
use crate::paths::{Paths, private_dir, write_private};

pub const MIN_PASSWORD_CHARS: usize = 10;
/// Ciphertext prefix fetched to read a transfer's header.
const PEEK_BYTES: u64 = 128 * 1024;
const RETRIES: u32 = 5;
/// Tor circuits differ a lot in speed. A download that gets less than
/// this in a window moves to a new circuit and resumes there.
const SLOW: SpeedRule = SpeedRule {
    window: Duration::from_secs(30),
    min_bytes: 2 * 1024 * 1024,
};
/// After this many circuit changes the speed is accepted as it is, and
/// only a complete stall ends the request.
const MAX_CIRCUIT_CHANGES: u32 = 3;
const STALLED: SpeedRule = SpeedRule {
    window: STALL_TIMEOUT,
    min_bytes: 1,
};

/// Client-side password policy; the server never sees the password.
pub fn check_password_strength(password: &str, id: &Username) -> Result<(), Error> {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < MIN_PASSWORD_CHARS {
        return Err(Error::Local(format!(
            "Password must be at least {MIN_PASSWORD_CHARS} characters"
        )));
    }
    let lower = password.to_lowercase();
    let weak = chars.iter().all(|c| *c == chars[0])
        || lower.contains(id.as_str())
        || ["password", "1234567890", "qwertyuiop", "letmein"]
            .iter()
            .any(|w| lower.contains(w));
    if weak {
        return Err(Error::Local("Password is too easy to guess".into()));
    }
    Ok(())
}

// ------------------------------------------------------------- progress

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Connecting,
    Preparing,
    Uploading,
    Downloading,
    Verifying,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Progress {
    pub phase: Phase,
    pub done: u64,
    pub total: u64,
}

/// Forwards progress at most every 200 ms (plus the final value).
pub struct Reporter {
    tx: Option<UnboundedSender<Progress>>,
    phase: Phase,
    total: u64,
    last: Option<Instant>,
}

impl Reporter {
    pub fn new(tx: Option<UnboundedSender<Progress>>, phase: Phase, total: u64) -> Self {
        Self {
            tx,
            phase,
            total,
            last: None,
        }
    }

    pub fn update(&mut self, done: u64) {
        let now = Instant::now();
        let due = self
            .last
            .is_none_or(|t| now - t >= Duration::from_millis(200));
        if (due || done >= self.total)
            && let Some(tx) = &self.tx
        {
            self.last = Some(now);
            let _ = tx.send(Progress {
                phase: self.phase,
                done,
                total: self.total,
            });
        }
    }
}

// --------------------------------------------------------------- signup

/// Creates keys, registers with OPAQUE and asks for approval. Keys are
/// saved before the final step and removed again if it fails.
pub async fn signup(
    net: &Net,
    paths: &Paths,
    user: &Username,
    password: &SecretString,
) -> Result<String, Error> {
    use age::secrecy::ExposeSecret;
    let dir = paths.account(user);
    if paths.identity_file(user).exists() {
        return Err(Error::Local(format!(
            "Keys for {user} already exist on this device"
        )));
    }
    let identity = Identity::generate();
    let bundle = identity.public_bundle(user, net.server());
    let fingerprint = bundle
        .verify(net.server(), Some(user))
        .map_err(|e| Error::Protocol(e.to_string()))?
        .fingerprint()
        .to_string();

    let c: Challenge = net
        .call(Method::GET, "/v1/signup/challenge", None, None::<&()>)
        .await?;
    let challenge = b64d(&c.challenge, pow::CHALLENGE_LEN)
        .filter(|b| b.len() == pow::CHALLENGE_LEN)
        .ok_or_else(|| Error::Protocol("Unexpected server reply".into()))?;
    if c.difficulty > 28 {
        return Err(Error::Protocol("Server asks for too much work".into()));
    }
    let nonce = {
        let (challenge, user) = (challenge.clone(), user.clone());
        tokio::task::spawn_blocking(move || pow::solve(&challenge, &user, c.difficulty))
            .await
            .map_err(|_| Error::Local("Proof of work failed".into()))?
    };

    let pw = password.expose_secret().as_bytes();
    let start = ClientRegistration::<Suite>::start(&mut OsRng, pw)
        .map_err(|_| Error::Protocol("OPAQUE failed".into()))?;
    let reply: SignupStartReply = net
        .call(
            Method::POST,
            "/v1/signup/start",
            None,
            Some(&SignupStart {
                username: user.to_string(),
                challenge: c.challenge.clone(),
                nonce,
                registration_request: b64e(start.message.serialize()),
            }),
        )
        .await?;
    let response = b64d(&reply.registration_response, 1024)
        .and_then(|b| RegistrationResponse::<Suite>::deserialize(&b).ok())
        .ok_or_else(|| Error::Protocol("Unexpected server reply".into()))?;
    let ksf = opaque_ke::argon2::Argon2::default();
    let finish = start
        .state
        .finish(
            &mut OsRng,
            pw,
            response,
            ClientRegistrationFinishParameters::new(identifiers(user, net.server()), Some(&ksf)),
        )
        .map_err(|_| Error::Protocol("OPAQUE failed".into()))?;

    private_dir(&dir)?;
    let sealed = identity
        .seal(password)
        .map_err(|e| Error::Local(e.to_string()))?;
    write_private(&paths.identity_file(user), &sealed)?;
    write_private(
        &paths.bundle_file(user),
        &serde_json::to_vec(&bundle).map_err(|_| Error::Local("Cannot save keys".into()))?,
    )?;

    let result: Result<(), Error> = net
        .call(
            Method::POST,
            "/v1/signup/finish",
            None,
            Some(&SignupFinish {
                username: user.to_string(),
                challenge: c.challenge,
                nonce,
                registration_upload: b64e(finish.message.serialize()),
                bundle,
                note: String::new(),
            }),
        )
        .await;
    if let Err(e) = result {
        let _ = fs::remove_dir_all(&dir);
        return Err(e);
    }
    Ok(fingerprint)
}

// ---------------------------------------------------------------- login

#[derive(Default, Serialize, Deserialize)]
struct Contacts {
    pinned: BTreeMap<String, SignedBundle>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Trust {
    /// Same keys as pinned earlier (or our own keys).
    Known,
    /// Never seen; the user must compare the fingerprint first.
    New,
    /// Different from the pinned keys: refuse.
    Changed,
}

/// A logged-in account. Lives in the agent's memory only.
pub struct Session {
    pub net: Net,
    pub paths: Paths,
    pub user: Username,
    identity: Identity,
    own: VerifiedBundle,
    token: Zeroizing<String>,
    pub expires: Instant,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

pub async fn login(
    net: Net,
    paths: Paths,
    user: &Username,
    password: &SecretString,
) -> Result<Session, Error> {
    use age::secrecy::ExposeSecret;
    let sealed = fs::read(paths.identity_file(user)).map_err(|_| {
        Error::Local(format!(
            "No keys for {user} on this device. Sign up on this device first."
        ))
    })?;
    let pw = password.expose_secret().as_bytes();
    let start = ClientLogin::<Suite>::start(&mut OsRng, pw)
        .map_err(|_| Error::Protocol("OPAQUE failed".into()))?;
    let reply: LoginStartReply = net
        .call(
            Method::POST,
            "/v1/login/start",
            None,
            Some(&LoginStart {
                username: user.to_string(),
                credential_request: b64e(start.message.serialize()),
            }),
        )
        .await?;
    let response = b64d(&reply.credential_response, 1024)
        .and_then(|b| CredentialResponse::<Suite>::deserialize(&b).ok())
        .ok_or_else(|| Error::Protocol("Unexpected server reply".into()))?;
    let ksf = opaque_ke::argon2::Argon2::default();
    // OPAQUE authenticates the server too: only a server holding this
    // account's registration can make this step succeed.
    let finish = start
        .state
        .finish(
            &mut OsRng,
            pw,
            response,
            ClientLoginFinishParameters::new(
                Some(OPAQUE_CONTEXT),
                identifiers(user, net.server()),
                Some(&ksf),
            ),
        )
        .map_err(|_| Error::Server {
            status: 401,
            message: "Invalid ID or password".into(),
        })?;
    let done: LoginFinishReply = net
        .call(
            Method::POST,
            "/v1/login/finish",
            None,
            Some(&LoginFinish {
                login_id: reply.login_id,
                credential_finalization: b64e(finish.message.serialize()),
            }),
        )
        .await?;
    if done.username != user.as_str() {
        return Err(Error::Protocol("Unexpected server reply".into()));
    }
    let identity = {
        let password = password.clone();
        tokio::task::spawn_blocking(move || Identity::unseal(&sealed, &password))
            .await
            .map_err(|_| Error::Local("Cannot unlock keys".into()))?
            .map_err(|_| Error::Local("Keys on this device do not match this password".into()))?
    };
    let own = identity
        .public_bundle(user, net.server())
        .verify(net.server(), Some(user))
        .map_err(|e| Error::Protocol(e.to_string()))?;
    Ok(Session {
        net,
        paths,
        user: user.clone(),
        identity,
        own,
        token: session_token(&finish.session_key),
        expires: Instant::now()
            + Duration::from_secs(done.expires_in.min(o2ee_protocol::SESSION_LIFETIME_SECS)),
    })
}

/// What the client found out about a transfer from its header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peek {
    pub id: String,
    pub sender: String,
    pub fingerprint: String,
    pub trust: Trust,
    pub name: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxItem {
    pub id: String,
    pub expires_in: u64,
    pub ciphertext_size: u64,
    pub peek: Option<Peek>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    File,
    Dir,
}

impl Session {
    pub fn fingerprint(&self) -> String {
        self.own.fingerprint().to_string()
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T, Error> {
        self.net.call(method, path, Some(&self.token), body).await
    }

    /// Asks the server whether the session is still valid.
    pub async fn me(&self) -> Result<Me, Error> {
        self.call(Method::GET, "/v1/me", None::<&()>).await
    }

    fn contacts(&self) -> Contacts {
        fs::read(self.paths.contacts_file(&self.user))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    async fn fetch_bundle(&self, user: &Username) -> Result<VerifiedBundle, Error> {
        if *user == self.user {
            return Ok(self.own.clone());
        }
        let signed: SignedBundle = self
            .call(Method::GET, &format!("/v1/accounts/{user}"), None::<&()>)
            .await?;
        signed
            .verify(self.net.server(), Some(user))
            .map_err(|_| Error::Protocol(format!("Server sent invalid keys for {user}")))
    }

    fn trust_of(&self, bundle: &VerifiedBundle) -> Trust {
        if bundle.username == self.user {
            return if bundle.signed == self.own.signed {
                Trust::Known
            } else {
                Trust::Changed
            };
        }
        match self.contacts().pinned.get(bundle.username.as_str()) {
            None => Trust::New,
            Some(p)
                if p.bundle.signing_key == bundle.signed.bundle.signing_key
                    && p.bundle.age_recipient == bundle.signed.bundle.age_recipient =>
            {
                Trust::Known
            }
            Some(_) => Trust::Changed,
        }
    }

    pub async fn lookup(&self, user: &Username) -> Result<(String, Trust), Error> {
        let bundle = self.fetch_bundle(user).await?;
        Ok((bundle.fingerprint().to_string(), self.trust_of(&bundle)))
    }

    /// Pins `user`'s keys after the user confirmed `fingerprint`. The keys
    /// are fetched again and must still match what was confirmed.
    pub async fn trust(&self, user: &Username, fingerprint: &str) -> Result<(), Error> {
        let bundle = self.fetch_bundle(user).await?;
        if bundle.fingerprint().to_string() != fingerprint {
            return Err(Error::Protocol(format!(
                "Keys for {user} changed. Try again."
            )));
        }
        match self.trust_of(&bundle) {
            Trust::Known => Ok(()),
            Trust::Changed => Err(key_changed(user)),
            Trust::New => {
                let mut c = self.contacts();
                c.pinned.insert(user.to_string(), bundle.signed);
                let bytes = serde_json::to_vec(&c)
                    .map_err(|_| Error::Local("Cannot save contacts".into()))?;
                write_private(&self.paths.contacts_file(&self.user), &bytes)
            }
        }
    }

    /// The pinned keys of `user`, or an error if they are not pinned yet or
    /// the server now serves different ones.
    async fn pinned(&self, user: &Username) -> Result<VerifiedBundle, Error> {
        let bundle = self.fetch_bundle(user).await?;
        match self.trust_of(&bundle) {
            Trust::Known => Ok(bundle),
            Trust::New => Err(Error::Local(format!(
                "Fingerprint of {user} is not verified"
            ))),
            Trust::Changed => Err(key_changed(user)),
        }
    }

    // ------------------------------------------------------------ send

    pub async fn send(
        &self,
        target: &Username,
        path: &Path,
        source: Source,
        progress: Option<UnboundedSender<Progress>>,
    ) -> Result<String, Error> {
        let recipient = self.pinned(target).await?;
        private_dir(&self.paths.outgoing())?;
        let id = new_transfer_id();
        let work = self.paths.outgoing().join(&id);
        let result = self
            .send_inner(&id, &work, &recipient, path, source, progress)
            .await;
        let _ = fs::remove_file(work.with_extension("zip"));
        let _ = fs::remove_file(work.with_extension("age"));
        result.map(|()| id)
    }

    async fn send_inner(
        &self,
        id: &str,
        work: &Path,
        recipient: &VerifiedBundle,
        path: &Path,
        source: Source,
        progress: Option<UnboundedSender<Progress>>,
    ) -> Result<(), Error> {
        let (plain, kind, name) = match source {
            Source::File => {
                let meta = fs::metadata(path).map_err(|e| local_io(path, e))?;
                if !meta.is_file() {
                    return Err(Error::Local(format!("Not a file: {}", path.display())));
                }
                (path.to_owned(), Kind::File, file_name(path, "file"))
            }
            Source::Dir => {
                let zip = work.with_extension("zip");
                let (dir, out) = (path.to_owned(), zip.clone());
                tokio::task::spawn_blocking(move || zip_dir(&dir, &out))
                    .await
                    .map_err(|_| Error::Local("Cannot create zip".into()))??;
                let name = format!("{}.zip", file_name(path, "folder"));
                (zip, Kind::Zip, name)
            }
        };
        let size = fs::metadata(&plain).map_err(|e| local_io(&plain, e))?.len();
        if size > MAX_FILE_BYTES {
            return Err(Error::Local("File is larger than 4 GiB".into()));
        }
        let header = Header {
            version: 1,
            transfer_id: id.to_owned(),
            sender: self.user.to_string(),
            recipient: recipient.username.to_string(),
            server: self.net.server().to_owned(),
            kind,
            name,
            size,
            sha256: String::new(),
        };
        let sealed = work.with_extension("age");
        {
            let (plain, sealed) = (plain.clone(), sealed.clone());
            let signer = self.identity.signing_key().clone();
            let to = recipient.age_recipient.clone();
            let progress = progress.clone();
            let mut header = header;
            tokio::task::spawn_blocking(move || -> Result<(), Error> {
                let mut r = Reporter::new(progress, Phase::Preparing, size.saturating_mul(2));
                header.sha256 = b64e(hash_file(&plain, |n| r.update(n))?);
                let input = File::open(&plain).map_err(|e| local_io(&plain, e))?;
                let counting = Counting::new(BufReader::new(input), |n| r.update(size + n));
                let out = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&sealed)
                    .map_err(|e| local_io(&sealed, e))?;
                let out = container::seal(
                    &header,
                    &signer,
                    &to,
                    counting,
                    std::io::BufWriter::new(out),
                )
                .map_err(|e| Error::Local(e.to_string()))?;
                out.into_inner()
                    .map_err(|_| Error::Local("Cannot write encrypted file".into()))?
                    .sync_all()
                    .map_err(|e| local_io(&sealed, e))
            })
            .await
            .map_err(|_| Error::Local("Encryption failed".into()))??;
        }

        let total = fs::metadata(&sealed)
            .map_err(|e| local_io(&sealed, e))?
            .len();
        let created: CreateTransferReply = self
            .call(
                Method::POST,
                "/v1/transfers",
                Some(&CreateTransfer {
                    id: id.to_owned(),
                    recipient: recipient.username.to_string(),
                    size: total,
                }),
            )
            .await?;
        let key = Zeroizing::new(created.upload_key);
        self.upload(id, &sealed, total, &key, progress).await?;
        let res = self
            .net
            .send(
                Method::POST,
                &format!("/v1/transfers/{id}/finish"),
                Some(&self.token),
                &[(UPLOAD_KEY_HEADER, key.to_string())],
                Bytes::new(),
            )
            .await?;
        let (status, body) = read_small(res).await?;
        if !status.is_success() {
            return Err(server_error(status, &body));
        }
        Ok(())
    }

    async fn upload_state(&self, id: &str, key: &str) -> Result<u64, Error> {
        let res = self
            .net
            .send(
                Method::GET,
                &format!("/v1/transfers/{id}/upload"),
                Some(&self.token),
                &[(UPLOAD_KEY_HEADER, key.to_owned())],
                Bytes::new(),
            )
            .await?;
        let (status, body) = read_small(res).await?;
        if !status.is_success() {
            return Err(server_error(status, &body));
        }
        serde_json::from_slice::<UploadState>(&body)
            .map(|s| s.received)
            .map_err(|_| Error::Protocol("Unexpected server reply".into()))
    }

    async fn upload(
        &self,
        id: &str,
        sealed: &Path,
        total: u64,
        key: &str,
        progress: Option<UnboundedSender<Progress>>,
    ) -> Result<(), Error> {
        let mut reporter = Reporter::new(progress, Phase::Uploading, total);
        let mut file = File::open(sealed).map_err(|e| local_io(sealed, e))?;
        let mut offset = 0u64;
        let mut failures = 0;
        reporter.update(0);
        while offset < total {
            let len = (total - offset).min(MAX_UPLOAD_CHUNK as u64) as usize;
            let mut chunk = vec![0u8; len];
            file.seek(SeekFrom::Start(offset))
                .and_then(|_| file.read_exact(&mut chunk))
                .map_err(|e| local_io(sealed, e))?;
            let outcome = self
                .net
                .send_watched(
                    Method::PUT,
                    &format!("/v1/transfers/{id}/data?offset={offset}"),
                    Some(&self.token),
                    &[
                        (UPLOAD_KEY_HEADER, key.to_owned()),
                        ("content-type", "application/octet-stream".to_owned()),
                    ],
                    Bytes::from(chunk),
                    |sent| reporter.update(offset + sent),
                )
                .await;
            match outcome {
                Ok((status, body)) if status.is_success() || status == StatusCode::CONFLICT => {
                    let received = serde_json::from_slice::<UploadState>(&body)
                        .map(|s| s.received)
                        .map_err(|_| Error::Protocol("Unexpected server reply".into()));
                    match received {
                        Ok(r) if r <= total => {
                            if r > offset {
                                failures = 0;
                            }
                            offset = r;
                        }
                        // The server may still hold the slot of a request
                        // that died on the way; it frees it after a while.
                        Err(_) if status == StatusCode::CONFLICT && failures < RETRIES => {
                            failures += 1;
                            tokio::time::sleep(Duration::from_secs(1 << failures.min(4))).await;
                        }
                        _ if status == StatusCode::CONFLICT => {
                            return Err(server_error(status, &body));
                        }
                        Ok(_) | Err(_) => {
                            return Err(Error::Protocol("Unexpected server reply".into()));
                        }
                    }
                }
                Ok((status, body))
                    if status.is_client_error() && status != StatusCode::REQUEST_TIMEOUT =>
                {
                    return Err(server_error(status, &body));
                }
                Ok(_) | Err(Error::Network(_)) => {
                    failures += 1;
                    if failures > RETRIES {
                        return Err(Error::Network("Upload failed after several retries".into()));
                    }
                    tokio::time::sleep(Duration::from_secs(1 << failures.min(4))).await;
                    offset = tokio::time::timeout(STALL_TIMEOUT, self.upload_state(id, key))
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .unwrap_or(offset);
                }
                Err(e) => return Err(e),
            }
            reporter.update(offset);
        }
        Ok(())
    }

    // ----------------------------------------------------------- inbox

    pub async fn inbox(&self) -> Result<Vec<InboxItem>, Error> {
        let inbox: Inbox = self.call(Method::GET, "/v1/inbox", None::<&()>).await?;
        let mut items = Vec::new();
        for e in inbox.transfers.into_iter().take(MAX_INBOX_ENTRIES) {
            if !valid_transfer_id(&e.id) {
                continue;
            }
            let peek = self.peek(&e.id).await.ok();
            items.push(InboxItem {
                id: e.id,
                expires_in: e.expires_in,
                ciphertext_size: e.size,
                peek,
            });
        }
        Ok(items)
    }

    fn part_file(&self, id: &str) -> PathBuf {
        self.paths.incoming().join(format!("{id}.part"))
    }

    /// Decrypts the start of a transfer to learn sender and file name.
    pub async fn peek(&self, id: &str) -> Result<Peek, Error> {
        check_id(id)?;
        let part = self.part_file(id);
        let prefix = match fs::read(&part) {
            Ok(bytes) if bytes.len() as u64 >= PEEK_BYTES => bytes,
            _ => {
                let res = self
                    .net
                    .send(
                        Method::GET,
                        &format!("/v1/transfers/{id}/data"),
                        Some(&self.token),
                        &[("range", format!("bytes=0-{}", PEEK_BYTES - 1))],
                        Bytes::new(),
                    )
                    .await?;
                let (status, body) = read_capped(res, PEEK_BYTES).await?;
                if !status.is_success() {
                    return Err(server_error(status, &body));
                }
                body.to_vec()
            }
        };
        let opened = container::open(&prefix[..], self.identity.age_identity())
            .map_err(|e| Error::Verify(e.to_string()))?;
        let h = opened.header.clone();
        let sender = Username::parse(&h.sender).map_err(|_| Error::Verify("Bad sender".into()))?;
        let bundle = self.fetch_bundle(&sender).await.map_err(|e| match e {
            Error::Server { status: 404, .. } => {
                Error::Verify(format!("Sender {sender} no longer exists; cannot verify"))
            }
            e => e,
        })?;
        opened
            .verify(&bundle, &self.user, id, self.net.server())
            .map_err(|e| Error::Verify(e.to_string()))?;
        Ok(Peek {
            id: id.to_owned(),
            sender: sender.to_string(),
            fingerprint: bundle.fingerprint().to_string(),
            trust: self.trust_of(&bundle),
            name: sanitize(&h.name, 255),
            size: h.size,
        })
    }

    // -------------------------------------------------------- download

    pub async fn download(
        &self,
        id: &str,
        output: &Path,
        progress: Option<UnboundedSender<Progress>>,
    ) -> Result<PathBuf, Error> {
        check_id(id)?;
        if !output.is_dir() {
            return Err(Error::Local(format!(
                "Output folder does not exist: {}",
                output.display()
            )));
        }
        let peek = self.peek(id).await?;
        let sender =
            Username::parse(&peek.sender).map_err(|_| Error::Verify("Bad sender".into()))?;
        let sender_bundle = self.pinned(&sender).await?;
        let total = self
            .call::<Inbox>(Method::GET, "/v1/inbox", None::<&()>)
            .await?
            .transfers
            .into_iter()
            .find(|t| t.id == id)
            .map(|t| t.size)
            .ok_or_else(|| Error::Server {
                status: 404,
                message: "Transfer not found".into(),
            })?;
        private_dir(&self.paths.incoming())?;
        let part = self.part_file(id);
        self.fetch(id, &part, total, progress.clone()).await?;

        // Decrypt and verify everything into a hidden temporary file next
        // to the destination; only a fully verified file gets its name.
        let tmp = output.join(format!(".o2ee-{id}.tmp"));
        let (part2, tmp2, out_dir) = (part.clone(), tmp.clone(), output.to_owned());
        let identity_age = self.identity.age_identity().clone();
        let (me, server, id2) = (
            self.user.clone(),
            self.net.server().to_owned(),
            id.to_owned(),
        );
        let result = tokio::task::spawn_blocking(move || -> Result<PathBuf, Error> {
            let input = BufReader::new(File::open(&part2).map_err(|e| local_io(&part2, e))?);
            let opened =
                container::open(input, &identity_age).map_err(|e| Error::Verify(e.to_string()))?;
            opened
                .verify(&sender_bundle, &me, &id2, &server)
                .map_err(|e| Error::Verify(e.to_string()))?;
            let (name, kind, size) = (
                opened.header.name.clone(),
                opened.header.kind,
                opened.header.size,
            );
            let mut out = std::io::BufWriter::new(
                fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp2)
                    .map_err(|e| local_io(&tmp2, e))?,
            );
            let mut r = Reporter::new(progress, Phase::Verifying, size);
            opened
                .copy_content(&mut out, |n| r.update(n))
                .map_err(|e| Error::Verify(e.to_string()))?;
            out.into_inner()
                .map_err(|_| Error::Local("Cannot write file".into()))?
                .sync_all()
                .map_err(|e| local_io(&tmp2, e))?;
            place(&tmp2, &out_dir, &safe_name(&name, kind))
        })
        .await
        .map_err(|_| Error::Local("Verification failed".into()))?;
        let _ = fs::remove_file(&tmp);
        let saved = match result {
            Ok(path) => path,
            Err(e) => {
                if matches!(e, Error::Verify(_)) {
                    // The ciphertext is bad; do not resume from it.
                    let _ = fs::remove_file(&part);
                }
                return Err(e);
            }
        };
        let res = self
            .net
            .send(
                Method::POST,
                &format!("/v1/transfers/{id}/ack"),
                Some(&self.token),
                &[],
                Bytes::new(),
            )
            .await;
        let _ = fs::remove_file(&part);
        if let Ok(res) = res {
            let _ = read_small(res).await;
        }
        Ok(saved)
    }

    /// Downloads the ciphertext into `part`, resuming where it left off.
    async fn fetch(
        &self,
        id: &str,
        part: &Path,
        total: u64,
        progress: Option<UnboundedSender<Progress>>,
    ) -> Result<(), Error> {
        let mut reporter = Reporter::new(progress, Phase::Downloading, total);
        let mut failures = 0;
        let mut changes = 0;
        loop {
            let have = fs::metadata(part).map(|m| m.len()).unwrap_or(0);
            if have > total {
                let _ = fs::remove_file(part);
                continue;
            }
            reporter.update(have);
            if have == total {
                return Ok(());
            }
            let rule = if changes < MAX_CIRCUIT_CHANGES {
                SLOW
            } else {
                STALLED
            };
            let result = self
                .fetch_from(id, part, have, total, &mut reporter, rule)
                .await;
            match result {
                Ok(Fetched::Complete) => failures = 0,
                Ok(Fetched::TooSlow) if changes < MAX_CIRCUIT_CHANGES => {
                    changes += 1;
                    self.net.new_circuit();
                }
                Ok(Fetched::TooSlow) | Err(Error::Network(_)) if failures < RETRIES => {
                    failures += 1;
                    self.net.new_circuit();
                    tokio::time::sleep(Duration::from_secs(1 << failures.min(4))).await;
                }
                Ok(Fetched::TooSlow) => return Err(Error::Network("Download stalled".into())),
                Err(e) => return Err(e),
            }
        }
    }

    async fn fetch_from(
        &self,
        id: &str,
        part: &Path,
        have: u64,
        total: u64,
        reporter: &mut Reporter,
        rule: SpeedRule,
    ) -> Result<Fetched, Error> {
        let res = tokio::time::timeout(
            STALL_TIMEOUT,
            self.net.send(
                Method::GET,
                &format!("/v1/transfers/{id}/data"),
                Some(&self.token),
                &[("range", format!("bytes={have}-"))],
                Bytes::new(),
            ),
        )
        .await
        .map_err(|_| Error::Network("Server stopped responding".into()))??;
        let status = res.status();
        if status != StatusCode::PARTIAL_CONTENT {
            let (status, body) = read_small(res).await?;
            return Err(server_error(status, &body));
        }
        let expected = format!("bytes {have}-{}/{total}", total - 1);
        let range_ok = res
            .headers()
            .get(hyper::header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            == Some(expected.as_str());
        if !range_ok {
            return Err(Error::Protocol("Unexpected server reply".into()));
        }
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(part)
            .map_err(|e| local_io(part, e))?;
        let mut got = have;
        let fetched = receive(res.into_body(), rule, |data| {
            got += data.len() as u64;
            if got > total {
                return Err(Error::Protocol("Server sent too much data".into()));
            }
            file.write_all(&data).map_err(|e| local_io(part, e))?;
            reporter.update(got);
            Ok(())
        })
        .await;
        // What arrived is kept either way and the next request resumes.
        file.sync_data().map_err(|e| local_io(part, e))?;
        match fetched? {
            Fetched::Complete if got < total => Err(Error::Network("Download interrupted".into())),
            fetched => Ok(fetched),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SpeedRule {
    window: Duration,
    min_bytes: u64,
}

#[derive(Debug, PartialEq)]
enum Fetched {
    /// The server finished sending.
    Complete,
    /// Less than the rule's minimum arrived in a window.
    TooSlow,
}

/// Passes a response body to `sink` piece by piece, giving up with
/// [`Fetched::TooSlow`] when a window brings too little.
async fn receive(
    mut body: hyper::body::Incoming,
    rule: SpeedRule,
    mut sink: impl FnMut(Bytes) -> Result<(), Error>,
) -> Result<Fetched, Error> {
    let mut window_end = tokio::time::Instant::now() + rule.window;
    let mut window_bytes = 0u64;
    loop {
        match tokio::time::timeout_at(window_end, body.frame()).await {
            Ok(None) => return Ok(Fetched::Complete),
            Ok(Some(frame)) => {
                let frame =
                    frame.map_err(|e| Error::Network(format!("Download interrupted: {e}")))?;
                if let Ok(data) = frame.into_data() {
                    window_bytes += data.len() as u64;
                    sink(data)?;
                }
            }
            Err(_) => {}
        }
        if tokio::time::Instant::now() >= window_end {
            if window_bytes < rule.min_bytes {
                return Ok(Fetched::TooSlow);
            }
            window_end = tokio::time::Instant::now() + rule.window;
            window_bytes = 0;
        }
    }
}

fn key_changed(user: &Username) -> Error {
    Error::Verify(format!(
        "Keys of {user} changed since you verified them. Refused."
    ))
}

fn check_id(id: &str) -> Result<(), Error> {
    if valid_transfer_id(id) {
        Ok(())
    } else {
        Err(Error::Local("Invalid transfer ID".into()))
    }
}

fn local_io(path: &Path, e: std::io::Error) -> Error {
    Error::Local(format!("{}: {e}", path.display()))
}

async fn read_capped(
    res: hyper::Response<hyper::body::Incoming>,
    max: u64,
) -> Result<(StatusCode, Bytes), Error> {
    let status = res.status();
    let body = http_body_util::Limited::new(res.into_body(), max as usize)
        .collect()
        .await
        .map_err(|_| Error::Protocol("Server reply is too large".into()))?
        .to_bytes();
    Ok((status, body))
}

fn file_name(path: &Path, fallback: &str) -> String {
    let name = path
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();
    let name = safe_component(&name);
    if name.is_empty() {
        fallback.to_owned()
    } else {
        name
    }
}

/// One path component with no separators, controls or reserved names,
/// at most 200 bytes.
fn safe_component(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_control()
                || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
                || o2ee_protocol::text::sanitize(&c.to_string(), 1) != c.to_string()
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    out = out.trim().trim_start_matches('.').to_owned();
    while out.len() > 200 {
        out.pop();
    }
    let stem = out
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        out.insert(0, '_');
    }
    out
}

/// The name a received file is saved under.
pub fn safe_name(name: &str, kind: Kind) -> String {
    let mut out = safe_component(name);
    if out.is_empty() {
        out = "download".into();
    }
    if kind == Kind::Zip && !out.to_ascii_lowercase().ends_with(".zip") {
        out.push_str(".zip");
    }
    out
}

/// Gives `tmp` its final name in `dir` without overwriting anything:
/// `name`, then `name (1)`, `name (2)`, ...
fn place(tmp: &Path, dir: &Path, name: &str) -> Result<PathBuf, Error> {
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 0..1000 {
        let candidate = if n == 0 {
            dir.join(name)
        } else {
            dir.join(format!("{stem} ({n}){ext}"))
        };
        match fs::hard_link(tmp, &candidate) {
            Ok(()) => {
                let _ = fs::remove_file(tmp);
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(local_io(&candidate, e)),
        }
    }
    Err(Error::Local("Too many files with the same name".into()))
}

fn hash_file(path: &Path, mut progress: impl FnMut(u64)) -> Result<[u8; 32], Error> {
    use sha2::Digest;
    let mut f = File::open(path).map_err(|e| local_io(path, e))?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut done = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|e| local_io(path, e))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        done += n as u64;
        progress(done);
    }
    Ok(h.finalize().into())
}

struct Counting<R, F> {
    inner: R,
    count: u64,
    f: F,
}

impl<R, F: FnMut(u64)> Counting<R, F> {
    fn new(inner: R, f: F) -> Self {
        Self { inner, count: 0, f }
    }
}

impl<R: Read, F: FnMut(u64)> Read for Counting<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        (self.f)(self.count);
        Ok(n)
    }
}

/// Zips `dir` into `out`. Symbolic links are skipped, never followed.
pub fn zip_dir(dir: &Path, out: &Path) -> Result<(), Error> {
    use zip::write::SimpleFileOptions;
    let meta = fs::symlink_metadata(dir).map_err(|e| local_io(dir, e))?;
    if !meta.is_dir() {
        return Err(Error::Local(format!("Not a folder: {}", dir.display())));
    }
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| local_io(out, e))?;
    let mut zip = zip::ZipWriter::new(std::io::BufWriter::new(file));
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .large_file(true);
    let mut stack = vec![(dir.to_owned(), String::new())];
    let mut total = 0u64;
    while let Some((path, prefix)) = stack.pop() {
        let mut entries: Vec<_> = fs::read_dir(&path)
            .map_err(|e| local_io(&path, e))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries.into_iter().rev() {
            let meta = entry.metadata().map_err(|e| local_io(&entry.path(), e))?;
            let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                zip.add_directory(format!("{name}/"), options)
                    .map_err(|e| Error::Local(format!("Cannot create zip: {e}")))?;
                stack.push((entry.path(), format!("{name}/")));
            } else if meta.is_file() {
                total += meta.len();
                if total > MAX_FILE_BYTES {
                    return Err(Error::Local("Folder is larger than 4 GiB".into()));
                }
                zip.start_file(name, options)
                    .map_err(|e| Error::Local(format!("Cannot create zip: {e}")))?;
                let mut f = File::open(entry.path()).map_err(|e| local_io(&entry.path(), e))?;
                std::io::copy(&mut f, &mut zip).map_err(|e| local_io(&entry.path(), e))?;
            }
        }
    }
    let w = zip
        .finish()
        .map_err(|e| Error::Local(format!("Cannot create zip: {e}")))?;
    w.into_inner()
        .map_err(|_| Error::Local("Cannot create zip".into()))?
        .sync_all()
        .map_err(|e| local_io(out, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_names() {
        assert_eq!(safe_name("report.pdf", Kind::File), "report.pdf");
        assert_eq!(safe_name("../../etc/passwd", Kind::File), "_.._etc_passwd");
        assert_eq!(safe_name(".bashrc", Kind::File), "bashrc");
        assert_eq!(safe_name("a\u{202E}gpj.exe", Kind::File), "a_gpj.exe");
        assert_eq!(safe_name("CON.txt", Kind::File), "_CON.txt");
        assert_eq!(safe_name("", Kind::File), "download");
        assert_eq!(safe_name("photos", Kind::Zip), "photos.zip");
        assert_eq!(safe_name("x\n\u{1b}[2J", Kind::File), "x__[2J");
    }

    #[test]
    fn place_never_overwrites() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let write = |name: &str| {
            let p = dir.path().join(name);
            fs::write(&p, name).unwrap_or_else(|e| panic!("{e}"));
            p
        };
        write("a.txt");
        let t1 = write("t1");
        let p1 = place(&t1, dir.path(), "a.txt").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p1.file_name().and_then(|n| n.to_str()), Some("a (1).txt"));
        assert_eq!(
            fs::read_to_string(dir.path().join("a.txt")).ok().as_deref(),
            Some("a.txt")
        );
        assert!(!t1.exists());
    }

    #[test]
    fn password_policy() {
        let id = Username::parse("alice").unwrap_or_else(|e| panic!("{e}"));
        assert!(check_password_strength("short", &id).is_err());
        assert!(check_password_strength("aaaaaaaaaaaa", &id).is_err());
        assert!(check_password_strength("alice-is-great", &id).is_err());
        assert!(check_password_strength("mypassword99", &id).is_err());
        assert!(check_password_strength("tangerine rocket 42", &id).is_ok());
    }

    #[test]
    fn zip_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let src = dir.path().join("src");
        fs::create_dir_all(src.join("sub")).unwrap_or_else(|e| panic!("{e}"));
        fs::write(src.join("a.txt"), "A").unwrap_or_else(|e| panic!("{e}"));
        fs::write(src.join("sub/b.txt"), "B").unwrap_or_else(|e| panic!("{e}"));
        std::os::unix::fs::symlink("/etc/passwd", src.join("link"))
            .unwrap_or_else(|e| panic!("{e}"));
        let out = dir.path().join("out.zip");
        zip_dir(&src, &out).unwrap_or_else(|e| panic!("{e}"));
        let mut z = zip::ZipArchive::new(File::open(&out).unwrap_or_else(|e| panic!("{e}")))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut names: Vec<String> = (0..z.len())
            .filter_map(|i| {
                z.by_index(i)
                    .ok()
                    .and_then(|f| f.name().ok().map(|n| n.to_string()))
            })
            .collect();
        names.sort();
        assert_eq!(names, ["a.txt", "sub/", "sub/b.txt"]);
    }

    /// Every local header's ZIP64 sizes must be real values. zip 9.0.5 left
    /// 0xFFFF_FFFF_FFFF_FFFF in folder entries, which strict readers reject.
    #[test]
    fn zip64_local_headers_have_real_sizes() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let src = dir.path().join("src");
        fs::create_dir_all(src.join("sub/deeper")).unwrap_or_else(|e| panic!("{e}"));
        fs::write(src.join("a.txt"), "A").unwrap_or_else(|e| panic!("{e}"));
        fs::write(src.join("sub/b.txt"), "BB").unwrap_or_else(|e| panic!("{e}"));
        let out = dir.path().join("out.zip");
        zip_dir(&src, &out).unwrap_or_else(|e| panic!("{e}"));
        let bytes = fs::read(&out).unwrap_or_else(|e| panic!("{e}"));
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(&bytes[..]))
            .unwrap_or_else(|e| panic!("{e}"));
        let u16_at = |p: usize| u16::from_le_bytes([bytes[p], bytes[p + 1]]);
        let mut checked = 0;
        for i in 0..z.len() {
            let f = z.by_index(i).unwrap_or_else(|e| panic!("{e}"));
            let (is_dir, size) = (f.is_dir(), f.size());
            let name = f.name().map(|n| n.into_owned()).unwrap_or_default();
            let h = usize::try_from(f.header_start()).unwrap_or(usize::MAX);
            assert_eq!(&bytes[h..h + 4], b"PK\x03\x04", "{name}");
            let name_len = usize::from(u16_at(h + 26));
            let extra_len = usize::from(u16_at(h + 28));
            let mut p = h + 30 + name_len;
            let end = p + extra_len;
            while p + 4 <= end {
                let (id, len) = (u16_at(p), usize::from(u16_at(p + 2)));
                if id == 0x0001 {
                    assert!(len >= 16, "{name}: short ZIP64 field");
                    let field = |o: usize| {
                        let mut b = [0u8; 8];
                        b.copy_from_slice(&bytes[p + 4 + o..p + 12 + o]);
                        u64::from_le_bytes(b)
                    };
                    let (plain, packed) = (field(0), field(8));
                    assert_ne!(plain, u64::MAX, "{name}: placeholder size");
                    assert_ne!(packed, u64::MAX, "{name}: placeholder size");
                    if is_dir {
                        assert_eq!((plain, packed), (0, 0), "{name}");
                    } else {
                        assert_eq!(plain, size, "{name}");
                    }
                    checked += 1;
                }
                p += 4 + len;
            }
        }
        assert_eq!(checked, z.len(), "every entry carries ZIP64 sizes");
    }

    /// A fake server that answers with `len` bytes, written in pieces of
    /// `piece` bytes with `pause` between them.
    #[cfg(debug_assertions)]
    async fn trickle(
        dir: &Path,
        len: usize,
        piece: usize,
        pause: Duration,
    ) -> hyper::body::Incoming {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let socket = dir.join("s.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap_or_else(|e| panic!("{e}"));
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let head = format!("HTTP/1.1 206 Partial Content\r\ncontent-length: {len}\r\n\r\n");
            let _ = stream.write_all(head.as_bytes()).await;
            let mut sent = 0;
            while sent < len {
                let n = piece.min(len - sent);
                if piece == 0 || stream.write_all(&vec![7u8; n]).await.is_err() {
                    break;
                }
                sent += n;
                tokio::time::sleep(pause).await;
            }
            // Keep the stream open, like a slow or dead circuit.
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let net = Net::direct(&socket, "test.onion");
        net.send(Method::GET, "/", None, &[], Bytes::new())
            .await
            .unwrap_or_else(|e| panic!("{e}"))
            .into_body()
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn slow_download_is_given_up() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let body = trickle(dir.path(), 100_000, 10, Duration::from_millis(50)).await;
        let rule = SpeedRule {
            window: Duration::from_millis(500),
            min_bytes: 1000,
        };
        let mut got = 0;
        let r = receive(body, rule, |d| {
            got += d.len();
            Ok(())
        })
        .await;
        assert_eq!(r.ok(), Some(Fetched::TooSlow));
        // What arrived before giving up was still passed on.
        assert!(got > 0 && got < 1000, "{got}");
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn fast_download_completes() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let body = trickle(dir.path(), 300_000, 64 * 1024, Duration::from_millis(1)).await;
        let rule = SpeedRule {
            window: Duration::from_millis(500),
            min_bytes: 1000,
        };
        let mut got = 0;
        let r = receive(body, rule, |d| {
            got += d.len();
            Ok(())
        })
        .await;
        assert_eq!(r.ok(), Some(Fetched::Complete));
        assert_eq!(got, 300_000);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn stalled_download_is_given_up() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let body = trickle(dir.path(), 1000, 0, Duration::ZERO).await;
        let rule = SpeedRule {
            window: Duration::from_millis(300),
            min_bytes: 1,
        };
        let r = receive(body, rule, |_| Ok(())).await;
        assert_eq!(r.ok(), Some(Fetched::TooSlow));
    }
}
