//! The server faced with a hostile client: raw HTTP requests that break
//! the protocol on purpose, plus the admin page's own defences.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::result_large_err)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use o2ee_protocol::api::*;
use o2ee_protocol::container::new_transfer_id;
use o2ee_protocol::crypto::{Identity, OPAQUE_CONTEXT, Suite, identifiers, pow, session_token};
use o2ee_protocol::text::{b64d, b64e};
use o2ee_protocol::{MIB, Username};
use o2ee_server::store::Status;
use o2ee_server::{App, bind_public, serve};
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};

const SERVER: &str = "o2eetestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";
const PW: &[u8] = b"tangerine rocket 42";

struct T {
    app: Arc<App>,
    _dir: tempfile::TempDir,
    socket: PathBuf,
    admin_port: u16,
}

async fn start() -> T {
    let dir = tempfile::tempdir().unwrap();
    let app = App::open(&dir.path().join("data"), SERVER, 4).unwrap();
    let socket = dir.path().join("public.sock");
    let public = bind_public(&socket).unwrap();
    let admin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin.local_addr().unwrap().port();
    tokio::spawn(serve(app.clone(), public, admin));
    T {
        app,
        _dir: dir,
        socket,
        admin_port,
    }
}

#[derive(Debug)]
struct Reply {
    status: StatusCode,
    headers: hyper::HeaderMap,
    body: Bytes,
}

impl Reply {
    fn error(&self) -> String {
        serde_json::from_slice::<ErrorBody>(&self.body)
            .map(|e| e.error)
            .unwrap_or_default()
    }
    fn json<T: serde::de::DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).unwrap()
    }
}

async fn send<S>(io: S, req: Request<Full<Bytes>>) -> Reply
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let res = sender.send_request(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body,
    }
}

impl T {
    async fn raw(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: impl Into<Bytes>,
    ) -> Reply {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header("host", SERVER);
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let io = tokio::net::UnixStream::connect(&self.socket).await.unwrap();
        send(io, b.body(Full::new(body.into())).unwrap()).await
    }

    async fn post<B: serde::Serialize>(&self, path: &str, token: Option<&str>, body: &B) -> Reply {
        self.raw(
            Method::POST,
            path,
            token,
            &[("content-type", "application/json")],
            serde_json::to_vec(body).unwrap(),
        )
        .await
    }

    async fn get(&self, path: &str, token: Option<&str>) -> Reply {
        self.raw(Method::GET, path, token, &[], Bytes::new()).await
    }

    fn approve(&self, user: &str) {
        let mut p = self.app.store.persist();
        p.accounts.get_mut(user).unwrap().status = Status::Active;
        self.app.store.save(&p).unwrap();
    }

    /// Full OPAQUE signup through the public API.
    async fn signup(&self, name: &str) -> Reply {
        let user = Username::parse(name).unwrap();
        let c: Challenge = self.get("/v1/signup/challenge", None).await.json();
        let challenge = b64d(&c.challenge, 64).unwrap();
        let nonce = pow::solve(&challenge, &user, c.difficulty);
        let start = ClientRegistration::<Suite>::start(&mut OsRng, PW).unwrap();
        let r = self
            .post(
                "/v1/signup/start",
                None,
                &SignupStart {
                    username: name.into(),
                    challenge: c.challenge.clone(),
                    nonce,
                    registration_request: b64e(start.message.serialize()),
                },
            )
            .await;
        if !r.status.is_success() {
            return r;
        }
        let reply: SignupStartReply = r.json();
        let resp = RegistrationResponse::<Suite>::deserialize(
            &b64d(&reply.registration_response, 1024).unwrap(),
        )
        .unwrap();
        let ksf = opaque_ke::argon2::Argon2::default();
        let fin = start
            .state
            .finish(
                &mut OsRng,
                PW,
                resp,
                ClientRegistrationFinishParameters::new(identifiers(&user, SERVER), Some(&ksf)),
            )
            .unwrap();
        self.post(
            "/v1/signup/finish",
            None,
            &SignupFinish {
                username: name.into(),
                challenge: c.challenge,
                nonce,
                registration_upload: b64e(fin.message.serialize()),
                bundle: Identity::generate().public_bundle(&user, SERVER),
                note: "hello".into(),
            },
        )
        .await
    }

    async fn login(&self, name: &str) -> Result<String, Reply> {
        let user = Username::parse(name).unwrap();
        let start = ClientLogin::<Suite>::start(&mut OsRng, PW).unwrap();
        let r = self
            .post(
                "/v1/login/start",
                None,
                &LoginStart {
                    username: name.into(),
                    credential_request: b64e(start.message.serialize()),
                },
            )
            .await;
        if !r.status.is_success() {
            return Err(r);
        }
        let reply: LoginStartReply = r.json();
        let resp = CredentialResponse::<Suite>::deserialize(
            &b64d(&reply.credential_response, 1024).unwrap(),
        )
        .unwrap();
        let ksf = opaque_ke::argon2::Argon2::default();
        let fin = start
            .state
            .finish(
                &mut OsRng,
                PW,
                resp,
                ClientLoginFinishParameters::new(
                    Some(OPAQUE_CONTEXT),
                    identifiers(&user, SERVER),
                    Some(&ksf),
                ),
            )
            .unwrap();
        let r = self
            .post(
                "/v1/login/finish",
                None,
                &LoginFinish {
                    login_id: reply.login_id,
                    credential_finalization: b64e(fin.message.serialize()),
                },
            )
            .await;
        if r.status.is_success() {
            Ok(session_token(&fin.session_key).to_string())
        } else {
            Err(r)
        }
    }

    async fn user(&self, name: &str) -> String {
        assert_eq!(self.signup(name).await.status, StatusCode::ACCEPTED);
        self.approve(name);
        self.login(name).await.map_err(|r| r.error()).unwrap()
    }

    async fn create(&self, token: &str, to: &str, size: u64) -> (String, Reply) {
        let id = new_transfer_id();
        let r = self
            .post(
                "/v1/transfers",
                Some(token),
                &CreateTransfer {
                    id: id.clone(),
                    recipient: to.into(),
                    size,
                },
            )
            .await;
        (id, r)
    }

    async fn put(&self, token: &str, id: &str, key: &str, offset: u64, data: Vec<u8>) -> Reply {
        self.raw(
            Method::PUT,
            &format!("/v1/transfers/{id}/data?offset={offset}"),
            Some(token),
            &[(UPLOAD_KEY_HEADER, key)],
            data,
        )
        .await
    }

    fn file(&self, id: &str) -> PathBuf {
        self.app.store.file_path(id)
    }
}

fn file_len(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_requests_are_rejected() {
    let t = start().await;
    for body in [&b"not json"[..], b"{}", b"{\"username\":\"a\"}"] {
        let r = t
            .raw(Method::POST, "/v1/login/start", None, &[], body.to_vec())
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert_eq!(r.error(), "Invalid request");
    }
    // Unknown fields are refused, not ignored.
    let r = t
        .raw(
            Method::POST,
            "/v1/login/start",
            None,
            &[],
            r#"{"username":"alice","credential_request":"AA","admin":true}"#,
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Oversized JSON bodies. The server may answer and close before the
    // client finished sending, so a dropped connection is also a refusal.
    let io = tokio::net::UnixStream::connect(&t.socket).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/login/start")
        .header("host", SERVER)
        .body(Full::new(Bytes::from(vec![b' '; 200_000])))
        .unwrap();
    if let Ok(res) = sender.send_request(req).await {
        assert!(res.status().is_client_error());
    }
    // Non-canonical account names.
    let r = t
        .post(
            "/v1/login/start",
            None,
            &LoginStart {
                username: "Alice".into(),
                credential_request: "AA".into(),
            },
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn everything_but_signup_and_login_needs_a_session() {
    let t = start().await;
    let id = new_transfer_id();
    for path in [
        "/v1/me".to_owned(),
        "/v1/inbox".to_owned(),
        "/v1/accounts/alice".to_owned(),
        format!("/v1/transfers/{id}/data"),
    ] {
        let r = t.get(&path, None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}");
        let r = t.get(&path, Some(&"0".repeat(64))).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}");
    }
    // The admin page is not reachable through the public socket.
    let r = t.get("/", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t.get("/login", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_proof_of_work_and_limits() {
    let t = start().await;
    let alice = Username::parse("alice").unwrap();
    let c: Challenge = t.get("/v1/signup/challenge", None).await.json();
    let challenge = b64d(&c.challenge, 64).unwrap();
    let mut bad = 0;
    while pow::verify(&challenge, &alice, bad, c.difficulty) {
        bad += 1;
    }
    let req = SignupStart {
        username: "alice".into(),
        challenge: c.challenge.clone(),
        nonce: bad,
        registration_request: "AA".into(),
    };
    let r = t.post("/v1/signup/start", None, &req).await;
    assert_eq!(r.error(), "Proof of work failed");
    // A forged challenge.
    let mut forged = challenge.clone();
    forged[0] ^= 1;
    let r = t
        .post(
            "/v1/signup/start",
            None,
            &SignupStart {
                challenge: b64e(&forged),
                ..req
            },
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    assert_eq!(t.signup("alice").await.status, StatusCode::ACCEPTED);
    assert_eq!(t.signup("alice").await.error(), "ID is already taken");
    // Pending accounts cannot log in, and say so only after a correct
    // password.
    assert_eq!(
        t.login("alice").await.unwrap_err().error(),
        "Account is waiting for approval"
    );
    assert_eq!(
        t.app.store.persist().accounts["alice"].status,
        Status::Pending
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_bundle_must_be_for_this_account_and_server() {
    let t = start().await;
    let user = Username::parse("alice").unwrap();
    let c: Challenge = t.get("/v1/signup/challenge", None).await.json();
    let challenge = b64d(&c.challenge, 64).unwrap();
    let nonce = pow::solve(&challenge, &user, c.difficulty);
    for bundle in [
        Identity::generate().public_bundle(&Username::parse("bob").unwrap(), SERVER),
        Identity::generate().public_bundle(&user, "other.onion"),
    ] {
        let r = t
            .post(
                "/v1/signup/finish",
                None,
                &SignupFinish {
                    username: "alice".into(),
                    challenge: c.challenge.clone(),
                    nonce,
                    registration_upload: "AA".into(),
                    bundle,
                    note: String::new(),
                },
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }
    assert!(t.app.store.persist().accounts.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn used_challenge_cannot_be_reused() {
    let t = start().await;
    let user = Username::parse("alice").unwrap();
    let c: Challenge = t.get("/v1/signup/challenge", None).await.json();
    let challenge = b64d(&c.challenge, 64).unwrap();
    let nonce = pow::solve(&challenge, &user, c.difficulty);
    let mk = |name: &str| SignupFinish {
        username: name.into(),
        challenge: c.challenge.clone(),
        nonce,
        registration_upload: String::new(),
        bundle: Identity::generate().public_bundle(&Username::parse(name).unwrap(), SERVER),
        note: String::new(),
    };
    // The real flow, then the same solved challenge again.
    let start_msg = ClientRegistration::<Suite>::start(&mut OsRng, PW).unwrap();
    let reply: SignupStartReply = t
        .post(
            "/v1/signup/start",
            None,
            &SignupStart {
                username: "alice".into(),
                challenge: c.challenge.clone(),
                nonce,
                registration_request: b64e(start_msg.message.serialize()),
            },
        )
        .await
        .json();
    let resp = RegistrationResponse::<Suite>::deserialize(
        &b64d(&reply.registration_response, 1024).unwrap(),
    )
    .unwrap();
    let ksf = opaque_ke::argon2::Argon2::default();
    let fin = start_msg
        .state
        .finish(
            &mut OsRng,
            PW,
            resp,
            ClientRegistrationFinishParameters::new(identifiers(&user, SERVER), Some(&ksf)),
        )
        .unwrap();
    let mut first = mk("alice");
    first.registration_upload = b64e(fin.message.serialize());
    assert_eq!(
        t.post("/v1/signup/finish", None, &first).await.status,
        StatusCode::ACCEPTED
    );
    // The solution is bound to "alice"; reusing it for her is refused as
    // used, and it is worthless for any other name.
    let again = t.post("/v1/signup/finish", None, &first).await;
    assert_eq!(again.error(), "Challenge expired");
    let other = t.post("/v1/signup/finish", None, &mk("bob")).await;
    assert!(other.status.is_client_error());
}

#[tokio::test(flavor = "multi_thread")]
async fn uploads_are_strict() {
    let t = start().await;
    let alice = t.user("alice").await;
    t.user("bob").await;

    // Size limits and recipient checks.
    let (_, r) = t.create(&alice, "bob", 10).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let (_, r) = t.create(&alice, "bob", 5 * 1024 * MIB).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let (_, r) = t.create(&alice, "nobody", MIB).await;
    assert_eq!(r.error(), "No such user");
    let bad_id = t
        .post(
            "/v1/transfers",
            Some(&alice),
            &CreateTransfer {
                id: "../../state".into(),
                recipient: "bob".into(),
                size: MIB,
            },
        )
        .await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST);

    let size = MIB + 100;
    let (id, r) = t.create(&alice, "bob", size).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let key = r.json::<CreateTransferReply>().upload_key;
    // Same id twice.
    let dup = t
        .post(
            "/v1/transfers",
            Some(&alice),
            &CreateTransfer {
                id: id.clone(),
                recipient: "bob".into(),
                size,
            },
        )
        .await;
    assert_eq!(dup.status, StatusCode::CONFLICT);

    // Wrong upload key looks like a missing transfer.
    let r = t.put(&alice, &id, &"0".repeat(64), 0, vec![1; 10]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // Out-of-order offset: told where to continue.
    let r = t.put(&alice, &id, &key, 5, vec![1; 10]).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.json::<UploadState>().received, 0);
    // Writing past the declared size is refused and leaves nothing behind.
    let r = t
        .put(&alice, &id, &key, 0, vec![1; (size + 1) as usize])
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(file_len(&t.file(&id)), 0);
    // Finishing early is refused; not visible to bob yet.
    let r = t
        .raw(
            Method::POST,
            &format!("/v1/transfers/{id}/finish"),
            Some(&alice),
            &[(UPLOAD_KEY_HEADER, &key)],
            Bytes::new(),
        )
        .await;
    assert_eq!(r.error(), "Upload incomplete");

    // A proper upload in two parts.
    let r = t.put(&alice, &id, &key, 0, vec![7; MIB as usize]).await;
    assert_eq!(r.json::<UploadState>().received, MIB);
    let r = t.put(&alice, &id, &key, MIB, vec![7; 100]).await;
    assert_eq!(r.json::<UploadState>().received, size);
    let r = t
        .raw(
            Method::POST,
            &format!("/v1/transfers/{id}/finish"),
            Some(&alice),
            &[(UPLOAD_KEY_HEADER, &key)],
            Bytes::new(),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    // Finished transfers accept no more data.
    let r = t.put(&alice, &id, &key, size, vec![1]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn downloads_are_for_the_recipient_only() {
    let t = start().await;
    let alice = t.user("alice").await;
    let bob = t.user("bob").await;
    let size = MIB;
    let (id, r) = t.create(&alice, "bob", size).await;
    let key = r.json::<CreateTransferReply>().upload_key;
    t.put(&alice, &id, &key, 0, vec![9; size as usize]).await;
    t.raw(
        Method::POST,
        &format!("/v1/transfers/{id}/finish"),
        Some(&alice),
        &[(UPLOAD_KEY_HEADER, &key)],
        Bytes::new(),
    )
    .await;

    // The sender cannot read it back or delete it.
    let path = format!("/v1/transfers/{id}/data");
    assert_eq!(
        t.get(&path, Some(&alice)).await.status,
        StatusCode::NOT_FOUND
    );
    let r = t
        .raw(
            Method::POST,
            &format!("/v1/transfers/{id}/ack"),
            Some(&alice),
            &[],
            Bytes::new(),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    let inbox: Inbox = t.get("/v1/inbox", Some(&bob)).await.json();
    assert_eq!(inbox.transfers.len(), 1);
    assert!(inbox.transfers[0].expires_in <= o2ee_protocol::TRANSFER_RETENTION_SECS + 3600);

    // Ranges.
    let r = t
        .raw(
            Method::GET,
            &path,
            Some(&bob),
            &[("range", "bytes=10-19")],
            Bytes::new(),
        )
        .await;
    assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.body.len(), 10);
    assert_eq!(
        r.headers.get("content-range").unwrap(),
        &format!("bytes 10-19/{size}")
    );
    let r = t
        .raw(
            Method::GET,
            &path,
            Some(&bob),
            &[("range", &format!("bytes={size}-"))],
            Bytes::new(),
        )
        .await;
    assert_eq!(r.status, StatusCode::RANGE_NOT_SATISFIABLE);
    let r = t
        .raw(
            Method::GET,
            &path,
            Some(&bob),
            &[("range", "bytes=-5")],
            Bytes::new(),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    let r = t
        .raw(
            Method::POST,
            &format!("/v1/transfers/{id}/ack"),
            Some(&bob),
            &[],
            Bytes::new(),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(!t.file(&id).exists());
    assert_eq!(t.get(&path, Some(&bob)).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn inbox_quota() {
    let t = start().await;
    let alice = t.user("alice").await;
    t.user("bob").await;
    let big = 4 * 1024 * MIB;
    assert_eq!(
        t.create(&alice, "bob", big).await.1.status,
        StatusCode::CREATED
    );
    assert_eq!(
        t.create(&alice, "bob", big).await.1.status,
        StatusCode::CREATED
    );
    let (_, r) = t.create(&alice, "bob", 10 * MIB).await;
    assert_eq!(r.error(), "Recipient inbox is full");
}

// ------------------------------------------------------------- admin page

async fn admin(t: &T, method: Method, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("127.0.0.1:{}", t.admin_port));
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let io = tokio::net::TcpStream::connect(("127.0.0.1", t.admin_port))
        .await
        .unwrap();
    send(io, b.body(Full::new(Bytes::from(body.to_owned()))).unwrap()).await
}

fn form() -> (&'static str, &'static str) {
    ("content-type", "application/x-www-form-urlencoded")
}

fn csrf_from(html: &str) -> String {
    let at = html.find("name=\"csrf\" value=\"").unwrap() + 19;
    html[at..at + 64].to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_page_defences_and_approval() {
    let t = start().await;
    let r = admin(&t, Method::GET, "/login", &[], "").await;
    assert!(String::from_utf8_lossy(&r.body).contains("Admin password is not set"));
    o2ee_server::admin::set_admin_password(t.app.store.dir(), "correct horse admin").unwrap();

    // DNS rebinding: any other Host is refused.
    let io = tokio::net::TcpStream::connect(("127.0.0.1", t.admin_port))
        .await
        .unwrap();
    let r = send(
        io,
        Request::builder()
            .uri("/login")
            .header("host", "evil.example:80")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // Cross-site form posts are refused.
    let r = admin(
        &t,
        Method::POST,
        "/login",
        &[form(), ("origin", "http://evil.example")],
        "password=correct+horse+admin",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = admin(
        &t,
        Method::POST,
        "/login",
        &[form(), ("sec-fetch-site", "cross-site")],
        "password=correct+horse+admin",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let r = admin(&t, Method::POST, "/login", &[form()], "password=wrong").await;
    assert!(String::from_utf8_lossy(&r.body).contains("Wrong password"));
    assert!(r.headers.get("set-cookie").is_none());

    let r = admin(
        &t,
        Method::POST,
        "/login",
        &[form()],
        "password=correct+horse+admin",
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let cookie = r
        .headers
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    let cookie = cookie.split(';').next().unwrap().to_owned();

    assert_eq!(t.signup("carol").await.status, StatusCode::ACCEPTED);
    let r = admin(&t, Method::GET, "/", &[("cookie", &cookie)], "").await;
    let html = String::from_utf8_lossy(&r.body).into_owned();
    assert!(html.contains("carol"));
    assert!(html.contains(&t.app.store.persist().accounts["carol"].fingerprint));
    assert!(
        r.headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );
    let csrf = csrf_from(&html);

    // Missing or wrong CSRF token.
    let r = admin(
        &t,
        Method::POST,
        "/action",
        &[form(), ("cookie", &cookie)],
        "csrf=00&action=approve&username=carol",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // No session.
    let r = admin(
        &t,
        Method::POST,
        "/action",
        &[form()],
        &format!("csrf={csrf}&action=approve&username=carol"),
    )
    .await;
    assert_eq!(r.headers.get("location").unwrap(), "/login");
    assert_eq!(
        t.app.store.persist().accounts["carol"].status,
        Status::Pending
    );

    let r = admin(
        &t,
        Method::POST,
        "/action",
        &[form(), ("cookie", &cookie)],
        &format!("csrf={csrf}&action=approve&username=carol"),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        t.app.store.persist().accounts["carol"].status,
        Status::Active
    );
    let token = t.login("carol").await.unwrap();

    // Suspending ends sessions at once.
    admin(
        &t,
        Method::POST,
        "/action",
        &[form(), ("cookie", &cookie)],
        &format!("csrf={csrf}&action=suspend&username=carol"),
    )
    .await;
    assert_eq!(
        t.get("/v1/me", Some(&token)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.login("carol").await.unwrap_err().error(),
        "Account is suspended"
    );

    // Delete needs the ID typed as confirmation.
    let r = admin(
        &t,
        Method::POST,
        "/action",
        &[form(), ("cookie", &cookie)],
        &format!("csrf={csrf}&action=delete&username=carol&confirm=nope"),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    admin(
        &t,
        Method::POST,
        "/action",
        &[form(), ("cookie", &cookie)],
        &format!("csrf={csrf}&action=delete&username=carol&confirm=carol"),
    )
    .await;
    assert!(!t.app.store.persist().accounts.contains_key("carol"));

    // Logging out kills the admin session.
    admin(
        &t,
        Method::POST,
        "/logout",
        &[form(), ("cookie", &cookie)],
        &format!("csrf={csrf}"),
    )
    .await;
    let r = admin(&t, Method::GET, "/", &[("cookie", &cookie)], "").await;
    assert_eq!(r.headers.get("location").unwrap(), "/login");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_notes_are_escaped() {
    let t = start().await;
    o2ee_server::admin::set_admin_password(t.app.store.dir(), "correct horse admin").unwrap();
    assert_eq!(t.signup("dave").await.status, StatusCode::ACCEPTED);
    t.app.store.persist().accounts.get_mut("dave").unwrap().note =
        "<script>alert(1)</script>".into();
    let r = admin(
        &t,
        Method::POST,
        "/login",
        &[form()],
        "password=correct+horse+admin",
    )
    .await;
    let cookie = r.headers.get("set-cookie").unwrap().to_str().unwrap();
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let r = admin(&t, Method::GET, "/", &[("cookie", &cookie)], "").await;
    let html = String::from_utf8_lossy(&r.body);
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_must_listen_on_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let app = App::open(&dir.path().join("d"), SERVER, 4).unwrap();
    let public = bind_public(&dir.path().join("s.sock")).unwrap();
    let admin = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    assert!(serve(app, public, admin).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn files_and_state_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let t = start().await;
    t.signup("alice").await;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let dir = t.app.store.dir();
    assert_eq!(mode(dir), 0o700);
    assert_eq!(mode(&dir.join("files")), 0o700);
    assert_eq!(mode(&dir.join("state.json")), 0o600);
    assert_eq!(mode(&dir.join("opaque_setup.bin")), 0o600);
    assert_eq!(mode(&t.socket), 0o600);
    // No log files of any kind.
    let names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(sorted, ["files", "opaque_setup.bin", "state.json"]);
}
