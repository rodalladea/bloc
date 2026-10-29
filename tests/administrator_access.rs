use bloc::credentials::{PasswordWorker, normalize_email, validate_password};

#[test]
fn email_policy() {
    let at_limit = format!(
        "{}@{}.{}.{}",
        "A".repeat(64),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(at_limit.len(), 254);
    assert_eq!(normalize_email(&at_limit).unwrap(), at_limit);
    assert!(normalize_email(&(at_limit + "d")).is_err());
    assert_eq!(
        normalize_email(" Owner+tag@EXAMPLE.test ").unwrap(),
        "Owner+tag@example.test"
    );
    for invalid in [
        "a",
        "a@@example.test",
        "a b@example.test",
        "é@example.test",
        "a@-example.test",
        "a@example..test",
    ] {
        assert!(normalize_email(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn password_policy() {
    assert!(validate_password(&"é".repeat(15), &"é".repeat(15)).is_ok());
    assert!(validate_password(&"a".repeat(128), &"a".repeat(128)).is_ok());
    assert!(validate_password(&"😀".repeat(128), &"😀".repeat(128)).is_ok());
    for p in ["a".repeat(14), "a".repeat(129)] {
        assert!(validate_password(&p, &p).is_err());
    }
    assert!(validate_password(" 12345678901234", "12345678901234 ").is_err());
}

#[tokio::test]
async fn password_hash_contract() {
    let worker = PasswordWorker::new();
    let a = worker.hash("a synthetic password".into()).await.unwrap();
    let b = worker.hash("a synthetic password".into()).await.unwrap();
    assert_ne!(a, b);
    assert!(a.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
    let fields: Vec<_> = a.split('$').collect();
    use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
    assert_eq!(STANDARD_NO_PAD.decode(fields[4]).unwrap().len(), 16);
    assert_eq!(STANDARD_NO_PAD.decode(fields[5]).unwrap().len(), 32);
    assert!(
        worker
            .verify("a synthetic password".into(), a.clone())
            .await
            .unwrap()
    );
    assert!(!worker.verify("wrong password".into(), a).await.unwrap());
}

#[tokio::test]
async fn password_hash_legacy_compatibility() {
    // Produced by argon2 0.5.3 with bloc's parameters and a synthetic 16-byte salt.
    let phc = "$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljLXNhbHQxNg$Zkyx/BYENw0KBYfrGZNKyxb+tYYdmKb7fr8+1iBG/bI";
    let worker = PasswordWorker::new();
    assert!(
        worker
            .verify("a synthetic password".into(), phc.into())
            .await
            .unwrap()
    );
    assert!(
        !worker
            .verify("wrong password".into(), phc.into())
            .await
            .unwrap()
    );
    assert!(
        worker
            .verify("a synthetic password".into(), "invalid PHC".into())
            .await
            .is_err()
    );
}

mod common;
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use bloc::{
    administrator::{Application, router},
    config::Config,
    request_security as sec,
};
use common::Fixture;
use std::collections::BTreeMap;
use tower::ServiceExt;

struct Browser {
    app: axum::Router,
    cookies: BTreeMap<String, String>,
}
impl Browser {
    async fn new(f: &Fixture) -> Self {
        let cfg = Config::new("https://bloc.example.test", "127.0.0.1/32", [7; 32]).unwrap();
        Self {
            app: router(Application::new(f.runtime.clone(), cfg).await.unwrap()),
            cookies: BTreeMap::new(),
        }
    }
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        fields: &[(&str, &str)],
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish();
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "bloc.example.test")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "192.0.2.4")
            .header("origin", "https://bloc.example.test")
            .header("content-type", "application/x-www-form-urlencoded")
            .header(
                "cookie",
                self.cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
            .body(Body::from(encoded))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:54321".parse::<std::net::SocketAddr>().unwrap(),
        ));
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        for cookie in headers.get_all("set-cookie") {
            let (key, value) = cookie
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .split_once('=')
                .unwrap();
            if value.is_empty() {
                self.cookies.remove(key);
            } else {
                self.cookies.insert(key.into(), value.into());
            }
        }
        let html = String::from_utf8(
            to_bytes(response.into_body(), 100000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        (status, html, headers)
    }
    async fn token(&mut self, path: &str) -> String {
        let (status, html, _) = self.request("GET", path, &[]).await;
        assert_eq!(status, StatusCode::OK, "{html}");
        html.split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .into()
    }
    async fn setup(&mut self, f: &Fixture) -> String {
        let code = sec::encode(&[1; 32]);
        f.operator
            .issue_setup_code(&sec::digest(&code))
            .await
            .unwrap();
        let csrf = self.token("/admin/setup").await;
        let (s, html, headers) = self
            .request(
                "POST",
                "/admin/setup",
                &[
                    ("csrf", &csrf),
                    ("code", &code),
                    ("email", " Owner@EXAMPLE.test "),
                    ("password", "a synthetic password"),
                    ("password_confirmation", "a synthetic password"),
                ],
            )
            .await;
        assert_eq!(s, StatusCode::SEE_OTHER, "{html}");
        assert_eq!(headers["location"], "/admin/login");
        code
    }
    async fn login(&mut self) {
        let csrf = self.token("/admin/login").await;
        let (s, html, headers) = self
            .request(
                "POST",
                "/admin/login",
                &[
                    ("csrf", &csrf),
                    ("email", "Owner@example.test"),
                    ("password", "a synthetic password"),
                ],
            )
            .await;
        assert_eq!(s, StatusCode::SEE_OTHER, "{html}");
        assert_eq!(headers["location"], "/admin");
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn setup_page() {
    let f = Fixture::new("accesspage").await;
    let mut b = Browser::new(&f).await;
    let (s, html, _) = b.request("GET", "/admin/setup", &[]).await;
    assert_eq!(s, 200);
    assert!(html.contains("bloc admin setup-code"));
    assert!(!html.contains("value=\"AAAAAAAA"));
    assert_eq!(f.count("installation_administrator").await, 0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn setup_success() {
    let f = Fixture::new("accesssetup").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    assert_eq!(f.count("installation_administrator").await, 1);
    assert!(!b.cookies.contains_key("__Host-bloc-admin"));
    let (email,consumed):(String,bool)=sqlx::query_as("SELECT email,consumed_at IS NOT NULL FROM bloc.installation_administrator,bloc.operator_code").fetch_one(&f.admin).await.unwrap();
    assert_eq!(email, "Owner@example.test");
    assert!(consumed);
    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bloc.security_audit_event WHERE action='setup' AND outcome='success'",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(audit, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn setup_code_refusal() {
    let f = Fixture::new("accesscode").await;
    let mut b = Browser::new(&f).await;
    let csrf = b.token("/admin/setup").await;
    let (s, html, _) = b
        .request(
            "POST",
            "/admin/setup",
            &[
                ("csrf", &csrf),
                ("code", &sec::encode(&[9; 32])),
                ("email", "Owner@example.test"),
                ("password", "a synthetic password"),
                ("password_confirmation", "a synthetic password"),
            ],
        )
        .await;
    assert_eq!(s, 400);
    assert!(html.contains("This code cannot be used."));
    assert_eq!(f.count("installation_administrator").await, 0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn setup_closed() {
    let f = Fixture::new("accessclosed").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    for method in ["GET", "POST"] {
        let (s, html, _) = b.request(method, "/admin/setup", &[]).await;
        assert_eq!(s, 409);
        assert!(html.contains("Setup is complete"));
    }
    assert_eq!(f.count("installation_administrator").await, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn login_success_rotation() {
    let f = Fixture::new("accesslogin").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    let previous = b.cookies.get("__Host-bloc-csrf").cloned();
    b.login().await;
    let bearer = b.cookies.get("__Host-bloc-admin").unwrap();
    assert!(sec::decode(bearer).is_some());
    assert_ne!(Some(bearer), previous.as_ref());
    assert_ne!(b.cookies.get("__Host-bloc-csrf"), Some(bearer));
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT session_digest FROM bloc.administrator_session WHERE revoked_at IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(stored, sec::digest(bearer));
    let first = bearer.clone();
    b.login().await;
    assert_ne!(b.cookies.get("__Host-bloc-admin"), Some(&first));
    assert_ne!(b.cookies.get("__Host-bloc-csrf"), previous.as_ref());
    let (s, html, _) = b.request("GET", "/admin", &[]).await;
    assert_eq!(s, 200);
    assert!(html.contains("Owner@example.test"));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn login_generic_failure() {
    let f = Fixture::new("accessgeneric").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    for email in ["Owner@example.test", "unknown@example.test"] {
        let csrf = b.token("/admin/login").await;
        let (s, html, _) = b
            .request(
                "POST",
                "/admin/login",
                &[("csrf", &csrf), ("email", email), ("password", "wrong")],
            )
            .await;
        assert_eq!(s, 401);
        assert!(html.contains("Email or password is incorrect."));
        assert!(!b.cookies.contains_key("__Host-bloc-admin"));
    }
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn session_cookie() {
    let f = Fixture::new("accesscookie").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    let csrf = b.token("/admin/login").await;
    let (s, _, headers) = b
        .request(
            "POST",
            "/admin/login",
            &[
                ("csrf", &csrf),
                ("email", "Owner@example.test"),
                ("password", "a synthetic password"),
            ],
        )
        .await;
    assert_eq!(s, 303);
    let cookie = headers
        .get_all("set-cookie")
        .iter()
        .find_map(|h| {
            let h = h.to_str().unwrap();
            h.starts_with("__Host-bloc-admin=").then_some(h)
        })
        .unwrap();
    for part in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(part));
    }
    for part in ["Domain", "Expires", "Max-Age"] {
        assert!(!cookie.contains(part));
    }
    let raw = b.cookies.get("__Host-bloc-admin").unwrap();
    let digest: Vec<u8> =
        sqlx::query_scalar("SELECT session_digest FROM bloc.administrator_session")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(digest, sec::digest(raw));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn logout_replay() {
    let f = Fixture::new("accesslogout").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    b.login().await;
    let old = b.cookies.clone();
    let csrf = b.token("/admin").await;
    let (s, _, _) = b.request("POST", "/admin/logout", &[("csrf", &csrf)]).await;
    assert_eq!(s, 303);
    assert!(!b.cookies.contains_key("__Host-bloc-admin"));
    let mut other = Browser::new(&f).await;
    other.cookies = old;
    let (s, _, h) = other.request("GET", "/admin", &[]).await;
    assert_eq!(s, 303);
    assert!(
        h.get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("/admin/login")
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn password_change_success() {
    let f = Fixture::new("accesspassword").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    b.login().await;
    let old = b.cookies.clone();
    let mut second = Browser::new(&f).await;
    second.login().await;
    f.operator.issue_recovery_code(&[81; 32]).await.unwrap();
    let csrf = b.token("/admin/password").await;
    let (s, html, headers) = b
        .request(
            "POST",
            "/admin/password",
            &[
                ("csrf", &csrf),
                ("current_password", "a synthetic password"),
                ("password", "the replacement password"),
                ("password_confirmation", "the replacement password"),
            ],
        )
        .await;
    assert_eq!(s, 303, "{html}");
    assert_eq!(headers["location"], "/admin/login");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM bloc.administrator_session WHERE revoked_at IS NULL"
        )
        .fetch_one(&f.admin)
        .await
        .unwrap(),
        0
    );
    assert!(!f.runtime.code_usable("recovery", &[81; 32]).await.unwrap());
    assert_eq!(second.request("GET", "/admin", &[]).await.0, 303);
    let owner = f.runtime.owner().await.unwrap().unwrap();
    assert_eq!(owner.version, 2);
    assert!(
        PasswordWorker::new()
            .verify("the replacement password".into(), owner.phc)
            .await
            .unwrap()
    );
    b.cookies = old;
    assert_eq!(b.request("GET", "/admin", &[]).await.0, 303);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn password_change_refusal() {
    let f = Fixture::new("accesspwrefuse").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    b.login().await;
    let before = f.runtime.owner().await.unwrap().unwrap();
    let csrf = b.token("/admin/password").await;
    let (s, html, _) = b
        .request(
            "POST",
            "/admin/password",
            &[
                ("csrf", &csrf),
                ("current_password", "wrong"),
                ("password", "the replacement password"),
                ("password_confirmation", "the replacement password"),
            ],
        )
        .await;
    assert_eq!(s, 400);
    assert!(html.contains("Password change was refused."));
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().version, 1);
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().phc, before.phc);
    b.login().await;
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn recovery_success() {
    let f = Fixture::new("accessrecovery").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    b.login().await;
    let old = b.cookies.clone();
    let before: (String, String, String, String) = sqlx::query_as(
        "SELECT id::text,password_hash,email,created_at::text FROM bloc.installation_administrator",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    let mut second = Browser::new(&f).await;
    second.login().await;
    let code = sec::encode(&[2; 32]);
    f.operator
        .issue_recovery_code(&sec::digest(&code))
        .await
        .unwrap();
    let mut recover = Browser::new(&f).await;
    let csrf = recover.token("/admin/recovery").await;
    let (s, html, headers) = recover
        .request(
            "POST",
            "/admin/recovery",
            &[
                ("csrf", &csrf),
                ("code", &code),
                ("password", "the replacement password"),
                ("password_confirmation", "the replacement password"),
            ],
        )
        .await;
    assert_eq!(s, 303, "{html}");
    assert_eq!(headers["location"], "/admin/login");
    let after: (String, String, String, String) = sqlx::query_as(
        "SELECT id::text,password_hash,email,created_at::text FROM bloc.installation_administrator",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(before.0, after.0);
    assert_eq!(before.2, after.2);
    assert_eq!(before.3, after.3);
    assert_ne!(before.1, after.1);
    assert!(
        PasswordWorker::new()
            .verify("the replacement password".into(), after.1)
            .await
            .unwrap()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM bloc.administrator_session WHERE revoked_at IS NULL"
        )
        .fetch_one(&f.admin)
        .await
        .unwrap(),
        0
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM bloc.security_audit_event WHERE action='recovery' AND outcome='success'").fetch_one(&f.admin).await.unwrap(),1);
    assert_eq!(second.request("GET", "/admin", &[]).await.0, 303);
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().version, 2);
    b.cookies = old;
    assert_eq!(b.request("GET", "/admin", &[]).await.0, 303);
    assert!(
        !f.runtime
            .code_usable("recovery", &sec::digest(&code))
            .await
            .unwrap()
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn restore_invalidation() {
    let f = Fixture::new("accessrestore").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    b.login().await;
    let before = f.runtime.owner().await.unwrap().unwrap();
    f.operator.invalidate_access().await.unwrap();
    let after = f.runtime.owner().await.unwrap().unwrap();
    assert_eq!(after.phc, before.phc);
    assert_eq!(after.version, before.version + 1);
    assert!(after.recovery_required);
    assert_eq!(b.request("GET", "/admin", &[]).await.0, 303);
    let csrf = b.token("/admin/login").await;
    assert_eq!(
        b.request(
            "POST",
            "/admin/login",
            &[
                ("csrf", &csrf),
                ("email", "Owner@example.test"),
                ("password", "a synthetic password")
            ]
        )
        .await
        .0,
        401
    );
    f.operator.issue_recovery_code(&[91; 32]).await.unwrap();
    assert!(
        f.runtime
            .replace_password(&[91; 32], 0, common::HASH, true)
            .await
            .unwrap()
    );
    assert!(!f.runtime.owner().await.unwrap().unwrap().recovery_required);
    let fresh = Fixture::new("accessrestoreempty").await;
    fresh.operator.issue_setup_code(&[1; 32]).await.unwrap();
    fresh.operator.invalidate_access().await.unwrap();
    assert!(!fresh.runtime.code_usable("setup", &[1; 32]).await.unwrap());
    fresh.operator.issue_setup_code(&[2; 32]).await.unwrap();
    assert!(fresh.runtime.code_usable("setup", &[2; 32]).await.unwrap());
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn shared_admission() {
    let f = Fixture::new("accessadmit").await;
    for _ in 0..10 {
        assert_eq!(
            f.runtime
                .reserve(&[("credential_source", [1; 32], 1)])
                .await
                .unwrap(),
            0
        );
    }
    assert!(
        f.runtime
            .reserve(&[("credential_source", [1; 32], 1)])
            .await
            .unwrap()
            > 0
    );
    assert_eq!(
        f.runtime
            .reserve(&[("password_change", [2; 32], 2)])
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        f.runtime
            .reserve(&[("password_change", [2; 32], 2)])
            .await
            .unwrap(),
        0
    );
    assert!(
        f.runtime
            .reserve(&[("password_change", [2; 32], 2)])
            .await
            .unwrap()
            > 0
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn admission_races() {
    let f = Fixture::new("accessadmitrace").await;
    for _ in 0..9 {
        assert_eq!(
            f.runtime
                .reserve(&[("credential_source", [1; 32], 1)])
                .await
                .unwrap(),
            0
        )
    }
    let other = bloc::storage::Storage::connect(&f.url("runtime_user"), &f.ca)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        f.runtime.reserve(&[("credential_source", [1; 32], 1)]),
        other.reserve(&[("credential_source", [1; 32], 1)])
    );
    let values = [a.unwrap(), b.unwrap()];
    assert_eq!(values.iter().filter(|&&x| x == 0).count(), 1);
    assert_eq!(values.iter().filter(|&&x| x > 0).count(), 1);
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM bloc.administrator_admission_bucket")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert!(
        f.runtime
            .reserve(&[
                ("credential_source", [1; 32], 1),
                ("login_identifier", [8; 32], 1)
            ])
            .await
            .unwrap()
            > 0
    );
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.administrator_admission_bucket")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(before, after);
}
#[test]
fn form_input_bounds() {
    assert!(sec::form(b"password=a&password=b").is_err());
    for s in [b"csrf=%".as_slice(), b"csrf=%GG", b"csrf=%FF"] {
        assert!(sec::form(s).is_err());
    }
    assert!(sec::form(&vec![b'a'; 16385]).is_err());
    let value = sec::encode(&[1; 32]);
    assert!(sec::decode(&value).is_some());
    assert!(sec::decode(&(value.clone() + "=")).is_none());
    assert!(sec::decode(&(" ".to_owned() + &value)).is_none());
    assert!(sec::decode(&(value.clone() + " ")).is_none());
    let mut bad_bits = value.into_bytes();
    let last = bad_bits.len() - 1;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let index = ALPHABET.iter().position(|b| *b == bad_bits[last]).unwrap();
    bad_bits[last] = ALPHABET[index + 1];
    assert!(sec::decode(std::str::from_utf8(&bad_bits).unwrap()).is_none());
}

async fn seeded(name: &str) -> (Fixture, [u8; 32]) {
    let f = Fixture::new(name).await;
    f.operator.issue_setup_code(&[1; 32]).await.unwrap();
    assert_eq!(
        f.runtime
            .claim_owner(&[1; 32], common::EMAIL, common::HASH)
            .await
            .unwrap(),
        bloc::storage::Claim::Created
    );
    let session = sec::digest(&sec::encode(&[3; 32]));
    assert!(
        f.runtime
            .authenticate(&session, 1, &[4; 32], &[5; 32], None)
            .await
            .unwrap()
    );
    (f, session)
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn session_deadlines() {
    for (name, sql) in [
        (
            "idle",
            "UPDATE bloc.administrator_session SET last_activity_at=clock_timestamp()-interval '30 minutes'",
        ),
        (
            "absolute",
            "UPDATE bloc.administrator_session SET created_at=statement_timestamp()-interval '12 hours',absolute_expires_at=statement_timestamp()",
        ),
    ] {
        let (f, s) = seeded(&format!("access{name}")).await;
        sqlx::query(sql).execute(&f.admin).await.unwrap();
        assert!(f.runtime.authorize(&s).await.unwrap().is_none());
    }
    for (name, pre, post) in [
        (
            "idlehttp",
            "UPDATE bloc.administrator_session SET last_activity_at=clock_timestamp()-interval '29 minutes 55 seconds'",
            "UPDATE bloc.administrator_session SET last_activity_at=clock_timestamp()-interval '30 minutes'",
        ),
        (
            "absolutehttp",
            "UPDATE bloc.administrator_session SET created_at=statement_timestamp()-interval '11 hours 59 minutes 55 seconds',absolute_expires_at=statement_timestamp()+interval '5 seconds'",
            "UPDATE bloc.administrator_session SET created_at=statement_timestamp()-interval '12 hours',absolute_expires_at=statement_timestamp()",
        ),
    ] {
        let (f, _) = seeded(&format!("access{name}")).await;
        let mut browser = Browser::new(&f).await;
        browser
            .cookies
            .insert("__Host-bloc-admin".into(), sec::encode(&[3; 32]));
        sqlx::query(pre).execute(&f.admin).await.unwrap();
        assert_eq!(browser.request("GET", "/admin", &[]).await.0, 200);
        sqlx::query(post).execute(&f.admin).await.unwrap();
        let (status, _, headers) = browser.request("GET", "/admin", &[]).await;
        assert_eq!(status, 303);
        assert!(
            headers["location"]
                .to_str()
                .unwrap()
                .starts_with("/admin/login")
        );
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn session_restart() {
    let (f, s) = seeded("accessrestart").await;
    let other = bloc::storage::Storage::connect(&f.url("runtime_user"), &f.ca)
        .await
        .unwrap();
    assert!(other.authorize(&s).await.unwrap().is_some());
    f.runtime.sign_out(&s).await.unwrap();
    assert!(other.authorize(&s).await.unwrap().is_none());
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn login_recovery_race() {
    let (f, _) = seeded("accessloginrace").await;
    f.operator.issue_recovery_code(&[8; 32]).await.unwrap();
    assert!(
        f.runtime
            .replace_password(&[8; 32], 0, common::HASH, true)
            .await
            .unwrap()
    );
    assert!(
        !f.runtime
            .authenticate(&[9; 32], 1, &[10; 32], &[11; 32], None)
            .await
            .unwrap()
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bloc.administrator_session WHERE session_digest=$1",
    )
    .bind(vec![9u8; 32])
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn credential_change_race() {
    let (f, s) = seeded("accesschangepwrace").await;
    f.operator.issue_recovery_code(&[8; 32]).await.unwrap();
    let other = bloc::storage::Storage::connect(&f.url("runtime_user"), &f.ca)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        f.runtime.replace_password(&s, 1, "first", false),
        other.replace_password(&[8; 32], 0, "second", true)
    );
    assert_eq!([a.unwrap(), b.unwrap()].iter().filter(|&&v| v).count(), 1);
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().version, 2);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn credential_atomicity() {
    let (f, s) = seeded("accessatomic").await;
    f.operator.issue_recovery_code(&[8; 32]).await.unwrap();
    f.fail_audit(true).await;
    assert!(
        f.runtime
            .replace_password(&[8; 32], 0, "new", true)
            .await
            .is_err()
    );
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().version, 1);
    assert!(f.runtime.code_usable("recovery", &[8; 32]).await.unwrap());
    assert!(f.runtime.authorize(&s).await.unwrap().is_some());
    f.fail_audit(false).await;
    assert!(
        f.runtime
            .replace_password(&[8; 32], 0, "new", true)
            .await
            .unwrap()
    );
    assert!(
        !f.runtime
            .replace_password(&[8; 32], 0, "other", true)
            .await
            .unwrap()
    );
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().phc, "new");
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn recovery_issue() {
    let fresh = Fixture::new("accessrecovernoowner").await;
    assert!(
        fresh
            .operator
            .issue_recovery_code(&[99; 32])
            .await
            .unwrap()
            .is_none()
    );
    let (f, s) = seeded("accessrecoverissue").await;
    let before = f.runtime.owner().await.unwrap().unwrap();
    assert!(
        f.operator
            .issue_recovery_code(&[8; 32])
            .await
            .unwrap()
            .is_some()
    );
    assert!(f.runtime.authorize(&s).await.unwrap().is_some());
    let after = f.runtime.owner().await.unwrap().unwrap();
    assert_eq!(after.phc, before.phc);
    assert_eq!(after.version, before.version);
    let bound:(String,i64)=sqlx::query_as("SELECT administrator_id::text,credential_version FROM bloc.operator_code WHERE purpose='recovery'").fetch_one(&f.admin).await.unwrap();
    let owner: String = sqlx::query_scalar("SELECT id::text FROM bloc.installation_administrator")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(bound, (owner, before.version));
    sqlx::query(
        "UPDATE bloc.installation_administrator SET credential_version=credential_version+1",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    assert!(!f.runtime.code_usable("recovery", &[8; 32]).await.unwrap());
    assert!(
        f.operator
            .issue_recovery_code(&[9; 32])
            .await
            .unwrap()
            .is_some()
    );
    assert!(f.runtime.code_usable("recovery", &[9; 32]).await.unwrap());
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn recovery_refusal() {
    let (f, s) = seeded("accessrecoverrefuse").await;
    let before = f.runtime.owner().await.unwrap().unwrap();
    f.operator.issue_recovery_code(&[8; 32]).await.unwrap();
    f.operator.issue_recovery_code(&[9; 32]).await.unwrap();
    for code in [[8; 32], [1; 32], [99; 32]] {
        assert!(
            !f.runtime
                .replace_password(&code, 0, "new", true)
                .await
                .unwrap()
        );
    }
    sqlx::query("UPDATE bloc.operator_code SET issued_at=statement_timestamp()-interval '15 minutes',expires_at=statement_timestamp() WHERE purpose='recovery'").execute(&f.admin).await.unwrap();
    assert!(
        !f.runtime
            .replace_password(&[9; 32], 0, "new", true)
            .await
            .unwrap()
    );
    assert!(f.runtime.authorize(&s).await.unwrap().is_some());
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().version, 1);
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().phc, before.phc);
    assert!(
        f.operator
            .issue_recovery_code(&[10; 32])
            .await
            .unwrap()
            .is_some()
    );
    assert!(f.runtime.authorize(&s).await.unwrap().is_some());
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().phc, before.phc);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn csrf_lifecycle() {
    let (f, s) = seeded("accesscsrflife").await;
    assert_eq!(
        f.runtime.form(&[4; 32], Some(&s), None).await.unwrap(),
        Some(vec![5; 32])
    );
    assert!(
        f.runtime
            .form(&[4; 32], None, None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.runtime
            .form(&[7; 32], None, Some(&[8; 32]))
            .await
            .unwrap(),
        Some(vec![8; 32])
    );
    let expiry: String = sqlx::query_scalar(
        "SELECT expires_at::text FROM bloc.administrator_form_state WHERE browser_digest=$1",
    )
    .bind(vec![7u8; 32])
    .fetch_one(&f.admin)
    .await
    .unwrap();
    let other = bloc::storage::Storage::connect(&f.url("runtime_user"), &f.ca)
        .await
        .unwrap();
    assert_eq!(
        other.form(&[7; 32], None, None).await.unwrap(),
        Some(vec![8; 32])
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT expires_at::text FROM bloc.administrator_form_state WHERE browser_digest=$1"
        )
        .bind(vec![7u8; 32])
        .fetch_one(&f.admin)
        .await
        .unwrap(),
        expiry
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM bloc.administrator_form_state WHERE browser_digest=$1 AND session_digest=$2").bind(vec![4u8;32]).bind(s.to_vec()).fetch_one(&f.admin).await.unwrap(),1);
    f.runtime.sign_out(&s).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM bloc.administrator_form_state WHERE session_digest=$1"
        )
        .bind(s.to_vec())
        .fetch_one(&f.admin)
        .await
        .unwrap(),
        0
    );
    sqlx::query("UPDATE bloc.administrator_form_state SET created_at=statement_timestamp()-interval '30 minutes',expires_at=statement_timestamp()").execute(&f.admin).await.unwrap();
    assert!(other.form(&[7; 32], None, None).await.unwrap().is_none());
    let fresh = Fixture::new("accesscsrfhttpdigest").await;
    let mut browser = Browser::new(&fresh).await;
    let token = browser.token("/admin/login").await;
    let bearer = browser.cookies["__Host-bloc-csrf"].clone();
    assert!(sec::decode(&token).is_some());
    assert!(sec::decode(&bearer).is_some());
    assert_ne!(token, bearer);
    let row: (Vec<u8>, Vec<u8>, String) = sqlx::query_as(
        "SELECT browser_digest,csrf_token,expires_at::text FROM bloc.administrator_form_state",
    )
    .fetch_one(&fresh.admin)
    .await
    .unwrap();
    assert_eq!(row.0, sec::digest(&bearer));
    assert_ne!(row.0, sec::decode(&bearer).unwrap());
    assert_eq!(row.1, sec::decode(&token).unwrap());
    let mut second = Browser::new(&fresh).await;
    second.cookies = browser.cookies.clone();
    assert_eq!(second.token("/admin/login").await, token);
    assert_eq!(browser.token("/admin/login").await, token);
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT expires_at::text FROM bloc.administrator_form_state"
        )
        .fetch_one(&fresh.admin)
        .await
        .unwrap(),
        row.2
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn security_audit_atomicity() {
    let (f, s) = seeded("accessauditall").await;
    f.operator.issue_recovery_code(&[8; 32]).await.unwrap();
    let snapshot: String = authority_snapshot(&f).await;
    f.fail_audit(true).await;
    assert!(
        f.runtime
            .replace_password(&[8; 32], 0, "recovery must roll back", true)
            .await
            .is_err()
    );
    assert_eq!(authority_snapshot(&f).await, snapshot);
    assert!(
        f.runtime
            .replace_password(&s, 1, "must roll back", false)
            .await
            .is_err()
    );
    assert_eq!(authority_snapshot(&f).await, snapshot);
    assert!(
        f.runtime
            .authenticate(&[20; 32], 1, &[21; 32], &[22; 32], None)
            .await
            .is_err()
    );
    assert!(f.runtime.sign_out(&s).await.is_err());
    assert!(f.operator.invalidate_access().await.is_err());
    assert!(f.operator.issue_recovery_code(&[8; 32]).await.is_err());
    assert_eq!(authority_snapshot(&f).await, snapshot);
    assert!(f.runtime.authorize(&s).await.unwrap().is_some());
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().version, 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.administrator_session")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let fresh = Fixture::new("accessauditfreshall").await;
    fresh.operator.issue_setup_code(&[1; 32]).await.unwrap();
    let original = authority_snapshot(&fresh).await;
    fresh.fail_audit(true).await;
    assert!(fresh.operator.issue_setup_code(&[2; 32]).await.is_err());
    assert_eq!(authority_snapshot(&fresh).await, original);
    assert!(
        fresh
            .runtime
            .claim_owner(&[1; 32], common::EMAIL, common::HASH)
            .await
            .is_err()
    );
    assert_eq!(authority_snapshot(&fresh).await, original);
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn capability_roles_extended() {
    let (f, s) = seeded("accessextroles").await;
    assert!(f.runtime.issue_recovery_code(&[7; 32]).await.is_err());
    assert!(f.runtime.invalidate_access().await.is_err());
    assert!(f.runtime.maintain_access().await.is_err());
    assert!(
        f.operator
            .authenticate(&[8; 32], 1, &[9; 32], &[10; 32], None)
            .await
            .is_err()
    );
    assert!(
        f.operator
            .replace_password(&s, 1, "unauthorized", false)
            .await
            .is_err()
    );
    let maintenance = bloc::storage::Storage::connect(&f.url("maintenance_user"), &f.ca)
        .await
        .unwrap();
    assert!(maintenance.maintain_access().await.is_ok());
    assert!(maintenance.issue_setup_code(&[9; 32]).await.is_err());
    let violations:i64=sqlx::query_scalar("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='bloc' AND (NOT p.prosecdef OR NOT ('search_path=pg_catalog, bloc, pg_temp'=ANY(p.proconfig)) OR has_function_privilege('public_user',p.oid,'EXECUTE'))").fetch_one(&f.admin).await.unwrap();
    assert_eq!(violations, 0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn maintenance_retention() {
    let (f, _) = seeded("accessretention").await;
    sqlx::query("INSERT INTO bloc.security_audit_event(installation_id,action,outcome,occurred_at) SELECT 1,'sign_in','success',clock_timestamp()-interval '91 days' FROM generate_series(1,1001)").execute(&f.admin).await.unwrap();
    f.runtime.deny("sign_in", "credentials").await.unwrap();
    sqlx::query(
        "UPDATE bloc.administrator_denial_aggregate SET minute=clock_timestamp()-interval '8 days'",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    let maintenance = bloc::storage::Storage::connect(&f.url("maintenance_user"), &f.ca)
        .await
        .unwrap();
    assert_eq!(maintenance.maintain_access().await.unwrap(), 1001);
    let remaining:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.security_audit_event WHERE occurred_at<clock_timestamp()-interval '90 days'").fetch_one(&f.admin).await.unwrap();
    assert_eq!(remaining, 1);
    assert_eq!(maintenance.maintain_access().await.unwrap(), 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn audit_data_bounds() {
    let (f, _) = seeded("accessauditdata").await;
    f.runtime.deny("sign_in", "credentials").await.unwrap();
    sqlx::query("UPDATE bloc.administrator_denial_aggregate SET count=9223372036854775807")
        .execute(&f.admin)
        .await
        .unwrap();
    f.runtime.deny("sign_in", "credentials").await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count FROM bloc.administrator_denial_aggregate")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(count, i64::MAX);
    assert!(
        f.runtime
            .deny("submitted@example.test", "credentials")
            .await
            .is_err()
    );
    let columns:Vec<String>=sqlx::query_scalar("SELECT column_name::text FROM information_schema.columns WHERE table_schema='bloc' AND table_name='administrator_denial_aggregate' ORDER BY ordinal_position").fetch_all(&f.admin).await.unwrap();
    assert_eq!(columns, ["minute", "action", "reason", "count"]);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn session_activity_races() {
    let (f, s) = seeded("accessactivity").await;
    let before: String =
        sqlx::query_scalar("SELECT last_activity_at::text FROM bloc.administrator_session")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let mut browser = Browser::new(&f).await;
    browser
        .cookies
        .insert("__Host-bloc-admin".into(), sec::encode(&[3; 32]));
    for path in ["/healthz", "/readyz", "/assets/admin.css"] {
        assert_eq!(browser.request("GET", path, &[]).await.0, 200);
    }
    let after: String =
        sqlx::query_scalar("SELECT last_activity_at::text FROM bloc.administrator_session")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(before, after);
    let initial: f64 = sqlx::query_scalar(
        "SELECT extract(epoch from last_activity_at)::float8 FROM bloc.administrator_session",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    let other = bloc::storage::Storage::connect(&f.url("runtime_user"), &f.ca)
        .await
        .unwrap();
    let (a, b) = tokio::join!(f.runtime.authorize(&s), other.authorize(&s));
    assert!(a.unwrap().is_some() && b.unwrap().is_some());
    let latest: f64 = sqlx::query_scalar(
        "SELECT extract(epoch from last_activity_at)::float8 FROM bloc.administrator_session",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert!(latest >= initial);
    f.runtime.authorize(&s).await.unwrap();
    let next: f64 = sqlx::query_scalar(
        "SELECT extract(epoch from last_activity_at)::float8 FROM bloc.administrator_session",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert!(next >= latest);
    sqlx::query("UPDATE bloc.administrator_session SET last_activity_at=clock_timestamp()-interval '30 minutes'").execute(&f.admin).await.unwrap();
    let (a, b) = tokio::join!(f.runtime.authorize(&s), other.authorize(&s));
    assert!(a.unwrap().is_none() && b.unwrap().is_none());
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn admission_capacity() {
    let f = Fixture::new("accesscapacity").await;
    sqlx::query("INSERT INTO bloc.administrator_admission_bucket SELECT 'credential_source',sha256(i::text::bytea),ARRAY[clock_timestamp()],clock_timestamp()+interval '2 minutes' FROM generate_series(1,10000) i").execute(&f.admin).await.unwrap();
    assert_eq!(
        f.runtime
            .reserve(&[("credential_source", [9; 32], 1)])
            .await
            .unwrap(),
        -1
    );
    let existing: Vec<u8> = sqlx::query_scalar(
        "SELECT subject_digest FROM bloc.administrator_admission_bucket LIMIT 1",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(
        f.runtime
            .reserve(&[("credential_source", existing.try_into().unwrap(), 1)])
            .await
            .unwrap(),
        0
    );
    sqlx::query("UPDATE bloc.administrator_admission_bucket SET expires_at=clock_timestamp()-interval '1 second'").execute(&f.admin).await.unwrap();
    assert_eq!(
        f.runtime
            .reserve(&[("credential_source", [9; 32], 1)])
            .await
            .unwrap(),
        0
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn csrf_capacity() {
    let f = Fixture::new("accesscsrfcap").await;
    let mut browser = Browser::new(&f).await;
    for _ in 0..10 {
        browser.cookies.clear();
        let (status, _, headers) = browser.request("GET", "/admin/login", &[]).await;
        assert_eq!(status, 200);
        let value = headers["set-cookie"].to_str().unwrap();
        for attribute in [
            "__Host-bloc-csrf=",
            "Secure",
            "HttpOnly",
            "SameSite=Strict",
            "Path=/",
        ] {
            assert!(value.contains(attribute));
        }
        assert!(!value.contains("Domain="));
    }
    browser.cookies.clear();
    let (status, _, headers) = browser.request("GET", "/admin/login", &[]).await;
    assert_eq!(status, 429);
    assert!(headers.contains_key("retry-after"));
    sqlx::query("DELETE FROM bloc.administrator_form_state")
        .execute(&f.admin)
        .await
        .unwrap();

    sqlx::query("INSERT INTO bloc.administrator_form_state SELECT sha256(i::text::bytea),sha256(i::text::bytea),NULL,statement_timestamp(),statement_timestamp()+interval '30 minutes' FROM generate_series(1,10000) i").execute(&f.admin).await.unwrap();
    assert!(
        f.runtime
            .form(&[99; 32], None, Some(&[98; 32]))
            .await
            .unwrap()
            .is_none()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.administrator_form_state")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(count, 10000);
    let (status, _, headers) = custom(
        &browser,
        "GET",
        "/admin/login",
        "",
        &[("x-forwarded-for", Some("192.0.2.99"))],
        "127.0.0.1:1",
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(headers["retry-after"], "60");
}
#[test]
fn proxy_authority() {
    let config = Config::new("https://bloc.example.test", "127.0.0.1/32", [1; 32]).unwrap();
    let mut h = axum::http::HeaderMap::new();
    h.insert("host", "bloc.example.test".parse().unwrap());
    h.insert("x-forwarded-for", "192.0.2.1".parse().unwrap());
    h.insert("x-forwarded-proto", "https".parse().unwrap());
    assert!(sec::source(&config, &h, "127.0.0.1:1".parse().unwrap()).is_ok());
    assert_eq!(
        sec::source(&config, &h, "10.0.0.1:1".parse().unwrap()).unwrap_err(),
        403
    );
    h.append("x-forwarded-for", "192.0.2.2".parse().unwrap());
    assert_eq!(
        sec::source(&config, &h, "127.0.0.1:1".parse().unwrap()).unwrap_err(),
        400
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn readiness_liveness() {
    let f = Fixture::new("accessready").await;
    let mut b = Browser::new(&f).await;
    assert_eq!(b.request("GET", "/readyz", &[]).await.0, 200);
    sqlx::query("UPDATE public._sqlx_migrations SET checksum=decode('00','hex') WHERE version=2")
        .execute(&f.admin)
        .await
        .unwrap();
    let (s, body, _) = b.request("GET", "/readyz", &[]).await;
    assert_eq!(s, 503);
    assert_eq!(body, "unavailable\n");
    let (s, body, _) = b.request("GET", "/healthz", &[]).await;
    assert_eq!(s, 200);
    assert_eq!(body, "ok\n");
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn authority_outage() {
    let (f, s) = seeded("accessoutage").await;
    f.runtime.sign_out(&s).await.unwrap();
    sqlx::query(
        "ALTER FUNCTION bloc.authorize_session(bytea) RENAME TO disabled_authorize_session",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    assert!(f.runtime.authorize(&s).await.is_err());
    sqlx::query(
        "ALTER FUNCTION bloc.disabled_authorize_session(bytea) RENAME TO authorize_session",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    assert!(f.runtime.authorize(&s).await.unwrap().is_none());
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn logout_failure() {
    let f = Fixture::new("accesslogoutfail").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    b.login().await;
    let csrf = b.token("/admin").await;
    f.fail_audit(true).await;
    let (s, html, _) = b.request("POST", "/admin/logout", &[("csrf", &csrf)]).await;
    assert_eq!(s, 503);
    assert!(html.contains("Sign-out could not be confirmed."));
    assert!(!b.cookies.contains_key("__Host-bloc-admin"));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bloc.administrator_session WHERE revoked_at IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(count, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn authorization_matrix() {
    let f = Fixture::new("accessauthmatrix").await;
    let mut b = Browser::new(&f).await;
    for (method, path) in [
        ("GET", "/admin"),
        ("GET", "/admin/password"),
        ("POST", "/admin/password"),
        ("POST", "/admin/logout"),
    ] {
        let (s, html, headers) = b.request(method, path, &[]).await;
        assert_eq!(s, 303);
        assert!(!html.contains("Installation administrator"));
        assert!(
            headers["location"]
                .to_str()
                .unwrap()
                .starts_with("/admin/login")
        );
    }
    for (name, mutation) in [
        (
            "expired",
            "UPDATE bloc.administrator_session SET last_activity_at=clock_timestamp()-interval '30 minutes'",
        ),
        (
            "revoked",
            "UPDATE bloc.administrator_session SET revoked_at=clock_timestamp()",
        ),
        (
            "obsolete",
            "UPDATE bloc.installation_administrator SET credential_version=2",
        ),
        (
            "missing",
            "DELETE FROM bloc.administrator_form_state; DELETE FROM bloc.administrator_session",
        ),
    ] {
        let (fixture, _) = seeded(&format!("accessmatrix{name}")).await;
        sqlx::raw_sql(mutation)
            .execute(&fixture.admin)
            .await
            .unwrap();
        let mut browser = Browser::new(&fixture).await;
        browser
            .cookies
            .insert("__Host-bloc-admin".into(), sec::encode(&[3; 32]));
        browser
            .cookies
            .insert("__Host-bloc-csrf".into(), sec::encode(&[4; 32]));
        let authority = authority_snapshot(&fixture).await;
        for (method, path) in [
            ("GET", "/admin"),
            ("GET", "/admin/password"),
            ("POST", "/admin/password"),
            ("POST", "/admin/logout"),
        ] {
            for enhanced in [false, true] {
                let headers = if enhanced {
                    vec![("hx-request", Some("true"))]
                } else {
                    vec![]
                };
                let (status, html, h) = custom(
                    &browser,
                    method,
                    path,
                    "csrf=bad&current_password=sentinel&password=sentinel",
                    &headers,
                    "127.0.0.1:1",
                )
                .await;
                assert_eq!(
                    status,
                    if enhanced { 401 } else { 303 },
                    "{name} {method} {path} enhanced={enhanced}: {html}"
                );
                assert!(
                    h[if enhanced { "hx-redirect" } else { "location" }]
                        .to_str()
                        .unwrap()
                        .starts_with("/admin/login")
                );
                for secret in [
                    "Installation administrator",
                    common::EMAIL,
                    "name=\"current_password\"",
                ] {
                    assert!(!html.contains(secret));
                }
            }
        }
        assert_eq!(authority_snapshot(&fixture).await, authority);
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn administration_home() {
    let f = Fixture::new("accesshome").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    b.login().await;
    sqlx::query(
        "UPDATE bloc.installation_administrator SET email='<script>alert(1)</script>@example.test'",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    let (s, html, _) = b.request("GET", "/admin", &[]).await;
    assert_eq!(s, 200);
    for value in [
        "Installation administrator",
        "Setup complete",
        env!("CARGO_PKG_VERSION"),
        "/admin/password",
        "/admin/logout",
    ] {
        assert!(html.contains(value))
    }
    let cell = html
        .split("<p class=\"account-email\">")
        .nth(1)
        .unwrap()
        .split("</p>")
        .next()
        .unwrap();
    assert!(!cell.contains('<'));
    assert_eq!(
        cell.replace("&#60;", "<")
            .replace("&#62;", ">")
            .replace("&lt;", "<")
            .replace("&gt;", ">"),
        "<script>alert(1)</script>@example.test"
    );
    assert!(!html.contains("<script>alert"));
    assert!(html.contains("href=\"/admin/realms\""));
    assert!(html.contains("aria-label=\"Administration\""));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn email_semantics() {
    let f = Fixture::new("accessemailsem").await;
    let mut b = Browser::new(&f).await;
    let (_, html, _) = b.request("GET", "/admin/setup", &[]).await;
    assert!(html.contains("No verification email will be sent."));
    assert!(!html.contains("verified email"));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn root_navigation() {
    let f = Fixture::new("accessroot").await;
    let mut b = Browser::new(&f).await;
    let (s, _, h) = b.request("GET", "/", &[]).await;
    assert_eq!(s, 303);
    assert_eq!(h["location"], "/admin/login");
    let (_, html, _) = b.request("GET", "/admin/login", &[]).await;
    assert!(!html.contains("/admin/setup"));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn setup_abandonment() {
    let f = Fixture::new("accessabandon").await;
    let mut b = Browser::new(&f).await;
    b.token("/admin/setup").await;
    f.operator.issue_setup_code(&[8; 32]).await.unwrap();
    assert_eq!(f.count("installation_administrator").await, 0);
    b.setup(&f).await;
    assert_eq!(f.count("installation_administrator").await, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn setup_http_race() {
    let f = Fixture::new("accesshttprace").await;
    let mut a = Browser::new(&f).await;
    let mut b = Browser::new(&f).await;
    let code = sec::encode(&[1; 32]);
    f.operator
        .issue_setup_code(&sec::digest(&code))
        .await
        .unwrap();
    let ac = a.token("/admin/setup").await;
    let bc = b.token("/admin/setup").await;
    let fields = |csrf| {
        vec![
            ("csrf", csrf),
            ("code", code.as_str()),
            ("email", "Owner@example.test"),
            ("password", "a synthetic password"),
            ("password_confirmation", "a synthetic password"),
        ]
    };
    let af = fields(ac.as_str());
    let bf = fields(bc.as_str());
    let (a, b) = tokio::join!(
        a.request("POST", "/admin/setup", &af),
        b.request("POST", "/admin/setup", &bf)
    );
    let mut statuses = [a.0.as_u16(), b.0.as_u16()];
    statuses.sort();
    assert_eq!(statuses, [303, 409]);
    assert_eq!(f.count("installation_administrator").await, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn operator_code_boundaries() {
    let f = Fixture::new("accessboundcode").await;
    f.operator.issue_setup_code(&[1; 32]).await.unwrap();
    f.operator.issue_setup_code(&[2; 32]).await.unwrap();
    assert!(!f.runtime.code_usable("setup", &[1; 32]).await.unwrap());
    assert!(!f.runtime.code_usable("recovery", &[2; 32]).await.unwrap());
    sqlx::query("UPDATE bloc.operator_code SET issued_at=statement_timestamp()-interval '15 minutes',expires_at=statement_timestamp()").execute(&f.admin).await.unwrap();
    assert!(!f.runtime.code_usable("setup", &[2; 32]).await.unwrap());
    let other = bloc::storage::Storage::connect(&f.url("runtime_user"), &f.ca)
        .await
        .unwrap();
    f.operator.issue_setup_code(&[3; 32]).await.unwrap();
    assert!(other.code_usable("setup", &[3; 32]).await.unwrap());
    assert_eq!(
        other
            .claim_owner(&[3; 32], common::EMAIL, common::HASH)
            .await
            .unwrap(),
        bloc::storage::Claim::Created
    );
    assert!(!f.runtime.code_usable("setup", &[3; 32]).await.unwrap());
    assert!(!other.code_usable("setup", &[3; 32]).await.unwrap());
    assert!(!other.code_usable("recovery", &[3; 32]).await.unwrap());
    f.operator.issue_recovery_code(&[4; 32]).await.unwrap();
    assert!(other.code_usable("recovery", &[4; 32]).await.unwrap());
    assert!(
        other
            .replace_password(&[4; 32], 0, common::HASH, true)
            .await
            .unwrap()
    );
    assert!(!f.runtime.code_usable("recovery", &[4; 32]).await.unwrap());
    assert!(!other.code_usable("recovery", &[4; 32]).await.unwrap());
    let lifetime: bool = sqlx::query_scalar(
        "SELECT bool_and(expires_at-issued_at=interval '15 minutes') FROM bloc.operator_code",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert!(lifetime);
}

#[test]
fn startup_configuration() {
    for name in [
        "BLOC_DATABASE_URL_FILE",
        "BLOC_DATABASE_CA_FILE",
        "BLOC_CANONICAL_ORIGIN",
        "BLOC_TRUSTED_PROXY_CIDRS",
        "BLOC_ABUSE_KEY_FILE",
    ] {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_bloc"));
        for key in [
            "BLOC_DATABASE_URL_FILE",
            "BLOC_DATABASE_CA_FILE",
            "BLOC_CANONICAL_ORIGIN",
            "BLOC_TRUSTED_PROXY_CIDRS",
            "BLOC_ABUSE_KEY_FILE",
        ] {
            cmd.env_remove(key);
        }
        cmd.env(name, "redaction-sentinel");
        let out = cmd.output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(out.stderr).unwrap(),
            "bloc: invalid server configuration\n"
        );
        assert!(out.stdout.is_empty());
    }
    for origin in [
        "http://bloc.example.test",
        "https://user@bloc.example.test",
        "https://bloc.example.test/path",
        "https://bloc.example.test?query",
    ] {
        assert!(Config::new(origin, "127.0.0.1/32", [1; 32]).is_err());
    }
}

struct Services {
    children: Vec<std::process::Child>,
    directory: std::path::PathBuf,
}
impl Drop for Services {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn spawn_service(f: &Fixture, directory: &std::path::Path, port: u16) -> std::process::Child {
    std::process::Command::new(env!("CARGO_BIN_EXE_bloc"))
        .env("BLOC_DATABASE_URL_FILE", directory.join("runtime"))
        .env("BLOC_DATABASE_CA_FILE", &f.ca)
        .env("BLOC_ABUSE_KEY_FILE", directory.join("abuse"))
        .env("BLOC_CANONICAL_ORIGIN", "https://bloc.example.test:4443")
        .env("BLOC_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
        .env("BLOC_BIND_ADDR", format!("127.0.0.1:{port}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}
async fn services(f: &Fixture) -> Services {
    let directory = std::env::temp_dir().join(format!(
        "bloc-services-{}-{}",
        std::process::id(),
        f.database
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("runtime"), f.url("runtime_user")).unwrap();
    std::fs::write(directory.join("operator"), f.url("operator_user")).unwrap();
    std::fs::write(directory.join("abuse"), [7; 32]).unwrap();
    let mut children = Vec::new();
    for port in [31001, 31002] {
        let child = spawn_service(f, &directory, port);
        children.push(child);
    }
    let services = Services {
        children,
        directory,
    };
    for port in [31001, 31002] {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "service did not listen"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    services
}
async fn browser_proof(mode: &str) {
    let f = Fixture::new(&format!("accessbrowser{}", mode.replace('_', ""))).await;
    let services = services(&f).await;
    let python = std::env::var("BLOC_BROWSER_PYTHON").expect("explicit Playwright Python required");
    let spki = std::env::var("BLOC_TEST_SPKI").expect("explicit synthetic TLS SPKI required");
    let mut command = std::process::Command::new(python);
    command
        .args(["tests/support/administrator_browser.py", mode])
        .env("BLOC_TEST_ORIGIN", "https://bloc.example.test:4443")
        .env("BLOC_TEST_SPKI", spki)
        .env("BLOC_TEST_BINARY", env!("CARGO_BIN_EXE_bloc"))
        .env(
            "BLOC_DATABASE_URL_FILE",
            services.directory.join("operator"),
        )
        .env("BLOC_DATABASE_CA_FILE", &f.ca);
    let output = tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn browser_no_javascript() {
    browser_proof("no_javascript").await;
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn browser_validation() {
    browser_proof("validation").await;
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn browser_loading_network() {
    browser_proof("loading_network").await;
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn browser_session_expiry() {
    browser_proof("session_expiry").await;
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn browser_preview() {
    browser_proof("preview").await;
}

async fn custom(
    b: &Browser,
    method: &str,
    path: &str,
    body: &str,
    changes: &[(&str, Option<&str>)],
    peer: &str,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "bloc.example.test")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "192.0.2.4")
        .header("origin", "https://bloc.example.test")
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "cookie",
            b.cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
        .body(Body::from(body.to_owned()))
        .unwrap();
    for (name, value) in changes {
        request.headers_mut().remove(*name);
        if let Some(value) = value {
            request.headers_mut().insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
    }
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()));
    let response = b.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let html = String::from_utf8(
        to_bytes(response.into_body(), 100000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, html, headers)
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn origin_csrf() {
    let f = Fixture::new("accessorigincsrf").await;
    let mut b = Browser::new(&f).await;
    let token = b.token("/admin/setup").await;
    let body = format!(
        "csrf={token}&code={}&email=Owner%40example.test&password=a+synthetic+password&password_confirmation=a+synthetic+password",
        sec::encode(&[1; 32])
    );
    for origin in [None, Some("null"), Some("https://evil.example")] {
        assert_eq!(
            custom(
                &b,
                "POST",
                "/admin/setup",
                &body,
                &[("origin", origin)],
                "127.0.0.1:1"
            )
            .await
            .0,
            403
        );
    }
    assert_eq!(
        custom(
            &b,
            "POST",
            "/admin/setup",
            &body,
            &[
                ("origin", None),
                ("referer", Some("https://bloc.example.test/path"))
            ],
            "127.0.0.1:1"
        )
        .await
        .0,
        400
    );
    let mut foreign = Browser::new(&f).await;
    foreign.token("/admin/setup").await;
    assert_eq!(
        custom(&foreign, "POST", "/admin/setup", &body, &[], "127.0.0.1:1")
            .await
            .0,
        403
    );
    assert_eq!(f.count("installation_administrator").await, 0);
    for equivalent in ["https://BLOC.example.test", "https://bloc.example.test:443"] {
        assert_eq!(
            custom(
                &b,
                "POST",
                "/admin/setup",
                &body,
                &[("origin", Some(equivalent))],
                "127.0.0.1:1"
            )
            .await
            .0,
            400
        );
    }
    for bad in [
        "https://bloc.example.test:444",
        "https://u@bloc.example.test",
        "https://bloc.example.test/path",
        "https://bloc.example.test?x",
        "https://bloc.example.test#x",
    ] {
        assert_eq!(
            custom(
                &b,
                "POST",
                "/admin/setup",
                &body,
                &[("origin", Some(bad))],
                "127.0.0.1:1"
            )
            .await
            .0,
            403
        );
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn expiry_navigation() {
    let f = Fixture::new("accessexpirynav").await;
    let b = Browser::new(&f).await;
    let (s, body, h) = custom(
        &b,
        "GET",
        "/admin/password",
        "",
        &[("hx-request", Some("true"))],
        "127.0.0.1:1",
    )
    .await;
    assert_eq!(s, 401);
    assert_eq!(h["hx-redirect"], "/admin/login?expired=1");
    assert!(body.contains("Your session ended. Sign in again."));
    let (s, _, h) = custom(&b, "GET", "/admin/password", "", &[], "127.0.0.1:1").await;
    assert_eq!(s, 303);
    assert_eq!(h["location"], "/admin/login?expired=1");
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn request_security_http() {
    let f = Fixture::new("accessrequesthttp").await;
    let b = Browser::new(&f).await;
    assert_eq!(
        custom(&b, "GET", "/admin/login", "", &[], "10.0.0.1:1")
            .await
            .0,
        403
    );
    for changes in [
        vec![("x-forwarded-for", Some("192.0.2.1, 192.0.2.2"))],
        vec![("x-forwarded-proto", Some("http"))],
        vec![("host", Some("evil.example"))],
    ] {
        assert_eq!(
            custom(&b, "GET", "/admin/login", "", &changes, "127.0.0.1:1")
                .await
                .0,
            400
        );
    }
    assert_eq!(
        custom(&b, "POST", "/admin/setup", "csrf=%GG", &[], "127.0.0.1:1")
            .await
            .0,
        400
    );
    assert_eq!(
        custom(
            &b,
            "POST",
            "/admin/setup",
            "csrf=x&csrf=y",
            &[],
            "127.0.0.1:1"
        )
        .await
        .0,
        400
    );
    assert_eq!(
        custom(
            &b,
            "POST",
            "/admin/setup",
            "{}",
            &[("content-type", Some("application/json"))],
            "127.0.0.1:1"
        )
        .await
        .0,
        415
    );
    assert_eq!(
        custom(
            &b,
            "POST",
            "/admin/setup",
            &"a".repeat(16385),
            &[],
            "127.0.0.1:1"
        )
        .await
        .0,
        413
    );
    for host in ["BLOC.example.test", "bloc.example.test:443"] {
        assert_eq!(
            custom(
                &b,
                "GET",
                "/admin/login",
                "",
                &[("host", Some(host))],
                "127.0.0.1:1"
            )
            .await
            .0,
            200
        );
    }
    for changes in [
        vec![("host", None)],
        vec![
            ("host", Some("evil.example")),
            ("x-forwarded-host", Some("bloc.example.test")),
        ],
        vec![("host", Some("bloc.example.test:444"))],
        vec![("x-forwarded-for", None)],
        vec![("x-forwarded-for", Some("bogus"))],
        vec![("x-forwarded-for", Some("192.0.2.4,192.0.2.5"))],
        vec![("x-forwarded-proto", None)],
        vec![("x-forwarded-proto", Some("https,http"))],
    ] {
        assert_eq!(
            custom(&b, "GET", "/admin/login", "", &changes, "127.0.0.1:1")
                .await
                .0,
            400
        );
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn hash_backpressure() {
    let worker = PasswordWorker::new();
    let worker2 = worker.clone();
    let first = tokio::spawn(async move { worker2.hash("a synthetic password".into()).await });
    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(
        worker.hash("another synthetic password".into()).await,
        Err(bloc::credentials::Error::Capacity)
    );
    assert!(first.await.unwrap().is_ok());
    let f = Fixture::new("accesshashunavail").await;
    let mut b = Browser::new(&f).await;
    let csrf = b.token("/admin/login").await;
    sqlx::query("ALTER FUNCTION bloc.reserve_admission(text[],bytea[],integer[]) RENAME TO disabled_admission").execute(&f.admin).await.unwrap();
    let (s, _, _) = b
        .request(
            "POST",
            "/admin/login",
            &[
                ("csrf", &csrf),
                ("email", "Owner@example.test"),
                ("password", "a synthetic password"),
            ],
        )
        .await;
    assert_eq!(s, 503);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn setup_cli_contract() {
    let f = Fixture::new("accessclicontract").await;
    let directory = std::env::temp_dir().join(format!("bloc-access-cli-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("url"), f.url("operator_user")).unwrap();
    let invoke = || {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_bloc"));
        c.args(["admin", "setup-code"])
            .env("BLOC_DATABASE_URL_FILE", directory.join("url"))
            .env("BLOC_DATABASE_CA_FILE", &f.ca);
        c
    };
    let mut c = invoke();
    let output = tokio::task::spawn_blocking(move || c.output().unwrap())
        .await
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let rows: Vec<_> = text.lines().collect();
    assert_eq!(rows.len(), 2);
    let code = rows[0].strip_prefix("code=").unwrap();
    assert!(sec::decode(code).is_some());
    assert!(rows[1].starts_with("expires_at="));
    assert!(rows[1].ends_with('Z'));
    assert!(
        f.runtime
            .code_usable("setup", &sec::digest(code))
            .await
            .unwrap()
    );
    f.fail_audit(true).await;
    let mut c = invoke();
    let output = tokio::task::spawn_blocking(move || c.output().unwrap())
        .await
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    std::fs::remove_dir_all(directory).unwrap();
}
fn wire(port: u16, cookie: Option<&str>) -> String {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let request = format!(
        "GET /admin HTTP/1.1\r\nHost: bloc.example.test:4443\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 192.0.2.4\r\nConnection: close\r\nCookie: __Host-bloc-admin={}\r\n\r\n",
        cookie.unwrap_or("")
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}
#[tokio::test]
#[ignore = "real service and TLS fixture"]
async fn two_instance_service() {
    let (f, _) = seeded("accesstwoservice").await;
    let mut services = services(&f).await;
    let raw = sec::encode(&[3; 32]);
    for port in [31001, 31002] {
        let response = wire(port, Some(&raw));
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains(common::EMAIL));
    }
    services.children[0].kill().unwrap();
    services.children[0].wait().unwrap();
    assert!(wire(31002, Some(&raw)).starts_with("HTTP/1.1 200"));
    f.runtime.sign_out(&sec::digest(&raw)).await.unwrap();
    assert!(wire(31002, Some(&raw)).starts_with("HTTP/1.1 303"));
    services.children[0] = spawn_service(&f, &services.directory, 31001);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::net::TcpStream::connect(("127.0.0.1", 31001)).is_err() {
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(wire(31001, Some(&raw)).starts_with("HTTP/1.1 303"));
}
#[tokio::test]
#[ignore = "real service and TLS fixture"]
async fn restore_two_instances() {
    let (f, _) = seeded("accessrestoretwo").await;
    let container = std::env::var("BLOC_SETUP_CONTAINER")
        .expect("actual disposable database container required for backup/restore proof");
    let database = f.database.clone();
    let dump_container = container.clone();
    let dump = tokio::task::spawn_blocking(move || {
        std::process::Command::new("docker")
            .args([
                "exec",
                &dump_container,
                "pg_dump",
                "-U",
                "probe",
                "-d",
                &database,
                "-Fc",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(dump.status.success());
    f.operator.issue_recovery_code(&[90; 32]).await.unwrap();
    assert!(
        f.runtime
            .replace_password(&[90; 32], 0, "post-backup-credential", true)
            .await
            .unwrap()
    );
    let database = f.database.clone();
    let restored = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut child = std::process::Command::new("docker")
            .args([
                "exec",
                "-i",
                &container,
                "pg_restore",
                "-U",
                "probe",
                "-d",
                &database,
                "--clean",
                "--if-exists",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&dump.stdout).unwrap();
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert!(restored.status.success(), "physical fixture restore failed");
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().version, 1);

    let _services = services(&f).await;
    let raw = sec::encode(&[3; 32]);
    f.operator.issue_recovery_code(&[8; 32]).await.unwrap();
    f.operator.invalidate_access().await.unwrap();
    for port in [31001, 31002] {
        assert!(wire(port, Some(&raw)).starts_with("HTTP/1.1 303"));
    }
    assert!(!f.runtime.code_usable("recovery", &[8; 32]).await.unwrap());
    assert!(
        f.runtime
            .form(&[4; 32], Some(&sec::digest(&raw)), None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(f.runtime.owner().await.unwrap().unwrap().recovery_required);
}
#[test]
fn deployment_contract() {
    let helm = std::env::var("BLOC_HELM").unwrap_or_else(|_| "helm".into());
    let output = std::process::Command::new(helm)
        .args([
            "template",
            "test",
            "charts/bloc",
            "--set",
            "image.digest=sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--set",
            "access.operatorPod=true",
            "--set",
            "access.migrationJob=true",
            "--set",
            "access.maintenanceJob=true",
        ])
        .output()
        .expect("Helm required for deployment proof");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for required in [
        "/readyz",
        "/healthz",
        "runtime-url",
        "operator-url",
        "migrator-url",
        "maintenance-url",
        "abuse-key",
        "MALLOC_MMAP_THRESHOLD_",
        "131072",
        "512Mi",
        "kind: CronJob",
        "kind: Job",
        "kind: Pod",
    ] {
        assert!(text.contains(required), "{required}");
    }
}
#[test]
fn operational_documentation() {
    let text = include_str!("../docs/administrator-access.md");
    for required in [
        "Fence ingress",
        "invalidate-access",
        "recovery-code",
        "setup-code",
        "both replicas",
        "Keep",
        "MFA",
        "90 days",
        "7 days",
        "16 KiB",
        "1 CPU/512 MiB",
        "384 MiB",
        "p95",
    ] {
        assert!(text.contains(required), "{required}");
    }
    assert!(
        include_str!("../docs/adr/0004-initial-administrator-access.md")
            .contains("Status: accepted — 2026-10-21")
    );
}
#[test]
#[ignore = "explicit native capacity proof; requires paired amd64 and arm64 evidence"]
fn native_service_capacity() {
    let Some(path) = std::env::var_os("BLOC_NATIVE_SERVICE_EVIDENCE") else {
        panic!(
            "BLOCKED: native full-service amd64+arm64 evidence is not available; no capacity pass"
        );
    };
    let output = std::process::Command::new("python3")
        .arg("tests/support/native_service_evidence.py")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn credential_validation_http() {
    let f = Fixture::new("accessvalidatehttp").await;
    let mut browser = Browser::new(&f).await;
    let code = sec::encode(&[1; 32]);
    f.operator
        .issue_setup_code(&sec::digest(&code))
        .await
        .unwrap();
    let csrf = browser.token("/admin/setup").await;
    for (email, password, confirmation, invalid_field, message) in [
        (
            "invalid",
            "a synthetic password",
            "a synthetic password",
            "email",
            "Enter an email address.",
        ),
        (
            "Owner@example.test",
            "short",
            "short",
            "password",
            "Choose a password with 15–128 characters and matching confirmation.",
        ),
        (
            "Owner@example.test",
            "a synthetic password",
            "a different password",
            "password",
            "Choose a password with 15–128 characters and matching confirmation.",
        ),
    ] {
        let (s, html, _) = browser
            .request(
                "POST",
                "/admin/setup",
                &[
                    ("csrf", &csrf),
                    ("code", &code),
                    ("email", email),
                    ("password", password),
                    ("password_confirmation", confirmation),
                ],
            )
            .await;
        assert_eq!(s, 422);
        assert!(!html.contains("role=\"alert\""));
        assert_eq!(html.matches("aria-invalid=\"true\"").count(), 1);
        let input = html
            .split(&format!("<input id=\"{invalid_field}\""))
            .nth(1)
            .unwrap()
            .split('>')
            .next()
            .unwrap();
        assert!(input.contains("aria-invalid=\"true\" aria-describedby=\"field-error\""));
        assert_eq!(html.matches("id=\"field-error\"").count(), 1);
        assert_eq!(html.matches(message).count(), 1);
        assert!(!html.contains(&format!("value=\"{code}\"")));
        assert!(!html.contains(&format!("value=\"{password}\"")));
        assert!(!html.contains(&format!("value=\"{confirmation}\"")));
        assert!(
            f.runtime
                .code_usable("setup", &sec::digest(&code))
                .await
                .unwrap()
        );
        assert_eq!(f.count("installation_administrator").await, 0);
    }
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn enhanced_success_navigation() {
    let f = Fixture::new("accessenhanced").await;
    let mut b = Browser::new(&f).await;
    let code = sec::encode(&[1; 32]);
    f.operator
        .issue_setup_code(&sec::digest(&code))
        .await
        .unwrap();
    let csrf = b.token("/admin/setup").await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("csrf", csrf.as_str()),
            ("code", code.as_str()),
            ("email", "Owner@example.test"),
            ("password", "a synthetic password"),
            ("password_confirmation", "a synthetic password"),
        ])
        .finish();
    let (s, _, headers) = custom(
        &b,
        "POST",
        "/admin/setup",
        &body,
        &[("hx-request", Some("true"))],
        "127.0.0.1:1",
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(headers["hx-redirect"], "/admin/login");
    assert_eq!(f.count("installation_administrator").await, 1);
}

#[test]
fn parsed_authority_contract() {
    let cfg = Config::new("https://BLOC.example.test:443", "127.0.0.1/32", [7; 32]).unwrap();
    assert_eq!(cfg.origin, "https://bloc.example.test");
    let mut h = axum::http::HeaderMap::new();
    h.insert("x-forwarded-proto", "https".parse().unwrap());
    h.insert("x-forwarded-for", "192.0.2.4".parse().unwrap());
    for host in [
        "bloc.example.test",
        "BLOC.example.test",
        "bloc.example.test:443",
    ] {
        h.insert("host", host.parse().unwrap());
        assert!(
            sec::source(&cfg, &h, "127.0.0.1:1".parse().unwrap()).is_ok(),
            "{host}"
        );
    }
    for origin in ["https://BLOC.example.test", "https://bloc.example.test:443"] {
        h.insert("origin", origin.parse().unwrap());
        assert!(sec::origin(&cfg, &h), "{origin}");
    }
    for bad in [
        "null",
        "https://evil.example",
        "https://bloc.example.test:444",
        "http://bloc.example.test",
        "https://u@bloc.example.test",
        "https://bloc.example.test/path",
        "https://bloc.example.test?x",
        "https://bloc.example.test#x",
        " https://bloc.example.test",
        "https://bloc.example.test\\x",
    ] {
        h.insert("origin", bad.parse().unwrap());
        assert!(!sec::origin(&cfg, &h), "{bad}");
    }
    for bad in [
        "evil.example",
        "bloc.example.test:444",
        "u@bloc.example.test",
        "bloc.example.test/path",
        "bloc.example.test?x",
        "bloc.example.test#x",
        " bloc.example.test",
    ] {
        h.insert("host", bad.parse().unwrap());
        assert_eq!(
            sec::source(&cfg, &h, "127.0.0.1:1".parse().unwrap()),
            Err(StatusCode::BAD_REQUEST),
            "{bad}"
        );
    }
}

async fn authority_snapshot(f: &Fixture) -> String {
    sqlx::query_scalar("SELECT jsonb_build_object('owner',(SELECT jsonb_agg(to_jsonb(a)) FROM bloc.installation_administrator a),'installation',(SELECT jsonb_agg(to_jsonb(i)) FROM bloc.installation i),'codes',(SELECT jsonb_agg(to_jsonb(c)) FROM bloc.operator_code c),'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY session_digest) FROM bloc.administrator_session s),'forms',(SELECT jsonb_agg(to_jsonb(b) ORDER BY browser_digest) FROM bloc.administrator_form_state b),'audit',(SELECT count(*) FROM bloc.security_audit_event))::text").fetch_one(&f.admin).await.unwrap()
}
#[tokio::test]
async fn passwords_preserve_exact_text() {
    let worker = PasswordWorker::new();
    for (original, different) in [
        (" a synthetic password ", "a synthetic password"),
        ("é synthetic password", "e\u{301} synthetic password"),
    ] {
        assert!(validate_password(original, original).is_ok());
        let phc = worker.hash(original.into()).await.unwrap();
        assert!(worker.verify(original.into(), phc.clone()).await.unwrap());
        assert!(!worker.verify(different.into(), phc).await.unwrap());
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn admission_full_contract() {
    let f = Fixture::new("accessfullbounds").await;
    let other = bloc::storage::Storage::connect(&f.url("runtime_user"), &f.ca)
        .await
        .unwrap();
    for (scope, limit) in [
        ("credential_source", 10),
        ("login_identifier", 10),
        ("operator_code", 10),
        ("password_change", 5),
        ("hash_work", 30),
    ] {
        for i in 0..limit {
            assert_eq!(
                if i % 2 == 0 {
                    f.runtime.reserve(&[(scope, [61; 32], 1)]).await
                } else {
                    other.reserve(&[(scope, [61; 32], 1)]).await
                }
                .unwrap(),
                0,
                "{scope} {i}"
            );
        }
        assert!(
            other.reserve(&[(scope, [61; 32], 1)]).await.unwrap() > 0,
            "{scope}"
        );
        let bounded:bool=sqlx::query_scalar("SELECT cardinality(admitted_at)=$2 AND expires_at-admitted_at[cardinality(admitted_at)]=interval '2 minutes' FROM bloc.administrator_admission_bucket WHERE scope=$1").bind(scope).bind(limit).fetch_one(&f.admin).await.unwrap();
        assert!(bounded);
        sqlx::query("UPDATE bloc.administrator_admission_bucket SET admitted_at=array_fill(clock_timestamp()-interval '59 seconds',ARRAY[$2::integer]) WHERE scope=$1").bind(scope).bind(limit).execute(&f.admin).await.unwrap();
        assert!(other.reserve(&[(scope, [61; 32], 1)]).await.unwrap() > 0);
        sqlx::query("UPDATE bloc.administrator_admission_bucket SET admitted_at=array_fill(clock_timestamp()-interval '60 seconds',ARRAY[$2::integer]) WHERE scope=$1").bind(scope).bind(limit).execute(&f.admin).await.unwrap();
        assert_eq!(other.reserve(&[(scope, [61; 32], 1)]).await.unwrap(), 0);
    }
    let f = Fixture::new("accesspwunits").await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    b.login().await;
    let csrf = b.token("/admin/password").await;
    sqlx::query("DELETE FROM bloc.administrator_admission_bucket")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        b.request(
            "POST",
            "/admin/password",
            &[
                ("csrf", &csrf),
                ("current_password", "wrong"),
                ("password", "replacement password"),
                ("password_confirmation", "replacement password")
            ]
        )
        .await
        .0,
        400
    );
    let rows:Vec<(String,i32)>=sqlx::query_as("SELECT scope,cardinality(admitted_at) FROM bloc.administrator_admission_bucket ORDER BY scope").fetch_all(&f.admin).await.unwrap();
    assert_eq!(
        rows,
        vec![
            ("credential_source".into(), 1),
            ("hash_work".into(), 2),
            ("password_change".into(), 1)
        ]
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn admission_http_retry_capacity() {
    let f = Fixture::new("accessretryhttp").await;
    let mut b = Browser::new(&f).await;
    let token = b.token("/admin/login").await;
    let cfg = Config::new("https://bloc.example.test", "127.0.0.1/32", [7; 32]).unwrap();
    let source = sec::keyed(&cfg, "source", "192.0.2.4").unwrap();
    let identifier = sec::keyed(&cfg, "identifier", "Owner@example.test").unwrap();
    let body = format!("csrf={token}&email=Owner%40example.test&password=wrong");
    for remaining in [50.25f64, 0.9f64] {
        sqlx::query("DELETE FROM bloc.administrator_admission_bucket")
            .execute(&f.admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bloc.administrator_admission_bucket VALUES ('credential_source',$1,array_fill(clock_timestamp()-(60-$3::float8/2)*interval '1 second',ARRAY[10]),clock_timestamp()+interval '2 minutes'),('login_identifier',$2,array_fill(clock_timestamp()-(60-$3::float8)*interval '1 second',ARRAY[10]),clock_timestamp()+interval '2 minutes')").bind(source.to_vec()).bind(identifier.to_vec()).bind(remaining).execute(&f.admin).await.unwrap();
        let before:f64=sqlx::query_scalar("SELECT greatest(1,ceil(extract(epoch from max(e)+interval '60 seconds'-clock_timestamp())))::float8 FROM bloc.administrator_admission_bucket CROSS JOIN LATERAL unnest(admitted_at) e").fetch_one(&f.admin).await.unwrap();
        let (status, _, h) = custom(&b, "POST", "/admin/login", &body, &[], "127.0.0.1:1").await;
        assert_eq!(status, 429);
        let retry: f64 = h["retry-after"].to_str().unwrap().parse().unwrap();
        let after:f64=sqlx::query_scalar("SELECT greatest(1,ceil(extract(epoch from max(e)+interval '60 seconds'-clock_timestamp())))::float8 FROM bloc.administrator_admission_bucket CROSS JOIN LATERAL unnest(admitted_at) e").fetch_one(&f.admin).await.unwrap();
        if remaining < 1.0 {
            assert_eq!(retry, 1.0);
        }
        assert!(
            retry >= after && retry <= before && retry >= 1.0,
            "{after} <= {retry} <= {before}"
        );
    }
    sqlx::query("DELETE FROM bloc.administrator_admission_bucket")
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO bloc.administrator_admission_bucket SELECT 'credential_source',sha256(i::text::bytea),ARRAY[clock_timestamp()-interval '90 seconds'],clock_timestamp()+interval '30 seconds' FROM generate_series(1,10000) i").execute(&f.admin).await.unwrap();
    let preserved:String=sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(b) ORDER BY subject_digest)::text FROM bloc.administrator_admission_bucket b").fetch_one(&f.admin).await.unwrap();
    let (status, _, h) = custom(&b, "POST", "/admin/login", &body, &[], "127.0.0.1:1").await;
    assert_eq!(status, 503);
    assert_eq!(h["retry-after"], "60");
    assert_eq!(sqlx::query_scalar::<_,String>("SELECT jsonb_agg(to_jsonb(b) ORDER BY subject_digest)::text FROM bloc.administrator_admission_bucket b").fetch_one(&f.admin).await.unwrap(),preserved);
    sqlx::query("UPDATE bloc.administrator_admission_bucket SET expires_at=clock_timestamp()")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        custom(&b, "POST", "/admin/login", &body, &[], "127.0.0.1:1")
            .await
            .0,
        401
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn authority_http_matrix() {
    let (f, s) = seeded("accesshttpauthority").await;
    let mut b = Browser::new(&f).await;
    b.cookies
        .insert("__Host-bloc-admin".into(), sec::encode(&[3; 32]));
    f.runtime.sign_out(&s).await.unwrap();
    for version in [1i64, 2] {
        let checksum: Vec<u8> =
            sqlx::query_scalar("SELECT checksum FROM public._sqlx_migrations WHERE version=$1")
                .bind(version)
                .fetch_one(&f.admin)
                .await
                .unwrap();
        for column in ["checksum", "success", "version"] {
            let change = match column {
                "checksum" => {
                    "UPDATE public._sqlx_migrations SET checksum=decode('00','hex') WHERE version=$1"
                }
                "success" => "UPDATE public._sqlx_migrations SET success=false WHERE version=$1",
                _ => "UPDATE public._sqlx_migrations SET version=version+100 WHERE version=$1",
            };
            sqlx::query(change)
                .bind(version)
                .execute(&f.admin)
                .await
                .unwrap();
            assert_probe(&mut b, 503, "unavailable\n").await;
            sqlx::query("UPDATE public._sqlx_migrations SET version=$1,checksum=$2,success=true WHERE version IN ($1,$1+100)").bind(version).bind(&checksum).execute(&f.admin).await.unwrap();
            assert_probe(&mut b, 200, "ready\n").await;
        }
    }
    sqlx::query("INSERT INTO public._sqlx_migrations(version,description,success,checksum,execution_time) VALUES(999,'unexpected',true,decode('00','hex'),0)").execute(&f.admin).await.unwrap();
    assert_probe(&mut b, 503, "unavailable\n").await;
    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version=999")
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER DATABASE {} SET default_transaction_read_only=on",
        f.database
    )))
    .execute(&f.admin)
    .await
    .unwrap();
    disconnect_runtime(&f).await;
    assert_probe(&mut b, 503, "unavailable\n").await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER DATABASE {} RESET default_transaction_read_only",
        f.database
    )))
    .execute(&f.admin)
    .await
    .unwrap();
    disconnect_runtime(&f).await;
    assert_probe(&mut b, 200, "ready\n").await;
    let root = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(Fixture::options("probe", "probe"))
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER DATABASE {} ALLOW_CONNECTIONS false",
        f.database
    )))
    .execute(&root)
    .await
    .unwrap();
    disconnect_runtime(&f).await;
    assert_eq!(b.request("GET", "/admin", &[]).await.0, 503);
    assert_probe(&mut b, 503, "unavailable\n").await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER DATABASE {} ALLOW_CONNECTIONS true",
        f.database
    )))
    .execute(&root)
    .await
    .unwrap();
    assert_probe(&mut b, 200, "ready\n").await;
    assert_eq!(b.request("GET", "/admin", &[]).await.0, 303);
    assert!(f.runtime.authorize(&s).await.unwrap().is_none());
}
async fn disconnect_runtime(f: &Fixture) {
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND usename='runtime_user'").bind(&f.database).execute(&f.admin).await.unwrap();
}
async fn assert_probe(b: &mut Browser, status: u16, body: &str) {
    let response = b.request("GET", "/readyz", &[]).await;
    assert_eq!(response.0, status);
    assert_eq!(response.1, body);
    let response = b.request("GET", "/healthz", &[]).await;
    assert_eq!(response.0, 200);
    assert_eq!(response.1, "ok\n");
}

#[tokio::test]
#[ignore = "real service and TLS fixture"]
async fn streaming_form_bounds() {
    let f = Fixture::new("accessstreaming").await;
    let b = Browser::new(&f).await;
    for length in ["1", "999999"] {
        assert_eq!(
            custom(
                &b,
                "POST",
                "/admin/setup",
                &"a".repeat(16385),
                &[("content-length", Some(length))],
                "127.0.0.1:1"
            )
            .await
            .0,
            413
        );
    }
    let _services = services(&f).await;
    let result=tokio::task::spawn_blocking(|| {
        use std::io::{Read,Write};
        let mut socket=std::net::TcpStream::connect(("127.0.0.1",31001)).unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        socket.write_all(b"POST /admin/setup HTTP/1.1\r\nHost: bloc.example.test:4443\r\nOrigin: https://bloc.example.test:4443\r\nX-Forwarded-For: 192.0.2.4\r\nX-Forwarded-Proto: https\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
        for _ in 0..17 {socket.write_all(b"400\r\n").unwrap();socket.write_all(&vec![b'a';1024]).unwrap();socket.write_all(b"\r\n").unwrap();}
        socket.write_all(b"0\r\n\r\n").unwrap();
        let mut response=String::new();socket.read_to_string(&mut response).unwrap();response
    }).await.unwrap();
    assert!(result.starts_with("HTTP/1.1 413"), "{result}");
    assert_eq!(f.count("installation_administrator").await, 0);
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn throttled_post_forms_remain_usable() {
    for hx in [false, true] {
        for (index, path) in [
            "/admin/setup",
            "/admin/login",
            "/admin/recovery",
            "/admin/password",
        ]
        .iter()
        .enumerate()
        {
            let f = Fixture::new(&format!("throttlepost{index}{}", u8::from(hx))).await;
            let mut b = Browser::new(&f).await;
            let code = sec::encode(&[2; 32]);
            if *path == "/admin/setup" {
                f.operator
                    .issue_setup_code(&sec::digest(&code))
                    .await
                    .unwrap();
            } else {
                b.setup(&f).await;
                if *path == "/admin/recovery" {
                    f.operator
                        .issue_recovery_code(&sec::digest(&code))
                        .await
                        .unwrap();
                } else if *path == "/admin/password" {
                    b.login().await;
                }
            }
            let token = b.token(path).await;
            let password = if *path == "/admin/login" {
                "a synthetic password"
            } else {
                "replacement synthetic password"
            };
            let fields = [
                ("csrf", token.as_str()),
                ("email", "Owner@example.test"),
                ("code", code.as_str()),
                ("password", password),
                ("password_confirmation", password),
                ("current_password", "a synthetic password"),
            ];
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields)
                .finish();
            let cfg = Config::new("https://bloc.example.test", "127.0.0.1/32", [7; 32]).unwrap();
            let source = sec::keyed(&cfg, "source", "192.0.2.4").unwrap();
            sqlx::query("INSERT INTO bloc.administrator_admission_bucket VALUES ('credential_source',$1,array_fill(clock_timestamp(),ARRAY[10]),clock_timestamp()+interval '2 minutes') ON CONFLICT (scope,subject_digest) DO UPDATE SET admitted_at=EXCLUDED.admitted_at,expires_at=EXCLUDED.expires_at").bind(source.to_vec()).execute(&f.admin).await.unwrap();
            let changes = if hx {
                vec![("hx-request", Some("true"))]
            } else {
                vec![]
            };
            let (status, html, headers) =
                custom(&b, "POST", path, &body, &changes, "127.0.0.1:1").await;
            assert_eq!(status, 429, "{path} hx={hx}: {html}");
            assert!(
                headers["retry-after"]
                    .to_str()
                    .unwrap()
                    .parse::<u32>()
                    .unwrap()
                    > 0
            );
            let returned_token = html
                .split("name=\"csrf\" value=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            assert!(!returned_token.is_empty(), "{path} hx={hx}");
            assert_eq!(returned_token, token);
            assert!(html.contains("Too many attempts."));
            assert_eq!(html.contains("<!doctype html>"), !hx);
            assert!(html.contains("id=\"content\""));
            if matches!(*path, "/admin/setup" | "/admin/login") {
                assert!(html.contains("value=\"Owner@example.test\""));
            }
            for secret in [code.as_str(), password, "a synthetic password"] {
                assert!(!html.contains(secret), "refilled secret for {path}");
            }
            sqlx::query("UPDATE bloc.administrator_admission_bucket SET admitted_at=array_fill(clock_timestamp()-interval '61 seconds',ARRAY[cardinality(admitted_at)])").execute(&f.admin).await.unwrap();
            let retry_body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields.map(|(name, value)| {
                    (
                        name,
                        if name == "csrf" {
                            returned_token
                        } else {
                            value
                        },
                    )
                }))
                .finish();
            let (status, html, headers) =
                custom(&b, "POST", path, &retry_body, &changes, "127.0.0.1:1").await;
            assert_eq!(status, if hx { 200 } else { 303 }, "{path} hx={hx}: {html}");
            let destination = if *path == "/admin/login" {
                "/admin"
            } else {
                "/admin/login"
            };
            assert_eq!(
                headers[if hx { "hx-redirect" } else { "location" }],
                destination
            );
            if *path != "/admin/login" {
                let csrf = b.token("/admin/login").await;
                let (status, html, _) = b
                    .request(
                        "POST",
                        "/admin/login",
                        &[
                            ("csrf", &csrf),
                            ("email", "Owner@example.test"),
                            ("password", password),
                        ],
                    )
                    .await;
                assert_eq!(status, 303, "new credential must work: {html}");
            }
        }
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn throttled_form_issuance_requires_reload() {
    for hx in [false, true] {
        for (index, path) in [
            "/admin/setup",
            "/admin/login",
            "/admin/recovery",
            "/admin/password",
            "/admin",
        ]
        .iter()
        .enumerate()
        {
            let f = Fixture::new(&format!("throttleissue{index}{}", u8::from(hx))).await;
            let mut b = Browser::new(&f).await;
            if matches!(*path, "/admin/password" | "/admin") {
                b.setup(&f).await;
                b.login().await;
            }
            b.cookies.remove("__Host-bloc-csrf");
            let cfg = Config::new("https://bloc.example.test", "127.0.0.1/32", [7; 32]).unwrap();
            let source = sec::keyed(&cfg, "source", "192.0.2.4").unwrap();
            sqlx::query("INSERT INTO bloc.administrator_admission_bucket VALUES ('form_issue_source',$1,array_fill(clock_timestamp(),ARRAY[30]),clock_timestamp()+interval '2 minutes') ON CONFLICT (scope,subject_digest) DO UPDATE SET admitted_at=EXCLUDED.admitted_at,expires_at=EXCLUDED.expires_at").bind(source.to_vec()).execute(&f.admin).await.unwrap();
            let changes = if hx {
                vec![("hx-request", Some("true"))]
            } else {
                vec![]
            };
            let (status, html, headers) =
                custom(&b, "GET", path, "", &changes, "127.0.0.1:1").await;
            assert_eq!(status, 429, "{path} hx={hx}: {html}");
            assert!(
                headers["retry-after"]
                    .to_str()
                    .unwrap()
                    .parse::<u32>()
                    .unwrap()
                    > 0
            );
            assert!(!html.contains("<form"), "{path}: {html}");
            assert!(!html.contains("name=\"csrf\""));
            assert!(html.contains("role=\"alert\""));
            assert!(html.contains("Too many attempts."));
            assert!(
                html.contains(&format!("href=\"{path}\">Reload form</a>")),
                "{path}: {html}"
            );
            sqlx::query("UPDATE bloc.administrator_admission_bucket SET admitted_at=array_fill(clock_timestamp()-interval '61 seconds',ARRAY[cardinality(admitted_at)])").execute(&f.admin).await.unwrap();
            let token = b.token(path).await;
            assert!(!token.is_empty());
            let post_path = if *path == "/admin" {
                "/admin/logout"
            } else {
                path
            };
            let (status, _, _) = b.request("POST", post_path, &[("csrf", &token)]).await;
            assert_eq!(status, if *path == "/admin" { 303 } else { 422 });
        }
    }
}
