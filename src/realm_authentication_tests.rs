//! Private worker observations supplement externally visible HTTP contracts.
use super::*;
use crate::test_common as common;
use axum::body::Body;
use tower::ServiceExt;
const REALM: &str = "11111111-1111-4111-8111-111111111111";
async fn fixture(name: &str) -> (common::Fixture, Application) {
    let f = common::Fixture::new(name).await;
    sqlx::query("INSERT INTO bloc.realm(id,name,created_at,updated_at) VALUES($1::text::uuid,'Acme',clock_timestamp(),clock_timestamp())").bind(REALM).execute(&f.admin).await.unwrap();
    let app = Application::new(
        f.runtime.clone(),
        crate::config::Config::new("https://bloc.example.test", "127.0.0.1/32", [7; 32]).unwrap(),
    )
    .await
    .unwrap();
    let hash = app
        .worker
        .hash("a synthetic realm password".into())
        .await
        .unwrap();
    for (email, status, credential) in [
        ("active@example.test", "active", true),
        ("pending@example.test", "active", false),
        ("suspended@example.test", "suspended", true),
    ] {
        let id:String=sqlx::query_scalar("INSERT INTO bloc.realm_user(id,realm_id,email,status,created_at,updated_at) VALUES(gen_random_uuid(),$1::text::uuid,$2,$3,clock_timestamp(),clock_timestamp()) RETURNING id::text").bind(REALM).bind(email).bind(status).fetch_one(&f.admin).await.unwrap();
        if credential {
            sqlx::query("INSERT INTO bloc.realm_user_credential VALUES($1::text::uuid,$2::text::uuid,$3,1,clock_timestamp())").bind(REALM).bind(id).bind(&hash).execute(&f.admin).await.unwrap();
        }
    }
    let b = sec::digest(&sec::encode(&[8; 32]));
    let t = [9; 32];
    app.storage
        .realm_form(Authority {
            realm: REALM,
            purpose: "anonymous",
            browser: &b,
            token: Some(&t),
            session: None,
            link: None,
        })
        .await
        .unwrap();
    (f, app)
}
async fn request(
    app: &Application,
    email: &str,
    body: Option<String>,
    headers: &[(&str, Option<&str>)],
) -> Response {
    let csrf = sec::encode(&[9; 32]);
    let content = body.unwrap_or_else(|| {
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("csrf", csrf.as_str()),
                ("email", email),
                ("password", "a wrong synthetic password"),
            ])
            .finish()
    });
    let mut req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/realms/{REALM}/login"))
        .header("host", "bloc.example.test")
        .header("origin", "https://bloc.example.test")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "192.0.2.4")
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "cookie",
            format!(
                "__Host-bloc-realm-{REALM}-anonymous={}",
                sec::encode(&[8; 32])
            ),
        )
        .body(Body::from(content))
        .unwrap();
    for (k, v) in headers {
        req.headers_mut().remove(*k);
        if let Some(v) = v {
            req.headers_mut().insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
    }
    req.extensions_mut()
        .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    crate::app(app.clone()).oneshot(req).await.unwrap()
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_worker_contract() {
    let (f, app) = fixture("realm_worker").await;
    for email in [
        "active@example.test",
        "unknown@example.test",
        "pending@example.test",
        "suspended@example.test",
    ] {
        let before = app.worker.observed_work();
        let r = request(&app, email, None, &[]).await;
        assert_eq!(r.status(), 422);
        let after = app.worker.observed_work();
        assert_eq!(
            std::array::from_fn::<_, 4, _>(|i| after[i] - before[i]),
            [0, 0, 1, 1]
        );
    }
    let before = app.worker.observed_work();
    let permit = app.worker.occupy();
    let start = std::time::Instant::now();
    let r = request(&app, "active@example.test", None, &[]).await;
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers()["retry-after"], "1");
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
    assert_eq!(app.worker.observed_work(), before);
    drop(permit);
    let work:i64=sqlx::query_scalar("SELECT cardinality(admitted_at)::bigint FROM bloc.realm_admission_bucket WHERE scope='public_work'").fetch_one(&f.admin).await.unwrap();
    assert_eq!(work, 5);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_request_order_contract() {
    let (_, app) = fixture("realm_request_order").await;
    let before = app.worker.observed_work();
    for (headers, status) in [
        (vec![("host", Some("foreign.example"))], 400),
        (vec![("origin", Some("https://foreign.example"))], 403),
        (vec![("content-type", Some("application/json"))], 415),
        (vec![("cookie", None)], 403),
    ] {
        assert_eq!(
            request(&app, "active@example.test", None, &headers)
                .await
                .status(),
            status
        );
    }
    for (body, status) in [
        ("csrf=%GG".into(), 400),
        ("csrf=x&csrf=y".into(), 400),
        ("csrf=x".into(), 403),
        (format!("csrf={}", "x".repeat(16385)), 413),
    ] {
        assert_eq!(request(&app, "", Some(body), &[]).await.status(), status);
    }
    assert_eq!(app.worker.observed_work(), before);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_policy_hash_race_contract() {
    let (f, app) = fixture("realm_policy_hash_race").await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET registration_enabled=true")
        .execute(&f.admin)
        .await
        .unwrap();
    let csrf = sec::encode(&[9; 32]);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("csrf", csrf.as_str()),
            ("email", "new@example.test"),
            ("display_name", "New user"),
            ("password", "a synthetic new password"),
            ("password_confirmation", "a synthetic new password"),
        ])
        .finish();
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/realms/{REALM}/register"))
        .header("host", "bloc.example.test")
        .header("origin", "https://bloc.example.test")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "192.0.2.4")
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "cookie",
            format!(
                "__Host-bloc-realm-{REALM}-anonymous={}",
                sec::encode(&[8; 32])
            ),
        )
        .body(Body::from(body))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    let before = app.worker.observed_work();
    let router = crate::app(app.clone());
    let task = tokio::spawn(async move { router.oneshot(request).await.unwrap() });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while app.worker.observed_work()[0] == before[0] {
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    sqlx::query("UPDATE bloc.realm_authentication_settings SET version=version+1,password_min_length=100 WHERE realm_id=$1::text::uuid").bind(REALM).execute(&f.admin).await.unwrap();
    let response = task.await.unwrap();
    assert_eq!(response.status(), 409);
    let body = to_bytes(response.into_body(), 100000).await.unwrap();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("100–128"));
    assert!(!html.contains("value=\"a synthetic new password\""));
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM bloc.realm_user WHERE email='new@example.test'")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(n, 0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_suspension_verify_race_contract() {
    for mutation in ["suspension", "email", "reset", "restore"] {
        let (f, app) = fixture(&format!("realm_verify_race_{mutation}")).await;
        if mutation == "restore" {
            sqlx::query("INSERT INTO bloc.installation_administrator(installation_id,email,password_hash,created_at,password_changed_at) VALUES(1,'operator@example.test',$1,statement_timestamp(),statement_timestamp())").bind(common::HASH).execute(&f.admin).await.unwrap();
        }
        let csrf = sec::encode(&[9; 32]);
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("csrf", csrf.as_str()),
                ("email", "active@example.test"),
                ("password", "a synthetic realm password"),
            ])
            .finish();
        let gate = app.worker.pause_verification();
        let cloned = app.clone();
        let task = tokio::spawn(async move { request(&cloned, "", Some(body), &[]).await });
        tokio::time::timeout(std::time::Duration::from_secs(10), gate.wait())
            .await
            .expect("verification did not reach the commit boundary");
        match mutation {
            "suspension" => {
                sqlx::query("UPDATE bloc.realm_user SET status='suspended',version=version+1 WHERE email='active@example.test'").execute(&f.admin).await.unwrap();
            }
            "email" => {
                sqlx::query("UPDATE bloc.realm_user SET email='changed@example.test',version=version+1 WHERE email='active@example.test'").execute(&f.admin).await.unwrap();
            }
            "reset" => {
                sqlx::query("UPDATE bloc.realm_user_credential SET credential_version=credential_version+1 WHERE user_id IN(SELECT id FROM bloc.realm_user WHERE email='active@example.test')").execute(&f.admin).await.unwrap();
            }
            "restore" => {
                f.operator.invalidate_access().await.unwrap();
            }
            _ => unreachable!(),
        }
        gate.wait().await;
        assert_eq!(
            task.await.unwrap().status(),
            if mutation == "restore" { 503 } else { 422 },
            "{mutation}"
        );
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.realm_user_session")
            .fetch_one(&f.admin)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_link_lifecycle_race_contract() {
    for mutation in ["replacement", "suspension", "email"] {
        let (f, app) = fixture(&format!("realm_link_race_{mutation}")).await;
        sqlx::query("INSERT INTO bloc.installation_administrator(installation_id,email,password_hash,created_at,password_changed_at) VALUES(1,'operator@example.test',$1,statement_timestamp(),statement_timestamp())").bind(common::HASH).execute(&f.admin).await.unwrap();
        let link = sec::digest(&sec::encode(&[10; 32]));
        sqlx::query("INSERT INTO bloc.realm_user_access_link(realm_id,user_id,purpose,token_digest,user_version,issued_by,issued_at,expires_at) SELECT u.realm_id,u.id,'activation',$1,1,a.id,statement_timestamp(),statement_timestamp()+interval '1 day' FROM bloc.realm_user u CROSS JOIN bloc.installation_administrator a WHERE u.email='pending@example.test'").bind(&link[..]).execute(&f.admin).await.unwrap();
        let browser = sec::digest(&sec::encode(&[11; 32]));
        app.storage
            .realm_form(Authority {
                realm: REALM,
                purpose: "activation",
                browser: &browser,
                token: Some(&[12; 32]),
                session: None,
                link: Some(&link),
            })
            .await
            .unwrap();
        let csrf = sec::encode(&[12; 32]);
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("csrf", csrf.as_str()),
                ("password", "a synthetic link password"),
                ("password_confirmation", "a synthetic link password"),
            ])
            .finish();
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/realms/{REALM}/activate"))
            .header("host", "bloc.example.test")
            .header("origin", "https://bloc.example.test")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "192.0.2.4")
            .header("content-type", "application/x-www-form-urlencoded")
            .header(
                "cookie",
                format!(
                    "__Host-bloc-realm-{REALM}-activation={}",
                    sec::encode(&[11; 32])
                ),
            )
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
        let before = app.worker.observed_work();
        let router = crate::app(app.clone());
        let task = tokio::spawn(async move { router.oneshot(req).await.unwrap() });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while app.worker.observed_work()[0] == before[0] {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let mut transaction = f.admin.begin().await.unwrap();
        sqlx::query("SELECT bloc.realm_lock()")
            .execute(&mut *transaction)
            .await
            .unwrap();
        match mutation {
            "replacement" => {
                sqlx::query("DELETE FROM bloc.realm_form_state WHERE link_digest=$1")
                    .bind(&link[..])
                    .execute(&mut *transaction)
                    .await
                    .unwrap();
                sqlx::query("UPDATE bloc.realm_user_access_link SET token_digest=$1")
                    .bind(&sec::digest(&sec::encode(&[13; 32]))[..])
                    .execute(&mut *transaction)
                    .await
                    .unwrap();
            }
            "suspension" => {
                sqlx::query("UPDATE bloc.realm_user SET status='suspended' WHERE email='pending@example.test'").execute(&mut *transaction).await.unwrap();
            }
            "email" => {
                sqlx::query("UPDATE bloc.realm_user SET email='changed@example.test' WHERE email='pending@example.test'").execute(&mut *transaction).await.unwrap();
            }
            _ => unreachable!(),
        }
        transaction.commit().await.unwrap();
        let response = task.await.unwrap();
        assert_eq!(response.status(), 403, "{mutation}");
        let body = to_bytes(response.into_body(), 100000).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("link-invalid"), "{mutation}: {html}");
        assert!(!html.contains("pending@example.test"));
        assert!(!html.contains("changed@example.test"));
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.realm_user_credential c JOIN bloc.realm_user u ON u.realm_id=c.realm_id AND u.id=c.user_id WHERE u.email IN('pending@example.test','changed@example.test')").fetch_one(&f.admin).await.unwrap();
        assert_eq!(count, 0, "{mutation}");
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_activation'",
        )
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert_eq!(events, 0, "{mutation}");
    }
}

async fn account_request(
    app: &Application,
    path: &str,
    cookies: &str,
    fields: Option<&[(&str, &str)]>,
) -> Response {
    let body = fields
        .map(|values| {
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(values.iter().copied())
                .finish()
        })
        .unwrap_or_default();
    let mut request = axum::http::Request::builder()
        .method(if fields.is_some() { "POST" } else { "GET" })
        .uri(path)
        .header("host", "bloc.example.test")
        .header("origin", "https://bloc.example.test")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "192.0.2.4")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", cookies)
        .body(Body::from(body))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    crate::app(app.clone()).oneshot(request).await.unwrap()
}
async fn account_authority(app: &Application) -> (String, String) {
    let csrf = sec::encode(&[9; 32]);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("csrf", csrf.as_str()),
            ("email", "active@example.test"),
            ("password", "a synthetic realm password"),
        ])
        .finish();
    let response = request(app, "", Some(body), &[]).await;
    assert_eq!(response.status(), 303);
    let cookies = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|h| h.to_str().unwrap().split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let response = account_request(
        app,
        &format!("/realms/{REALM}/account/password"),
        &cookies,
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    let bytes = to_bytes(response.into_body(), 100000).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    let token = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();
    (cookies, token)
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_password_admission_contract() {
    let (f, app) = fixture("realm_password_admission").await;
    let (cookies, csrf) = account_authority(&app).await;
    sqlx::query("DELETE FROM bloc.administrator_admission_bucket")
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO bloc.administrator_admission_bucket VALUES('hash_work',decode(repeat('00',32),'hex'),array_fill(clock_timestamp(),ARRAY[29]),clock_timestamp()+interval '2 minutes')").execute(&f.admin).await.unwrap();
    let before = app.worker.observed_work();
    let response = account_request(
        &app,
        &format!("/realms/{REALM}/account/password"),
        &cookies,
        Some(&[
            ("csrf", &csrf),
            ("current_password", "a synthetic realm password"),
            ("password", "a compliant replacement password"),
            ("password_confirmation", "a compliant replacement password"),
        ]),
    )
    .await;
    assert_eq!(response.status(), 429);
    assert_eq!(app.worker.observed_work(), before);
    let version: i64 =
        sqlx::query_scalar("SELECT max(credential_version) FROM bloc.realm_user_credential")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(version, 1);
    let work:i32=sqlx::query_scalar("SELECT cardinality(admitted_at) FROM bloc.administrator_admission_bucket WHERE scope='hash_work'").fetch_one(&f.admin).await.unwrap();
    assert_eq!(work, 29);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_password_authority_race_contract() {
    for mutation in ["reset", "suspension"] {
        let (f, app) = fixture(&format!("realm_password_race_{mutation}")).await;
        let (cookies, csrf) = account_authority(&app).await;
        let before = app.worker.observed_work();
        let cloned = app.clone();
        let task = tokio::spawn(async move {
            account_request(
                &cloned,
                &format!("/realms/{REALM}/account/password"),
                &cookies,
                Some(&[
                    ("csrf", &csrf),
                    ("current_password", "a synthetic realm password"),
                    ("password", "a compliant replacement password"),
                    ("password_confirmation", "a compliant replacement password"),
                ]),
            )
            .await
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while app.worker.observed_work()[2] == before[2] {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let mut transaction = f.admin.begin().await.unwrap();
        sqlx::query("SELECT bloc.realm_lock()")
            .execute(&mut *transaction)
            .await
            .unwrap();
        if mutation == "reset" {
            sqlx::query("UPDATE bloc.realm_user_credential SET credential_version=credential_version+1 WHERE user_id IN(SELECT id FROM bloc.realm_user WHERE email='active@example.test')").execute(&mut *transaction).await.unwrap();
            sqlx::query("SELECT bloc.realm_invalidate(realm_id,id) FROM bloc.realm_user WHERE email='active@example.test'").execute(&mut *transaction).await.unwrap();
        } else {
            sqlx::query("UPDATE bloc.realm_user SET status='suspended',version=version+1 WHERE email='active@example.test'").execute(&mut *transaction).await.unwrap();
        }
        transaction.commit().await.unwrap();
        let response = task.await.unwrap();
        assert_eq!(response.status(), 303);
        assert_eq!(
            response.headers()["location"],
            format!("/realms/{REALM}/login?expired=1")
        );
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_password_change'",
        )
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert_eq!(events, 0);
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL",
        )
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert_eq!(active, 0);
    }
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_registration_duplicate_hash_contract() {
    let (f, app) = fixture("realm_registration_duplicate_hash").await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET registration_enabled=true")
        .execute(&f.admin)
        .await
        .unwrap();
    let before: String = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(c) ORDER BY user_id)::text FROM bloc.realm_user_credential c",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    let observed = app.worker.observed_work();
    let csrf = sec::encode(&[9; 32]);
    let response = account_request(
        &app,
        &format!("/realms/{REALM}/register"),
        &format!(
            "__Host-bloc-realm-{REALM}-anonymous={}",
            sec::encode(&[8; 32])
        ),
        Some(&[
            ("csrf", &csrf),
            ("email", "active@example.test"),
            ("display_name", "Collision"),
            ("password", "a compliant replacement password"),
            ("password_confirmation", "a compliant replacement password"),
        ]),
    )
    .await;
    assert_eq!(response.status(), 422);
    let after = app.worker.observed_work();
    assert_eq!(
        std::array::from_fn::<_, 4, _>(|i| after[i] - observed[i]),
        [1, 1, 0, 0]
    );
    let unchanged: String = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(c) ORDER BY user_id)::text FROM bloc.realm_user_credential c",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(before, unchanged);
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.realm_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(users, 3);
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_registration'",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(events, 0);
}

#[test]
fn realm_native_origin_headers() {
    let values = [
        ("origin", "null"),
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
    ];
    let mut headers = HeaderMap::new();
    for (key, value) in values {
        headers.insert(key, HeaderValue::from_static(value));
    }
    assert!(native_origin(&headers));
    for (key, value) in values {
        let mut missing = headers.clone();
        missing.remove(key);
        assert!(!native_origin(&missing), "missing {key}");
        let mut repeated = headers.clone();
        repeated.append(key, HeaderValue::from_static(value));
        assert!(!native_origin(&repeated), "duplicate {key}");
        for invalid in [
            "",
            "null",
            "same-site",
            "cross-site",
            "navigate, navigate",
            "same-origin ",
            "cors",
            "iframe",
            "https://foreign.example",
        ] {
            if invalid == value {
                continue;
            }
            let mut wrong = headers.clone();
            wrong.insert(key, HeaderValue::from_str(invalid).unwrap());
            assert!(!native_origin(&wrong), "{key}: {invalid}");
        }
    }
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_native_origin_contract() {
    let (_, app) = fixture("realm_native_origin").await;
    let native = [
        ("origin", Some("null")),
        ("sec-fetch-site", Some("same-origin")),
        ("sec-fetch-mode", Some("navigate")),
        ("sec-fetch-dest", Some("document")),
    ];
    assert_eq!(
        request(&app, "active@example.test", None, &native)
            .await
            .status(),
        422
    );
    let before = app.worker.observed_work();
    for (name, value) in [
        ("sec-fetch-site", Some("same-site")),
        ("sec-fetch-site", Some("cross-site")),
        ("sec-fetch-site", None),
        ("sec-fetch-mode", Some("cors")),
        ("sec-fetch-mode", None),
        ("sec-fetch-dest", Some("iframe")),
        ("sec-fetch-dest", None),
        ("origin", None),
        ("origin", Some("https://foreign.example")),
        ("cookie", None),
    ] {
        let mut changed = native.to_vec();
        changed.retain(|(key, _)| *key != name);
        changed.push((name, value));
        assert_eq!(
            request(&app, "active@example.test", None, &changed)
                .await
                .status(),
            403,
            "{name}: {value:?}"
        );
    }
    let mut wrong_host = native.to_vec();
    wrong_host.push(("host", Some("foreign.example")));
    assert_eq!(
        request(&app, "active@example.test", None, &wrong_host)
            .await
            .status(),
        400
    );
    assert_eq!(app.worker.observed_work(), before);
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_registration_state_race_contract() {
    for mutation in ["disabled", "suspended", "missing"] {
        let (f, app) = fixture(&format!("registration_state_race_{mutation}")).await;
        sqlx::query("UPDATE bloc.realm_authentication_settings SET registration_enabled=true")
            .execute(&f.admin)
            .await
            .unwrap();
        let csrf = sec::encode(&[9; 32]);
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("csrf", csrf.as_str()),
                ("email", "new@example.test"),
                ("display_name", "New user"),
                ("password", "a synthetic new password"),
                ("password_confirmation", "a synthetic new password"),
            ])
            .finish();
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/realms/{REALM}/register"))
            .header("host", "bloc.example.test")
            .header("origin", "https://bloc.example.test")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "192.0.2.4")
            .header("content-type", "application/x-www-form-urlencoded")
            .header(
                "cookie",
                format!(
                    "__Host-bloc-realm-{REALM}-anonymous={}",
                    sec::encode(&[8; 32])
                ),
            )
            .body(Body::from(body))
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
        let before = app.worker.observed_work();
        let router = crate::app(app.clone());
        let task = tokio::spawn(async move { router.oneshot(request).await.unwrap() });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while app.worker.observed_work()[0] == before[0] {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        match mutation {
            "disabled" => {
                sqlx::query("UPDATE bloc.realm_authentication_settings SET registration_enabled=false,version=version+1").execute(&f.admin).await.unwrap();
            }
            "suspended" => {
                sqlx::query("UPDATE bloc.realm SET status='suspended'")
                    .execute(&f.admin)
                    .await
                    .unwrap();
            }
            _ => {
                sqlx::raw_sql("DELETE FROM bloc.realm_form_state;DELETE FROM bloc.realm_user_credential;DELETE FROM bloc.realm_user;DELETE FROM bloc.realm_authentication_settings;DELETE FROM bloc.realm;").execute(&f.admin).await.unwrap();
            }
        }
        let response = task.await.unwrap();
        assert_eq!(
            response.status(),
            if mutation == "disabled" { 403 } else { 404 }
        );
        let body = to_bytes(response.into_body(), 100000).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(!html.contains("value=\"a synthetic new password\""));
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM bloc.realm_user WHERE email='new@example.test'",
        )
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert_eq!(n, 0);
    }
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_profile_authority_race_contract() {
    for mutation in ["reset", "suspension"] {
        let (f, app) = fixture(&format!("profile_authority_race_{mutation}")).await;
        let (cookies, csrf) = account_authority(&app).await;
        let mut transaction = f.admin.begin().await.unwrap();
        sqlx::query("SELECT bloc.realm_lock()")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let other = app.clone();
        let request = tokio::spawn(async move {
            account_request(
                &other,
                &format!("/realms/{REALM}/account/profile"),
                &cookies,
                Some(&[
                    ("csrf", &csrf),
                    ("version", "1"),
                    ("display_name", "Stale profile"),
                ]),
            )
            .await
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%realm_%')").fetch_one(&f.admin).await.unwrap();
            if waiting {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        if mutation == "reset" {
            sqlx::query("UPDATE bloc.realm_user_credential SET credential_version=credential_version+1 WHERE user_id IN(SELECT id FROM bloc.realm_user WHERE email='active@example.test')").execute(&mut *transaction).await.unwrap();
            sqlx::query("SELECT bloc.realm_invalidate(realm_id,id) FROM bloc.realm_user WHERE email='active@example.test'").execute(&mut *transaction).await.unwrap();
        } else {
            sqlx::query("UPDATE bloc.realm_user SET status='suspended',version=version+1 WHERE email='active@example.test'").execute(&mut *transaction).await.unwrap();
        }
        transaction.commit().await.unwrap();
        let response = request.await.unwrap();
        assert_eq!(response.status(), 303);
        assert_eq!(
            response.headers()["location"],
            format!("/realms/{REALM}/login?expired=1")
        );
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM bloc.realm_user WHERE display_name='Stale profile'",
        )
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert_eq!(n, 0);
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_profile_update'",
        )
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert_eq!(n, 0);
    }
}
