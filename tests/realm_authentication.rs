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
            app: router(
                Application::new(
                    bloc::storage::Storage::connect(&f.url("runtime_user"), &f.ca)
                        .await
                        .unwrap(),
                    cfg,
                )
                .await
                .unwrap(),
            ),
            cookies: BTreeMap::new(),
        }
    }
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        fields: &[(&str, &str)],
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        self.request_headers(method, path, fields, &[]).await
    }
    async fn request_headers(
        &mut self,
        method: &str,
        path: &str,
        fields: &[(&str, &str)],
        headers: &[(&str, &str)],
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
        for (name, value) in headers {
            request.headers_mut().insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
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

const REALM: &str = "11111111-1111-4111-8111-111111111111";
const OTHER: &str = "33333333-3333-4333-8333-333333333333";
const USER: &str = "22222222-2222-4222-8222-222222222222";
async fn signed(name: &str) -> (Fixture, Browser) {
    let f = Fixture::new(name).await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    b.login().await;
    (f, b)
}
async fn create_realm(b: &mut Browser, id: &str, name: &str) {
    let csrf = b.token("/admin/realms/new").await;
    let (s, h, r) = b
        .request(
            "POST",
            "/admin/realms",
            &[("csrf", &csrf), ("creation_id", id), ("name", name)],
        )
        .await;
    assert_eq!(s, 303, "{h}");
    assert_eq!(r["location"], format!("/admin/realms/{id}"));
}
#[test]
fn administrator_policy_unchanged() {
    assert!(bloc::credentials::validate_password("abcdefghijklmno", "abcdefghijklmno").is_ok());
    assert!(bloc::credentials::validate_password("abcdefghijklmn", "abcdefghijklmn").is_err());
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c01() {
    let (f, mut b) = signed("realmauthc01").await;
    create_realm(&mut b, REALM, "Acme").await;
    let (status, html, _) = b
        .request("GET", &format!("/admin/realms/{REALM}/authentication"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("Authentication"));
    let row: (bool, i16, bool, bool, bool, bool, i32, i32, i32, i32, i16) = sqlx::query_as("SELECT registration_enabled,password_min_length,require_uppercase,require_lowercase,require_number,require_special,activation_ttl_seconds,reset_ttl_seconds,session_idle_seconds,session_absolute_seconds,session_limit FROM bloc.realm_authentication_settings WHERE realm_id=$1::text::uuid").bind(REALM).fetch_one(&f.admin).await.unwrap();
    assert_eq!(
        row,
        (
            false, 16, false, false, false, false, 86400, 1800, 1800, 43200, 10
        )
    );
    sqlx::query("UPDATE bloc.realm SET status='suspended' WHERE id=$1::text::uuid")
        .bind(REALM)
        .execute(&f.admin)
        .await
        .unwrap();
    let (status, html, _) = b
        .request("GET", &format!("/admin/realms/{REALM}/authentication"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("Authentication"));
}

include!("support/realm_authentication_contracts.rs");

include!("support/realm_authentication_security.rs");

include!("support/realm_authentication_runtime.rs");
