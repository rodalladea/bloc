//! Private observations of the real password worker at the production HTTP boundary.
use super::*;
#[path = "../tests/common/mod.rs"]
mod common;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use common::Fixture;
use tower::ServiceExt;

#[test]
fn interface_theme_picker_is_only_available_inside_the_application() {
    for path in [
        "/admin",
        "/admin/login",
        "/admin/setup",
        "/admin/recovery",
        "/admin/password",
    ] {
        let page = Page::new(path);
        let html = Full { page: &page }.render().unwrap();
        assert!(html.contains("href=\"/assets/ui.css\""));
        assert!(html.contains("src=\"/assets/ui.js\""));
        if path != "/admin" && path != "/admin/password" {
            assert!(!html.contains("aria-label=\"Appearance\""));
            assert!(html.contains("data-ui-theme=\"system\" data-ui-theme-fixed"));
            continue;
        }
        assert!(html.contains("aria-label=\"Appearance\""));
        for theme in ["system", "light", "dark"] {
            assert!(
                html.contains(&format!("value=\"{theme}\""))
                    || html.contains(&format!("data-ui-theme-choice=\"{theme}\""))
            );
        }
        let fragment = Fragment { page: &page }.render().unwrap();
        assert!(!fragment.contains("data-ui-theme-control"));
    }
}

#[test]
fn dashboard_navigation_and_actions() {
    let mut page = Page::new("/admin");
    page.email = "Owner@example.test".into();
    let html = Full { page: &page }.render().unwrap();
    assert!(html.contains("aria-label=\"Administration\""));
    assert!(html.contains("href=\"/admin\" aria-current=\"page\""));
    assert!(html.contains("href=\"/admin/realms/new\""));
    let menu = html.split("<nav class=\"sidebar-nav\"").next().unwrap();
    assert!(!menu.contains("href=\"/admin/realms\""));
    let nav = html.split("<nav class=\"sidebar-nav\"").nth(1).unwrap();
    let settings = nav.find(">Settings</p>").unwrap();
    let realms = nav.find(">Manage realms</a>").unwrap();
    assert!(settings < realms);
    assert!(html.contains("href=\"/admin/realms\""));
    assert!(html.contains("href=\"/admin/password\""));
    assert!(html.contains("Owner@example.test"));
    assert!(html.contains("action=\"/admin/logout\""));
    assert!(html.contains("Directory users cannot sign in"));
    assert!(!html.contains("workspace-header"));
    assert!(html.contains("aria-label=\"Workspace menu\""));
    assert!(html.contains("aria-label=\"Help\""));
    assert!(html.contains("data-ui-theme-choice=\"dark\""));
    let fragment = Fragment { page: &page }.render().unwrap();
    assert!(!fragment.contains("class=\"sidebar\""));
    assert_eq!(fragment.matches("id=\"content\"").count(), 1);
}

#[test]
fn dashboard_navigation_stays_out_of_public_access_forms() {
    for path in ["/admin/login", "/admin/setup", "/admin/recovery"] {
        let page = Page::new(path);
        let html = Full { page: &page }.render().unwrap();
        assert!(!html.contains("class=\"sidebar\""));
        assert!(html.contains("href=\"#content\""));
    }
    let page = Page::new("/admin/password");
    let html = Full { page: &page }.render().unwrap();
    assert!(html.contains("href=\"/admin/password\" aria-current=\"page\""));
}

struct Http {
    app: Application,
    anonymous: String,
    signed: String,
    token: String,
}
impl Http {
    async fn new(f: &Fixture, owned: bool) -> Self {
        let app = Application::new(
            f.runtime.clone(),
            Config::new("https://bloc.example.test", "127.0.0.1/32", [7; 32]).unwrap(),
        )
        .await
        .unwrap();
        if owned {
            f.operator.issue_setup_code(&[1; 32]).await.unwrap();
            let phc = app
                .worker
                .hash("a synthetic password".into())
                .await
                .unwrap();
            assert_eq!(
                f.runtime
                    .claim_owner(&[1; 32], common::EMAIL, &phc)
                    .await
                    .unwrap(),
                Claim::Created
            );
            assert!(
                f.runtime
                    .authenticate(
                        &security::digest(&security::encode(&[3; 32])),
                        1,
                        &security::digest(&security::encode(&[4; 32])),
                        &[5; 32],
                        None
                    )
                    .await
                    .unwrap()
            );
        }
        let anonymous = security::encode(&[6; 32]);
        assert_eq!(
            f.runtime
                .form(&security::digest(&anonymous), None, Some(&[5; 32]))
                .await
                .unwrap(),
            Some(vec![5; 32])
        );
        Self {
            app,
            anonymous,
            signed: security::encode(&[4; 32]),
            token: security::encode(&[5; 32]),
        }
    }
    async fn post(&self, path: &str, email: &str, changes: &[(&str, Option<&str>)]) -> Response {
        let protected = matches!(path, "/admin/password" | "/admin/logout");
        let csrf_cookie = if protected {
            &self.signed
        } else {
            &self.anonymous
        };
        let cookie = format!(
            "__Host-bloc-csrf={csrf_cookie}; __Host-bloc-admin={}",
            security::encode(&[3; 32])
        );
        let fields = [
            ("csrf", self.token.as_str()),
            ("email", email),
            ("password", "a wrong synthetic password"),
            ("password_confirmation", "a wrong synthetic password"),
            ("current_password", "a wrong synthetic password"),
            ("code", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ];
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "bloc.example.test")
            .header("origin", "https://bloc.example.test")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "192.0.2.4")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", cookie)
            .body(Body::from(body))
            .unwrap();
        for (key, value) in changes {
            request.headers_mut().remove(*key);
            if let Some(value) = value {
                request.headers_mut().insert(
                    axum::http::HeaderName::from_bytes(key.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
        }
        request
            .extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1".parse::<SocketAddr>().unwrap()));
        router(self.app.clone()).oneshot(request).await.unwrap()
    }
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn dummy_work_equivalence() {
    let f = Fixture::new("accessdummywork").await;
    let h = Http::new(&f, true).await;
    let real = f.runtime.owner().await.unwrap().unwrap().phc;
    for phc in [&real, &h.app.dummy] {
        assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
        let parts: Vec<_> = phc.split('$').collect();
        assert_eq!(STANDARD_NO_PAD.decode(parts[4]).unwrap().len(), 16);
        assert_eq!(STANDARD_NO_PAD.decode(parts[5]).unwrap().len(), 32);
    }
    for email in [common::EMAIL, "unknown@example.test"] {
        let before = h.app.worker.observed_work();
        let response = h.post("/admin/login", email, &[]).await;
        assert_eq!(response.status(), 401);
        assert!(!response.headers().contains_key("set-cookie"));
        let body = to_bytes(response.into_body(), 100000).await.unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("Email or password is incorrect.")
        );
        let after = h.app.worker.observed_work();
        assert_eq!(
            std::array::from_fn::<_, 4, _>(|i| after[i] - before[i]),
            [0, 0, 1, 1]
        );
    }
    // The safe identifier is echoed in each page; the public error copy/status are identical.
    assert_eq!(f.runtime.owner().await.unwrap().unwrap().version, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM bloc.administrator_session")
            .fetch_one(&f.admin)
            .await
            .unwrap(),
        1
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn request_rejections_precede_password_work() {
    for owned in [false, true] {
        let f = Fixture::new(if owned {
            "accesspreworkowned"
        } else {
            "accesspreworkfresh"
        })
        .await;
        let mut h = Http::new(&f, owned).await;
        let paths: Vec<_> = if owned {
            vec![
                "/admin/login",
                "/admin/recovery",
                "/admin/password",
                "/admin/logout",
            ]
        } else {
            vec!["/admin/setup"]
        };
        for path in paths {
            for enhanced in [false, true] {
                for origin in [
                    None,
                    Some("null"),
                    Some("https://evil.example"),
                    Some("https://bloc.example.test:444"),
                    Some("https://u@bloc.example.test"),
                    Some("https://bloc.example.test/path"),
                ] {
                    let mut changes = vec![("origin", origin)];
                    if enhanced {
                        changes.push(("hx-request", Some("true")));
                    }
                    let before = h.app.worker.observed_work();
                    assert_eq!(
                        h.post(path, common::EMAIL, &changes).await.status(),
                        403,
                        "{path} {origin:?}"
                    );
                    assert_eq!(h.app.worker.observed_work(), before);
                }
                let original = h.token.clone();
                for invalid in [String::new(), "bad".into(), security::encode(&[99; 32])] {
                    h.token = invalid;
                    let before = h.app.worker.observed_work();
                    assert_eq!(
                        h.post(
                            path,
                            common::EMAIL,
                            &[("hx-request", if enhanced { Some("true") } else { None })]
                        )
                        .await
                        .status(),
                        403
                    );
                    assert_eq!(h.app.worker.observed_work(), before);
                }
                h.token = original;
                let bad_cookie = format!(
                    "__Host-bloc-csrf={}; __Host-bloc-admin={}",
                    security::encode(&[99; 32]),
                    security::encode(&[3; 32])
                );
                let before = h.app.worker.observed_work();
                assert_eq!(
                    h.post(
                        path,
                        common::EMAIL,
                        &[
                            ("cookie", Some(&bad_cookie)),
                            ("hx-request", if enhanced { Some("true") } else { None })
                        ]
                    )
                    .await
                    .status(),
                    403
                );
                assert_eq!(h.app.worker.observed_work(), before);
            }
        }
    }
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn http_worker_saturation_and_authority_order() {
    let f = Fixture::new("accessworkerhttp").await;
    let h = Http::new(&f, true).await;
    let hold = h.app.worker.occupy();
    let before = h.app.worker.observed_work();
    for i in 1..=20 {
        let source = format!("192.0.2.{i}");
        let email = format!("unknown{i}@example.test");
        let response = h
            .post(
                "/admin/login",
                &email,
                &[("x-forwarded-for", Some(&source))],
            )
            .await;
        assert_eq!(response.status(), 503);
        assert_eq!(response.headers()["retry-after"], "1");
    }
    assert_eq!(h.app.worker.observed_work(), before);
    sqlx::query("ALTER FUNCTION bloc.reserve_admission(text[],bytea[],integer[]) RENAME TO temporarily_disabled_admission").execute(&f.admin).await.unwrap();
    let response = h.post("/admin/login", common::EMAIL, &[]).await;
    assert_eq!(response.status(), 503);
    assert!(!response.headers().contains_key("retry-after"));
    assert_eq!(h.app.worker.observed_work(), before);
    sqlx::query("ALTER FUNCTION bloc.temporarily_disabled_admission(text[],bytea[],integer[]) RENAME TO reserve_admission").execute(&f.admin).await.unwrap();
    drop(hold);
    let request = h.post("/admin/login", common::EMAIL, &[]);
    tokio::pin!(request);
    let mut observed_inside = false;
    let response = loop {
        tokio::select! {
            response=&mut request=>break response,
            ()=tokio::task::yield_now()=>{
                let now=h.app.worker.observed_work();
                if now[2]>before[2] && now[3]==before[3] {
                    let idle:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename='runtime_user' AND state LIKE 'idle in transaction%'").fetch_one(&f.admin).await.unwrap();
                    assert_eq!(idle,0,"no authority transaction remains open during real Argon2 work");
                    observed_inside=true;
                    break request.await;
                }
            }
        }
    };
    assert!(
        observed_inside,
        "must inspect database transactions while real password work is running"
    );
    assert_eq!(response.status(), 401);
    let after = h.app.worker.observed_work();
    assert_eq!(after[2] - before[2], 1);
    assert_eq!(after[3] - before[3], 1);
}
