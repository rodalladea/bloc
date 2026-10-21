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

const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const OTHER: &str = "33333333-3333-4333-8333-333333333333";
const USER: &str = "22222222-2222-4222-8222-222222222222";
async fn signed(name: &str) -> (Fixture, Browser) {
    let f = Fixture::new(name).await;
    let mut b = Browser::new(&f).await;
    b.setup(&f).await;
    b.login().await;
    (f, b)
}
async fn create_tenant(b: &mut Browser, id: &str, name: &str) {
    let csrf = b.token("/admin/tenants/new").await;
    let (s, h, r) = b
        .request(
            "POST",
            "/admin/tenants",
            &[("csrf", &csrf), ("creation_id", id), ("name", name)],
        )
        .await;
    assert_eq!(s, 303, "{h}");
    assert_eq!(r["location"], format!("/admin/tenants/{id}"));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn directory_c01() {
    let (f, mut b) = signed("directoryc01").await;
    let (s, h, _) = b.request("GET", "/admin/tenants", &[]).await;
    assert_eq!(s, 200, "{h}");
    assert!(h.contains("No tenants yet"));
    assert!(h.contains("Create tenant"));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.tenant")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn directory_c02() {
    let (f, mut b) = signed("directoryc02").await;
    create_tenant(&mut b, TENANT, " Acme ").await;
    let (s, h, _) = b
        .request("GET", &format!("/admin/tenants/{TENANT}"), &[])
        .await;
    assert_eq!(s, 200);
    assert!(h.contains("Acme"));
    assert!(h.contains(TENANT));
    assert!(h.contains("Active"));
    let row: (String, String, i64, bool) = sqlx::query_as(
        "SELECT name,status,version,created_at=updated_at FROM bloc.tenant WHERE id=$1::text::uuid",
    )
    .bind(TENANT)
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(row, ("Acme".into(), "active".into(), 1, true));
}
async fn user(
    b: &mut Browser,
    tenant: &str,
    id: &str,
    email: &str,
    name: &str,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let path = format!("/admin/tenants/{tenant}/users");
    let csrf = b.token(&format!("{path}/new")).await;
    b.request(
        "POST",
        &path,
        &[
            ("csrf", &csrf),
            ("creation_id", id),
            ("email", email),
            ("display_name", name),
        ],
    )
    .await
}
async fn edit(
    b: &mut Browser,
    path: &str,
    fields: &[(&str, &str)],
) -> (StatusCode, String, axum::http::HeaderMap) {
    let csrf = b.token(path.trim_end_matches("/status")).await;
    let mut fields = fields.to_vec();
    fields.push(("csrf", &csrf));
    b.request("POST", path, &fields).await
}
async fn events(f: &Fixture) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM bloc.security_audit_event WHERE action LIKE 'tenant%'")
        .fetch_one(&f.admin)
        .await
        .unwrap()
}
async fn tenant_row(f: &Fixture) -> (String, String, i64, String) {
    sqlx::query_as(
        "SELECT name,status,version,updated_at::text FROM bloc.tenant WHERE id=$1::text::uuid",
    )
    .bind(TENANT)
    .fetch_one(&f.admin)
    .await
    .unwrap()
}
async fn user_row(f: &Fixture) -> (String, Option<String>, String, i64, String) {
    sqlx::query_as("SELECT email,display_name,status,version,updated_at::text FROM bloc.tenant_user WHERE id=$1::text::uuid").bind(USER).fetch_one(&f.admin).await.unwrap()
}
fn tenant_path() -> String {
    format!("/admin/tenants/{TENANT}")
}
fn user_path() -> String {
    format!("/admin/tenants/{TENANT}/users/{USER}")
}
macro_rules! check {
    ($name:ident,$f:ident,$b:ident,$body:block) => {
        #[tokio::test]
        #[ignore = "TLS fixture"]
        async fn $name() {
            let ($f, mut $b) = signed(stringify!($name)).await;
            $body
        }
    };
}
check!(directory_c03, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    create_tenant(&mut b, OTHER, "Acme").await;
    let (_, h, _) = b.request("GET", "/admin/tenants", &[]).await;
    assert!(h.contains(TENANT) && h.contains(OTHER));
    assert_eq!(events(&f).await, 2);
});
check!(directory_c04, f, b, {
    let csrf = b.token("/admin/tenants/new").await;
    for name in [
        "".into(),
        "  ".into(),
        "bad\nname".into(),
        "a".repeat(129),
        "😀".repeat(129),
    ] {
        let (s, h, _) = b
            .request(
                "POST",
                "/admin/tenants",
                &[("csrf", &csrf), ("creation_id", TENANT), ("name", &name)],
            )
            .await;
        assert_eq!(s, 422, "{h}");
        assert!(h.contains("control characters"));
    }
    assert_eq!(events(&f).await, 0);
    create_tenant(&mut b, TENANT, &"😀".repeat(128)).await;
});
check!(directory_c05, f, b, {
    let csrf = b.token("/admin/tenants/new").await;
    let mut c = Browser::new(&f).await;
    c.cookies = b.cookies.clone();
    let fields = [
        ("csrf", csrf.as_str()),
        ("creation_id", TENANT),
        ("name", "Acme"),
    ];
    let (a, z) = tokio::join!(
        b.request("POST", "/admin/tenants", &fields),
        c.request("POST", "/admin/tenants", &fields)
    );
    let mut codes = [a.0.as_u16(), z.0.as_u16()];
    codes.sort();
    assert_eq!(codes, [303, 409]);
    assert!((a.1 + &z.1).contains("Review existing tenant"));
    assert_eq!(events(&f).await, 1);
});
check!(directory_c06, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    assert_eq!(
        user(&mut b, TENANT, USER, "Alice@example.com", "").await.0,
        303
    );
    let old = tenant_row(&f).await;
    assert_eq!(
        edit(
            &mut b,
            &tenant_path(),
            &[("name", "Renamed"), ("version", "1")]
        )
        .await
        .0,
        303
    );
    let new = tenant_row(&f).await;
    assert_eq!((new.0, new.2), ("Renamed".into(), 2));
    assert_ne!(old.3, new.3);
    let parent: String = sqlx::query_scalar("SELECT tenant_id::text FROM bloc.tenant_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(parent, TENANT);
});
check!(directory_c07, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    let old = user_row(&f).await;
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", tenant_path()),
            &[("status", "suspended"), ("version", "1")]
        )
        .await
        .0,
        303
    );
    assert_eq!(user_row(&f).await, old);
    assert_eq!(tenant_row(&f).await.1, "suspended");
    let (_, h, _) = b.request("GET", &tenant_path(), &[]).await;
    assert!(h.contains("user statuses"));
});
check!(directory_c08, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", user_path()),
            &[("status", "suspended"), ("version", "1")]
        )
        .await
        .0,
        303
    );
    for (v, s) in [("1", "suspended"), ("2", "active")] {
        assert_eq!(
            edit(
                &mut b,
                &format!("{}/status", tenant_path()),
                &[("status", s), ("version", v)]
            )
            .await
            .0,
            303
        );
    }
    assert_eq!(tenant_row(&f).await.1, "active");
    assert_eq!(user_row(&f).await.2, "suspended");
});
check!(directory_c09, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    edit(
        &mut b,
        &format!("{}/status", tenant_path()),
        &[("status", "suspended"), ("version", "1")],
    )
    .await;
    assert_eq!(
        user(&mut b, TENANT, USER, "Alice@example.com", "").await.0,
        303
    );
    assert_eq!(
        edit(
            &mut b,
            &user_path(),
            &[("email", "Bob@example.com"), ("version", "1")]
        )
        .await
        .0,
        303
    );
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", user_path()),
            &[("status", "suspended"), ("version", "2")]
        )
        .await
        .0,
        303
    );
    assert_eq!(
        edit(
            &mut b,
            &tenant_path(),
            &[("name", "Renamed"), ("version", "2")]
        )
        .await
        .0,
        303
    );
    let (_, h, _) = b.request("GET", &user_path(), &[]).await;
    assert!(h.contains("This tenant is suspended"));
    assert_eq!(tenant_row(&f).await.1, "suspended");
});
check!(directory_c10, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    let csrf = b.token(&tenant_path()).await;
    let mut c = Browser::new(&f).await;
    c.cookies = b.cookies.clone();
    let a = [("csrf", csrf.as_str()), ("name", "One"), ("version", "1")];
    let z = [("csrf", csrf.as_str()), ("name", "Two"), ("version", "1")];
    let path = tenant_path();
    let (a, z) = tokio::join!(b.request("POST", &path, &a), c.request("POST", &path, &z));
    let mut codes = [a.0.as_u16(), z.0.as_u16()];
    codes.sort();
    assert_eq!(codes, [303, 409]);
    assert!((a.1 + &z.1).contains("Reload current record"));
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", tenant_path()),
            &[("status", "suspended"), ("version", "1")]
        )
        .await
        .0,
        409
    );
    assert_eq!(events(&f).await, 2);
});
check!(directory_c11, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    let old = tenant_row(&f).await;
    assert_eq!(
        edit(
            &mut b,
            &tenant_path(),
            &[("name", " Acme "), ("version", "1")]
        )
        .await
        .0,
        303
    );
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", tenant_path()),
            &[("status", "active"), ("version", "1")]
        )
        .await
        .0,
        303
    );
    assert_eq!(old, tenant_row(&f).await);
    assert_eq!(events(&f).await, 1);
});
check!(directory_c12, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    edit(
        &mut b,
        &tenant_path(),
        &[("name", "Renamed"), ("version", "1")],
    )
    .await;
    let mut c = Browser::new(&f).await;
    c.cookies = b.cookies.clone();
    let (s, h, _) = c.request("GET", &tenant_path(), &[]).await;
    assert_eq!(s, 200);
    assert!(h.contains("Renamed"));
    assert!(h.contains(TENANT));
    assert!(h.contains(">2<"));
    let mut processes = services(&f).await;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: bloc.example.test:4443\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 192.0.2.4\r\nCookie: __Host-bloc-admin={}\r\nConnection: close\r\n\r\n",
        tenant_path(),
        b.cookies["__Host-bloc-admin"]
    );
    let read = |request: &str| {
        use std::io::{Read, Write};
        let mut socket = std::net::TcpStream::connect(("127.0.0.1", 31001)).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        socket.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
        response
    };
    let first = read(&request);
    assert!(first.starts_with("HTTP/1.1 200"));
    assert!(first.contains("Renamed"));
    processes.children[0].kill().unwrap();
    processes.children[0].wait().unwrap();
    processes.children[0] = spawn_service(&f, &processes.directory, 31001);
    for attempt in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", 31001)).is_ok() {
            break;
        }
        assert!(attempt < 99);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let restarted = read(&request);
    assert!(restarted.starts_with("HTTP/1.1 200"));
    assert!(restarted.contains("Renamed"));
    assert!(restarted.contains(TENANT));
    assert!(restarted.contains(">2<"));
});
async fn seed_tenants(b: &mut Browser, n: usize) {
    for i in 1..=n {
        create_tenant(b, &format!("00000000-0000-4000-8000-{i:012}"), "Repeated").await;
    }
}
fn next(html: &str) -> String {
    html.split("rel=\"next\" href=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .replace("&amp;", "&")
}
check!(directory_c13, f, b, {
    seed_tenants(&mut b, 51).await;
    sqlx::query("UPDATE bloc.tenant SET created_at='2026-01-01T00:00:00Z'")
        .execute(&f.admin)
        .await
        .unwrap();
    let (_, h, _) = b.request("GET", "/admin/tenants", &[]).await;
    assert_eq!(h.matches("<tr data-record=").count(), 50);
    let (_, last, _) = b.request("GET", &next(&h), &[]).await;
    assert_eq!(last.matches("<tr data-record=").count(), 1);
    for i in 1..=50 {
        let id = format!("00000000-0000-4000-8000-{i:012}");
        assert!(h.contains(&id));
        assert!(!last.contains(&id));
    }
    assert!(last.contains("00000000-0000-4000-8000-000000000051"));
    assert!(!last.contains("rel=\"next\""));
    assert!(!h.contains("Search"));
    assert_eq!(events(&f).await, 51);
});
check!(directory_c14, f, b, {
    let (_, h, _) = b.request("GET", "/admin/tenants/new", &[]).await;
    assert!(h.contains(">Cancel</a>"));
    assert_eq!(events(&f).await, 0);
    create_tenant(&mut b, TENANT, "Acme").await;
    let (_, h, _) = b
        .request(
            "GET",
            &format!("{}/status?status=suspended&version=1", tenant_path()),
            &[],
        )
        .await;
    assert!(h.contains("Suspend this tenant?"));
    assert!(h.contains(TENANT));
    assert!(h.contains("name=\"version\" value=\"1\""));
    assert_eq!(events(&f).await, 1);
});
check!(directory_c15, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    let (s, h, _) = b
        .request("GET", &format!("{}/users", tenant_path()), &[])
        .await;
    assert_eq!(s, 200);
    for text in ["No users yet", "Create user", "Acme", TENANT] {
        assert!(h.contains(text));
    }
    assert_eq!(events(&f).await, 1);
});
check!(directory_c16, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    let (s, h, r) = user(&mut b, TENANT, USER, " Alice@EXAMPLE.com ", " Alice ").await;
    assert_eq!(s, 303, "{h}");
    assert_eq!(r["location"], user_path());
    let row = user_row(&f).await;
    assert_eq!(
        (row.0, row.1, row.2, row.3),
        (
            "Alice@example.com".into(),
            Some("Alice".into()),
            "active".into(),
            1
        )
    );
    let (_, h, _) = b.request("GET", &user_path(), &[]).await;
    for text in [USER, TENANT, "Unverified", "This user cannot sign in"] {
        assert!(h.contains(text));
    }
    let equal: bool = sqlx::query_scalar("SELECT created_at=updated_at FROM bloc.tenant_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert!(equal);
});
check!(directory_c17, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    create_tenant(&mut b, OTHER, "Contoso").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    assert_eq!(
        user(&mut b, OTHER, OTHER, "Alice@example.com", "").await.0,
        303
    );
    edit(
        &mut b,
        &user_path(),
        &[("email", "Bob@example.com"), ("version", "1")],
    )
    .await;
    let row: (String, i64, String) =
        sqlx::query_as("SELECT email,version,status FROM bloc.tenant_user WHERE id=$1::text::uuid")
            .bind(OTHER)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(row, ("Alice@example.com".into(), 1, "active".into()));
});
check!(directory_c18, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    edit(
        &mut b,
        &format!("{}/status", user_path()),
        &[("status", "suspended"), ("version", "1")],
    )
    .await;
    for email in ["Alice@EXAMPLE.com", " Alice@example.com "] {
        assert_eq!(user(&mut b, TENANT, OTHER, email, "").await.0, 409);
    }
    assert_eq!(
        user(&mut b, TENANT, OTHER, "alice@example.com", "").await.0,
        303
    );
    assert_eq!(events(&f).await, 4);
});
check!(directory_c19, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    for email in [
        "Alice@",
        "é@example.com",
        "a b@example.com",
        "a..b@example.com",
    ] {
        assert!(bloc::credentials::normalize_email(email).is_err());
        assert_eq!(user(&mut b, TENANT, USER, email, "").await.0, 422);
    }
    for email in [
        format!("{}@example.com", "a".repeat(65)),
        format!("a@{}.test", "b".repeat(64)),
        ".a@example.com".into(),
        "a.@example.com".into(),
        "a@-example.com".into(),
        "a@example-.com".into(),
        "a@example..com".into(),
        format!(
            "{}@{}.{}.{}",
            "a".repeat(64),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        ),
    ] {
        assert!(bloc::credentials::normalize_email(&email).is_err());
        assert_eq!(user(&mut b, TENANT, USER, &email, "").await.0, 422);
    }
    assert_eq!(events(&f).await, 1);
    assert_eq!(
        user(&mut b, TENANT, USER, "Alice+tag@EXAMPLE.com", "")
            .await
            .0,
        303
    );
    assert_eq!(user_row(&f).await.0, "Alice+tag@example.com");
    let maximum = format!(
        "{}@{}.{}.{}",
        "a".repeat(64),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(maximum.len(), 254);
    assert_eq!(user(&mut b, TENANT, OTHER, &maximum, "").await.0, 303);
});
check!(directory_c20, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    for name in ["bad\nname".into(), "a".repeat(129), "😀".repeat(129)] {
        let (s, h, _) = user(&mut b, TENANT, USER, "Alice@example.com", &name).await;
        assert_eq!(s, 422);
        assert!(h.contains("Control characters"));
    }
    assert_eq!(events(&f).await, 1);
    assert_eq!(
        user(&mut b, TENANT, USER, "Alice@example.com", "  ")
            .await
            .0,
        303
    );
    assert_eq!(user_row(&f).await.1, None);
    let maximum = "😀".repeat(128);
    assert_eq!(
        edit(
            &mut b,
            &user_path(),
            &[
                ("email", "Alice@example.com"),
                ("display_name", &maximum),
                ("version", "1")
            ]
        )
        .await
        .0,
        303
    );
    assert_eq!(user_row(&f).await.1, Some(maximum));
});
check!(directory_c21, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "Alice").await;
    let old = user_row(&f).await;
    assert_eq!(
        edit(
            &mut b,
            &user_path(),
            &[
                ("email", " Alice@EXAMPLE.com "),
                ("display_name", " Alice "),
                ("version", "1")
            ]
        )
        .await
        .0,
        303
    );
    assert_eq!(old, user_row(&f).await);
    assert_eq!(events(&f).await, 2);
    assert_eq!(
        edit(
            &mut b,
            &user_path(),
            &[
                ("email", "Bob@example.com"),
                ("display_name", "Bob"),
                ("version", "1")
            ]
        )
        .await
        .0,
        303
    );
    let new = user_row(&f).await;
    assert_eq!(new.3, 2);
    assert_ne!(old.4, new.4);
});
check!(directory_c22, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    let parent = tenant_row(&f).await;
    for (v, s) in [("1", "suspended"), ("2", "active"), ("3", "active")] {
        assert_eq!(
            edit(
                &mut b,
                &format!("{}/status", user_path()),
                &[("status", s), ("version", v)]
            )
            .await
            .0,
            303
        );
    }
    assert_eq!(user_row(&f).await.3, 3);
    assert_eq!(events(&f).await, 4);
    assert_eq!(parent, tenant_row(&f).await);
});
check!(directory_c23, _f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    for (tv, uv, text) in [
        ("1", "1", "Active"),
        ("1", "1", "Tenant suspended"),
        ("2", "1", "Tenant suspended and user suspended"),
    ] {
        let (_, h, _) = b.request("GET", &user_path(), &[]).await;
        assert!(h.contains("Combined directory status"));
        assert!(h.contains("This user cannot sign in"));
        if tv == "1" && uv == "1" && text == "Active" {
            edit(
                &mut b,
                &format!("{}/status", tenant_path()),
                &[("version", tv), ("status", "suspended")],
            )
            .await;
        } else if text == "Tenant suspended" {
            assert!(h.contains(text));
            edit(
                &mut b,
                &format!("{}/status", user_path()),
                &[("version", uv), ("status", "suspended")],
            )
            .await;
        } else {
            assert!(h.contains(text));
        }
    }
});
check!(directory_c24, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    for field in ["tenant_id", "roles", "verified", "password"] {
        assert_eq!(
            edit(
                &mut b,
                &user_path(),
                &[
                    ("email", "Bob@example.com"),
                    ("version", "1"),
                    (field, OTHER)
                ]
            )
            .await
            .0,
            422
        );
    }
    let csrf = b.token(&user_path()).await;
    for path in [
        "/admin/tenants".into(),
        tenant_path(),
        format!("{}/status", tenant_path()),
        format!("{}/users", tenant_path()),
        user_path(),
        format!("{}/status", user_path()),
    ] {
        let (status, _, _) = b
            .request(
                "POST",
                &path,
                &[
                    ("csrf", &csrf),
                    ("creation_id", OTHER),
                    ("name", "Changed"),
                    ("email", "Bob@example.com"),
                    ("version", "1"),
                    ("status", "suspended"),
                    ("roles", "owner"),
                ],
            )
            .await;
        assert_eq!(status, 422);
    }
    assert_eq!(user_row(&f).await.3, 1);
    assert_eq!(events(&f).await, 2);
});
check!(directory_c25, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    create_tenant(&mut b, OTHER, "Contoso").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    let csrf = b.token(&user_path()).await;
    for target in [USER, OTHER] {
        let path = format!("/admin/tenants/{OTHER}/users/{target}");
        for (method, suffix, fields) in [
            ("GET", "", vec![]),
            (
                "POST",
                "",
                vec![
                    ("csrf", csrf.as_str()),
                    ("email", "Bob@example.com"),
                    ("version", "1"),
                ],
            ),
            (
                "POST",
                "/status",
                vec![
                    ("csrf", csrf.as_str()),
                    ("status", "suspended"),
                    ("version", "1"),
                ],
            ),
        ] {
            let (s, h, _) = b.request(method, &format!("{path}{suffix}"), &fields).await;
            assert_eq!(s, 404, "{h}");
            assert!(!h.contains("Alice@example.com"));
        }
    }
    let pool = f.pool("runtime_user").await;
    let mut connection = pool.acquire().await.unwrap();
    sqlx::query("SELECT set_config('bloc.tenant_id',$1,false)")
        .bind(TENANT)
        .execute(&mut *connection)
        .await
        .unwrap();
    let session = sec::digest(&b.cookies["__Host-bloc-admin"]);
    let rows = sqlx::query(
        "SELECT * FROM bloc.directory_users($1,$2::text::uuid,$3::text::uuid,NULL,NULL)",
    )
    .bind(session.as_slice())
    .bind(OTHER)
    .bind(USER)
    .fetch_all(&mut *connection)
    .await
    .unwrap();
    assert!(rows.is_empty());
    for operation in ["user_update", "user_status"] {
        let outcome:String=sqlx::query_scalar("SELECT bloc.directory_mutate($1,$2,$3::text::uuid,$4::text::uuid,1,'Wrong@example.com',NULL,'suspended')").bind(session.as_slice()).bind(operation).bind(OTHER).bind(USER).fetch_one(&mut *connection).await.unwrap();
        assert_eq!(outcome, "missing");
    }
    for (method, suffix) in [("GET", ""), ("POST", ""), ("POST", "/status")] {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("csrf", csrf.as_str()),
                ("email", "Wrong@example.com"),
                ("version", "1"),
                ("status", "suspended"),
            ])
            .finish();
        let a = format!("/admin/tenants/{OTHER}/users/{USER}{suffix}");
        let z = format!("/admin/tenants/{OTHER}/users/{OTHER}{suffix}");
        let (ac, ah, _) = raw(&b, method, &a, body.clone(), &[("hx-request", "true")]).await;
        let (zc, zh, _) = raw(&b, method, &z, body, &[("hx-request", "true")]).await;
        assert_eq!(ac, 404);
        assert_eq!(zc, 404);
        assert_eq!(ah, zh);
        assert!(!ah.contains("Alice@example.com"));
    }
    assert_eq!(events(&f).await, 3);
});
check!(directory_c26, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    let csrf = b.token(&format!("{}/users/new", tenant_path())).await;
    let mut c = Browser::new(&f).await;
    c.cookies = b.cookies.clone();
    let a = [
        ("csrf", csrf.as_str()),
        ("creation_id", USER),
        ("email", "Alice@EXAMPLE.com"),
    ];
    let z = [
        ("csrf", csrf.as_str()),
        ("creation_id", OTHER),
        ("email", " Alice@example.com "),
    ];
    let path = format!("{}/users", tenant_path());
    let (a, z) = tokio::join!(b.request("POST", &path, &a), c.request("POST", &path, &z));
    let mut codes = [a.0.as_u16(), z.0.as_u16()];
    codes.sort();
    assert_eq!(codes, [303, 409]);
    let first: String = sqlx::query_scalar("SELECT id::text FROM bloc.tenant_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    let second = "44444444-4444-4444-8444-444444444444";
    assert_eq!(
        user(&mut b, TENANT, second, "Second@example.com", "")
            .await
            .0,
        303
    );
    let left = format!("{}/users/{first}", tenant_path());
    let right = format!("{}/users/{second}", tenant_path());
    let csrf = b.token(&left).await;
    c.cookies = b.cookies.clone();
    let a = [
        ("csrf", csrf.as_str()),
        ("email", "Shared@EXAMPLE.com"),
        ("version", "1"),
    ];
    let z = [
        ("csrf", csrf.as_str()),
        ("email", " Shared@example.com "),
        ("version", "1"),
    ];
    let (a, z) = tokio::join!(b.request("POST", &left, &a), c.request("POST", &right, &z));
    let mut codes = [a.0.as_u16(), z.0.as_u16()];
    codes.sort();
    assert_eq!(codes, [303, 409]);
    assert_eq!(events(&f).await, 4);
});
check!(directory_c27, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    create_tenant(&mut b, OTHER, "Contoso").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    let (s, h, _) = user(&mut b, TENANT, USER, "Bob@example.com", "").await;
    assert_eq!(s, 409);
    assert!(h.contains("Review existing user"));
    let (s, h, _) = user(&mut b, OTHER, USER, "Bob@example.com", "").await;
    assert_eq!(s, 409);
    assert!(!h.contains("Review existing user"));
    assert!(!h.contains(USER));
    assert!(!h.contains("Alice@example.com"));
    assert_eq!(events(&f).await, 3);
});
check!(directory_c28, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    let csrf = b.token(&user_path()).await;
    let mut c = Browser::new(&f).await;
    c.cookies = b.cookies.clone();
    let a = [
        ("csrf", csrf.as_str()),
        ("email", "Bob@example.com"),
        ("version", "1"),
    ];
    let z = [
        ("csrf", csrf.as_str()),
        ("status", "suspended"),
        ("version", "1"),
    ];
    let p = user_path();
    let status = format!("{p}/status");
    let (a, z) = tokio::join!(b.request("POST", &p, &a), c.request("POST", &status, &z));
    let mut codes = [a.0.as_u16(), z.0.as_u16()];
    codes.sort();
    assert_eq!(codes, [303, 409]);
    assert_eq!(events(&f).await, 3);
});
check!(directory_c29, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    create_tenant(&mut b, OTHER, "Contoso").await;
    user(&mut b, OTHER, OTHER, "Other@example.com", "").await;
    for i in 1..=51 {
        assert_eq!(
            user(
                &mut b,
                TENANT,
                &format!("00000000-0000-4000-8000-{i:012}"),
                &format!("User{i}@example.com"),
                ""
            )
            .await
            .0,
            303
        );
    }
    let path = format!("{}/users", tenant_path());
    let (_, h, _) = b.request("GET", &path, &[]).await;
    assert_eq!(h.matches("<tr data-record=").count(), 50);
    assert!(!h.contains("Other@example.com"));
    let (_, last, _) = b.request("GET", &next(&h), &[]).await;
    assert_eq!(last.matches("<tr data-record=").count(), 1);
    assert_eq!(events(&f).await, 54);
});
check!(directory_c30, f, b, {
    create_tenant(&mut b, TENANT, "Private").await;
    user(&mut b, TENANT, USER, "Private@example.com", "").await;
    let mut unauth = Browser::new(&f).await;
    for path in [
        "/admin/tenants".into(),
        "/admin/tenants/new".into(),
        tenant_path(),
        format!("{}/status", tenant_path()),
        format!("{}/users", tenant_path()),
        format!("{}/users/new", tenant_path()),
        user_path(),
        format!("{}/status", user_path()),
    ] {
        for method in ["GET", "POST"] {
            let (s, h, r) = unauth.request(method, &path, &[]).await;
            assert_eq!(s, 303, "{path}: {h}");
            assert_eq!(r["location"], "/admin/login?expired=1");
            assert!(!h.contains("Private"));
        }
    }
    for path in [
        "/admin/tenants".into(),
        "/admin/tenants/new".into(),
        tenant_path(),
        format!("{}/status", tenant_path()),
        format!("{}/users", tenant_path()),
        format!("{}/users/new", tenant_path()),
        user_path(),
        format!("{}/status", user_path()),
    ] {
        for method in ["GET", "POST"] {
            let (status, html, headers) = raw(
                &unauth,
                method,
                &path,
                String::new(),
                &[("hx-request", "true")],
            )
            .await;
            assert_eq!(status, 401);
            assert_eq!(headers["hx-redirect"], "/admin/login?expired=1");
            assert!(!html.contains("Private"));
        }
    }
    f.operator.invalidate_access().await.unwrap();
    let (s, h, _) = b.request("GET", &tenant_path(), &[]).await;
    assert_eq!(s, 303);
    assert!(!h.contains("Private"));
});
#[tokio::test]
#[ignore = "TLS fixture"]
async fn directory_c31() {
    for mode in ["signout", "password", "restore"] {
        for before in [false, true] {
            let f = Fixture::new(&format!("directoryorder{mode}{before}")).await;
            let code = sec::digest(&sec::encode(&[1; 32]));
            f.operator.issue_setup_code(&code).await.unwrap();
            f.runtime
                .claim_owner(&code, common::EMAIL, common::HASH)
                .await
                .unwrap();
            assert!(
                f.runtime
                    .authenticate(&[9; 32], 1, &[8; 32], &[7; 32], None)
                    .await
                    .unwrap()
            );
            let mut lock = f.admin.begin().await.unwrap();
            sqlx::query("SELECT id FROM bloc.installation WHERE id=1 FOR UPDATE")
                .execute(&mut *lock)
                .await
                .unwrap();
            let runtime = f.pool("runtime_user").await;
            if before {
                let outcome:String=sqlx::query_scalar("SELECT bloc.directory_mutate($1,'tenant_create',$2::text::uuid,NULL,0,'Acme',NULL,NULL)").bind(&[9u8;32][..]).bind(TENANT).fetch_one(&mut *lock).await.unwrap();
                assert_eq!(outcome, "ok");
            }
            let revoke = match mode {
                "signout" => "SELECT bloc.sign_out($1)",
                "password" => {
                    "SELECT bloc.replace_password($1,1,'synthetic-replacement-hash',false)"
                }
                _ => "SELECT bloc.invalidate_access()",
            };
            // Revoke while holding the same installation lock, then let a separate runtime connection contend.
            if mode == "restore" {
                sqlx::query(revoke).execute(&mut *lock).await.unwrap();
            } else {
                sqlx::query(revoke)
                    .bind(&[9u8; 32][..])
                    .execute(&mut *lock)
                    .await
                    .unwrap();
            }
            let job = tokio::spawn(async move {
                sqlx::query_scalar::<_,String>("SELECT bloc.directory_mutate($1,'tenant_create',$2::text::uuid,NULL,0,'Wrong',NULL,NULL)").bind(&[9u8;32][..]).bind(OTHER).fetch_one(&runtime).await
            });
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            assert!(!job.is_finished());
            lock.commit().await.unwrap();
            let error = job.await.unwrap().unwrap_err();
            assert_eq!(
                error.as_database_error().unwrap().code().as_deref(),
                Some("28000")
            );
            assert_eq!(events(&f).await, if before { 1 } else { 0 });
        }
    }
}
check!(directory_c32, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    let csrf = b.token(&tenant_path()).await;
    let valid = format!("csrf={csrf}&name=Wrong&version=1");
    let routes = [
        "/admin/tenants".into(),
        tenant_path(),
        format!("{}/status", tenant_path()),
        format!("{}/users", tenant_path()),
        user_path(),
        format!("{}/status", user_path()),
    ];
    for path in routes {
        for (body, headers, expected) in [
            (
                valid.clone(),
                vec![("origin", "https://foreign.example")],
                403,
            ),
            (
                valid.clone(),
                vec![("content-type", "application/json")],
                415,
            ),
            ("x".repeat(16385), vec![], 413),
            (format!("{valid}&csrf={csrf}"), vec![], 400),
            ("bad=%GG".into(), vec![], 400),
            ("csrf=invalid".into(), vec![], 403),
        ] {
            let (status, html, _) = raw(&b, "POST", &path, body, &headers).await;
            assert_eq!(status, expected, "{path}: {html}");
        }
    }
    let (s, _, _) = b
        .request(
            "POST",
            &tenant_path(),
            &[("csrf", "wrong"), ("name", "Wrong"), ("version", "1")],
        )
        .await;
    assert_eq!(s, 403);
    let csrf = b.token(&tenant_path()).await;
    let second_session = sec::encode(&[12; 32]);
    let second_browser = sec::encode(&[13; 32]);
    assert!(
        f.runtime
            .authenticate(
                &sec::digest(&second_session),
                1,
                &sec::digest(&second_browser),
                &[14; 32],
                None
            )
            .await
            .unwrap()
    );
    let wrong_session = format!(
        "__Host-bloc-admin={second_session}; __Host-bloc-csrf={}",
        b.cookies["__Host-bloc-csrf"]
    );
    assert_eq!(
        raw(
            &b,
            "POST",
            &tenant_path(),
            format!("csrf={csrf}&name=Wrong&version=1"),
            &[("cookie", &wrong_session)]
        )
        .await
        .0,
        403
    );
    let wrong_browser = format!(
        "__Host-bloc-admin={}; __Host-bloc-csrf={second_browser}",
        b.cookies["__Host-bloc-admin"]
    );
    assert_eq!(
        raw(
            &b,
            "POST",
            &tenant_path(),
            format!("csrf={csrf}&name=Wrong&version=1"),
            &[("cookie", &wrong_browser)]
        )
        .await
        .0,
        403
    );
    sqlx::query("UPDATE bloc.administrator_form_state SET created_at=statement_timestamp()-interval '31 minutes',expires_at=statement_timestamp()-interval '1 minute'").execute(&f.admin).await.unwrap();
    assert_eq!(
        b.request(
            "POST",
            &tenant_path(),
            &[("csrf", &csrf), ("name", "Wrong"), ("version", "1")]
        )
        .await
        .0,
        403
    );
    sqlx::query("DELETE FROM bloc.administrator_admission_bucket WHERE scope='form_issue_source'")
        .execute(&f.admin)
        .await
        .unwrap();
    let cookie = format!("__Host-bloc-admin={}", b.cookies["__Host-bloc-admin"]);
    for _ in 0..10 {
        assert_eq!(
            raw(
                &b,
                "GET",
                "/admin/tenants/new",
                String::new(),
                &[("cookie", &cookie)]
            )
            .await
            .0,
            200
        );
    }
    let (status, html, headers) = raw(
        &b,
        "GET",
        "/admin/tenants/new",
        String::new(),
        &[("cookie", &cookie)],
    )
    .await;
    assert_eq!(status, 429);
    assert!(
        headers["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u32>()
            .unwrap()
            > 0
    );
    assert!(html.contains("Reload form"));
    let _services = services(&f).await;
    use std::io::{Read, Write};
    let mut socket = std::net::TcpStream::connect(("127.0.0.1", 31001)).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: bloc.example.test:4443\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 192.0.2.4\r\nOrigin: https://bloc.example.test:4443\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: __Host-bloc-admin={}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        tenant_path(),
        b.cookies["__Host-bloc-admin"]
    );
    socket.write_all(head.as_bytes()).unwrap();
    for size in [8192, 8192, 1] {
        socket
            .write_all(format!("{size:X}\r\n").as_bytes())
            .unwrap();
        socket.write_all(&vec![b'x'; size]).unwrap();
        socket.write_all(b"\r\n").unwrap();
    }
    socket.write_all(b"0\r\n\r\n").unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert_eq!(events(&f).await, 2);
});
check!(directory_c33, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    let original = user_row(&f).await;
    let csrf = b.token(&tenant_path()).await;
    f.fail_audit(true).await;
    let (s, h, _) = b
        .request(
            "POST",
            &tenant_path(),
            &[("csrf", &csrf), ("name", "Wrong"), ("version", "1")],
        )
        .await;
    assert_eq!(s, 503);
    assert!(!h.contains("Acme"));
    assert_eq!(tenant_row(&f).await.0, "Acme");
    assert_eq!(
        edit(
            &mut b,
            &user_path(),
            &[("email", "Wrong@example.com"), ("version", "1")]
        )
        .await
        .0,
        503
    );
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", user_path()),
            &[("status", "suspended"), ("version", "1")]
        )
        .await
        .0,
        503
    );
    assert_eq!(
        user(&mut b, TENANT, OTHER, "New@example.com", "").await.0,
        503
    );
    assert_eq!(user_row(&f).await, original);
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.tenant_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(users, 1);
    assert_eq!(events(&f).await, 2);
    f.fail_audit(false).await;
    sqlx::query("UPDATE public._sqlx_migrations SET checksum='invalid'::bytea WHERE version=3")
        .execute(&f.admin)
        .await
        .unwrap();
    let (s, h, _) = b.request("GET", "/admin/tenants", &[]).await;
    assert_eq!(s, 503);
    assert!(!h.contains("No tenants yet"));
});
check!(directory_c34, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    edit(
        &mut b,
        &tenant_path(),
        &[("name", "Renamed"), ("version", "1")],
    )
    .await;
    edit(
        &mut b,
        &user_path(),
        &[("email", "Bob@example.com"), ("version", "1")],
    )
    .await;
    for (v, s) in [("2", "suspended"), ("3", "active")] {
        edit(
            &mut b,
            &format!("{}/status", tenant_path()),
            &[("status", s), ("version", v)],
        )
        .await;
        edit(
            &mut b,
            &format!("{}/status", user_path()),
            &[("status", s), ("version", v)],
        )
        .await;
    }
    let rows:Vec<(String,String,Option<String>,bool)>=sqlx::query_as("SELECT action,tenant_id::text,tenant_user_id::text,administrator_id IS NOT NULL AND request_id IS NOT NULL AND occurred_at<=clock_timestamp() FROM bloc.security_audit_event WHERE action LIKE 'tenant%' ORDER BY occurred_at").fetch_all(&f.admin).await.unwrap();
    assert_eq!(rows.len(), 8);
    for (action, t, u, valid) in rows {
        assert_eq!(t, TENANT);
        assert!(valid);
        assert_eq!(
            u,
            if action.starts_with("tenant_user_") {
                Some(USER.into())
            } else {
                None
            }
        );
    }
    assert_eq!(
        edit(
            &mut b,
            &tenant_path(),
            &[("name", "Renamed"), ("version", "4")]
        )
        .await
        .0,
        303
    );
    assert_eq!(events(&f).await, 8);
    let csrf = b.token("/admin/tenants/new").await;
    assert_eq!(
        b.request(
            "POST",
            "/admin/tenants",
            &[
                ("csrf", &csrf),
                ("creation_id", TENANT),
                ("name", "Replace")
            ]
        )
        .await
        .0,
        409
    );
    assert_eq!(
        user(&mut b, TENANT, USER, "Replace@example.com", "")
            .await
            .0,
        409
    );
    assert_eq!(
        edit(&mut b, &tenant_path(), &[("name", ""), ("version", "4")])
            .await
            .0,
        422
    );
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", tenant_path()),
            &[("status", "suspended"), ("version", "1")]
        )
        .await
        .0,
        409
    );
    assert_eq!(
        edit(&mut b, &user_path(), &[("email", "bad"), ("version", "4")])
            .await
            .0,
        422
    );
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", user_path()),
            &[("status", "active"), ("version", "4")]
        )
        .await
        .0,
        303
    );
    assert_eq!(
        edit(
            &mut b,
            &user_path(),
            &[("email", "Bob@example.com"), ("version", "4")]
        )
        .await
        .0,
        303
    );
    assert_eq!(events(&f).await, 8);
});
check!(directory_c35, f, b, {
    create_tenant(&mut b, TENANT, "Secret name").await;
    user(&mut b, TENANT, USER, "Secret@example.com", "Secret display").await;
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT row_to_json(e)::text FROM bloc.security_audit_event e")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    for row in rows {
        for value in [
            "Secret",
            "email",
            "display_name",
            "session_digest",
            "source_ip",
            "password",
            "token",
        ] {
            assert!(!row.contains(value));
        }
    }
    let _ = b.request("POST", &tenant_path(), &[]).await;
    assert_eq!(
        b.request("POST", &user_path(), &[("csrf", "invalid")])
            .await
            .0,
        403
    );
    let actions:Vec<String>=sqlx::query_scalar("SELECT DISTINCT action FROM bloc.administrator_denial_aggregate WHERE action LIKE 'tenant%' ORDER BY action").fetch_all(&f.admin).await.unwrap();
    assert_eq!(actions, vec!["tenant_management", "tenant_user_management"]);
});
check!(directory_c36, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    user(&mut b, TENANT, USER, "Alice@example.com", "").await;
    sqlx::query("UPDATE bloc.security_audit_event SET occurred_at=clock_timestamp()-interval '91 days' WHERE action LIKE 'tenant%'").execute(&f.admin).await.unwrap();
    let maintenance = bloc::storage::Storage::connect(&f.url("maintenance_user"), &f.ca)
        .await
        .unwrap();
    assert_eq!(maintenance.maintain_access().await.unwrap(), 2);
    sqlx::query("INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome,tenant_id,tenant_user_id,occurred_at) SELECT 1,(SELECT id FROM bloc.installation_administrator),CASE WHEN n%2=0 THEN 'tenant_user_update' ELSE 'tenant_update' END,'success',$1::text::uuid,CASE WHEN n%2=0 THEN $2::text::uuid ELSE NULL END,clock_timestamp()-interval '91 days' FROM generate_series(1,1001)n").bind(TENANT).bind(USER).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.administrator_denial_aggregate(minute,action,reason,count) SELECT clock_timestamp()-interval '8 days'-n*interval '1 minute','tenant_management','malformed',1 FROM generate_series(1,1001)n").execute(&f.admin).await.unwrap();
    assert_eq!(maintenance.maintain_access().await.unwrap(), 2000);
    let successes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bloc.security_audit_event WHERE action LIKE 'tenant%'",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(successes, 1);
    let denials:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.administrator_denial_aggregate WHERE minute<clock_timestamp()-interval '7 days'").fetch_one(&f.admin).await.unwrap();
    assert_eq!(denials, 1);
    assert_eq!(maintenance.maintain_access().await.unwrap(), 2);
    let nulls:bool=sqlx::query_scalar("SELECT bool_and(tenant_id IS NULL AND tenant_user_id IS NULL) FROM bloc.security_audit_event").fetch_one(&f.admin).await.unwrap();
    assert!(nulls);
    assert_eq!(b.request("GET", "/admin", &[]).await.0, 200);
});
check!(directory_c37, f, _b, {
    for role in [
        "runtime_user",
        "operator_user",
        "maintenance_user",
        "public_user",
    ] {
        let pool = f.pool(role).await;
        for table in ["tenant", "tenant_user"] {
            let query = format!("SELECT * FROM bloc.{table}");
            assert!(
                sqlx::query(sqlx::AssertSqlSafe(query))
                    .fetch_all(&pool)
                    .await
                    .is_err()
            );
        }
        if role != "runtime_user" {
            assert!(
                sqlx::query("SELECT * FROM bloc.directory_tenants($1,NULL,NULL,NULL)")
                    .bind(&[0u8; 32][..])
                    .fetch_all(&pool)
                    .await
                    .is_err()
            );
        }
    }
    let pool = f.pool("runtime_user").await;
    let session = sec::digest(&_b.cookies["__Host-bloc-admin"]);
    let outcome: String = sqlx::query_scalar(
        "SELECT bloc.directory_mutate($1,'tenant_create',$2::text::uuid,NULL,0,'Acme',NULL,NULL)",
    )
    .bind(session.as_slice())
    .bind(TENANT)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outcome, "ok");
    for expected in [None, Some(0), Some(-1)] {
        let outcome:String=sqlx::query_scalar("SELECT bloc.directory_mutate($1,'tenant_update',$2::text::uuid,NULL,$3,'Wrong',NULL,NULL)").bind(session.as_slice()).bind(TENANT).bind(expected).fetch_one(&pool).await.unwrap();
        assert_eq!(outcome, "stale");
    }
    for query in [
        "SELECT * FROM bloc.directory_tenants($1,NULL,NULL,NULL)",
        "SELECT * FROM bloc.directory_users($1,NULL,NULL,NULL,NULL)",
    ] {
        let e = sqlx::query(query)
            .bind(&[0u8; 32][..])
            .fetch_all(&pool)
            .await
            .unwrap_err();
        assert_eq!(
            e.as_database_error().unwrap().code().as_deref(),
            Some("28000")
        );
    }
    for role in [
        "runtime_user",
        "operator_user",
        "maintenance_user",
        "public_user",
    ] {
        let pool = f.pool(role).await;
        for query in [
            "INSERT INTO bloc.tenant(id,name,created_at,updated_at) VALUES(gen_random_uuid(),'Wrong',clock_timestamp(),clock_timestamp())",
            "UPDATE bloc.tenant SET name='Wrong'",
            "DELETE FROM bloc.tenant",
            "INSERT INTO bloc.tenant_user(id,tenant_id,email,created_at,updated_at) VALUES(gen_random_uuid(),gen_random_uuid(),'Wrong@example.com',clock_timestamp(),clock_timestamp())",
            "UPDATE bloc.tenant_user SET tenant_id=gen_random_uuid()",
            "DELETE FROM bloc.tenant_user",
        ] {
            let e = sqlx::query(query).execute(&pool).await.unwrap_err();
            assert_eq!(
                e.as_database_error().unwrap().code().as_deref(),
                Some("42501")
            );
        }
        for signature in [
            "bloc.directory_tenants(bytea,uuid,bigint,uuid)",
            "bloc.directory_users(bytea,uuid,uuid,bigint,uuid)",
            "bloc.directory_mutate(bytea,text,uuid,uuid,bigint,text,text,text)",
            "bloc.directory_authority(bytea)",
        ] {
            let allowed: bool =
                sqlx::query_scalar("SELECT has_function_privilege($1::name,$2,'EXECUTE')")
                    .bind(role)
                    .bind(signature)
                    .fetch_one(&f.admin)
                    .await
                    .unwrap();
            assert_eq!(
                allowed,
                role == "runtime_user" && !signature.starts_with("bloc.directory_authority")
            );
        }
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(n, 3);
    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version=3")
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(f.runtime.compatible().await.is_err());
    let app = Browser::new(&f).await;
    assert_eq!(
        app.app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        503
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(count, 2);
    // Rebuild a coherent legacy database through its original checksum migrations, then upgrade.
    sqlx::raw_sql("DROP SCHEMA bloc CASCADE; DROP TABLE public._sqlx_migrations")
        .execute(&f.admin)
        .await
        .unwrap();
    let old = sqlx::migrate::Migrator {
        migrations: vec![
            sqlx::migrate::Migration::new(
                1,
                "setup".into(),
                sqlx::migrate::MigrationType::Simple,
                sqlx::SqlStr::from_static(include_str!("../migrations/0001_setup.sql")),
                false,
            ),
            sqlx::migrate::Migration::new(
                2,
                "access".into(),
                sqlx::migrate::MigrationType::Simple,
                sqlx::SqlStr::from_static(include_str!("../migrations/0002_access.sql")),
                false,
            ),
        ]
        .into(),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    let migrator = f.pool("migrator_user").await;
    old.run(&migrator).await.unwrap();
    assert!(f.runtime.compatible().await.is_err());
    let operator = f.pool("operator_user").await;
    sqlx::query("SELECT bloc.issue_setup_code($1)")
        .bind(&[1u8; 32][..])
        .execute(&operator)
        .await
        .unwrap();
    sqlx::query("SELECT bloc.claim_owner($1,$2,$3)")
        .bind(&[1u8; 32][..])
        .bind(common::EMAIL)
        .bind(common::HASH)
        .execute(&pool)
        .await
        .unwrap();
    f.migrator.migrate().await.unwrap();
    f.runtime.compatible().await.unwrap();
    let nulls:bool=sqlx::query_scalar("SELECT bool_and(tenant_id IS NULL AND tenant_user_id IS NULL) FROM bloc.security_audit_event").fetch_one(&f.admin).await.unwrap();
    assert!(nulls);
    assert_eq!(f.count("installation_administrator").await, 1);
});
check!(directory_input_refusals, f, b, {
    create_tenant(&mut b, TENANT, "Acme").await;
    for path in [
        "/admin/tenants/new/users",
        "/admin/tenants/new/status",
        &format!("{}/users/new/status", tenant_path()),
    ] {
        assert_eq!(b.request("GET", path, &[]).await.0, 404, "{path}");
    }
    assert_eq!(
        b.request("GET", "/admin/tenants/not-a-uuid", &[]).await.0,
        404
    );
    assert_eq!(
        b.request("GET", "/admin/tenants?cursor=bad", &[]).await.0,
        422
    );
    for v in ["0", "-1", "bad", "9223372036854775808"] {
        assert_eq!(
            edit(&mut b, &tenant_path(), &[("name", "Wrong"), ("version", v)])
                .await
                .0,
            422
        );
    }
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", tenant_path()),
            &[("status", "unknown"), ("version", "1")]
        )
        .await
        .0,
        422
    );
    let csrf = b.token(&tenant_path()).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("csrf", csrf.as_str()), ("name", "Wrong"), ("version", "1")])
        .finish();
    assert_eq!(raw(&b, "HEAD", &tenant_path(), body, &[]).await.0, 200);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("csrf", csrf.as_str()),
            ("status", "suspended"),
            ("version", "1"),
        ])
        .finish();
    assert_eq!(
        raw(
            &b,
            "HEAD",
            &format!("{}/status?status=suspended&version=1", tenant_path()),
            body,
            &[]
        )
        .await
        .0,
        200
    );
    assert_eq!(tenant_row(&f).await.1, "active");
    assert_eq!(tenant_row(&f).await.0, "Acme");
    assert_eq!(events(&f).await, 1);
});
check!(directory_response_policy, _f, b, {
    create_tenant(&mut b, TENANT, "<script>name</script>").await;
    let (_, h, r) = b.request("GET", &tenant_path(), &[]).await;
    assert!(!h.contains("<script>name</script>"));
    let heading = h
        .split("<h1>")
        .nth(1)
        .unwrap()
        .split("</h1>")
        .next()
        .unwrap();
    assert!(!heading.contains('<'));
    assert_eq!(
        heading
            .replace("&#60;", "<")
            .replace("&#62;", ">")
            .replace("&lt;", "<")
            .replace("&gt;", ">"),
        "<script>name</script>"
    );
    let main = h
        .split("<main ")
        .nth(1)
        .unwrap()
        .split("</main>")
        .next()
        .unwrap();
    assert!(!main.contains("<script"));
    assert_eq!(r["vary"], "HX-Request");
    assert_eq!(r["cache-control"], "no-store");
    assert!(r.contains_key("content-security-policy"));
    let pages = [
        "/admin/tenants".into(),
        "/admin/tenants/new".into(),
        tenant_path(),
        format!("{}/users", tenant_path()),
        format!("{}/users/new", tenant_path()),
    ];
    for path in pages {
        let (status, html, headers) =
            raw(&b, "GET", &path, String::new(), &[("hx-request", "true")]).await;
        assert_eq!(status, 200);
        assert!(!html.contains("<!doctype"));
        assert_eq!(headers["vary"], "HX-Request");
        assert_eq!(headers["cache-control"], "no-store");
    }
    let csrf = b.token(&tenant_path()).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("csrf", csrf.as_str()),
            ("version", "1"),
            ("name", "Changed"),
        ])
        .finish();
    let (status, _, headers) =
        raw(&b, "POST", &tenant_path(), body, &[("hx-request", "true")]).await;
    assert_eq!(status, 200);
    assert_eq!(headers["hx-redirect"], tenant_path());
    assert_eq!(headers["vary"], "HX-Request");
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("csrf", csrf.as_str()), ("version", "2"), ("name", "Again")])
        .finish();
    let (status, _, headers) = raw(&b, "POST", &tenant_path(), body, &[]).await;
    assert_eq!(status, 303);
    assert_eq!(headers["location"], tenant_path());
    assert_eq!(headers["vary"], "HX-Request");
});

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
    let f = Fixture::new(&format!("directorybrowser{}", mode.replace('_', ""))).await;
    let services = services(&f).await;
    let python = std::env::var("BLOC_BROWSER_PYTHON").expect("explicit Playwright Python required");
    let spki = std::env::var("BLOC_TEST_SPKI").expect("explicit synthetic TLS SPKI required");
    let mut command = std::process::Command::new(python);
    command
        .args(["tests/support/directory_browser.py", mode])
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
async fn directory_screen_t1() {
    browser_proof("t1").await;
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn directory_screen_t2() {
    browser_proof("t2").await;
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn directory_screen_t3() {
    browser_proof("t3").await;
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn directory_screen_u1() {
    browser_proof("u1").await;
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn directory_screen_u2() {
    browser_proof("u2").await;
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn directory_screen_u3() {
    browser_proof("u3").await;
}
#[tokio::test]
#[ignore = "real browser and TLS proxy"]
async fn directory_browser_interactions() {
    browser_proof("interactions").await;
}
async fn raw(
    b: &Browser,
    method: &str,
    path: &str,
    body: String,
    extra: &[(&str, &str)],
) -> (StatusCode, String, axum::http::HeaderMap) {
    let mut headers = BTreeMap::from([
        ("host", "bloc.example.test".to_string()),
        ("x-forwarded-proto", "https".into()),
        ("x-forwarded-for", "192.0.2.4".into()),
        ("origin", "https://bloc.example.test".into()),
        ("content-type", "application/x-www-form-urlencoded".into()),
        (
            "cookie",
            b.cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        ),
    ]);
    for (k, v) in extra {
        headers.insert(k, (*v).into());
    }
    let mut request = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        request = request.header(k, v);
    }
    let mut request = request.body(Body::from(body)).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:54321".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = b.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let html = String::from_utf8(
        to_bytes(response.into_body(), 200000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, html, headers)
}
