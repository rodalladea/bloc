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
#[tokio::test]
#[ignore = "TLS fixture"]
async fn directory_c01() {
    let (f, mut b) = signed("directoryc01").await;
    let (s, h, _) = b.request("GET", "/admin/realms", &[]).await;
    assert_eq!(s, 200, "{h}");
    assert!(h.contains("No realms yet"));
    assert!(h.contains("Create realm"));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.realm")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn directory_c02() {
    let (f, mut b) = signed("directoryc02").await;
    let lower = database_time(&f).await;
    create_realm(&mut b, REALM, " Acme ").await;
    let (s, h, _) = b
        .request("GET", &format!("/admin/realms/{REALM}"), &[])
        .await;
    assert_eq!(s, 200);
    assert!(h.contains("Acme"));
    assert!(h.contains(REALM));
    assert!(h.contains("Active"));
    let row: (String, String, i64, bool) = sqlx::query_as(
        "SELECT name,status,version,created_at=updated_at FROM bloc.realm WHERE id=$1::text::uuid",
    )
    .bind(REALM)
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(row, ("Acme".into(), "active".into(), 1, true));
    metadata(&f, &h, false, lower, true).await;
}
async fn user(
    b: &mut Browser,
    realm: &str,
    id: &str,
    email: &str,
    name: &str,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let path = format!("/admin/realms/{realm}/users");
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
    if path.contains("/users/") && fields.iter().any(|(name, _)| *name == "email") {
        fields.push(("email_confirmed", "true"));
    }
    let result = b.request("POST", path, &fields).await;
    if result.0 == StatusCode::SEE_OTHER {
        assert_eq!(result.2["location"], path.trim_end_matches("/status"));
    }
    result
}
async fn events(f: &Fixture) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM bloc.security_audit_event WHERE action LIKE 'realm%'")
        .fetch_one(&f.admin)
        .await
        .unwrap()
}
async fn realm_row(f: &Fixture) -> (String, String, i64, String) {
    sqlx::query_as(
        "SELECT name,status,version,updated_at::text FROM bloc.realm WHERE id=$1::text::uuid",
    )
    .bind(REALM)
    .fetch_one(&f.admin)
    .await
    .unwrap()
}
async fn user_row(f: &Fixture) -> (String, Option<String>, String, i64, String) {
    sqlx::query_as("SELECT email,display_name,status,version,updated_at::text FROM bloc.realm_user WHERE id=$1::text::uuid").bind(USER).fetch_one(&f.admin).await.unwrap()
}
fn realm_path() -> String {
    format!("/admin/realms/{REALM}")
}
fn user_path() -> String {
    format!("/admin/realms/{REALM}/users/{USER}")
}

async fn database_time(f: &Fixture) -> i64 {
    sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
        .fetch_one(&f.admin)
        .await
        .unwrap()
}
fn record_value<'a>(html: &'a str, label: &str) -> &'a str {
    let tail = html.split(&format!("<dt>{label}</dt>")).nth(1).unwrap();
    tail.split_once('>')
        .unwrap()
        .1
        .split("</dd>")
        .next()
        .unwrap()
}
async fn metadata(f: &Fixture, html: &str, user: bool, lower: i64, initial: bool) {
    let table = if user { "realm_user" } else { "realm" };
    let id = if user { USER } else { REALM };
    let sql = format!(
        "SELECT version,(extract(epoch FROM created_at)*1000000)::bigint,(extract(epoch FROM updated_at)*1000000)::bigint,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),to_char(updated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM bloc.{table} WHERE id=$1::text::uuid"
    );
    let (version, created, updated, created_text, updated_text): (i64, i64, i64, String, String) =
        sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(id)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let upper = database_time(f).await;
    assert!(updated >= lower && updated <= upper);
    if initial {
        assert_eq!(created, updated);
        assert!(created >= lower);
    }
    assert_eq!(record_value(html, "Version"), version.to_string());
    assert_eq!(record_value(html, "Created"), created_text);
    assert_eq!(record_value(html, "Updated"), updated_text);
}
fn row_ids(html: &str) -> Vec<String> {
    html.split("<tr data-record=\"")
        .skip(1)
        .map(|s| s.split('"').next().unwrap().to_string())
        .collect()
}
fn no_extra_list_controls(html: &str) {
    for absent in [
        "Search",
        "Filter",
        "total",
        "Total",
        "Count",
        "type=\"search\"",
    ] {
        assert!(!html.contains(absent), "{absent}");
    }
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
    create_realm(&mut b, REALM, "Acme").await;
    create_realm(&mut b, OTHER, "Acme").await;
    let (_, h, _) = b.request("GET", "/admin/realms", &[]).await;
    assert!(h.contains(REALM) && h.contains(OTHER));
    assert_eq!(events(&f).await, 2);
});
check!(directory_c04, f, b, {
    let csrf = b.token("/admin/realms/new").await;
    let (status, _, _) = b
        .request(
            "POST",
            "/admin/realms",
            &[("csrf", &csrf), ("creation_id", REALM)],
        )
        .await;
    assert_eq!(status, 422);
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
                "/admin/realms",
                &[("csrf", &csrf), ("creation_id", REALM), ("name", &name)],
            )
            .await;
        assert_eq!(s, 422, "{h}");
        assert!(h.contains("control characters"));
        if !name.contains('\n') {
            assert!(h.contains(&format!("value=\"{name}\"")));
        }
    }
    assert_eq!(events(&f).await, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM bloc.realm")
            .fetch_one(&f.admin)
            .await
            .unwrap(),
        0
    );
    create_realm(&mut b, REALM, &"😀".repeat(128)).await;
});
check!(directory_c05, f, b, {
    let csrf = b.token("/admin/realms/new").await;
    let mut c = Browser::new(&f).await;
    c.cookies = b.cookies.clone();
    let fields = [
        ("csrf", csrf.as_str()),
        ("creation_id", REALM),
        ("name", "Acme"),
    ];
    let (a, z) = tokio::join!(
        b.request("POST", "/admin/realms", &fields),
        c.request("POST", "/admin/realms", &fields)
    );
    let mut codes = [a.0.as_u16(), z.0.as_u16()];
    codes.sort();
    assert_eq!(codes, [303, 409]);
    assert!((a.1 + &z.1).contains("Review existing realm"));
    assert_eq!(events(&f).await, 1);
    let original = realm_row(&f).await;
    assert_eq!((original.0.as_str(), original.2), ("Acme", 1));
    let (s, h, _) = b
        .request(
            "POST",
            "/admin/realms",
            &[
                ("csrf", &csrf),
                ("creation_id", REALM),
                ("name", "Replacement"),
            ],
        )
        .await;
    assert_eq!(s, 409);
    assert!(h.contains(&format!("href=\"{}\">Review existing realm", realm_path())));
    assert_eq!(realm_row(&f).await, original);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM bloc.realm")
            .fetch_one(&f.admin)
            .await
            .unwrap(),
        1
    );
    assert_eq!(events(&f).await, 1);
});
check!(directory_c06, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    assert_eq!(
        user(&mut b, REALM, USER, "Alice@example.com", "").await.0,
        303
    );
    let old = realm_row(&f).await;
    let lower = database_time(&f).await;
    assert_eq!(
        edit(
            &mut b,
            &realm_path(),
            &[("name", "Renamed"), ("version", "1")]
        )
        .await
        .0,
        303
    );
    let new = realm_row(&f).await;
    assert_eq!((new.0, new.2), ("Renamed".into(), 2));
    assert_ne!(old.3, new.3);
    let parent: String = sqlx::query_scalar("SELECT realm_id::text FROM bloc.realm_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(parent, REALM);
    let (_, html, _) = b.request("GET", &realm_path(), &[]).await;
    metadata(&f, &html, false, lower, false).await;
});
check!(directory_c07, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    let old = user_row(&f).await;
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", realm_path()),
            &[("status", "suspended"), ("version", "1")]
        )
        .await
        .0,
        303
    );
    assert_eq!(user_row(&f).await, old);
    assert_eq!(realm_row(&f).await.1, "suspended");
    let (_, h, _) = b.request("GET", &realm_path(), &[]).await;
    assert!(h.contains("user statuses"));
    assert!(h.contains(">Suspended</span>"));
});
check!(directory_c08, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
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
                &format!("{}/status", realm_path()),
                &[("status", s), ("version", v)]
            )
            .await
            .0,
            303
        );
    }
    assert_eq!(realm_row(&f).await.1, "active");
    assert_eq!(user_row(&f).await.2, "suspended");
    let (s, h, _) = b.request("GET", &realm_path(), &[]).await;
    assert_eq!(s, 200);
    assert!(h.contains(">Active</span>"));
});
check!(directory_c09, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    edit(
        &mut b,
        &format!("{}/status", realm_path()),
        &[("status", "suspended"), ("version", "1")],
    )
    .await;
    assert_eq!(
        user(&mut b, REALM, USER, "Alice@example.com", "").await.0,
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
            &realm_path(),
            &[("name", "Renamed"), ("version", "2")]
        )
        .await
        .0,
        303
    );
    let (_, h, _) = b.request("GET", &user_path(), &[]).await;
    assert!(h.contains("This realm is suspended"));
    assert_eq!(realm_row(&f).await.1, "suspended");
    let (s, h, _) = b.request("GET", "/admin/realms", &[]).await;
    assert_eq!(s, 200);
    assert!(h.contains(REALM));
    assert!(h.contains("Renamed"));
    assert!(h.contains("Suspended"));
});
check!(directory_c10, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    let csrf = b.token(&realm_path()).await;
    let mut c = Browser::new(&f).await;
    c.cookies = b.cookies.clone();
    let a = [("csrf", csrf.as_str()), ("name", "One"), ("version", "1")];
    let z = [("csrf", csrf.as_str()), ("name", "Two"), ("version", "1")];
    let path = realm_path();
    let (a, z) = tokio::join!(b.request("POST", &path, &a), c.request("POST", &path, &z));
    let mut codes = [a.0.as_u16(), z.0.as_u16()];
    codes.sort();
    assert_eq!(codes, [303, 409]);
    let winner = if a.0 == 303 { "One" } else { "Two" };
    let snapshot = realm_row(&f).await;
    assert_eq!(
        (snapshot.0.as_str(), snapshot.1.as_str(), snapshot.2),
        (winner, "active", 2)
    );
    assert!((a.1 + &z.1).contains("Reload current record"));
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", realm_path()),
            &[("status", "suspended"), ("version", "1")]
        )
        .await
        .0,
        409
    );
    assert_eq!(events(&f).await, 2);
    assert_eq!(realm_row(&f).await, snapshot);
});
check!(directory_c11, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    let old = realm_row(&f).await;
    assert_eq!(
        edit(
            &mut b,
            &realm_path(),
            &[("name", " Acme "), ("version", "1")]
        )
        .await
        .0,
        303
    );
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", realm_path()),
            &[("status", "active"), ("version", "1")]
        )
        .await
        .0,
        303
    );
    assert_eq!(old, realm_row(&f).await);
    assert_eq!(events(&f).await, 1);
});
check!(directory_c12, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    edit(
        &mut b,
        &realm_path(),
        &[("name", "Renamed"), ("version", "1")],
    )
    .await;
    let mut c = Browser::new(&f).await;
    c.cookies = b.cookies.clone();
    let (s, h, _) = c.request("GET", &realm_path(), &[]).await;
    assert_eq!(s, 200);
    assert!(h.contains("Renamed"));
    assert!(h.contains(REALM));
    assert!(h.contains(">2<"));
    assert!(h.contains(">Active</span>"));
    let mut processes = services(&f).await;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: bloc.example.test:4443\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 192.0.2.4\r\nCookie: __Host-bloc-admin={}\r\nConnection: close\r\n\r\n",
        realm_path(),
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
    assert!(restarted.contains(REALM));
    assert!(restarted.contains(">2<"));
    assert!(restarted.contains(">Active</span>"));
});
async fn seed_realms(b: &mut Browser, n: usize) {
    for i in 1..=n {
        create_realm(b, &format!("00000000-0000-4000-8000-{i:012}"), "Repeated").await;
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
    seed_realms(&mut b, 51).await;
    sqlx::query("UPDATE bloc.realm SET created_at='2026-01-01T00:00:00Z'")
        .execute(&f.admin)
        .await
        .unwrap();
    let (_, h, _) = b.request("GET", "/admin/realms", &[]).await;
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
    no_extra_list_controls(&h);
    assert_eq!(
        row_ids(&h),
        (1..=50)
            .map(|i| format!("00000000-0000-4000-8000-{i:012}"))
            .collect::<Vec<_>>()
    );
    sqlx::query("UPDATE bloc.realm SET created_at='2026-01-01T00:00:00Z'::timestamptz + (substring(id::text,25)::bigint % 7)*interval '1 second'").execute(&f.admin).await.unwrap();
    let expected: Vec<String> =
        sqlx::query_scalar("SELECT id::text FROM bloc.realm ORDER BY created_at,id")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    let (_, first, _) = b.request("GET", "/admin/realms", &[]).await;
    let (_, last, _) = b.request("GET", &next(&first), &[]).await;
    assert_eq!(row_ids(&first), expected[..50]);
    assert_eq!(row_ids(&last), expected[50..]);
    assert!(!last.contains("rel=\"next\""));
    no_extra_list_controls(&last);
});
check!(directory_c14, f, b, {
    let (_, h, _) = b.request("GET", "/admin/realms/new", &[]).await;
    assert!(h.contains(">Cancel</a>"));
    assert_eq!(events(&f).await, 0);
    create_realm(&mut b, REALM, "Acme").await;
    let (_, h, _) = b
        .request(
            "GET",
            &format!("{}/status?status=suspended&version=1", realm_path()),
            &[],
        )
        .await;
    assert!(h.contains("Suspend this realm?"));
    assert!(h.contains(REALM));
    assert!(h.contains("name=\"version\" value=\"1\""));
    assert_eq!(events(&f).await, 1);
});
check!(directory_c15, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    let (s, h, _) = b
        .request("GET", &format!("{}/users", realm_path()), &[])
        .await;
    assert_eq!(s, 200);
    for text in ["No users yet", "Create user", "Acme", REALM] {
        assert!(h.contains(text));
    }
    assert_eq!(events(&f).await, 1);
});
check!(directory_c16, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    let lower = database_time(&f).await;
    let (s, h, r) = user(&mut b, REALM, USER, " Alice@EXAMPLE.com ", " Alice ").await;
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
    for text in [
        USER,
        REALM,
        "Unverified",
        "Sign-in also requires credentials and an active realm. Suspension ends sessions and access links.",
    ] {
        assert!(h.contains(text));
    }
    let equal: bool = sqlx::query_scalar("SELECT created_at=updated_at FROM bloc.realm_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert!(equal);
    assert!(h.contains(">Active</span>"));
    let lifecycle = h
        .split("<h2>User status</h2>")
        .nth(1)
        .unwrap()
        .split("<dl>")
        .next()
        .unwrap();
    assert!(lifecycle.contains(">Active</span>"));
    metadata(&f, &h, true, lower, true).await;
});
check!(directory_c17, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    create_realm(&mut b, OTHER, "Contoso").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    assert_eq!(
        user(&mut b, OTHER, OTHER, "Alice@example.com", "").await.0,
        303
    );
    let changed = edit(
        &mut b,
        &user_path(),
        &[("email", "Bob@example.com"), ("version", "1")],
    )
    .await;
    assert_eq!(changed.0, 303);
    assert_eq!(changed.2["location"], user_path());
    assert_eq!(user_row(&f).await.0, "Bob@example.com");
    let other_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM bloc.realm_user WHERE id=$1::text::uuid")
            .bind(OTHER)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(other_name, None);
    let row: (String, i64, String) =
        sqlx::query_as("SELECT email,version,status FROM bloc.realm_user WHERE id=$1::text::uuid")
            .bind(OTHER)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(row, ("Alice@example.com".into(), 1, "active".into()));
});
check!(directory_c18, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    edit(
        &mut b,
        &format!("{}/status", user_path()),
        &[("status", "suspended"), ("version", "1")],
    )
    .await;
    for email in ["Alice@EXAMPLE.com", " Alice@example.com "] {
        assert_eq!(user(&mut b, REALM, OTHER, email, "").await.0, 409);
    }
    assert_eq!(
        user(&mut b, REALM, OTHER, "alice@example.com", "").await.0,
        303
    );
    assert_eq!(events(&f).await, 4);
});
check!(directory_c19, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    for email in [
        "Alice@",
        "é@example.com",
        "a b@example.com",
        "a..b@example.com",
    ] {
        assert!(bloc::credentials::normalize_email(email).is_err());
        assert_eq!(user(&mut b, REALM, USER, email, "").await.0, 422);
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
        assert_eq!(user(&mut b, REALM, USER, &email, "").await.0, 422);
    }
    assert_eq!(events(&f).await, 1);
    assert_eq!(
        user(&mut b, REALM, USER, "Alice+tag@EXAMPLE.com", "")
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
    assert_eq!(user(&mut b, REALM, OTHER, &maximum, "").await.0, 303);
    let old = user_row(&f).await;
    let n = events(&f).await;
    let (status, html, _) = edit(
        &mut b,
        &user_path(),
        &[("email", "bad email"), ("version", "1")],
    )
    .await;
    assert_eq!(status, 422);
    assert!(html.contains("id=\"email-error\""));
    assert!(html.contains("Enter a valid ASCII email address, up to 254 bytes."));
    assert_eq!(user_row(&f).await, old);
    assert_eq!(events(&f).await, n);
});
check!(directory_c20, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    for name in ["bad\nname".into(), "a".repeat(129), "😀".repeat(129)] {
        let (s, h, _) = user(&mut b, REALM, USER, "Alice@example.com", &name).await;
        assert_eq!(s, 422);
        assert!(h.contains("Control characters"));
        if !name.contains('\n') {
            assert!(h.contains(&format!("name=\"display_name\" value=\"{name}\"")));
        }
    }
    assert_eq!(events(&f).await, 1);
    assert_eq!(
        user(&mut b, REALM, USER, "Alice@example.com", "  ").await.0,
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
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "Alice").await;
    let old = user_row(&f).await;
    let original_targets: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id::text,realm_id::text,realm_user_id::text FROM bloc.security_audit_event ORDER BY id",
    )
    .fetch_all(&f.admin)
    .await
    .unwrap();
    let lower = database_time(&f).await;
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
    assert_eq!(
        (&new.0, &new.1, &new.2),
        (
            &"Bob@example.com".to_string(),
            &Some("Bob".to_string()),
            &old.2
        )
    );
    let parent: String =
        sqlx::query_scalar("SELECT realm_id::text FROM bloc.realm_user WHERE id=$1::text::uuid")
            .bind(USER)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(parent, REALM);
    let preserved:Vec<(String,Option<String>,Option<String>)>=sqlx::query_as("SELECT id::text,realm_id::text,realm_user_id::text FROM bloc.security_audit_event WHERE id::text=ANY($1) ORDER BY id").bind(original_targets.iter().map(|r|r.0.clone()).collect::<Vec<_>>()).fetch_all(&f.admin).await.unwrap();
    assert_eq!(preserved, original_targets);
    let (_, h, _) = b.request("GET", &user_path(), &[]).await;
    metadata(&f, &h, true, lower, false).await;
});
check!(directory_c22, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    let parent = realm_row(&f).await;
    for (v, s) in [("1", "suspended"), ("2", "active"), ("3", "active")] {
        let before = user_row(&f).await;
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
        let after = user_row(&f).await;
        assert_eq!(after.2, s);
        if v == "3" {
            assert_eq!(before, after);
        }
        let (_, h, _) = b.request("GET", &user_path(), &[]).await;
        assert!(h.contains(USER));
        let expected = if s == "active" { "Active" } else { "Suspended" };
        assert!(h.contains(&format!(">{expected}</span>")));
    }
    assert_eq!(user_row(&f).await.3, 3);
    assert_eq!(events(&f).await, 4);
    assert_eq!(parent, realm_row(&f).await);
});
check!(directory_c23, _f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    for (tv, uv, text) in [
        ("1", "1", "Active"),
        ("1", "1", "Realm suspended"),
        ("2", "1", "Realm suspended and user suspended"),
    ] {
        let (_, h, _) = b.request("GET", &user_path(), &[]).await;
        assert!(h.contains("Combined directory status"));
        assert_eq!(record_value(&h, "Combined directory status"), text);
        assert!(h.contains("Sign-in also requires credentials and an active realm. Suspension ends sessions and access links."));
        if tv == "1" && uv == "1" && text == "Active" {
            edit(
                &mut b,
                &format!("{}/status", realm_path()),
                &[("version", tv), ("status", "suspended")],
            )
            .await;
        } else if text == "Realm suspended" {
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
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", realm_path()),
            &[("version", "2"), ("status", "active")]
        )
        .await
        .0,
        303
    );
    let (_, h, _) = b.request("GET", &user_path(), &[]).await;
    assert_eq!(record_value(&h, "Realm status"), "Active");
    assert_eq!(
        record_value(&h, "Combined directory status"),
        "User suspended"
    );
    assert!(h.contains("Sign-in also requires credentials and an active realm. Suspension ends sessions and access links."));
});
check!(directory_c24, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    for field in ["realm_id", "roles", "verified", "password"] {
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
        "/admin/realms".into(),
        realm_path(),
        format!("{}/status", realm_path()),
        format!("{}/users", realm_path()),
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
    create_realm(&mut b, REALM, "Acme").await;
    create_realm(&mut b, OTHER, "Contoso").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    let csrf = b.token(&user_path()).await;
    for target in [USER, OTHER] {
        let path = format!("/admin/realms/{OTHER}/users/{target}");
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
    sqlx::query("SELECT set_config('bloc.realm_id',$1,false)")
        .bind(REALM)
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
        let a = format!("/admin/realms/{OTHER}/users/{USER}{suffix}");
        let z = format!("/admin/realms/{OTHER}/users/{OTHER}{suffix}");
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
    create_realm(&mut b, REALM, "Acme").await;
    let csrf = b.token(&format!("{}/users/new", realm_path())).await;
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
    let path = format!("{}/users", realm_path());
    let (a, z) = tokio::join!(b.request("POST", &path, &a), c.request("POST", &path, &z));
    let mut codes = [a.0.as_u16(), z.0.as_u16()];
    codes.sort();
    assert_eq!(codes, [303, 409]);
    let first: String = sqlx::query_scalar("SELECT id::text FROM bloc.realm_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    let second = "44444444-4444-4444-8444-444444444444";
    assert_eq!(
        user(&mut b, REALM, second, "Second@example.com", "")
            .await
            .0,
        303
    );
    let left = format!("{}/users/{first}", realm_path());
    let right = format!("{}/users/{second}", realm_path());
    let csrf = b.token(&left).await;
    c.cookies = b.cookies.clone();
    let a = [
        ("csrf", csrf.as_str()),
        ("email", "Shared@EXAMPLE.com"),
        ("email_confirmed", "true"),
        ("version", "1"),
    ];
    let z = [
        ("csrf", csrf.as_str()),
        ("email", " Shared@example.com "),
        ("email_confirmed", "true"),
        ("version", "1"),
    ];
    let (a, z) = tokio::join!(b.request("POST", &left, &a), c.request("POST", &right, &z));
    let mut codes = [a.0.as_u16(), z.0.as_u16()];
    codes.sort();
    assert_eq!(codes, [303, 409]);
    assert_eq!(events(&f).await, 4);
});
check!(directory_c27, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    create_realm(&mut b, OTHER, "Contoso").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    let original = user_row(&f).await;
    let (s, h, _) = user(&mut b, REALM, USER, "Bob@example.com", "Replacement").await;
    assert_eq!(s, 409);
    assert!(h.contains("Review existing user"));
    assert!(h.contains(&format!("href=\"{}\">Review existing user", user_path())));
    assert_eq!(user_row(&f).await, original);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM bloc.realm_user")
            .fetch_one(&f.admin)
            .await
            .unwrap(),
        1
    );
    let (s, h, _) = user(&mut b, OTHER, USER, "Bob@example.com", "").await;
    assert_eq!(s, 409);
    assert!(!h.contains("Review existing user"));
    assert!(!h.contains(USER));
    assert!(!h.contains("Alice@example.com"));
    assert_eq!(events(&f).await, 3);
});
check!(directory_c28, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    let csrf = b.token(&user_path()).await;
    let mut c = Browser::new(&f).await;
    c.cookies = b.cookies.clone();
    let a = [
        ("csrf", csrf.as_str()),
        ("email", "Bob@example.com"),
        ("email_confirmed", "true"),
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
    create_realm(&mut b, REALM, "Acme").await;
    create_realm(&mut b, OTHER, "Contoso").await;
    user(&mut b, OTHER, OTHER, "Other@example.com", "").await;
    for i in 1..=51 {
        assert_eq!(
            user(
                &mut b,
                REALM,
                &format!("00000000-0000-4000-8000-{i:012}"),
                &format!("User{i}@example.com"),
                ""
            )
            .await
            .0,
            303
        );
    }
    let path = format!("{}/users", realm_path());
    let (_, h, _) = b.request("GET", &path, &[]).await;
    assert_eq!(h.matches("<tr data-record=").count(), 50);
    assert!(!h.contains("Other@example.com"));
    let (_, last, _) = b.request("GET", &next(&h), &[]).await;
    assert_eq!(last.matches("<tr data-record=").count(), 1);
    assert_eq!(events(&f).await, 54);
    sqlx::query("UPDATE bloc.realm_user SET created_at='2026-01-01T00:00:00Z'::timestamptz + (substring(id::text,25)::bigint % 7)*interval '1 second' WHERE realm_id=$1::text::uuid").bind(REALM).execute(&f.admin).await.unwrap();
    let expected: Vec<String> = sqlx::query_scalar(
        "SELECT id::text FROM bloc.realm_user WHERE realm_id=$1::text::uuid ORDER BY created_at,id",
    )
    .bind(REALM)
    .fetch_all(&f.admin)
    .await
    .unwrap();
    let (_, first, _) = b.request("GET", &path, &[]).await;
    let (_, last, _) = b.request("GET", &next(&first), &[]).await;
    assert_eq!(row_ids(&first), expected[..50]);
    assert_eq!(row_ids(&last), expected[50..]);
    assert!(!first.contains(OTHER));
    assert!(!last.contains(OTHER));
    assert!(!last.contains("rel=\"next\""));
    no_extra_list_controls(&first);
    no_extra_list_controls(&last);
});
check!(directory_c30, f, b, {
    create_realm(&mut b, REALM, "Private").await;
    user(&mut b, REALM, USER, "Private@example.com", "").await;
    let mut unauth = Browser::new(&f).await;
    for path in [
        "/admin/realms".into(),
        "/admin/realms/new".into(),
        realm_path(),
        format!("{}/status", realm_path()),
        format!("{}/users", realm_path()),
        format!("{}/users/new", realm_path()),
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
        "/admin/realms".into(),
        "/admin/realms/new".into(),
        realm_path(),
        format!("{}/status", realm_path()),
        format!("{}/users", realm_path()),
        format!("{}/users/new", realm_path()),
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
    let snapshot = user_row(&f).await;
    let n = events(&f).await;
    sqlx::query("UPDATE bloc.administrator_session SET last_activity_at=clock_timestamp()-interval '30 minutes'").execute(&f.admin).await.unwrap();
    for method in ["GET", "POST"] {
        for enhanced in [false, true] {
            let extra = if enhanced {
                vec![("hx-request", "true")]
            } else {
                vec![]
            };
            let (code, h, headers) = raw(&b, method, &user_path(), String::new(), &extra).await;
            assert_eq!(code, if enhanced { 401 } else { 303 });
            assert_eq!(
                headers[if enhanced { "hx-redirect" } else { "location" }],
                "/admin/login?expired=1"
            );
            assert!(!h.contains("Private"));
        }
    }
    assert_eq!(user_row(&f).await, snapshot);
    assert_eq!(events(&f).await, n);
    b.login().await;
    f.operator.invalidate_access().await.unwrap();
    let (s, h, _) = b.request("GET", &realm_path(), &[]).await;
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
                let outcome:String=sqlx::query_scalar("SELECT bloc.directory_mutate($1,'realm_create',$2::text::uuid,NULL,0,'Acme',NULL,NULL)").bind(&[9u8;32][..]).bind(REALM).fetch_one(&mut *lock).await.unwrap();
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
                sqlx::query_scalar::<_,String>("SELECT bloc.directory_mutate($1,'realm_create',$2::text::uuid,NULL,0,'Wrong',NULL,NULL)").bind(&[9u8;32][..]).bind(OTHER).fetch_one(&runtime).await
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
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    let csrf = b.token(&realm_path()).await;
    let valid = format!("csrf={csrf}&name=Wrong&version=1");
    let routes = [
        "/admin/realms".into(),
        realm_path(),
        format!("{}/status", realm_path()),
        format!("{}/users", realm_path()),
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
            &realm_path(),
            &[("csrf", "wrong"), ("name", "Wrong"), ("version", "1")],
        )
        .await;
    assert_eq!(s, 403);
    let csrf = b.token(&realm_path()).await;
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
            &realm_path(),
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
            &realm_path(),
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
            &realm_path(),
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
                "/admin/realms/new",
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
        "/admin/realms/new",
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
        realm_path(),
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
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    let original = user_row(&f).await;
    let csrf = b.token(&realm_path()).await;
    f.fail_audit(true).await;
    let (s, h, _) = b
        .request(
            "POST",
            &realm_path(),
            &[("csrf", &csrf), ("name", "Wrong"), ("version", "1")],
        )
        .await;
    assert_eq!(s, 503);
    assert!(!h.contains("Acme"));
    assert_eq!(realm_row(&f).await.0, "Acme");
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
        user(&mut b, REALM, OTHER, "New@example.com", "").await.0,
        503
    );
    assert_eq!(user_row(&f).await, original);
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.realm_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(users, 1);
    assert_eq!(events(&f).await, 2);
    f.fail_audit(false).await;
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
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND usename='runtime_user'").bind(&f.database).execute(&f.admin).await.unwrap();
    for method in ["GET", "POST"] {
        let (status, h, _) = b
            .request(
                method,
                &realm_path(),
                &[
                    ("csrf", &csrf),
                    ("name", "Unavailable change"),
                    ("version", "1"),
                ],
            )
            .await;
        assert_eq!(status, 503);
        assert!(!h.contains("No realms yet"));
        assert!(!h.contains("Acme"));
    }
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER DATABASE {} ALLOW_CONNECTIONS true",
        f.database
    )))
    .execute(&root)
    .await
    .unwrap();
    assert_eq!(realm_row(&f).await.0, "Acme");
    assert_eq!(user_row(&f).await, original);
    assert_eq!(events(&f).await, 2);
    sqlx::query("UPDATE public._sqlx_migrations SET checksum='invalid'::bytea WHERE version=3")
        .execute(&f.admin)
        .await
        .unwrap();
    let (s, h, _) = b.request("GET", "/admin/realms", &[]).await;
    assert_eq!(s, 503);
    assert!(!h.contains("No realms yet"));
});
check!(directory_c34, f, b, {
    let lower = database_time(&f).await;
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    edit(
        &mut b,
        &realm_path(),
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
            &format!("{}/status", realm_path()),
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
    let rows:Vec<(String,String,Option<String>,bool)>=sqlx::query_as("SELECT action,realm_id::text,realm_user_id::text,administrator_id IS NOT NULL AND request_id IS NOT NULL AND occurred_at<=clock_timestamp() FROM bloc.security_audit_event WHERE action LIKE 'realm%' ORDER BY occurred_at").fetch_all(&f.admin).await.unwrap();
    assert_eq!(rows.len(), 8);
    let mut actual = rows.iter().map(|r| r.0.as_str()).collect::<Vec<_>>();
    actual.sort();
    assert_eq!(
        actual,
        vec![
            "realm_create",
            "realm_reactivate",
            "realm_suspend",
            "realm_update",
            "realm_user_create",
            "realm_user_reactivate",
            "realm_user_suspend",
            "realm_user_update"
        ]
    );
    let valid:bool=sqlx::query_scalar("SELECT bool_and(administrator_id=(SELECT id FROM bloc.installation_administrator) AND (extract(epoch FROM occurred_at)*1000000)::bigint BETWEEN $1 AND (extract(epoch FROM clock_timestamp())*1000000)::bigint AND request_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') FROM bloc.security_audit_event WHERE action LIKE 'realm%'").bind(lower).fetch_one(&f.admin).await.unwrap();
    assert!(valid);
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(DISTINCT request_id) FROM bloc.security_audit_event WHERE action LIKE 'realm%'").fetch_one(&f.admin).await.unwrap(),8);
    for (action, t, u, valid) in rows {
        assert_eq!(t, REALM);
        assert!(valid);
        assert_eq!(
            u,
            if action.starts_with("realm_user_") {
                Some(USER.into())
            } else {
                None
            }
        );
    }
    assert_eq!(
        edit(
            &mut b,
            &realm_path(),
            &[("name", "Renamed"), ("version", "4")]
        )
        .await
        .0,
        303
    );
    assert_eq!(events(&f).await, 8);
    let csrf = b.token("/admin/realms/new").await;
    assert_eq!(
        b.request(
            "POST",
            "/admin/realms",
            &[("csrf", &csrf), ("creation_id", REALM), ("name", "Replace")]
        )
        .await
        .0,
        409
    );
    assert_eq!(
        user(&mut b, REALM, USER, "Replace@example.com", "").await.0,
        409
    );
    assert_eq!(
        edit(&mut b, &realm_path(), &[("name", ""), ("version", "4")])
            .await
            .0,
        422
    );
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", realm_path()),
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
    create_realm(&mut b, REALM, "Secret name").await;
    user(&mut b, REALM, USER, "Secret@example.com", "Secret display").await;
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
    let _ = b.request("POST", &realm_path(), &[]).await;
    assert_eq!(
        b.request("POST", &user_path(), &[("csrf", "invalid")])
            .await
            .0,
        403
    );
    let actions:Vec<String>=sqlx::query_scalar("SELECT DISTINCT action FROM bloc.administrator_denial_aggregate WHERE action LIKE 'realm%' ORDER BY action").fetch_all(&f.admin).await.unwrap();
    assert_eq!(actions, vec!["realm_management", "realm_user_management"]);
});
check!(directory_c36, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    user(&mut b, REALM, USER, "Alice@example.com", "").await;
    sqlx::query("UPDATE bloc.security_audit_event SET occurred_at=clock_timestamp()-interval '91 days' WHERE action LIKE 'realm%'").execute(&f.admin).await.unwrap();
    let maintenance = bloc::storage::Storage::connect(&f.url("maintenance_user"), &f.ca)
        .await
        .unwrap();
    assert_eq!(maintenance.maintain_access().await.unwrap(), 2);
    sqlx::query("INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome,realm_id,realm_user_id,occurred_at) SELECT 1,(SELECT id FROM bloc.installation_administrator),CASE WHEN n%2=0 THEN 'realm_user_update' ELSE 'realm_update' END,'success',$1::text::uuid,CASE WHEN n%2=0 THEN $2::text::uuid ELSE NULL END,clock_timestamp()-interval '91 days' FROM generate_series(1,1001)n").bind(REALM).bind(USER).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.administrator_denial_aggregate(minute,action,reason,count) SELECT clock_timestamp()-interval '8 days'-n*interval '1 minute','realm_management','malformed',1 FROM generate_series(1,1001)n").execute(&f.admin).await.unwrap();
    assert_eq!(maintenance.maintain_access().await.unwrap(), 2000);
    let successes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bloc.security_audit_event WHERE action LIKE 'realm%'",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(successes, 1);
    let denials:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.administrator_denial_aggregate WHERE minute<clock_timestamp()-interval '7 days'").fetch_one(&f.admin).await.unwrap();
    assert_eq!(denials, 1);
    assert_eq!(maintenance.maintain_access().await.unwrap(), 2);
    let nulls:bool=sqlx::query_scalar("SELECT bool_and(realm_id IS NULL AND realm_user_id IS NULL) FROM bloc.security_audit_event").fetch_one(&f.admin).await.unwrap();
    assert!(nulls);
    assert_eq!(b.request("GET", "/admin", &[]).await.0, 200);
    let csrf = b.token("/admin").await;
    assert_eq!(
        b.request("POST", "/admin/logout", &[("csrf", &csrf)])
            .await
            .0,
        303
    );
    assert_eq!(b.request("GET", "/admin", &[]).await.0, 303);
    b.login().await;
    let csrf = b.token("/admin/password").await;
    let (status, _, headers) = b
        .request(
            "POST",
            "/admin/password",
            &[
                ("csrf", &csrf),
                ("current_password", "a synthetic password"),
                ("password", "a replacement synthetic password"),
                ("password_confirmation", "a replacement synthetic password"),
            ],
        )
        .await;
    assert_eq!(status, 303);
    assert_eq!(headers["location"], "/admin/login");
    let csrf = b.token("/admin/login").await;
    assert_eq!(
        b.request(
            "POST",
            "/admin/login",
            &[
                ("csrf", &csrf),
                ("email", "Owner@example.test"),
                ("password", "a replacement synthetic password")
            ]
        )
        .await
        .0,
        303
    );
    assert_eq!(b.request("GET", "/admin", &[]).await.0, 200);
    let csrf = b.token("/admin").await;
    assert_eq!(
        b.request("POST", "/admin/logout", &[("csrf", &csrf)])
            .await
            .0,
        303
    );
    assert_eq!(b.request("GET", "/admin", &[]).await.0, 303);
});
check!(directory_c37, f, _b, {
    for role in [
        "runtime_user",
        "operator_user",
        "maintenance_user",
        "public_user",
    ] {
        let pool = f.pool(role).await;
        for table in ["realm", "realm_user"] {
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
                sqlx::query("SELECT * FROM bloc.directory_realms($1,NULL,NULL,NULL)")
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
        "SELECT bloc.directory_mutate($1,'realm_create',$2::text::uuid,NULL,0,'Acme',NULL,NULL)",
    )
    .bind(session.as_slice())
    .bind(REALM)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outcome, "ok");
    for expected in [None, Some(0), Some(-1)] {
        let outcome:String=sqlx::query_scalar("SELECT bloc.directory_mutate($1,'realm_update',$2::text::uuid,NULL,$3,'Wrong',NULL,NULL)").bind(session.as_slice()).bind(REALM).bind(expected).fetch_one(&pool).await.unwrap();
        assert_eq!(outcome, "stale");
    }
    for query in [
        "SELECT * FROM bloc.directory_realms($1,NULL,NULL,NULL)",
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
            "INSERT INTO bloc.realm(id,name,created_at,updated_at) VALUES(gen_random_uuid(),'Wrong',clock_timestamp(),clock_timestamp())",
            "UPDATE bloc.realm SET name='Wrong'",
            "DELETE FROM bloc.realm",
            "INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES(gen_random_uuid(),gen_random_uuid(),'Wrong@example.com',clock_timestamp(),clock_timestamp())",
            "UPDATE bloc.realm_user SET realm_id=gen_random_uuid()",
            "DELETE FROM bloc.realm_user",
        ] {
            let e = sqlx::query(query).execute(&pool).await.unwrap_err();
            assert_eq!(
                e.as_database_error().unwrap().code().as_deref(),
                Some("42501")
            );
        }
        for signature in [
            "bloc.directory_realms(bytea,uuid,bigint,uuid)",
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
    assert_eq!(n, 5);
    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version=4")
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
    assert_eq!(count, 4);
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
    let nulls:bool=sqlx::query_scalar("SELECT bool_and(realm_id IS NULL AND realm_user_id IS NULL) FROM bloc.security_audit_event").fetch_one(&f.admin).await.unwrap();
    assert!(nulls);
    assert_eq!(f.count("installation_administrator").await, 1);
});
check!(directory_input_refusals, f, b, {
    create_realm(&mut b, REALM, "Acme").await;
    for path in [
        "/admin/realms/new/users",
        "/admin/realms/new/status",
        &format!("{}/users/new/status", realm_path()),
    ] {
        assert_eq!(b.request("GET", path, &[]).await.0, 404, "{path}");
    }
    assert_eq!(
        b.request("GET", "/admin/realms/not-a-uuid", &[]).await.0,
        404
    );
    assert_eq!(
        b.request("GET", "/admin/realms?cursor=bad", &[]).await.0,
        422
    );
    for v in ["0", "-1", "bad", "9223372036854775808"] {
        assert_eq!(
            edit(&mut b, &realm_path(), &[("name", "Wrong"), ("version", v)])
                .await
                .0,
            422
        );
    }
    assert_eq!(
        edit(
            &mut b,
            &format!("{}/status", realm_path()),
            &[("status", "unknown"), ("version", "1")]
        )
        .await
        .0,
        422
    );
    let csrf = b.token(&realm_path()).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("csrf", csrf.as_str()), ("name", "Wrong"), ("version", "1")])
        .finish();
    assert_eq!(raw(&b, "HEAD", &realm_path(), body, &[]).await.0, 200);
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
            &format!("{}/status?status=suspended&version=1", realm_path()),
            body,
            &[]
        )
        .await
        .0,
        200
    );
    assert_eq!(realm_row(&f).await.1, "active");
    assert_eq!(realm_row(&f).await.0, "Acme");
    assert_eq!(events(&f).await, 1);
    for path in [
        format!("{}/users/not-a-uuid", realm_path()),
        format!("/admin/realms/not-a-uuid/users/{USER}"),
        format!("{}/users/not-a-uuid/status", realm_path()),
    ] {
        for method in ["GET", "POST"] {
            assert_eq!(b.request(method, &path, &[]).await.0, 404);
        }
    }
    let csrf = b.token("/admin/realms/new").await;
    let (status, h, _) = b
        .request(
            "POST",
            "/admin/realms",
            &[
                ("csrf", &csrf),
                ("creation_id", "invalid-uuid"),
                ("name", "Safe name"),
            ],
        )
        .await;
    assert_eq!(status, 422);
    assert!(h.contains("Safe name"));
    assert!(h.contains("Reload"));
    let (status, h, _) = user(&mut b, REALM, "invalid-uuid", "Safe@example.com", "").await;
    assert_eq!(status, 422);
    assert!(h.contains("Safe@example.com"));
    assert!(h.contains("Reload"));
    let (status, h, _) = b
        .request(
            "GET",
            &format!("{}/users?cursor=invalid", realm_path()),
            &[],
        )
        .await;
    assert_eq!(status, 422);
    assert!(h.contains("First page"));
    assert!(h.contains("href=\"/admin/realms/"));
    assert_eq!(realm_row(&f).await.0, "Acme");
    assert_eq!(events(&f).await, 1);
});
check!(directory_response_policy, _f, b, {
    create_realm(&mut b, REALM, "<script>name</script>").await;
    let (_, h, r) = b.request("GET", &realm_path(), &[]).await;
    let csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
    assert_eq!(r["content-security-policy"], csp);
    let config = h
        .split("name=\"htmx-config\" content='")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap();
    assert_eq!(
        config,
        r#"{"allowEval":false,"allowScriptTags":false,"selfRequestsOnly":true,"historyCacheSize":0,"includeIndicatorStyles":false,"historyRestoreAsHxRequest":false}"#
    );
    assert_eq!(
        user(
            &mut b,
            REALM,
            USER,
            "Alice@example.com",
            "<script>user</script>"
        )
        .await
        .0,
        303
    );
    assert!(!h.contains("<script>name</script>"));
    let heading = h
        .split("<h1 tabindex=\"-1\">")
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
        "/admin/realms".into(),
        "/admin/realms/new".into(),
        realm_path(),
        format!("{}/users", realm_path()),
        format!("{}/users/new", realm_path()),
        user_path(),
    ];
    for path in pages {
        let (full_status, full_html, full_headers) = b.request("GET", &path, &[]).await;
        assert_eq!(full_status, 200);
        assert_eq!(full_headers["content-security-policy"], csp);
        assert_eq!(full_headers["cache-control"], "no-store");
        assert_eq!(full_headers["vary"], "HX-Request");
        assert!(full_html.contains(config));
        assert!(!full_html.contains("<script>user</script>"));
        assert!(!full_html.contains("<script>name</script>"));
        let (status, html, headers) =
            raw(&b, "GET", &path, String::new(), &[("hx-request", "true")]).await;
        assert_eq!(status, 200);
        assert!(!html.contains("<!doctype"));
        assert_eq!(headers["vary"], "HX-Request");
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["content-security-policy"], csp);
        assert!(!html.contains("<script"));
        assert!(!html.contains("htmx-config"));
        if path == realm_path() || path == user_path() {
            let payload = if path == realm_path() {
                "<script>name</script>"
            } else {
                "<script>user</script>"
            };
            assert!(!html.contains(payload));
            let decoded = html
                .replace("&#60;", "<")
                .replace("&#62;", ">")
                .replace("&lt;", "<")
                .replace("&gt;", ">");
            assert!(decoded.contains(payload));
        }
    }
    let csrf = b.token(&realm_path()).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("csrf", csrf.as_str()),
            ("version", "1"),
            ("name", "Changed"),
        ])
        .finish();
    let (status, _, headers) =
        raw(&b, "POST", &realm_path(), body, &[("hx-request", "true")]).await;
    assert_eq!(status, 200);
    assert_eq!(headers["hx-redirect"], realm_path());
    assert_eq!(headers["vary"], "HX-Request");
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("csrf", csrf.as_str()), ("version", "2"), ("name", "Again")])
        .finish();
    let (status, _, headers) = raw(&b, "POST", &realm_path(), body, &[]).await;
    assert_eq!(status, 303);
    assert_eq!(headers["location"], realm_path());
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

#[tokio::test]
#[ignore = "TLS fixture"]
async fn directory_realm_upgrade() {
    let f = Fixture::new("realm_upgrade").await;
    sqlx::raw_sql("DROP SCHEMA bloc CASCADE; DROP TABLE public._sqlx_migrations")
        .execute(&f.admin)
        .await
        .unwrap();
    let old = sqlx::migrate::Migrator {
        migrations: [
            (1, "setup", include_str!("../migrations/0001_setup.sql")),
            (2, "access", include_str!("../migrations/0002_access.sql")),
            (
                3,
                "directory",
                include_str!("../migrations/0003_directory.sql"),
            ),
        ]
        .into_iter()
        .map(|(version, description, sql)| {
            sqlx::migrate::Migration::new(
                version,
                description.into(),
                sqlx::migrate::MigrationType::Simple,
                sqlx::SqlStr::from_static(sql),
                false,
            )
        })
        .collect::<Vec<_>>()
        .into(),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    old.run(&f.pool("migrator_user").await).await.unwrap();
    sqlx::raw_sql("INSERT INTO bloc.tenant(id,name,status,version,created_at,updated_at) VALUES('00000000-0000-4000-8000-000000000001','Acme','suspended',7,'2026-10-20Z','2026-10-21Z');
        INSERT INTO bloc.tenant_user(id,tenant_id,email,display_name,version,created_at,updated_at) VALUES('00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000001','user@example.test','Synthetic user',3,'2026-10-20Z','2026-10-21Z');
        INSERT INTO bloc.security_audit_event(installation_id,action,outcome,tenant_id,tenant_user_id) VALUES(1,'tenant_user_create','success','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002');")
        .execute(&f.admin).await.unwrap();
    let before: String = sqlx::query_scalar("SELECT row_to_json(t)::text FROM bloc.tenant t")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    let user_before: String =
        sqlx::query_scalar("SELECT row_to_json(u)::text FROM bloc.tenant_user u")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert!(f.runtime.compatible().await.is_err());
    f.migrator.migrate().await.unwrap();
    f.runtime.compatible().await.unwrap();
    let after: String = sqlx::query_scalar("SELECT row_to_json(t)::text FROM bloc.realm t")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    let user_after: String =
        sqlx::query_scalar("SELECT row_to_json(u)::text FROM bloc.realm_user u")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(before, after);
    assert_eq!(user_before.replace("tenant_id", "realm_id"), user_after);
    let targets: (String,String,String) = sqlx::query_as("SELECT action,realm_id::text,realm_user_id::text FROM bloc.security_audit_event WHERE action='tenant_user_create'").fetch_one(&f.admin).await.unwrap();
    assert_eq!(
        targets,
        (
            "tenant_user_create".into(),
            "00000000-0000-4000-8000-000000000001".into(),
            "00000000-0000-4000-8000-000000000002".into()
        )
    );
}
