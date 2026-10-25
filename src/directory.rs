//! Installation-administrator directory management. Users have no authentication capability.
use crate::{
    administrator::{Application, cookie, expired, navigation},
    credentials,
    directory_storage::{DirectoryError, Mutation, Record},
    request_security as sec,
};
use askama::Template;
use axum::{
    body::to_bytes,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use std::{collections::BTreeMap, net::SocketAddr};
use subtle::ConstantTimeEq;
struct Page {
    title: String,
    intro: &'static str,
    list_path: String,
    detail_path: String,
    realm_path: String,
    user: bool,
    list: bool,
    create: bool,
    realm: Record,
    record: Record,
    rows: Vec<Record>,
    csrf: String,
    email: String,
    creation: String,
    version: String,
    next: String,
    feedback: String,
    recovery: String,
    recovery_label: &'static str,
    invalid: &'static str,
    error: &'static str,
    hidden: bool,
    confirm: bool,
    status: String,
    combined: &'static str,
    cancel_focus: bool,
}
impl Page {
    fn new() -> Self {
        Self {
            title: "Directory access".into(),
            intro: "",
            list_path: "/admin/realms".into(),
            detail_path: String::new(),
            realm_path: String::new(),
            user: false,
            list: false,
            create: false,
            realm: Record::default(),
            record: Record::default(),
            rows: vec![],
            csrf: String::new(),
            email: String::new(),
            creation: String::new(),
            version: String::new(),
            next: String::new(),
            feedback: String::new(),
            recovery: "/admin/realms".into(),
            recovery_label: "Back to realms",
            invalid: "",
            error: "",
            hidden: false,
            confirm: false,
            status: String::new(),
            combined: "Active",
            cancel_focus: false,
        }
    }
    fn form_path(&self) -> String {
        if self.create {
            format!("{}/new", self.list_path)
        } else {
            self.detail_path.clone()
        }
    }
    fn fail(&mut self, feedback: &str, recovery: &str, label: &'static str) {
        self.feedback = feedback.into();
        self.recovery = recovery.into();
        self.recovery_label = label;
    }
}
#[derive(Template)]
#[template(path = "directory.html")]
struct Full<'a> {
    p: &'a Page,
}
#[derive(Template)]
#[template(path = "directory_content.html")]
struct Fragment<'a> {
    p: &'a Page,
}
fn render(p: &Page, status: StatusCode, hx: bool) -> Response {
    let result = if hx {
        Fragment { p }.render()
    } else {
        Full { p }.render()
    };
    let mut response = match result {
        Ok(html) => (status, Html(html)).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("HX-Request"));
    response
}
fn failure(path: &str, status: StatusCode, hx: bool) -> Response {
    let mut p = Page::new();
    p.hidden = true;
    let reload = if path == "/admin/realms" || path.ends_with("/users") {
        format!("{path}/new")
    } else {
        path.trim_end_matches("/status").to_owned()
    };
    match status {
        StatusCode::SERVICE_UNAVAILABLE => p.fail(
            "bloc cannot access the information needed for this request. Try again shortly.",
            path,
            "Try again",
        ),
        StatusCode::NOT_FOUND => {
            p.title = "Record not found".into();
            p.fail(
                "This record is not available at this address.",
                "/admin/realms",
                "Back to realms",
            )
        }
        StatusCode::FORBIDDEN => p.fail(
            "This form cannot be submitted. Nothing was changed. Reload the form to continue.",
            &reload,
            "Reload form",
        ),
        StatusCode::PAYLOAD_TOO_LARGE => {
            p.fail("The submitted form is too large.", path, "Reload form")
        }
        StatusCode::UNSUPPORTED_MEDIA_TYPE => p.fail(
            "Submit this form using the supported format.",
            &reload,
            "Reload form",
        ),
        _ => p.fail("The request could not be read.", path, "Reload form"),
    };
    render(&p, status, hx)
}
fn storage_failure(e: DirectoryError, path: &str, hx: bool) -> Response {
    match e {
        DirectoryError::Authority => expired(hx),
        DirectoryError::Storage => failure(path, StatusCode::SERVICE_UNAVAILABLE, hx),
    }
}
fn field<'a>(f: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    f.get(name).map(String::as_str).unwrap_or("")
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}
fn new_uuid() -> Result<String, ()> {
    let mut b = sec::random().map_err(|_| ())?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    let h = b[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
fn name(value: &str, optional: bool) -> Result<String, ()> {
    if value.chars().any(char::is_control) {
        return Err(());
    }
    let value = value.trim();
    if (!optional && value.is_empty()) || value.chars().count() > 128 || value.len() > 512 {
        Err(())
    } else {
        Ok(value.into())
    }
}
fn version(value: &str) -> Option<i64> {
    value.parse::<i64>().ok().filter(|v| *v > 0)
}
enum TokenError {
    Storage,
    Capacity,
    Throttled(i32),
}
async fn token(
    app: &Application,
    headers: &HeaderMap,
    session: &[u8; 32],
    source: &str,
) -> Result<(String, Option<String>), TokenError> {
    if let Some(browser) = sec::cookie(headers, "__Host-bloc-csrf")
        && let Some(t) = app
            .storage
            .form(&sec::digest(&browser), Some(session), None)
            .await
            .map_err(|_| TokenError::Storage)?
    {
        return Ok((sec::encode(&t), None));
    }
    let key = sec::keyed(&app.config, "source", source).map_err(|_| TokenError::Storage)?;
    match app
        .storage
        .reserve(&[("form_issue_source", key, 1)])
        .await
        .map_err(|_| TokenError::Storage)?
    {
        0 => {}
        -1 => return Err(TokenError::Capacity),
        wait => return Err(TokenError::Throttled(wait)),
    }
    let browser = sec::encode(&sec::random().map_err(|_| TokenError::Storage)?);
    let t = sec::random().map_err(|_| TokenError::Storage)?;
    let t = app
        .storage
        .form(&sec::digest(&browser), Some(session), Some(&t))
        .await
        .map_err(|_| TokenError::Storage)?
        .ok_or(TokenError::Capacity)?;
    Ok((sec::encode(&t), Some(browser)))
}
pub(crate) async fn handler(State(app): State<Application>, request: Request) -> Response {
    let category = if request.uri().path().contains("/users") {
        "realm_user_management"
    } else {
        "realm_management"
    };
    let mut response = handle(&app, request).await;
    let expired_redirect = response
        .headers()
        .get(header::LOCATION)
        .is_some_and(|v| v == "/admin/login?expired=1");
    if response.status().is_client_error()
        || response.status().is_server_error()
        || expired_redirect
    {
        let reason = match response.status() {
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => "malformed",
            StatusCode::FORBIDDEN => "authority",
            StatusCode::CONFLICT => "conflict",
            StatusCode::PAYLOAD_TOO_LARGE => "oversized",
            StatusCode::UNSUPPORTED_MEDIA_TYPE => "media_type",
            StatusCode::UNAUTHORIZED => "credentials",
            StatusCode::TOO_MANY_REQUESTS => "admission",
            StatusCode::SEE_OTHER => "authority",
            _ => "storage",
        };
        if app.storage.deny(category, reason).await.is_err() {
            tracing::warn!("directory denial observation unavailable");
        }
    }
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("HX-Request"));
    response
}
async fn handle(app: &Application, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    let headers = request.headers().clone();
    let hx = sec::one(&headers, "hx-request") == Some("true");
    let Some(peer) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
    else {
        return failure(&path, StatusCode::FORBIDDEN, hx);
    };
    let source = match sec::source(&app.config, &headers, peer) {
        Ok(s) => s.to_string(),
        Err(s) => return failure(&path, s, hx),
    };
    let Some(session) = sec::cookie(&headers, "__Host-bloc-admin").map(|v| sec::digest(&v)) else {
        return expired(hx);
    };
    let owner = match app.storage.authorize(&session).await {
        Ok(Some(owner)) => owner,
        Ok(None) => return expired(hx),
        Err(_) => return failure(&path, StatusCode::SERVICE_UNAVAILABLE, hx),
    };
    let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    let mut p = Page::new();
    p.email = owner.email;
    p.user = parts.get(3) == Some(&"users");
    let status_route = parts.last() == Some(&"status");
    let realm_id = parts
        .get(2)
        .copied()
        .filter(|v| !(*v == "new" && parts.len() == 3));
    let user_id = parts
        .get(4)
        .copied()
        .filter(|v| !(*v == "new" && parts.len() == 5));
    if realm_id.is_some_and(|v| !uuid(v))
        || user_id.is_some_and(|v| !uuid(v))
        || parts.len() > if p.user { 6 } else { 4 }
        || parts.len() == 4 && !p.user && !status_route
        || parts.len() == 6 && !status_route
    {
        return failure(&path, StatusCode::NOT_FOUND, hx);
    }
    let is_get = request.method() == Method::GET || request.method() == Method::HEAD;
    let form = if is_get {
        BTreeMap::new()
    } else {
        if !sec::origin(&app.config, &headers) {
            return failure(&path, StatusCode::FORBIDDEN, hx);
        }
        if sec::one(&headers, "content-type").and_then(|v| v.split(';').next())
            != Some("application/x-www-form-urlencoded")
        {
            return failure(&path, StatusCode::UNSUPPORTED_MEDIA_TYPE, hx);
        }
        let bytes = match to_bytes(request.into_body(), 16384).await {
            Ok(b) => b,
            Err(_) => return failure(&path, StatusCode::PAYLOAD_TOO_LARGE, hx),
        };
        let form = match sec::form_fields(&bytes) {
            Ok(f) => f,
            Err(s) => return failure(&path, s, hx),
        };
        let browser = sec::cookie(&headers, "__Host-bloc-csrf");
        let submitted = sec::decode(field(&form, "csrf"));
        match (browser, submitted) {
            (Some(browser), Some(submitted)) => match app
                .storage
                .form(&sec::digest(&browser), Some(&session), None)
                .await
            {
                Ok(Some(t)) if bool::from(t.as_slice().ct_eq(&submitted)) => {}
                Ok(_) => return failure(&path, StatusCode::FORBIDDEN, hx),
                Err(_) => return failure(&path, StatusCode::SERVICE_UNAVAILABLE, hx),
            },
            _ => return failure(&path, StatusCode::FORBIDDEN, hx),
        }
        form
    };
    p.create = parts.last() == Some(&"new");
    p.list = if p.user {
        parts.len() == 4
    } else {
        parts.len() == 2
    };
    p.realm_path = realm_id
        .map(|id| format!("/admin/realms/{id}"))
        .unwrap_or_default();
    p.list_path = if p.user {
        format!("{}/users", p.realm_path)
    } else {
        "/admin/realms".into()
    };
    p.detail_path = if p.user {
        user_id
            .map(|id| format!("{}/{id}", p.list_path))
            .unwrap_or_default()
    } else {
        p.realm_path.clone()
    };
    if let Some(id) = realm_id {
        match app.storage.directory_realms(&session, Some(id), None).await {
            Ok(mut rows) => {
                if rows.is_empty() {
                    return failure(&path, StatusCode::NOT_FOUND, hx);
                }
                p.realm = rows.remove(0);
            }
            Err(e) => return storage_failure(e, &path, hx),
        }
    }
    if p.user {
        if let Some(id) = user_id {
            match app
                .storage
                .directory_users(&session, realm_id.unwrap_or(""), Some(id), None)
                .await
            {
                Ok(mut rows) => {
                    if rows.is_empty() {
                        return failure(&path, StatusCode::NOT_FOUND, hx);
                    }
                    p.record = rows.remove(0);
                }
                Err(e) => return storage_failure(e, &path, hx),
            }
        }
    } else {
        p.record = p.realm.clone()
    }
    p.version = p.record.version.to_string();
    p.creation = match new_uuid() {
        Ok(id) => id,
        Err(_) => return failure(&path, StatusCode::SERVICE_UNAVAILABLE, hx),
    };
    p.title = if p.list {
        if p.user {
            "Users".into()
        } else {
            "Realms".into()
        }
    } else if p.create {
        if p.user {
            "Create user".into()
        } else {
            "Create realm".into()
        }
    } else if p.user {
        "User details".into()
    } else {
        p.realm.name.clone()
    };
    p.intro = if p.list {
        if p.user {
            "Independent users belonging to this realm. Directory records do not authenticate anyone."
        } else {
            "Independent directories managed by the installation administrator."
        }
    } else if p.create {
        if p.user {
            "Add an independent user to this realm."
        } else {
            "Give this directory a name. Its identity stays fixed when the name changes."
        }
    } else if p.user {
        "Manage the profile and directory status. Ownership and user ID stay fixed."
    } else {
        "Manage this directory’s name, users and status."
    };
    p.combined = match (p.realm.status.as_str(), p.record.status.as_str()) {
        ("suspended", "suspended") => "Realm suspended and user suspended",
        ("suspended", _) => "Realm suspended",
        (_, "suspended") => "User suspended",
        _ => "Active",
    };
    let mut response_status = StatusCode::OK;
    if is_get {
        let params = match if query.is_empty() {
            Ok(BTreeMap::new())
        } else {
            sec::form_fields(query.as_bytes())
        } {
            Ok(q) => q,
            Err(s) => return failure(&path, s, hx),
        };
        if p.list {
            let cursor = if let Some(c) = params.get("cursor") {
                let parsed = c.split_once('.').and_then(|(t, id)| {
                    t.parse::<i64>()
                        .ok()
                        .filter(|n| *n >= 0)
                        .filter(|_| uuid(id))
                        .map(|n| (n, id))
                });
                if parsed.is_none() {
                    p.fail(
                        "This page link is invalid. Return to the first page.",
                        &p.list_path.clone(),
                        "First page",
                    );
                    return render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx);
                }
                parsed
            } else {
                None
            };
            let result = if p.user {
                app.storage
                    .directory_users(&session, realm_id.unwrap_or(""), None, cursor)
                    .await
            } else {
                app.storage.directory_realms(&session, None, cursor).await
            };
            p.rows = match result {
                Ok(rows) => rows,
                Err(e) => return storage_failure(e, &path, hx),
            };
            if p.rows.len() > 50 {
                p.rows.truncate(50);
                if let Some(last) = p.rows.last() {
                    p.next = format!("{}?cursor={}.{}", p.list_path, last.cursor, last.id);
                }
            }
        } else if status_route {
            let v = field(&params, "version");
            let s = field(&params, "status");
            if version(v).is_none() || !matches!(s, "active" | "suspended") {
                p.fail(
                    "This form contains an invalid value. Reload the form to continue.",
                    &p.detail_path.clone(),
                    "Reload current record",
                );
                response_status = StatusCode::UNPROCESSABLE_ENTITY;
            } else {
                p.confirm = true;
                p.status = s.into();
                p.version = v.into();
            }
        } else {
            p.cancel_focus = field(&params, "cancel") == "1";
        }
    } else {
        let creating = p.list;
        p.list = false;
        p.create = creating;
        if creating {
            p.title = if p.user {
                "Create user".into()
            } else {
                "Create realm".into()
            };
        }
        let allowed = if status_route {
            vec!["csrf", "version", "status"]
        } else if p.user {
            if creating {
                vec!["csrf", "creation_id", "email", "display_name"]
            } else {
                vec!["csrf", "version", "email", "display_name"]
            }
        } else if creating {
            vec!["csrf", "creation_id", "name"]
        } else {
            vec!["csrf", "version", "name"]
        };
        let mut invalid = false;
        if form.keys().any(|k| !allowed.contains(&k.as_str())) {
            p.fail(
                "This form contains unsupported fields. Nothing was changed.",
                &p.form_path(),
                "Reload form",
            );
            invalid = true;
        }
        p.creation = field(&form, "creation_id").into();
        p.version = field(&form, "version").into();
        p.status = field(&form, "status").into();
        if creating && !uuid(&p.creation)
            || !creating && version(&p.version).is_none()
            || status_route && !matches!(p.status.as_str(), "active" | "suspended")
        {
            p.fail(
                "This form contains an invalid value. Reload the form to continue.",
                &p.form_path(),
                "Reload form",
            );
            invalid = true;
        }
        if !status_route {
            if p.user {
                p.record.email = field(&form, "email").into();
                p.record.display_name = field(&form, "display_name").into();
                match credentials::normalize_email(&p.record.email) {
                    Ok(e) => p.record.email = e,
                    Err(_) => {
                        p.invalid = "email";
                        p.error = "Enter a valid ASCII email address, up to 254 bytes.";
                        invalid = true;
                    }
                }
                match name(&p.record.display_name, true) {
                    Ok(n) => p.record.display_name = n,
                    Err(_) => {
                        p.invalid = "display-name";
                        p.error = "Up to 128 characters and 512 UTF-8 bytes. Control characters are not allowed.";
                        invalid = true;
                    }
                }
            } else {
                p.record.name = field(&form, "name").into();
                match name(&p.record.name, false) {
                    Ok(n) => p.record.name = n,
                    Err(_) => {
                        p.invalid = "name";
                        p.error = "Enter a name without control characters, within both limits.";
                        invalid = true;
                    }
                }
            }
        }
        if invalid {
            response_status = StatusCode::UNPROCESSABLE_ENTITY;
        } else {
            let id = if creating {
                p.creation.as_str()
            } else if p.user {
                user_id.unwrap_or("")
            } else {
                realm_id.unwrap_or("")
            };
            let realm = if p.user { realm_id.unwrap_or("") } else { id };
            let operation = match (p.user, creating, status_route) {
                (true, true, _) => "user_create",
                (true, false, true) => "user_status",
                (true, false, false) => "user_update",
                (false, true, _) => "realm_create",
                (false, false, true) => "realm_status",
                _ => "realm_update",
            };
            let result = app
                .storage
                .directory_mutate(
                    &session,
                    Mutation {
                        operation,
                        realm,
                        user: p.user.then_some(id),
                        version: version(&p.version).unwrap_or(0),
                        profile: if p.user {
                            &p.record.email
                        } else {
                            &p.record.name
                        },
                        display: if p.record.display_name.is_empty() {
                            None
                        } else {
                            Some(&p.record.display_name)
                        },
                        status: &p.status,
                    },
                )
                .await;
            let target = if p.user {
                format!("{}/{id}", p.list_path)
            } else {
                format!("/admin/realms/{id}")
            };
            match result {
                Err(e) => return storage_failure(e, &path, hx),
                Ok(outcome) => match outcome.as_str() {
                    "ok" => return navigation(&target, hx),
                    "missing" => return failure(&path, StatusCode::NOT_FOUND, hx),
                    "stale" => p.fail(
                        "This record changed after you opened the form. Nothing was saved. Reload the current record before editing again.",
                        &target, "Reload current record"),
                    "email_conflict" => p.fail(
                        if creating { "This email is already used in this realm. Choose another email address." }
                        else { "This email is already used in this realm. Nothing was changed." }, "", ""),
                    "foreign_creation" => {
                        p.creation.clear();
                        p.fail("This creation form cannot be used. Nothing was created. Open a new form to continue.",
                            &format!("{}/new", p.list_path), "Open new form");
                    }
                    "reused" => p.fail(
                        if p.user { "This creation form has already been used. No second user was created." }
                        else { "This creation form has already been used. No second realm was created." },
                        &target, if p.user { "Review existing user" } else { "Review existing realm" }),
                    _ => return failure(&path, StatusCode::SERVICE_UNAVAILABLE, hx),
                },
            }
            response_status = StatusCode::CONFLICT;
        }
    }
    match token(app, &headers, &session, &source).await {
        Ok((t, browser)) => {
            p.csrf = t;
            let mut r = render(&p, response_status, hx);
            if let Some(browser) = browser {
                cookie(&mut r, "__Host-bloc-csrf", &browser);
            }
            r
        }
        Err(TokenError::Throttled(wait)) => {
            let mut p = Page::new();
            p.hidden = true;
            p.fail(
                &format!("Too many attempts. Wait {wait} seconds, then reload the form."),
                &path,
                "Reload form",
            );
            let mut response = render(&p, StatusCode::TOO_MANY_REQUESTS, hx);
            if let Ok(value) = HeaderValue::from_str(&wait.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        Err(error) => {
            let mut response = failure(&path, StatusCode::SERVICE_UNAVAILABLE, hx);
            if matches!(error, TokenError::Capacity) {
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            }
            response
        }
    }
}

#[test]
fn realm_creation_has_one_entry_per_list_state() {
    for populated in [false, true] {
        let mut p = Page::new();
        p.list = true;
        p.title = "Realms".into();
        if populated {
            p.rows.push(Record::default());
        }
        let html = Full { p: &p }.render().unwrap();
        assert_eq!(html.matches("href=\"/admin/realms/new\"").count(), 2);
        let fragment = Fragment { p: &p }.render().unwrap();
        assert_eq!(fragment.matches("href=\"/admin/realms/new\"").count(), 1);
    }
}

#[test]
fn directory_feedback_separates_field_and_general_errors() {
    for creating in [false, true] {
        for field in ["name", "email", "display-name"] {
            let mut p = Page::new();
            p.create = creating;
            p.user = field != "name";
            p.invalid = field;
            p.error = "Correct this value.";
            for html in [
                Full { p: &p }.render().unwrap(),
                Fragment { p: &p }.render().unwrap(),
            ] {
                assert!(!html.contains("role=\"alert\""));
                assert!(html.contains("aria-invalid=\"true\" autofocus"));
                assert!(html.contains("Correct this value."));
            }
            p.fail(
                "The record changed. Reload before saving.",
                "/admin/realms",
                "Reload",
            );
            for html in [
                Full { p: &p }.render().unwrap(),
                Fragment { p: &p }.render().unwrap(),
            ] {
                assert!(
                    html.find("id=\"feedback\"").unwrap()
                        < html.find("class=\"breadcrumbs\"").unwrap()
                );
                assert!(html.contains("The record changed. Reload before saving."));
                assert!(html.contains(">Reload</a>"));
            }
        }
    }
}

#[test]
fn directory_actions_expose_pending_labels() {
    for user in [false, true] {
        for create in [false, true] {
            let mut p = Page::new();
            p.user = user;
            p.create = create;
            let html = Fragment { p: &p }.render().unwrap();
            let label = match (user, create) {
                (true, true) => "Creating user…",
                (false, true) => "Creating realm…",
                (_, false) => "Saving changes…",
            };
            assert!(html.contains(&format!("data-pending-label=\"{label}\"")));
            assert!(html.contains("working ui-sr-only\" role=\"status\" hidden"));
        }
        for status in ["active", "suspended"] {
            let mut p = Page::new();
            p.user = user;
            p.confirm = true;
            p.status = status.into();
            let label = if status == "active" {
                "Reactivating…"
            } else {
                "Suspending…"
            };
            assert!(
                Fragment { p: &p }
                    .render()
                    .unwrap()
                    .contains(&format!("data-pending-label=\"{label}\""))
            );
        }
    }
}
