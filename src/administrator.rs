//! Built-in administrator interface. Shared PostgreSQL is the only authority.
use crate::{
    config::Config,
    credentials::{self, PasswordWorker},
    request_security as security,
    storage::{Claim, Credentials, Storage},
};
use askama::Template;
use axum::{
    Router,
    body::to_bytes,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use std::{collections::BTreeMap, net::SocketAddr};
use subtle::ConstantTimeEq;
#[derive(Clone)]
pub struct Application {
    pub storage: Storage,
    pub config: Config,
    worker: PasswordWorker,
    dummy: String,
}
impl Application {
    pub async fn new(storage: Storage, config: Config) -> Result<Self, credentials::Error> {
        let worker = PasswordWorker::new();
        let dummy = worker
            .hash("unknown administrator dummy password".into())
            .await?;
        Ok(Self {
            storage,
            config,
            worker,
            dummy,
        })
    }
}
struct Field {
    name: &'static str,
    label: &'static str,
    kind: &'static str,
    autocomplete: &'static str,
}
struct Page {
    title: &'static str,
    intro: &'static str,
    path: String,
    home: bool,
    closed: bool,
    unavailable: bool,
    reload: bool,
    email: String,
    csrf: String,
    feedback: String,
    invalid: &'static str,
    field_error: &'static str,
    fields: Vec<Field>,
    command: &'static str,
    action: &'static str,
    change: bool,
    secondary: &'static str,
    secondary_path: &'static str,
    version: &'static str,
}
impl Page {
    fn new(path: &str) -> Self {
        let (title, intro, action, names, command) = match path {
            "/admin/setup" => (
                "Set up bloc",
                "Create the installation administrator using a code generated through deployment access.",
                "Create administrator",
                vec!["code", "email", "password", "password_confirmation"],
                "bloc admin setup-code",
            ),
            "/admin/recovery" => (
                "Recover administrator access",
                "Generate a recovery code through deployment access, then choose a new password.",
                "Reset password",
                vec!["code", "password", "password_confirmation"],
                "bloc admin recovery-code",
            ),
            "/admin/password" => (
                "Change password",
                "Enter your current password and choose a replacement.",
                "Change password",
                vec!["current_password", "password", "password_confirmation"],
                "",
            ),
            "/admin" | "/admin/logout" => (
                "Overview",
                "Manage your installation and its directories.",
                "Sign out",
                vec![],
                "",
            ),
            _ => (
                "Sign in to bloc",
                "Use your installation administrator account.",
                "Sign in",
                vec!["email", "password"],
                "",
            ),
        };
        let fields = names
            .into_iter()
            .map(|name| {
                let (label, kind, autocomplete) = match name {
                    "code" => ("Operator code", "text", "off"),
                    "email" => ("Email address", "email", "username"),
                    "current_password" => ("Current password", "password", "current-password"),
                    "password_confirmation" => ("Confirm password", "password", "new-password"),
                    _ => (
                        if matches!(path, "/admin/recovery" | "/admin/password") {
                            "New password"
                        } else {
                            "Password"
                        },
                        "password",
                        if path == "/admin/login" {
                            "current-password"
                        } else {
                            "new-password"
                        },
                    ),
                };
                Field {
                    name,
                    label,
                    kind,
                    autocomplete,
                }
            })
            .collect();
        Self {
            title,
            intro,
            action,
            fields,
            command,
            path: if path == "/admin" {
                "/admin/logout".into()
            } else {
                path.into()
            },
            home: matches!(path, "/admin" | "/admin/logout"),
            closed: false,
            unavailable: false,
            reload: false,
            email: String::new(),
            csrf: String::new(),
            feedback: String::new(),
            invalid: "",
            field_error: "",
            change: matches!(path, "/admin/password" | "/admin/recovery"),
            secondary: if path == "/admin/login" {
                "Recover access"
            } else if path == "/admin/password" {
                "Back to administration"
            } else {
                "Back to sign in"
            },
            secondary_path: if path == "/admin/login" {
                "/admin/recovery"
            } else if path == "/admin/password" {
                "/admin"
            } else {
                "/admin/login"
            },
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}
#[derive(Template)]
#[template(path = "admin.html")]
struct Full<'a> {
    page: &'a Page,
}
#[derive(Template)]
#[template(path = "admin_content.html")]
struct Fragment<'a> {
    page: &'a Page,
}
fn render(page: &Page, status: StatusCode, hx: bool) -> Response {
    let html = if hx {
        Fragment { page }.render()
    } else {
        Full { page }.render()
    };
    let mut response = match html {
        Ok(html) => (status, Html(html)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "Temporarily unavailable").into_response(),
    };
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("HX-Request"));
    response
}
pub(crate) fn cookie(response: &mut Response, name: &str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(&format!(
        "{name}={value}; Secure; HttpOnly; SameSite=Strict; Path=/"
    )) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}
fn clear(response: &mut Response) {
    for name in ["__Host-bloc-admin", "__Host-bloc-csrf"] {
        if let Ok(value) = HeaderValue::from_str(&format!(
            "{name}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        )) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}
pub(crate) fn navigation(path: &str, hx: bool) -> Response {
    let mut response = Redirect::to(path).into_response();
    if hx {
        *response.status_mut() = StatusCode::OK;
        response.headers_mut().insert(
            "hx-redirect",
            HeaderValue::from_str(path).unwrap_or(HeaderValue::from_static("/admin/login")),
        );
    }
    response
}
pub(crate) fn expired(hx: bool) -> Response {
    if hx {
        let mut response = (
            StatusCode::UNAUTHORIZED,
            "Your session ended. Sign in again.",
        )
            .into_response();
        response.headers_mut().insert(
            "hx-redirect",
            HeaderValue::from_static("/admin/login?expired=1"),
        );
        response
    } else {
        navigation("/admin/login?expired=1", false)
    }
}
fn unavailable(path: &str, hx: bool) -> Response {
    let mut page = Page::new(path);
    page.title = "Temporarily unavailable";
    page.unavailable = true;
    render(&page, StatusCode::SERVICE_UNAVAILABLE, hx)
}
fn retry(mut response: Response, seconds: i32) -> Response {
    if let Ok(v) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, v);
    }
    response
}
enum AdmissionError {
    Throttled(i32),
    Capacity,
    Storage,
}
impl AdmissionError {
    fn response(self, path: &str, hx: bool) -> Response {
        match self {
            Self::Throttled(wait) => {
                let mut page = Page::new(path);
                page.path = path.into();
                page.reload = true;
                page.feedback = throttle_feedback(wait);
                retry(render(&page, StatusCode::TOO_MANY_REQUESTS, hx), wait)
            }
            Self::Capacity => retry(unavailable(path, hx), 60),
            Self::Storage => unavailable(path, hx),
        }
    }
}
fn throttle_feedback(wait: i32) -> String {
    format!("Too many attempts. Wait {wait} seconds, then try again.")
}
async fn admission(
    app: &Application,
    buckets: &[(&str, [u8; 32], i32)],
) -> Result<(), AdmissionError> {
    match app.storage.reserve(buckets).await {
        Ok(0) => Ok(()),
        Ok(-1) => Err(AdmissionError::Capacity),
        Ok(wait) => Err(AdmissionError::Throttled(wait)),
        Err(_) => Err(AdmissionError::Storage),
    }
}
async fn form_page(
    app: &Application,
    mut page: Page,
    headers: &HeaderMap,
    session: Option<&[u8; 32]>,
    source: &str,
    status: StatusCode,
    hx: bool,
) -> Response {
    let existing = security::cookie(headers, "__Host-bloc-csrf");
    if let Some(ref bearer) = existing {
        match app
            .storage
            .form(&security::digest(bearer), session, None)
            .await
        {
            Ok(Some(token)) => {
                page.csrf = security::encode(&token);
                return render(&page, status, hx);
            }
            Ok(None) => {}
            Err(_) => return unavailable(&page.path, hx),
        }
    }
    let source_key = match security::keyed(&app.config, "source", source) {
        Ok(k) => k,
        Err(_) => return unavailable(&page.path, hx),
    };
    if let Err(error) = admission(app, &[("form_issue_source", source_key, 1)]).await {
        return error.response(if page.home { "/admin" } else { &page.path }, hx);
    }
    let (browser, token) = match (security::random(), security::random()) {
        (Ok(b), Ok(t)) => (security::encode(&b), t),
        _ => return unavailable(&page.path, hx),
    };
    match app
        .storage
        .form(&security::digest(&browser), session, Some(&token))
        .await
    {
        Ok(Some(token)) => {
            page.csrf = security::encode(&token);
            let mut r = render(&page, status, hx);
            cookie(&mut r, "__Host-bloc-csrf", &browser);
            r
        }
        Ok(None) => retry(unavailable(&page.path, hx), 60),
        Err(_) => unavailable(&page.path, hx),
    }
}
fn field<'a>(form: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    form.get(name).map(String::as_str).unwrap_or("")
}
async fn handler(State(app): State<Application>, request: Request) -> Response {
    let category = action(request.uri().path());
    let response = handle_request(State(app.clone()), request).await;
    if response.status().is_client_error() || response.status().is_server_error() {
        let reason = match response.status() {
            StatusCode::BAD_REQUEST => "malformed",
            StatusCode::FORBIDDEN => "authority",
            StatusCode::UNAUTHORIZED => "credentials",
            StatusCode::CONFLICT => "conflict",
            StatusCode::UNPROCESSABLE_ENTITY => "malformed",
            StatusCode::PAYLOAD_TOO_LARGE => "oversized",
            StatusCode::UNSUPPORTED_MEDIA_TYPE => "media_type",
            StatusCode::TOO_MANY_REQUESTS => "admission",
            _ => "storage",
        };
        if app.storage.deny(category, reason).await.is_err() {
            tracing::warn!("administrator denial observation unavailable");
        }
    }
    response
}

async fn handle_request(State(app): State<Application>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let hx = security::one(request.headers(), "hx-request") == Some("true");
    let headers = request.headers().clone();
    let Some(peer) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
    else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let source = match security::source(&app.config, &headers, peer) {
        Ok(source) => source.to_string(),
        Err(status) => return status.into_response(),
    };
    let protected = matches!(
        path.as_str(),
        "/admin" | "/admin/password" | "/admin/logout"
    );
    let session = security::cookie(&headers, "__Host-bloc-admin").map(|v| security::digest(&v));
    let owner = if protected {
        match session {
            Some(ref digest) => match app.storage.authorize(digest).await {
                Ok(Some(owner)) => Some(owner),
                Ok(None) => return expired(hx),
                Err(_) => return unavailable(&path, hx),
            },
            None => return expired(hx),
        }
    } else {
        None
    };
    let mut page = Page::new(&path);
    if let Some(ref owner) = owner {
        page.email = owner.email.clone();
    }
    if path == "/admin/setup" {
        match app.storage.owner().await {
            Ok(Some(_)) => {
                page.closed = true;
                page.title = "Setup is complete";
                page.intro = "This installation already has an administrator.";
                return render(&page, StatusCode::CONFLICT, hx);
            }
            Ok(None) => {}
            Err(_) => return unavailable(&path, hx),
        }
    }
    if request.method() == Method::GET {
        if request.uri().query() == Some("expired=1") {
            page.feedback = "Your session ended. Sign in again.".into()
        }
        return form_page(
            &app,
            page,
            &headers,
            if protected { session.as_ref() } else { None },
            &source,
            StatusCode::OK,
            hx,
        )
        .await;
    }
    if !security::origin(&app.config, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if security::one(&headers, "content-type").and_then(|v| v.split(';').next())
        != Some("application/x-www-form-urlencoded")
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let bytes = match to_bytes(request.into_body(), 16384).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let form = match security::form(&bytes) {
        Ok(f) => f,
        Err(status) => return status.into_response(),
    };
    let Some(browser) = security::cookie(&headers, "__Host-bloc-csrf") else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Some(submitted) = security::decode(field(&form, "csrf")) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    match app
        .storage
        .form(
            &security::digest(&browser),
            if protected { session.as_ref() } else { None },
            None,
        )
        .await
    {
        Ok(Some(token)) if bool::from(token.as_slice().ct_eq(&submitted)) => {}
        Ok(_) => return StatusCode::FORBIDDEN.into_response(),
        Err(_) => return unavailable(&path, hx),
    }
    if path == "/admin/logout" {
        let mut response = match app
            .storage
            .sign_out(session.as_ref().unwrap_or(&[0; 32]))
            .await
        {
            Ok(true) => navigation("/admin/login", hx),
            Ok(false) => expired(hx),
            Err(_) => {
                let mut p = Page::new(&path);
                p.feedback = "Sign-out could not be confirmed. Try again shortly.".into();
                render(&p, StatusCode::SERVICE_UNAVAILABLE, hx)
            }
        };
        clear(&mut response);
        return response;
    }
    let source_key = match security::keyed(&app.config, "source", &source) {
        Ok(k) => k,
        Err(_) => return unavailable(&path, hx),
    };
    let email = credentials::normalize_email(field(&form, "email"));
    if matches!(path.as_str(), "/admin/setup" | "/admin/login") && email.is_err() {
        page.invalid = "email";
        page.field_error = "Enter an email address.";
        page.feedback = "Check the highlighted field.".into();
        return form_page(
            &app,
            page,
            &headers,
            session.as_ref().filter(|_| protected),
            &source,
            StatusCode::UNPROCESSABLE_ENTITY,
            hx,
        )
        .await;
    }
    if let Ok(ref email) = email {
        page.email = email.clone();
    }
    if path != "/admin/login"
        && credentials::validate_password(
            field(&form, "password"),
            field(&form, "password_confirmation"),
        )
        .is_err()
    {
        page.invalid = "password";
        page.field_error = "Choose a password with 15–128 characters and matching confirmation.";
        page.feedback = "Check the highlighted field.".into();
        return form_page(
            &app,
            page,
            &headers,
            session.as_ref().filter(|_| protected),
            &source,
            StatusCode::UNPROCESSABLE_ENTITY,
            hx,
        )
        .await;
    }
    let mut buckets = vec![
        ("credential_source", source_key, 1),
        (
            "hash_work",
            [0; 32],
            if path == "/admin/password" { 2 } else { 1 },
        ),
    ];
    if path == "/admin/login" {
        match security::keyed(&app.config, "identifier", email.as_deref().unwrap_or("")) {
            Ok(key) => buckets.push(("login_identifier", key, 1)),
            Err(_) => return unavailable(&path, hx),
        }
    } else if path == "/admin/password" {
        buckets.push(("password_change", [0; 32], 1))
    } else {
        buckets.push(("operator_code", [0; 32], 1))
    }
    match admission(&app, &buckets).await {
        Ok(()) => {}
        Err(AdmissionError::Throttled(wait)) => {
            page.feedback = throttle_feedback(wait);
            return retry(
                form_page(
                    &app,
                    page,
                    &headers,
                    session.as_ref().filter(|_| protected),
                    &source,
                    StatusCode::TOO_MANY_REQUESTS,
                    hx,
                )
                .await,
                wait,
            );
        }
        Err(error) => return error.response(&path, hx),
    }
    if matches!(path.as_str(), "/admin/setup" | "/admin/recovery") {
        let code = field(&form, "code");
        if security::decode(code).is_none() {
            page.feedback = "This code cannot be used. Generate a new code and try again.".into();
            return form_page(
                &app,
                page,
                &headers,
                None,
                &source,
                StatusCode::BAD_REQUEST,
                hx,
            )
            .await;
        }
        match app
            .storage
            .code_usable(
                if path == "/admin/setup" {
                    "setup"
                } else {
                    "recovery"
                },
                &security::digest(code),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                if path == "/admin/setup" {
                    match app.storage.owner().await {
                        Ok(Some(_)) => {
                            page.closed = true;
                            page.title = "Setup is complete";
                            page.intro = "This installation already has an administrator.";
                            return render(&page, StatusCode::CONFLICT, hx);
                        }
                        Ok(None) => {}
                        Err(_) => return unavailable(&path, hx),
                    }
                }
                page.feedback =
                    "This code cannot be used. Generate a new code and try again.".into();
                return form_page(
                    &app,
                    page,
                    &headers,
                    None,
                    &source,
                    StatusCode::BAD_REQUEST,
                    hx,
                )
                .await;
            }
            Err(_) => return unavailable(&path, hx),
        }
    }
    let result = if path == "/admin/login" {
        login(
            &app,
            &form,
            email.as_deref().unwrap_or(""),
            &security::digest(&browser),
        )
        .await
    } else if path == "/admin/password" {
        change(
            &app,
            &form,
            session.as_ref().unwrap_or(&[0; 32]),
            owner.as_ref(),
        )
        .await
    } else {
        setup_or_recover(&app, &form, &path, email.as_deref().unwrap_or("")).await
    };
    match result {
        Ok(mut response) => {
            if matches!(path.as_str(), "/admin/password" | "/admin/recovery") {
                clear(&mut response)
            }
            if hx && response.status() == StatusCode::SEE_OTHER {
                let location = response.headers().get(header::LOCATION).cloned();
                if let Some(location) = location {
                    *response.status_mut() = StatusCode::OK;
                    response.headers_mut().insert("hx-redirect", location);
                }
            }
            response
        }
        Err(Failure::Status(status, message)) => {
            page.feedback = message.into();
            form_page(
                &app,
                page,
                &headers,
                session.as_ref().filter(|_| protected),
                &source,
                status,
                hx,
            )
            .await
        }
        Err(Failure::Storage) => unavailable(&path, hx),
        Err(Failure::Capacity) => retry(unavailable(&path, hx), 1),
    }
}
fn action(path: &str) -> &'static str {
    match path {
        "/admin/setup" => "setup",
        "/admin/login" => "sign_in",
        "/admin/logout" => "sign_out",
        "/admin/password" => "password_change",
        _ => "recovery",
    }
}
enum Failure {
    Status(StatusCode, &'static str),
    Storage,
    Capacity,
}
impl From<credentials::Error> for Failure {
    fn from(e: credentials::Error) -> Self {
        if e == credentials::Error::Capacity {
            Self::Capacity
        } else {
            Self::Storage
        }
    }
}
async fn login(
    app: &Application,
    form: &BTreeMap<String, String>,
    email: &str,
    old_browser: &[u8; 32],
) -> Result<Response, Failure> {
    let owner = app.storage.owner().await.map_err(|_| Failure::Storage)?;
    let valid = owner
        .as_ref()
        .is_some_and(|o| o.email == email && !o.recovery_required);
    let phc = if valid {
        owner
            .as_ref()
            .map(|o| o.phc.clone())
            .unwrap_or_else(|| app.dummy.clone())
    } else {
        app.dummy.clone()
    };
    let verified = app
        .worker
        .verify(field(form, "password").into(), phc)
        .await?;
    if !valid || !verified {
        return Err(Failure::Status(
            StatusCode::UNAUTHORIZED,
            "Email or password is incorrect.",
        ));
    }
    let (session, browser, token) = (
        security::random().map_err(|_| Failure::Storage)?,
        security::random().map_err(|_| Failure::Storage)?,
        security::random().map_err(|_| Failure::Storage)?,
    );
    let (session, browser) = (security::encode(&session), security::encode(&browser));
    if !app
        .storage
        .authenticate(
            &security::digest(&session),
            owner.map(|o| o.version).unwrap_or(0),
            &security::digest(&browser),
            &token,
            Some(old_browser),
        )
        .await
        .map_err(|_| Failure::Storage)?
    {
        return Err(Failure::Status(
            StatusCode::UNAUTHORIZED,
            "Email or password is incorrect.",
        ));
    }
    let mut response = navigation("/admin", false);
    cookie(&mut response, "__Host-bloc-admin", &session);
    cookie(&mut response, "__Host-bloc-csrf", &browser);
    Ok(response)
}
async fn change(
    app: &Application,
    form: &BTreeMap<String, String>,
    session: &[u8; 32],
    owner: Option<&Credentials>,
) -> Result<Response, Failure> {
    let Some(owner) = owner else {
        return Err(Failure::Storage);
    };
    if !app
        .worker
        .verify(field(form, "current_password").into(), owner.phc.clone())
        .await?
    {
        return Err(Failure::Status(
            StatusCode::BAD_REQUEST,
            "Password change was refused. Check your current password.",
        ));
    }
    let phc = app.worker.hash(field(form, "password").into()).await?;
    if !app
        .storage
        .replace_password(session, owner.version, &phc, false)
        .await
        .map_err(|_| Failure::Storage)?
    {
        return Err(Failure::Status(
            StatusCode::CONFLICT,
            "Your credentials changed. Sign in again.",
        ));
    }
    Ok(navigation("/admin/login", false))
}
async fn setup_or_recover(
    app: &Application,
    form: &BTreeMap<String, String>,
    path: &str,
    email: &str,
) -> Result<Response, Failure> {
    let phc = app.worker.hash(field(form, "password").into()).await?;
    let digest = security::digest(field(form, "code"));
    if path == "/admin/setup" {
        match app
            .storage
            .claim_owner(&digest, email, &phc)
            .await
            .map_err(|_| Failure::Storage)?
        {
            Claim::Created => {}
            Claim::Closed => {
                return Err(Failure::Status(
                    StatusCode::CONFLICT,
                    "This installation already has an administrator.",
                ));
            }
            Claim::Unusable => {
                return Err(Failure::Status(
                    StatusCode::BAD_REQUEST,
                    "This code cannot be used. Generate a new code and try again.",
                ));
            }
        }
    } else if !app
        .storage
        .replace_password(&digest, 0, &phc, true)
        .await
        .map_err(|_| Failure::Storage)?
    {
        return Err(Failure::Status(
            StatusCode::BAD_REQUEST,
            "This code cannot be used. Generate a new code and try again.",
        ));
    }
    Ok(navigation("/admin/login", false))
}
/// Production assembly; callers provide validated configuration and shared storage.
pub fn router(app: Application) -> Router {
    Router::new()
        .route(
            "/assets/ui.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../assets/ui.css"),
                )
            }),
        )
        .route(
            "/assets/ui.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../assets/ui.js"),
                )
            }),
        )
        .route("/", get(|| async { Redirect::to("/admin/login") }))
        .route("/healthz", get(|| async { "ok\n" }))
        .route(
            "/readyz",
            get(|State(app): State<Application>| async move {
                if app.storage.compatible().await.is_ok() {
                    (StatusCode::OK, "ready\n")
                } else {
                    (StatusCode::SERVICE_UNAVAILABLE, "unavailable\n")
                }
            }),
        )
        .route(
            "/admin/realms",
            get(crate::directory::handler).post(crate::directory::handler),
        )
        .route(
            "/admin/realms/{*resource}",
            get(crate::directory::handler).post(crate::directory::handler),
        )
        .route(
            "/assets/directory.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../assets/directory.css"),
                )
            }),
        )
        .route(
            "/assets/directory.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../assets/directory.js"),
                )
            }),
        )
        .route("/admin", get(handler))
        .route("/admin/setup", get(handler).post(handler))
        .route("/admin/login", get(handler).post(handler))
        .route("/admin/recovery", get(handler).post(handler))
        .route("/admin/password", get(handler).post(handler))
        .route("/admin/logout", axum::routing::post(handler))
        .route(
            "/assets/admin.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../assets/admin.css"),
                )
            }),
        )
        .route(
            "/assets/navigation.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../assets/navigation.js"),
                )
            }),
        )
        .route(
            "/assets/admin.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../assets/admin.js"),
                )
            }),
        )
        .route(
            "/assets/htmx.min.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../assets/vendor/htmx-2.0.8.min.js"),
                )
            }),
        )
        .with_state(app)
        .layer(axum::middleware::from_fn(crate::security_headers))
}

#[cfg(test)]
#[path = "administrator_tests.rs"]
mod tests;
