//! Realm-scoped HTML authentication and own-account controls.
use crate::{
    administrator::Application,
    credentials, directory,
    realm_storage::{self, Account, Authority, Commit, Policy, Session},
    request_security as sec,
};
use askama::Template;
use axum::{
    body::to_bytes,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use sec::native_origin;
use std::{collections::BTreeMap, net::SocketAddr};
use subtle::ConstantTimeEq;
type Form = BTreeMap<String, String>;
mod access;
mod account;
mod admin;
mod submission;
mod view;
pub(crate) use admin::admin_handler;
use view::*;
fn cookie_name(r: &str, p: Option<&str>) -> String {
    match p {
        Some(p) => format!("__Host-bloc-realm-{r}-{p}"),
        None => format!("__Host-bloc-realm-{r}"),
    }
}
fn cookie(response: &mut Response, name: &str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(&format!(
        "{name}={value}; Secure; HttpOnly; SameSite=Lax; Path=/{}",
        if value.is_empty() { "; Max-Age=0" } else { "" }
    )) {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
}
fn clear(response: &mut Response, r: &str) {
    cookie(response, &cookie_name(r, None), "");
    cookie(response, &cookie_name(r, Some("account")), "");
}
fn nav(path: &str, hx: bool) -> Response {
    let mut response = crate::administrator::navigation(path, hx);
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}
fn val<'a>(f: &'a Form, n: &str) -> &'a str {
    f.get(n).map(String::as_str).unwrap_or("")
}
fn version(f: &Form) -> i64 {
    val(f, "version").parse().unwrap_or(0)
}
#[derive(Debug)]
struct Failure {
    status: StatusCode,
    state: &'static str,
    message: &'static str,
    retry: Option<i32>,
}
impl Failure {
    fn new(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            state: "error",
            message,
            retry: None,
        }
    }
    fn csrf() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "This form cannot be submitted. Reload the page to continue. For an access link, reopen the original link or enter its code again.",
        )
    }
    fn link() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            state: "link-invalid",
            message: "It may have expired or been replaced. Ask your administrator for a new link.",
            retry: None,
        }
    }
    fn response(self, r: &str, path: &str, hx: bool) -> Response {
        let mut p = Page::new(r, path);
        p.hidden = true;
        p.state = self.state;
        p.title = match self.state {
            "link-invalid" => "This link can’t be used",
            "unavailable" => "This realm is unavailable",
            "registration-disabled" => "Registration is unavailable",
            "throttled" => "Try again shortly",
            _ => "Temporarily unavailable",
        }
        .into();
        p.feedback = self.message.into();
        p.error = true;
        let mut response = render(&p, self.status, hx);
        if let Some(s) = self.retry
            && let Ok(v) = HeaderValue::from_str(&s.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, v);
        }
        response
    }
}
impl From<realm_storage::Error> for Failure {
    fn from(e: realm_storage::Error) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            state: "service-unavailable",
            message: "bloc cannot confirm this request. Try again shortly.",
            retry: if matches!(e, realm_storage::Error::Capacity) {
                Some(60)
            } else {
                None
            },
        }
    }
}
impl From<credentials::Error> for Failure {
    fn from(e: credentials::Error) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            state: "service-unavailable",
            message: "Try again shortly. Your password has not been changed.",
            retry: if e == credentials::Error::Capacity {
                Some(1)
            } else {
                None
            },
        }
    }
}
fn random() -> Result<String, Failure> {
    sec::random()
        .map(|x| sec::encode(&x))
        .map_err(|_| realm_storage::Error::Storage.into())
}
fn key(app: &Application, p: &str, v: &str) -> Result<[u8; 32], Failure> {
    sec::keyed(&app.config, p, v).map_err(|_| realm_storage::Error::Storage.into())
}
async fn reserve(app: &Application, b: &[(&str, [u8; 32], i32)]) -> Result<(), Failure> {
    match app.storage.realm_reserve(b).await? {
        0 => Ok(()),
        -1 => Err(realm_storage::Error::Capacity.into()),
        s => Err(Failure {
            status: StatusCode::TOO_MANY_REQUESTS,
            state: "throttled",
            message: "Too many attempts. Wait before trying again.",
            retry: Some(s),
        }),
    }
}
async fn post(app: &Application, request: Request) -> Result<Form, Failure> {
    if !sec::origin(&app.config, request.headers()) && !native_origin(request.headers()) {
        return Err(Failure::csrf());
    }
    if sec::one(request.headers(), "content-type").and_then(|x| x.split(';').next())
        != Some("application/x-www-form-urlencoded")
    {
        return Err(Failure::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Submit this form using the supported format.",
        ));
    }
    let b = to_bytes(request.into_body(), 16384).await.map_err(|_| {
        Failure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "The submitted form is too large.",
        )
    })?;
    sec::form_fields(&b).map_err(|s| Failure::new(s, "The request could not be read."))
}
fn source(app: &Application, request: &Request) -> Result<String, Failure> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .ok_or_else(Failure::csrf)?;
    sec::source(&app.config, request.headers(), peer.0)
        .map(|x| x.to_string())
        .map_err(|s| Failure::new(s, "The request could not be accepted."))
}
async fn form_token(
    app: &Application,
    p: &mut Page,
    h: &HeaderMap,
    purpose: &str,
    session: Option<&[u8; 32]>,
    link: Option<&[u8; 32]>,
    source: &str,
) -> Result<Option<String>, Failure> {
    let name = cookie_name(&p.realm, Some(purpose));
    if let Some(b) = sec::cookie(h, &name)
        && let Some(t) = app
            .storage
            .realm_form(Authority {
                realm: &p.realm,
                purpose,
                browser: &sec::digest(&b),
                token: None,
                session,
                link,
            })
            .await?
    {
        p.csrf = sec::encode(&t);
        return Ok(None);
    }
    if purpose == "anonymous" {
        reserve(
            app,
            &[("form_source", key(app, "realm-form-source", source)?, 1)],
        )
        .await?;
    }
    let b = random()?;
    let token = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let t = app
        .storage
        .realm_form(Authority {
            realm: &p.realm,
            purpose,
            browser: &sec::digest(&b),
            token: Some(&token),
            session,
            link,
        })
        .await?
        .ok_or_else(Failure::csrf)?;
    p.csrf = sec::encode(&t);
    Ok(Some(b))
}
fn device(h: &HeaderMap) -> String {
    let Some(ua) = sec::one(h, "user-agent") else {
        return "Unknown device".into();
    };
    let browser = if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Chrome/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        return "Unknown device".into();
    };
    let os = if ua.contains("iPhone") {
        "iPhone"
    } else if ua.contains("iPad") {
        "iPad"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "Unknown device"
    };
    format!("{browser} · {os}")
}
pub(crate) async fn handler(State(app): State<Application>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let hx = sec::one(request.headers(), "hx-request") == Some("true");
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    let realm = parts.get(1).copied().unwrap_or("");
    let action = match parts.last().copied().unwrap_or("") {
        "register" => "registration",
        "login" => "sign_in",
        "logout" => "sign_out",
        "exchange" => "link_exchange",
        "activate" => "activation",
        "reset-password" => "reset",
        "profile" => "profile",
        "password" => "password_change",
        "revoke" | "revoke-others" => "session_revoke",
        _ => "form_issue",
    };
    let mut response = match handle(&app, request, &path, hx).await {
        Ok(r) => r,
        Err(f) => f.response(realm, &path, hx),
    };
    if path.ends_with("/logout") && response.status() == StatusCode::SERVICE_UNAVAILABLE {
        clear(&mut response, realm)
    }
    if response.status().is_client_error() || response.status().is_server_error() {
        let reason = match response.status() {
            StatusCode::FORBIDDEN => "authority",
            StatusCode::UNPROCESSABLE_ENTITY => "credentials",
            StatusCode::CONFLICT => "conflict",
            StatusCode::TOO_MANY_REQUESTS => "admission",
            StatusCode::PAYLOAD_TOO_LARGE => "oversized",
            StatusCode::UNSUPPORTED_MEDIA_TYPE => "media_type",
            StatusCode::BAD_REQUEST => "malformed",
            _ => "storage",
        };
        if app.storage.realm_deny(action, reason).await.is_err() {
            tracing::warn!("realm denial observation unavailable")
        }
    }
    response
}
struct Flow {
    source: String,
    h: HeaderMap,
    query: String,
    route: String,
    target: Option<String>,
    realm: String,
    get: bool,
    policy: Policy,
    p: Page,
    session: Option<[u8; 32]>,
    form: Form,
    link: Option<[u8; 32]>,
    purpose: &'static str,
    form_purpose: &'static str,
    path: String,
}
async fn handle(
    app: &Application,
    request: Request,
    path: &str,
    hx: bool,
) -> Result<Response, Failure> {
    let source = source(app, &request)?;
    let h = request.headers().clone();
    let query = request.uri().query().unwrap_or("").to_owned();
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    if parts.len() < 3 || !directory::uuid(parts[1]) {
        return Err(Failure::new(
            StatusCode::NOT_FOUND,
            "This realm is unavailable.",
        ));
    }
    let r = parts[1];
    let route = parts[2..].join("/");
    let target = if parts.len() == 6
        && parts[2] == "account"
        && parts[3] == "sessions"
        && parts[5] == "revoke"
        && directory::uuid(parts[4])
    {
        Some(parts[4])
    } else {
        None
    };
    if !matches!(
        route.as_str(),
        "login"
            | "register"
            | "activate"
            | "reset-password"
            | "activate/exchange"
            | "reset-password/exchange"
            | "logout"
            | "account"
            | "account/profile"
            | "account/password"
            | "account/sessions"
            | "account/sessions/revoke-others"
    ) && target.is_none()
    {
        return Err(Failure::new(
            StatusCode::NOT_FOUND,
            "This page is unavailable.",
        ));
    }
    let get = request.method() == Method::GET || request.method() == Method::HEAD;
    let allowed = if get && (route == "logout" || route.ends_with("/exchange")) {
        Some("POST")
    } else if !get && matches!(route.as_str(), "account" | "account/sessions") {
        Some("GET, HEAD")
    } else {
        None
    };
    if let Some(allowed) = allowed {
        let mut response = Failure::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "Use the page link or form to continue.",
        )
        .response(r, path, hx);
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static(allowed));
        return Ok(response);
    }
    let policy = app.storage.realm_policy(r, None).await?.ok_or(Failure {
        status: StatusCode::NOT_FOUND,
        state: "unavailable",
        message: "Check the address or contact your administrator.",
        retry: None,
    })?;
    let mut p = Page::new(r, path);
    p.name = app.storage.realm_name(r).await?.unwrap_or_default();
    p.registration = policy.registration;
    p.protected = route.starts_with("account") || route == "logout";
    let session = sec::cookie(&h, &cookie_name(r, None)).map(|x| sec::digest(&x));
    if p.protected {
        p.account = match session.as_ref() {
            Some(s) => app.storage.realm_account(r, s, get).await?,
            None => None,
        }
        .unwrap_or_default();
        if p.account.user.is_empty() {
            return Ok(nav(&format!("{}/login?expired=1", p.base), hx));
        }
    }
    if route == "account" {
        let destination = if query == "password-saved=1" {
            "password?saved=1"
        } else {
            "profile"
        };
        return Ok(nav(&format!("{}/account/{destination}", p.base), hx));
    }
    if route == "register" && !policy.registration {
        return Err(Failure {
            status: StatusCode::FORBIDDEN,
            state: "registration-disabled",
            message: "Contact your administrator to get access.",
            retry: None,
        });
    }
    let form = if get {
        Form::new()
    } else {
        post(app, request).await?
    };
    let link_route = route.starts_with("activate") || route.starts_with("reset-password");
    let purpose = if route.starts_with("activate") {
        "activation"
    } else {
        "reset"
    };
    if link_route && !query.is_empty() {
        return Err(Failure::link());
    }
    let mut link = None;
    if link_route
        && !route.ends_with("/exchange")
        && let Some(b) = sec::cookie(&h, &cookie_name(r, Some(purpose)))
    {
        link = app
            .storage
            .realm_form_link(r, purpose, &sec::digest(&b))
            .await?;
    }
    if link_route && !get && !route.ends_with("/exchange") && link.is_none() {
        if let Some(b) = sec::cookie(&h, &cookie_name(r, Some(purpose))) {
            if app
                .storage
                .realm_form_expired(r, purpose, &sec::digest(&b))
                .await?
            {
                return Err(Failure::csrf());
            }
            return Err(Failure::link());
        }
        return Err(Failure::csrf());
    }
    let form_purpose = if p.protected {
        "account"
    } else if link.is_some() {
        purpose
    } else {
        "anonymous"
    };
    p.state = match route.as_str() {
        "register" => "registration",
        "account/profile" => "profile",
        "account/password" => "password",
        "account/sessions" | "account/sessions/revoke-others" => "sessions",
        _ if target.is_some() => "sessions",
        _ if link_route && link.is_none() => "link-entry",
        _ if link_route => purpose,
        _ => "login",
    };
    p.version = if p.state == "profile" {
        p.account.version
    } else {
        policy.version
    };
    let flow = Flow {
        source,
        h,
        query,
        route,
        target: target.map(str::to_owned),
        realm: r.into(),
        get,
        policy,
        p,
        session,
        form,
        link,
        purpose,
        form_purpose,
        path: path.into(),
    };
    if flow.p.protected {
        account::handle(app, flow, hx).await
    } else {
        access::handle(app, flow, hx).await
    }
}
#[cfg(test)]
#[path = "realm_authentication_tests.rs"]
mod tests;
