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
use std::{collections::BTreeMap, net::SocketAddr};
use subtle::ConstantTimeEq;
type Form = BTreeMap<String, String>;
struct Field {
    name: String,
    label: String,
    kind: &'static str,
    value: String,
    help: String,
    error: String,
    autocomplete: &'static str,
}
struct Toggle {
    name: &'static str,
    label: &'static str,
    checked: bool,
}
struct Lifetime {
    name: &'static str,
    label: &'static str,
    value: String,
    unit: &'static str,
    help: &'static str,
    error: String,
}
struct Page {
    title: String,
    intro: String,
    state: &'static str,
    realm: String,
    name: String,
    path: String,
    base: String,
    account: Account,
    admin: bool,
    protected: bool,
    csrf: String,
    fields: Vec<Field>,
    toggles: Vec<Toggle>,
    lifetimes: Vec<Lifetime>,
    feedback: String,
    error: bool,
    hidden: bool,
    action: &'static str,
    version: i64,
    registration: bool,
    sessions: Vec<Session>,
    confirm: String,
    confirm_values: Vec<(String, String)>,
    hidden_fields: Vec<(String, String)>,
    secret: String,
    link: String,
    expiry: String,
    purpose: String,
}
impl Page {
    fn new(r: &str, path: &str) -> Self {
        Self {
            title: String::new(),
            intro: String::new(),
            state: "login",
            realm: r.into(),
            name: String::new(),
            path: path.into(),
            base: format!("/realms/{r}"),
            account: Account::default(),
            admin: false,
            protected: false,
            csrf: String::new(),
            fields: vec![],
            toggles: vec![],
            lifetimes: vec![],
            feedback: String::new(),
            error: false,
            hidden: false,
            action: "Continue",
            version: 0,
            registration: false,
            sessions: vec![],
            confirm: String::new(),
            confirm_values: vec![],
            hidden_fields: vec![],
            secret: String::new(),
            link: String::new(),
            expiry: String::new(),
            purpose: String::new(),
        }
    }
    fn field(&mut self, name: &str, label: &str, kind: &'static str, value: &str, help: &str) {
        self.fields.push(Field {
            name: name.into(),
            label: label.into(),
            kind,
            value: if kind == "password" {
                String::new()
            } else {
                value.into()
            },
            help: help.into(),
            error: String::new(),
            autocomplete: if name == "current_password"
                || name == "password" && self.state == "login"
            {
                "current-password"
            } else if kind == "password" {
                "new-password"
            } else if name == "email" {
                "username"
            } else {
                "off"
            },
        })
    }
    fn invalid(&mut self, name: &str, message: &str) {
        self.error = true;
        self.feedback = "Check the highlighted field.".into();
        if let Some(f) = self.fields.iter_mut().find(|x| x.name == name) {
            f.error = message.into()
        }
        if let Some(t) = self.lifetimes.iter_mut().find(|x| x.name == name) {
            t.error = message.into();
        }
    }
    fn passwords(&mut self, p: &Policy) {
        self.field(
            "password",
            if self.state == "password" {
                "New password"
            } else {
                "Password"
            },
            "password",
            "",
            &p.requirements(),
        );
        self.field(
            "password_confirmation",
            "Confirm password",
            "password",
            "",
            "",
        );
    }
}
#[derive(Template)]
#[template(path = "realm.html")]
struct Full<'a> {
    p: &'a Page,
}
#[derive(Template)]
#[template(path = "realm_content.html")]
struct Fragment<'a> {
    p: &'a Page,
}
fn render(p: &Page, status: StatusCode, hx: bool) -> Response {
    let html = if hx {
        Fragment { p }.render()
    } else {
        Full { p }.render()
    };
    let mut r = match html {
        Ok(h) => (status, Html(h)).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    r.headers_mut()
        .insert(header::VARY, HeaderValue::from_static("HX-Request"));
    r.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    r
}
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
fn native_origin(headers: &HeaderMap) -> bool {
    // no-referrer serializes native form Origin as null. Fetch Metadata is
    // browser-controlled; canonical HTTPS ingress and CSRF remain mandatory.
    sec::one(headers, "origin") == Some("null")
        && sec::one(headers, "sec-fetch-site") == Some("same-origin")
        && sec::one(headers, "sec-fetch-mode") == Some("navigate")
        && sec::one(headers, "sec-fetch-dest") == Some("document")
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
    match p.state {
        "registration" => {
            p.title = "Create your account".into();
            p.intro = format!("Create an account in {}.", p.name);
            p.field(
                "display_name",
                "Display name",
                "text",
                val(&form, "display_name"),
                "Optional. You can change this later.",
            );
            p.field(
                "email",
                "Email address",
                "email",
                val(&form, "email"),
                "Your email will not be verified yet.",
            );
            p.passwords(&policy);
            p.action = "Create account";
        }
        "login" => {
            p.title = format!("Sign in to {}", p.name);
            p.intro = "Use your realm account to continue.".into();
            p.field("email", "Email address", "email", val(&form, "email"), "");
            p.field("password", "Password", "password", "", "");
            p.action = "Sign in";
            if query == "expired=1" {
                p.state = "expired";
                p.feedback = "Your session ended. Sign in again.".into()
            }
            if query == "registered=1" || query == "activated=1" {
                p.title = "Your account is ready".into();
                p.feedback = "Sign in with your email and password.".into();
                p.state = "success"
            }
            if query == "reset=1" {
                p.title = "Your password was reset".into();
                p.state = "reset-success";
                p.feedback = "Sign in with your new password.".into()
            }
            if query == "help=1" {
                p.title = "Need a new password?".into();
                p.state = "forgot";
                p.hidden = true;
                p.feedback="Contact your administrator. They will confirm your identity and share a password-reset link. bloc does not send recovery emails.".into()
            }
        }
        "link-entry" => {
            p.title = "Continue with your access code".into();
            p.intro = "Paste the code your administrator shared with you.".into();
            p.field("code", "Access code", "password", "", "");
            p.path = format!("{}/exchange", path.trim_end_matches("/exchange"));
        }
        "activation" | "reset" => {
            p.title = if purpose == "activation" {
                "Set your password"
            } else {
                "Choose a new password"
            }
            .into();
            p.passwords(&policy);
            p.action = "Save password";
        }
        "profile" => {
            p.title = "Profile".into();
            p.intro = format!("Manage your personal information in {}.", p.name);
            let display = if get {
                p.account.display.clone()
            } else {
                val(&form, "display_name").into()
            };
            p.field(
                "display_name",
                "Display name",
                "text",
                &display,
                "How your name appears in your account.",
            );
            p.action = "Save changes";
            if query == "saved=1" {
                p.state = "profile-saved";
                p.feedback = "Your profile was saved.".into()
            }
        }
        "password" => {
            p.title = "Password".into();
            p.intro = format!("Keep your {} account secure.", p.name);
            p.field("current_password", "Current password", "password", "", "");
            p.passwords(&policy);
            p.action = "Change password";
            if query == "saved=1" {
                p.state = "password-saved";
                p.feedback = "Your password was changed. This session was renewed.".into()
            }
        }
        "sessions" => {
            p.title = "Sessions".into();
            p.intro = format!("Manage where you’re signed in to {}.", p.name);
            p.sessions = app
                .storage
                .realm_sessions(r, session.as_ref().ok_or_else(Failure::csrf)?)
                .await?;
            if route.ends_with("revoke-others") {
                p.confirm = format!("End all other {} sessions?", p.name);
                p.state = "revoke";
                p.action = "End other sessions";
            } else if let Some(t) = target {
                if let Some(s) = p.sessions.iter().find(|s| s.id == t) {
                    p.confirm = if s.current {
                        format!("End this {} session?", p.name)
                    } else {
                        format!("End the {} session?", s.device)
                    };
                    p.state = if s.current {
                        "revoke-current"
                    } else {
                        "revoke-one"
                    };
                    p.action = "End session";
                } else if get {
                    return Err(Failure::new(
                        StatusCode::NOT_FOUND,
                        "This session is unavailable.",
                    ));
                }
            }
            if query == "ended=1" {
                p.state = "sessions-ended";
                p.feedback = "The selected sessions have ended.".into()
            }
        }
        _ => {}
    }
    if get {
        let protected = p.protected;
        let b = form_token(
            app,
            &mut p,
            &h,
            form_purpose,
            session.as_ref().filter(|_| protected),
            link.as_ref(),
            &source,
        )
        .await?;
        let mut response = render(&p, StatusCode::OK, hx);
        if let Some(b) = b {
            cookie(&mut response, &cookie_name(r, Some(form_purpose)), &b)
        }
        return Ok(response);
    }
    let browser = sec::cookie(&h, &cookie_name(r, Some(form_purpose)))
        .map(|x| sec::digest(&x))
        .ok_or_else(Failure::csrf)?;
    let token = sec::decode(val(&form, "csrf")).ok_or_else(Failure::csrf)?;
    let stored = app
        .storage
        .realm_form(Authority {
            realm: r,
            purpose: form_purpose,
            browser: &browser,
            token: None,
            session: session.as_ref().filter(|_| p.protected),
            link: link.as_ref(),
        })
        .await?
        .ok_or_else(Failure::csrf)?;
    if !bool::from(stored.as_slice().ct_eq(&token)) {
        return Err(Failure::csrf());
    }
    p.csrf = sec::encode(&token);
    let allowed: &[&str] = if route == "register" {
        &[
            "csrf",
            "email",
            "display_name",
            "password",
            "password_confirmation",
        ]
    } else if route == "login" {
        &["csrf", "email", "password"]
    } else if route.ends_with("/exchange") {
        &["csrf", "code"]
    } else if route == "account/profile" {
        &["csrf", "version", "display_name"]
    } else if route == "account/password" {
        &[
            "csrf",
            "current_password",
            "password",
            "password_confirmation",
        ]
    } else if link_route {
        &["csrf", "password", "password_confirmation"]
    } else {
        &["csrf", "confirmed"]
    };
    if form.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(Failure::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "This form contains unsupported fields.",
        ));
    }
    if route.ends_with("/exchange") {
        reserve(
            app,
            &[
                (
                    "exchange_source",
                    key(app, "realm-exchange-source", &source)?,
                    1,
                ),
                ("exchange_realm", key(app, "realm-exchange-realm", r)?, 1),
            ],
        )
        .await?;
        if sec::decode(val(&form, "code")).is_none() {
            return Err(Failure::link());
        }
        let digest = sec::digest(val(&form, "code"));
        let b = random()?;
        let t = sec::random().map_err(|_| realm_storage::Error::Storage)?;
        let out = app
            .storage
            .realm_exchange(
                Authority {
                    realm: r,
                    purpose,
                    browser: &browser,
                    token: Some(&token),
                    session: None,
                    link: Some(&digest),
                },
                &sec::digest(&b),
                &t,
            )
            .await?;
        if out != "ok" {
            return Err(Failure::link());
        }
        let mut response = nav(path.trim_end_matches("/exchange"), hx);
        cookie(&mut response, &cookie_name(r, Some(purpose)), &b);
        return Ok(response);
    }
    if link_route && link.is_none() {
        return Err(Failure::csrf());
    }
    let operation = match route.as_str() {
        "register" => "register",
        "login" => "login",
        "account/profile" => "profile",
        "account/password" => "password",
        "logout" => "logout",
        "account/sessions/revoke-others" => "revoke_others",
        _ if target.is_some() => "revoke",
        _ => purpose,
    };
    let mut values = vec![];
    let mut expected = 0;
    let mut policy_version = policy.version;
    let mut user = None;
    if matches!(operation, "revoke" | "revoke_others") && val(&form, "confirmed") != "true" {
        return Ok(render(&p, StatusCode::OK, hx));
    }
    if operation == "profile" {
        match directory::name(val(&form, "display_name"), true) {
            Ok(n) => values.push(n),
            Err(_) => {
                p.invalid(
                    "display_name",
                    "Use at most 128 characters and 512 bytes, without control characters.",
                );
                return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
            }
        }
        expected = version(&form);
    }
    let email = if matches!(operation, "login" | "register") {
        match credentials::normalize_email(val(&form, "email")) {
            Ok(e) => e,
            Err(_) => {
                p.invalid("email", "Enter an email address.");
                return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
            }
        }
    } else {
        String::new()
    };
    if operation == "register" {
        let display = match directory::name(val(&form, "display_name"), true) {
            Ok(n) => n,
            Err(_) => {
                p.invalid(
                    "display_name",
                    "Use at most 128 characters and 512 bytes, without control characters.",
                );
                return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
            }
        };
        values = vec![email.clone(), display];
    }
    if matches!(operation, "register" | "activation" | "reset" | "password")
        && !policy.accepts(val(&form, "password"), val(&form, "password_confirmation"))
    {
        if operation == "register" {
            p.state = "policy-error";
        }
        p.invalid(
            "password",
            "Follow the current password requirements and enter matching confirmation.",
        );
        return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
    }
    let credential_work = matches!(
        operation,
        "login" | "register" | "activation" | "reset" | "password"
    );
    if credential_work {
        let units = if operation == "password" { 2 } else { 1 };
        let mut buckets = vec![
            (
                "credential_source",
                key(app, "realm-credential-source", &source)?,
                1,
            ),
            ("public_work", [0; 32], units),
            ("hash_work", [0; 32], units),
        ];
        match operation {
            "login" => buckets.push((
                "login_identifier",
                key(app, "realm-login-identifier", &format!("{r}:{email}"))?,
                1,
            )),
            "register" => {
                buckets.push(("registration_realm", key(app, "realm-registration", r)?, 1));
                buckets.push((
                    "registration_identifier",
                    key(
                        app,
                        "realm-registration-identifier",
                        &format!("{r}:{email}"),
                    )?,
                    1,
                ));
            }
            "password" => buckets.push((
                "password_change",
                key(
                    app,
                    "realm-password-change",
                    &format!("{r}:{}", p.account.user),
                )?,
                1,
            )),
            _ => buckets.push((
                "link",
                key(
                    app,
                    "realm-link-attempt",
                    &format!(
                        "{r}:{purpose}:{}",
                        sec::encode(link.as_ref().ok_or_else(Failure::csrf)?)
                    ),
                )?,
                1,
            )),
        };
        reserve(app, &buckets).await?;
        if operation == "login" {
            let credential = app.storage.realm_credentials(r, &email).await?;
            let verified = app
                .worker
                .verify(
                    val(&form, "password").into(),
                    credential
                        .as_ref()
                        .map(|c| c.phc.clone())
                        .unwrap_or_else(|| app.dummy.clone()),
                )
                .await?;
            if !verified || credential.is_none() {
                p.feedback = "Email or password is incorrect.".into();
                p.error = true;
                p.state = "login-error";
                return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
            }
            if let Some(c) = credential {
                expected = c.version;
                policy_version = c.user_version;
                user = Some(c.user);
            }
            values.push(device(&h));
        } else {
            if operation == "password" {
                if !app
                    .worker
                    .verify(val(&form, "current_password").into(), p.account.phc.clone())
                    .await?
                {
                    p.invalid("current_password", "Check your current password.");
                    return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
                }
                expected = p.account.credential;
            }
            values.push(app.worker.hash(val(&form, "password").into()).await?);
            if operation == "password" {
                values.push(device(&h))
            }
        }
    } else {
        reserve(
            app,
            &[(
                "account_mutation",
                key(
                    app,
                    "realm-account-mutation",
                    &format!("{r}:{}", p.account.user),
                )?,
                1,
            )],
        )
        .await?;
    }
    let fresh = matches!(operation, "login" | "password");
    let (new_session, new_browser, new_token) = if fresh {
        (
            random()?,
            random()?,
            sec::random().map_err(|_| realm_storage::Error::Storage)?,
        )
    } else {
        (String::new(), String::new(), [0; 32])
    };
    let sd = sec::digest(&new_session);
    let bd = sec::digest(&new_browser);
    let out = app
        .storage
        .realm_commit(Commit {
            operation,
            authority: Authority {
                realm: r,
                purpose: form_purpose,
                browser: &browser,
                token: Some(&token),
                session: session.as_ref().filter(|_| p.protected),
                link: link.as_ref(),
            },
            target: user.as_deref().or(target),
            expected,
            policy: policy_version,
            values,
            new_session: fresh.then_some(&sd),
            new_browser: fresh.then_some(&bd),
            new_token: fresh.then_some(&new_token),
        })
        .await?;
    if out != "ok" {
        match out.as_str() {
            "csrf" => return Err(Failure::csrf()),
            "link" => return Err(Failure::link()),
            "credentials" if operation == "login" => {
                p.state = "login-error";
                p.error = true;
                p.feedback = "Email or password is incorrect.".into();
                return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
            }
            "authority" | "credentials" => {
                return Ok(nav(&format!("{}/login?expired=1", p.base), hx));
            }
            "missing" => {
                return Err(Failure::new(
                    StatusCode::NOT_FOUND,
                    "This realm or session is unavailable.",
                ));
            }
            "disabled" => {
                return Err(Failure {
                    status: StatusCode::FORBIDDEN,
                    state: "registration-disabled",
                    message: "Contact your administrator to get access.",
                    retry: None,
                });
            }
            "collision" => {
                p.state = "registration-error";
                p.feedback = "We couldn’t create your account. Contact your administrator.".into();
                p.error = true;
                return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
            }
            _ => {
                p.feedback="This information changed. Reload the page and review the current requirements before trying again.".into();
                p.error = true;
                if operation == "profile" {
                    p.state = "profile-conflict";
                }
                if out == "policy"
                    && let Some(current) = app.storage.realm_policy(r, None).await?
                {
                    for f in &mut p.fields {
                        if f.name == "password" {
                            f.help = current.requirements()
                        }
                    }
                }
                return Ok(render(&p, StatusCode::CONFLICT, hx));
            }
        }
    }
    let destination = match operation {
        "register" => format!("{}/login?registered=1", p.base),
        "activation" => format!("{}/login?activated=1", p.base),
        "reset" => format!("{}/login?reset=1", p.base),
        "login" => format!("{}/account", p.base),
        "password" => format!("{}/account?password-saved=1", p.base),
        "profile" => format!("{}/account/profile?saved=1", p.base),
        "logout" => format!("{}/login", p.base),
        "revoke" if target == Some(p.account.session.as_str()) => format!("{}/login", p.base),
        _ => format!("{}/account/sessions?ended=1", p.base),
    };
    let mut response = nav(&destination, hx);
    if fresh {
        cookie(&mut response, &cookie_name(r, None), &new_session);
        cookie(
            &mut response,
            &cookie_name(r, Some("account")),
            &new_browser,
        );
    }
    if operation == "logout" || operation == "revoke" && target == Some(p.account.session.as_str())
    {
        clear(&mut response, r)
    }
    Ok(response)
}
fn settings_fields(p: &mut Page, policy: &Policy) {
    p.field(
        "password_min_length",
        "Minimum length",
        "number",
        &policy.minimum.to_string(),
        "16–128 characters. Maximum password length is 128 characters.",
    );
    p.field(
        "session_limit",
        "Active sessions per user",
        "number",
        &policy.limit.to_string(),
        "1–100. New sign-ins end the oldest session at this limit.",
    );
    p.toggles = vec![
        Toggle {
            name: "registration_enabled",
            label: "Allow users to create accounts",
            checked: policy.registration,
        },
        Toggle {
            name: "require_uppercase",
            label: "Require an uppercase letter",
            checked: policy.upper,
        },
        Toggle {
            name: "require_lowercase",
            label: "Require a lowercase letter",
            checked: policy.lower,
        },
        Toggle {
            name: "require_number",
            label: "Require a number",
            checked: policy.number,
        },
        Toggle {
            name: "require_special",
            label: "Require a special character",
            checked: policy.special,
        },
    ];
    for (name, label, seconds, help) in [
        (
            "activation_ttl_seconds",
            "Activation link lifetime",
            policy.activation,
            "5 minutes–7 days.",
        ),
        (
            "reset_ttl_seconds",
            "Password-reset link lifetime",
            policy.reset,
            "5 minutes–24 hours.",
        ),
        (
            "session_idle_seconds",
            "Inactivity timeout",
            policy.idle,
            "1 minute–24 hours. Cannot exceed the total lifetime.",
        ),
        (
            "session_absolute_seconds",
            "Total session lifetime",
            policy.absolute,
            "5 minutes–30 days.",
        ),
    ] {
        let (value, unit) = if seconds % 86400 == 0 {
            (seconds / 86400, "days")
        } else if seconds % 3600 == 0 {
            (seconds / 3600, "hours")
        } else if seconds % 60 == 0 {
            (seconds / 60, "minutes")
        } else {
            (seconds, "seconds")
        };
        p.lifetimes.push(Lifetime {
            name,
            label,
            value: value.to_string(),
            unit,
            help,
            error: String::new(),
        })
    }
}
fn settings_values(form: &Form) -> Result<Vec<String>, String> {
    let mut values = vec![];
    for n in [
        "registration_enabled",
        "password_min_length",
        "require_uppercase",
        "require_lowercase",
        "require_number",
        "require_special",
        "activation_ttl_seconds",
        "reset_ttl_seconds",
        "session_idle_seconds",
        "session_absolute_seconds",
        "session_limit",
    ] {
        if matches!(
            n,
            "registration_enabled"
                | "require_uppercase"
                | "require_lowercase"
                | "require_number"
                | "require_special"
        ) {
            let v = val(form, n);
            if !matches!(v, "" | "true" | "false" | "on") {
                return Err(n.into());
            }
            values.push(matches!(v, "true" | "on").to_string());
        } else {
            let v = val(form, n).parse::<i32>().map_err(|_| n.to_owned())?;
            let multiplier = match val(form, &format!("{n}_unit")) {
                "" | "seconds" => 1,
                "minutes" => 60,
                "hours" => 3600,
                "days" => 86400,
                _ => return Err(n.into()),
            };
            values.push(
                v.checked_mul(multiplier)
                    .ok_or_else(|| n.to_owned())?
                    .to_string(),
            );
        }
    }
    for (index, name, minimum, maximum) in [
        (1, "password_min_length", 16, 128),
        (6, "activation_ttl_seconds", 300, 604800),
        (7, "reset_ttl_seconds", 300, 86400),
        (8, "session_idle_seconds", 60, 86400),
        (9, "session_absolute_seconds", 300, 2592000),
        (10, "session_limit", 1, 100),
    ] {
        let v = values[index].parse::<i32>().map_err(|_| name.to_owned())?;
        if !(minimum..=maximum).contains(&v) {
            return Err(name.into());
        }
    }
    if values[8].parse::<i32>().unwrap_or(0) > values[9].parse::<i32>().unwrap_or(0) {
        return Err("session_idle_seconds".into());
    }
    Ok(values)
}
pub(crate) async fn admin_handler(State(app): State<Application>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let hx = sec::one(request.headers(), "hx-request") == Some("true");
    let r = path.split('/').nth(3).unwrap_or("").to_owned();
    let response = match admin_handle(&app, request, &path, hx).await {
        Ok(r) => r,
        Err(f) => f.response(&r, &path, hx),
    };
    if response.status().is_client_error() || response.status().is_server_error() {
        let a = if path.ends_with("authentication") {
            "settings"
        } else {
            "link_issue"
        };
        let reason = if response.status() == StatusCode::CONFLICT {
            "conflict"
        } else if response.status() == StatusCode::TOO_MANY_REQUESTS {
            "admission"
        } else {
            "authority"
        };
        if app.storage.realm_deny(a, reason).await.is_err() {
            tracing::warn!("realm denial observation unavailable")
        }
    }
    response
}
async fn admin_handle(
    app: &Application,
    request: Request,
    path: &str,
    hx: bool,
) -> Result<Response, Failure> {
    let source = source(app, &request)?;
    let h = request.headers().clone();
    let query = request.uri().query().unwrap_or("").to_owned();
    let get = request.method() == Method::GET || request.method() == Method::HEAD;
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    if parts.len() < 4
        || !directory::uuid(parts[2])
        || !(parts.len() == 4 && parts[3] == "authentication"
            || parts.len() == 6
                && parts[3] == "users"
                && directory::uuid(parts[4])
                && parts[5] == "access-links")
    {
        return Err(Failure::new(
            StatusCode::NOT_FOUND,
            "This record is unavailable.",
        ));
    }
    let r = parts[2];
    let Some(session) = sec::cookie(&h, "__Host-bloc-admin").map(|x| sec::digest(&x)) else {
        return Ok(crate::administrator::expired(hx));
    };
    let Some(owner) = app
        .storage
        .authorize(&session)
        .await
        .map_err(|_| realm_storage::Error::Storage)?
    else {
        return Ok(crate::administrator::expired(hx));
    };
    let realm = app
        .storage
        .directory_realms(&session, Some(r), None)
        .await
        .map_err(|_| realm_storage::Error::Storage)?
        .into_iter()
        .next()
        .ok_or_else(|| Failure::new(StatusCode::NOT_FOUND, "This realm is unavailable."))?;
    let policy = app
        .storage
        .realm_policy(r, Some(&session))
        .await?
        .ok_or_else(|| Failure::new(StatusCode::NOT_FOUND, "This realm is unavailable."))?;
    let mut p = Page::new(r, path);
    p.name = realm.name;
    p.admin = true;
    p.protected = true;
    p.account.email = owner.email;
    p.version = policy.version;
    let user = if parts.len() == 6 {
        app.storage
            .directory_users(&session, r, Some(parts[4]), None)
            .await
            .map_err(|_| realm_storage::Error::Storage)?
            .into_iter()
            .next()
    } else {
        None
    };
    if parts.len() == 6 && user.is_none() {
        return Err(Failure::new(
            StatusCode::NOT_FOUND,
            "This user is unavailable.",
        ));
    }
    if let Some(u) = &user {
        let credential = app.storage.realm_has_credential(r, &u.id, &session).await?;
        p.purpose = if credential { "reset" } else { "activation" }.into();
        p.state = if credential {
            "issue"
        } else {
            "issue-activation"
        };
        p.title = "User access".into();
        p.intro = format!("{} · {}", u.display_name, u.email);
        p.version = u.version;
        p.hidden = u.status != "active" || realm.status != "active";
        if p.hidden {
            p.feedback = "Activate the realm and user before issuing access.".into()
        }
        p.action = if credential {
            "Create reset link"
        } else {
            "Create activation link"
        };
    } else {
        p.title = "Authentication".into();
        p.state = "settings";
        p.intro = format!("Configure access to the {} realm.", p.name);
        p.action = "Save settings";
        settings_fields(&mut p, &policy);
        if query == "saved=1" {
            p.state = "settings-saved";
            p.feedback = "Authentication settings saved.".into()
        }
    }
    let mut browser_cookie = None;
    let mut browser = sec::cookie(&h, "__Host-bloc-csrf").map(|x| sec::digest(&x));
    let existing = match browser.as_ref() {
        Some(b) => app
            .storage
            .form(b, Some(&session), None)
            .await
            .map_err(|_| realm_storage::Error::Storage)?,
        None => None,
    };
    let token = if let Some(t) = existing {
        t
    } else if get {
        let key = key(app, "source", &source)?;
        match app
            .storage
            .reserve(&[("form_issue_source", key, 1)])
            .await
            .map_err(|_| realm_storage::Error::Storage)?
        {
            0 => {}
            -1 => return Err(realm_storage::Error::Capacity.into()),
            n => {
                return Err(Failure {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    state: "throttled",
                    message: "Too many attempts. Wait before trying again.",
                    retry: Some(n),
                });
            }
        }
        let b = random()?;
        let d = sec::digest(&b);
        let t = sec::random().map_err(|_| realm_storage::Error::Storage)?;
        let stored = app
            .storage
            .form(&d, Some(&session), Some(&t))
            .await
            .map_err(|_| realm_storage::Error::Storage)?
            .ok_or(realm_storage::Error::Capacity)?;
        browser = Some(d);
        browser_cookie = Some(b);
        stored
    } else {
        return Err(Failure::csrf());
    };
    p.csrf = sec::encode(&token);
    if get {
        let mut response = render(&p, StatusCode::OK, hx);
        if let Some(b) = browser_cookie {
            crate::administrator::cookie(&mut response, "__Host-bloc-csrf", &b)
        }
        return Ok(response);
    }
    let form = post(app, request).await?;
    let submitted = sec::decode(val(&form, "csrf")).ok_or_else(Failure::csrf)?;
    if !bool::from(token.as_slice().ct_eq(&submitted)) {
        return Err(Failure::csrf());
    }
    let b = browser.ok_or_else(Failure::csrf)?;
    if let Some(u) = user {
        if form.keys().any(|k| {
            !matches!(
                k.as_str(),
                "csrf" | "purpose" | "version" | "identity_confirmed"
            )
        }) {
            return Err(Failure::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "This form contains unsupported fields.",
            ));
        }
        if val(&form, "identity_confirmed") != "true" {
            p.error = true;
            p.feedback = "Confirm this person’s identity before creating a link.".into();
            return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
        }
        reserve(
            app,
            &[(
                "link_issue",
                key(
                    app,
                    "realm-link-issue",
                    &format!("{r}:{}:{}", u.id, val(&form, "purpose")),
                )?,
                1,
            )],
        )
        .await?;
        let code = random()?;
        let digest = sec::digest(&code);
        let out = app
            .storage
            .realm_issue_link(
                Authority {
                    realm: r,
                    purpose: val(&form, "purpose"),
                    browser: &b,
                    token: Some(&submitted),
                    session: Some(&session),
                    link: Some(&digest),
                },
                &u.id,
                version(&form),
                true,
            )
            .await?;
        if matches!(out.as_str(), "stale" | "invalid" | "csrf" | "missing") {
            if out == "csrf" {
                return Err(Failure::csrf());
            }
            p.error = true;
            p.feedback =
                "The user or their access changed. Reload before creating another link.".into();
            return Ok(render(&p, StatusCode::CONFLICT, hx));
        }
        p.secret = code;
        p.expiry = out;
        p.state = if p.purpose == "activation" {
            "activation-output"
        } else {
            "link-output"
        };
        p.title = if p.purpose == "activation" {
            "Activation link"
        } else {
            "Password-reset link"
        }
        .into();
        p.link = format!(
            "{}{}/{}#code={}",
            app.config.origin,
            p.base,
            if p.purpose == "activation" {
                "activate"
            } else {
                "reset-password"
            },
            p.secret
        );
        p.feedback = "Copy this link now. You won’t be able to retrieve it again.".into();
        return Ok(render(&p, StatusCode::OK, hx));
    }
    let known = [
        "csrf",
        "version",
        "confirmed",
        "registration_enabled",
        "password_min_length",
        "require_uppercase",
        "require_lowercase",
        "require_number",
        "require_special",
        "activation_ttl_seconds",
        "reset_ttl_seconds",
        "session_idle_seconds",
        "session_absolute_seconds",
        "session_limit",
        "activation_ttl_seconds_unit",
        "reset_ttl_seconds_unit",
        "session_idle_seconds_unit",
        "session_absolute_seconds_unit",
    ];
    if form.keys().any(|k| !known.contains(&k.as_str())) {
        return Err(Failure::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "This form contains unsupported fields.",
        ));
    }
    let values = match settings_values(&form) {
        Ok(v) => v,
        Err(field) => {
            p.invalid(&field, "Enter a complete value within the allowed range.");
            p.state = "settings-invalid";
            return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
        }
    };
    let out = app
        .storage
        .realm_save_settings(
            Authority {
                realm: r,
                purpose: "settings",
                browser: &b,
                token: Some(&submitted),
                session: Some(&session),
                link: None,
            },
            version(&form),
            &values,
            val(&form, "confirmed") == "true",
        )
        .await?;
    match out.as_str() {
        "ok" => Ok(nav(&format!("{path}?saved=1"), hx)),
        "csrf" => Err(Failure::csrf()),
        "confirm" => {
            p.state = "settings-confirm";
            p.title = "Review session changes".into();
            p.confirm = "Apply new session limits?".into();
            p.confirm_values = vec![
                (
                    "Inactivity timeout".into(),
                    format!("{} seconds", values[8]),
                ),
                (
                    "Total session lifetime".into(),
                    format!("{} seconds", values[9]),
                ),
                ("Active sessions per user".into(), values[10].clone()),
            ];
            p.hidden_fields = form
                .into_iter()
                .filter(|(k, _)| k != "csrf" && k != "confirmed")
                .collect();
            p.action = "Apply settings";
            Ok(render(&p, StatusCode::OK, hx))
        }
        "invalid" => {
            p.state = "settings-invalid";
            p.error = true;
            p.feedback="Check the allowed ranges. Inactivity timeout cannot exceed total session lifetime.".into();
            Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx))
        }
        _ => {
            p.state = "settings-conflict";
            p.error = true;
            p.feedback =
                "These settings changed. Reload and review the current values before saving again."
                    .into();
            Ok(render(&p, StatusCode::CONFLICT, hx))
        }
    }
}
#[cfg(test)]
#[path = "realm_authentication_tests.rs"]
mod tests;
