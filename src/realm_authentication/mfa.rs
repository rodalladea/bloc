use super::*;
mod enrollment;
pub(super) mod handoff;

pub(super) fn flow_cookie(response: &mut Response, r: &str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(&format!(
        "__Host-bloc-realm-mfa-{r}={value}; Secure; HttpOnly; SameSite=Strict; Path=/{}",
        if value.is_empty() { "; Max-Age=0" } else { "" }
    )) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}
pub(super) fn bearer(h: &HeaderMap, r: &str) -> Option<[u8; 32]> {
    sec::cookie(h, &format!("__Host-bloc-realm-mfa-{r}")).map(|v| sec::digest(&v))
}
pub(super) async fn handle(
    app: &Application,
    request: Request,
    r: &str,
    route: &str,
    hx: bool,
) -> Result<Response, Failure> {
    if route.starts_with("recover-mfa") || route == "mfa/recovery-code" {
        return super::recovery::handle(app, request, r, route, hx).await;
    }
    if matches!(
        route,
        "account/security/webauthn/setup"
            | "account/security/webauthn/register/options"
            | "account/security/webauthn/register/finish"
            | "mfa/webauthn"
            | "mfa/webauthn/options"
            | "mfa/webauthn/finish"
    ) {
        return super::webauthn::handle(app, request, r, route, hx).await;
    }
    if matches!(
        route,
        "account/security"
            | "account/security/reauthenticate"
            | "account/security/continue"
            | "account/security/preferred"
            | "account/security/recovery-codes/regenerate"
    ) || route.starts_with("account/security/factors/")
    {
        return super::security::handle(app, request, r, route, hx).await;
    }
    let request_source = source(app, &request)?;
    let h = request.headers().clone();
    let head = request.method() == Method::HEAD;
    let get = request.method() == Method::GET || head;
    app.storage
        .mfa_ready(app.config.mfa_keyring.as_ref())
        .await
        .map_err(|_| realm_storage::Error::Storage)?;
    let form = if get {
        Form::new()
    } else {
        post(app, request).await?
    };
    let token = if get {
        None
    } else {
        Some(sec::decode(val(&form, "csrf")).ok_or_else(Failure::csrf)?)
    };
    let (status, access) = resolve_flow(app, r, &h, token.as_ref()).await?;
    if status == "expired" {
        let mut response = nav(&format!("/realms/{r}/login?expired=mfa"), hx);
        flow_cookie(&mut response, r, "");
        return Ok(response);
    }
    if status != "ok" {
        return Err(if status == "missing" {
            Failure::new(
                StatusCode::NOT_FOUND,
                "This realm or account is unavailable.",
            )
        } else if status == "csrf" {
            Failure::csrf()
        } else {
            Failure::new(
                StatusCode::CONFLICT,
                "This verification flow changed or was consumed. Sign in again to continue.",
            )
        });
    }
    let access = access.ok_or(realm_storage::Error::Storage)?;
    let flow = access.bearer;
    let browser = access.browser;
    let snapshot = &access.snapshot;
    if route == "account/security/totp/confirm" && !get {
        admit(
            app,
            r,
            &request_source,
            &flow,
            &browser,
            token.as_ref().ok_or_else(Failure::csrf)?,
        )
        .await?;
        return enrollment::confirm(
            app,
            r,
            &h,
            &access,
            token.as_ref().ok_or_else(Failure::csrf)?,
            &form,
            hx,
        )
        .await;
    }
    if route == "account/security/recovery-codes/replace" {
        if get {
            let mut p = Page::new(r, &format!("/realms/{r}/account/security/recovery-codes"));
            p.name = app.storage.realm_name(r).await?.unwrap_or_default();
            p.state = "mfa-codes-lost";
            p.title = "Replace unsaved codes".into();
            p.csrf = sec::encode(&snapshot.csrf);
            p.feedback = "Create a new set only while setup authority is still valid. Every code in the previous set will stop working.".into();
            return Ok(render(&p, StatusCode::OK, false));
        }
        reserve(
            app,
            &[(
                "form_source",
                key(app, "realm-mfa-handoff-source", &request_source)?,
                1,
            )],
        )
        .await?;
        return handoff::replace(
            app,
            r,
            &h,
            &access,
            token.as_ref().ok_or_else(Failure::csrf)?,
            hx,
        )
        .await;
    }
    if route == "account/security/recovery-codes" && get {
        if head {
            return Ok(if hx {
                nav(&format!("/realms/{r}/{route}"), true)
            } else {
                ([(header::VARY, "HX-Request")], StatusCode::OK).into_response()
            });
        }
        return handoff::show(app, r, &flow, &browser, snapshot, hx).await;
    }
    if route == "account/security/recovery-codes/acknowledge" && !get {
        return handoff::acknowledge(
            app,
            r,
            &h,
            &access,
            token.as_ref().ok_or_else(Failure::csrf)?,
            &form,
            hx,
        )
        .await;
    }
    if route == "account/security/totp/start" && !get {
        reserve(
            app,
            &[(
                "form_source",
                key(app, "realm-mfa-enrollment-source", &request_source)?,
                1,
            )],
        )
        .await?;
        return enrollment::start(
            app,
            r,
            &flow,
            &browser,
            token.as_ref().ok_or_else(Failure::csrf)?,
            snapshot,
            hx,
        )
        .await;
    }
    if get
        && matches!(
            route,
            "account/security/totp/setup" | "account/security/totp/qr"
        )
    {
        reserve(
            app,
            &[(
                "form_source",
                key(app, "realm-mfa-enrollment-source", &request_source)?,
                1,
            )],
        )
        .await?;
        return enrollment::setup(
            app,
            r,
            &flow,
            &browser,
            snapshot,
            route.ends_with("/qr"),
            hx,
        )
        .await;
    }
    if route == "mfa/verify" && !get {
        let token = token.as_ref().ok_or_else(Failure::csrf)?;
        admit(app, r, &request_source, &flow, &browser, token).await?;
        return verify(app, r, &h, &access, token, &form, hx).await;
    }
    if route == "mfa/cancel" {
        if get {
            return Err(Failure::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "Use the cancel form to continue.",
            ));
        }
        let outcome = app
            .storage
            .realm_mfa_cancel(r, &flow, &browser, &token.ok_or_else(Failure::csrf)?)
            .await?;
        if outcome != "ok" {
            return Err(Failure::new(
                StatusCode::CONFLICT,
                "This verification flow changed. Sign in again.",
            ));
        }
        let mut response = nav(&format!("/realms/{r}/login?mfa-canceled=1"), hx);
        flow_cookie(&mut response, r, "");
        return Ok(response);
    }
    if !get || !matches!(route, "mfa" | "mfa/methods") {
        return Err(Failure::new(
            StatusCode::NOT_FOUND,
            "This verification page is unavailable.",
        ));
    }
    let policy = app
        .storage
        .realm_policy(r, None)
        .await?
        .ok_or_else(|| Failure::new(StatusCode::NOT_FOUND, "This realm is unavailable."))?;
    let mut p = Page::new(r, &format!("/realms/{r}/mfa"));
    p.mfa_policy = policy.mfa;
    p.name = app.storage.realm_name(r).await?.unwrap_or_default();
    p.csrf = sec::encode(&snapshot.csrf);
    apply_choices(app, r, &flow, &browser, &mut p).await?;
    p.mfa_pending_totp = snapshot.purpose == "totp_enrollment";
    if p.mfa_pending_totp && p.purpose == "reauthenticate" {
        return Ok(nav(&format!("/realms/{r}/account/security/totp/setup"), hx));
    }
    if matches!(p.purpose.as_str(), "initial_enrollment" | "recovery") {
        p.state = "mfa-required";
        p.title = if p.purpose == "recovery" {
            "Replace your factors"
        } else {
            "Set up two-factor authentication"
        }
        .into();
        p.feedback = if p.purpose == "recovery" {
            "Your existing factors remain until a replacement is confirmed. You can only replace factors, cancel or sign out.".into()
        } else {
            format!(
                "{} requires a second factor. Complete setup before you can access your account.",
                p.name
            )
        };
    } else {
        p.state = if route == "mfa/methods" {
            "mfa-methods"
        } else {
            "mfa-challenge"
        };
        p.title = if route == "mfa/methods" {
            "Choose a verification method"
        } else {
            "Verify it’s you"
        }
        .into();
        p.intro = if route == "mfa/methods" {
            "Use an allowed factor enrolled on this account."
        } else if p.mfa_has_totp {
            "Enter the six-digit code from your authenticator app."
        } else if !p.mfa_has_webauthn {
            "None of your existing factors are currently allowed. Use recovery, or contact an administrator about the realm policy."
        } else {
            "Choose an available method to verify it’s you."
        }
        .into();
    }
    if snapshot.purpose == "login"
        && !p.mfa_has_totp
        && !p.mfa_has_webauthn
        && !p.mfa_codes_available
        && !p.mfa_policy.assisted
    {
        p.state = "mfa-no-recovery";
        p.title = "Contact your administrator".into();
        p.intro.clear();
        p.feedback = "No allowed factor or enabled recovery path is available. An administrator must change the policy before you can continue.".into();
    }
    Ok(render(&p, StatusCode::OK, hx))
}

pub(super) fn uuid(value: &str) -> Result<[u8; 16], Failure> {
    Ok(*uuid::Uuid::parse_str(value)
        .map_err(|_| realm_storage::Error::Storage)?
        .as_bytes())
}
async fn verify(
    app: &Application,
    r: &str,
    h: &HeaderMap,
    access: &MfaAccess,
    token: &[u8; 32],
    form: &Form,
    hx: bool,
) -> Result<Response, Failure> {
    let MfaAccess {
        bearer,
        browser,
        snapshot,
    } = access;
    let mut factor = None;
    let mut step = None;
    if val(form, "method") == "totp"
        && form
            .keys()
            .all(|k| matches!(k.as_str(), "csrf" | "method" | "code"))
        && let Some(material) = app
            .storage
            .realm_mfa_totp(r, bearer, browser, token)
            .await?
    {
        let binding = crate::mfa::Binding {
            installation: uuid(&material.installation)?,
            realm: uuid(r)?,
            user: uuid(&material.user)?,
            record: uuid(&material.factor)?,
            purpose: crate::mfa::Purpose::ActiveTotp,
            payload_version: 1,
        };
        let ring = app
            .config
            .mfa_keyring
            .clone()
            .ok_or(realm_storage::Error::Storage)?;
        let code = val(form, "code").to_owned();
        factor = Some(material.factor);
        step = app
            .worker
            .factor(move || {
                let secret = ring.decrypt(&binding, &material.envelope)?;
                crate::mfa::totp::accepted_step(&secret, &code, material.now, material.floor)
            })
            .await?
            .map_err(|_| realm_storage::Error::BeforeCommit)?;
    }
    let new_session = random()?;
    let new_browser = random()?;
    let new_token = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let outcome = app
        .storage
        .realm_mfa_verify(realm_storage::MfaVerification {
            realm: r,
            bearer,
            browser,
            token,
            factor: factor.as_deref(),
            step,
            session: &sec::digest(&new_session),
            new_browser: &sec::digest(&new_browser),
            new_token: &new_token,
            device: device(h),
        })
        .await?;
    if outcome == "handoff_required" {
        return handoff::replace(app, r, h, access, token, hx).await;
    }
    if outcome == "reauthenticated" {
        return Ok(nav(&format!("/realms/{r}/account/security/continue"), hx));
    }
    if outcome == "ok" {
        let mut response = nav(&format!("/realms/{r}/account"), hx);
        cookie(&mut response, &cookie_name(r, None), &new_session);
        cookie(
            &mut response,
            &cookie_name(r, Some("account")),
            &new_browser,
        );
        flow_cookie(&mut response, r, "");
        return Ok(response);
    }
    if outcome == "limited" {
        return Err(Failure {
            status: StatusCode::TOO_MANY_REQUESTS,
            state: "throttled",
            message: "Too many unsuccessful attempts. This flow has ended. Wait before starting again.",
            retry: Some(60),
        });
    }
    if outcome != "invalid" {
        return Err(Failure::new(
            StatusCode::CONFLICT,
            "This verification flow changed. Sign in again to continue.",
        ));
    }
    let mut p = Page::new(r, &format!("/realms/{r}/mfa"));
    p.name = app.storage.realm_name(r).await?.unwrap_or_default();
    p.state = "mfa-challenge";
    p.title = "Check your code".into();
    p.csrf = sec::encode(&snapshot.csrf);
    apply_choices(app, r, bearer, browser, &mut p).await?;
    p.error = true;
    p.feedback =
        "We couldn’t verify that proof. Try a new code or choose another available method.".into();
    Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx))
}

pub(super) fn issued(r: &str, session: &str, browser: &str, hx: bool) -> Response {
    let mut response = nav(&format!("/realms/{r}/account"), hx);
    cookie(&mut response, &cookie_name(r, None), session);
    cookie(&mut response, &cookie_name(r, Some("account")), browser);
    flow_cookie(&mut response, r, "");
    response
}
pub(super) fn limited() -> Failure {
    Failure {
        status: StatusCode::TOO_MANY_REQUESTS,
        state: "throttled",
        message: "Too many unsuccessful attempts. This flow has ended. Wait before starting again.",
        retry: Some(60),
    }
}
pub(super) async fn admit(
    app: &Application,
    r: &str,
    source: &str,
    bearer: &[u8; 32],
    browser: &[u8; 32],
    token: &[u8; 32],
) -> Result<(), Failure> {
    match app
        .storage
        .realm_mfa_admit(
            r,
            bearer,
            browser,
            token,
            &key(app, "realm-mfa-source", source)?,
        )
        .await?
    {
        0 => Ok(()),
        -1 => Err(realm_storage::Error::Capacity.into()),
        -2 => Err(Failure::new(
            StatusCode::CONFLICT,
            "This verification flow changed. Sign in again.",
        )),
        seconds => Err(Failure {
            status: StatusCode::TOO_MANY_REQUESTS,
            state: "throttled",
            message: "Too many unsuccessful attempts. Wait before starting again.",
            retry: Some(seconds),
        }),
    }
}

pub(super) struct MfaAccess {
    pub bearer: [u8; 32],
    pub browser: [u8; 32],
    pub snapshot: realm_storage::MfaFlow,
}
pub(super) async fn resolve_flow(
    app: &Application,
    r: &str,
    h: &HeaderMap,
    token: Option<&[u8; 32]>,
) -> Result<(String, Option<MfaAccess>), Failure> {
    let bearer = bearer(h, r)
        .ok_or_else(|| Failure::new(StatusCode::FORBIDDEN, "Sign in to start verification."))?;
    for purpose in ["anonymous", "account", "mfa-recovery"] {
        let Some(browser) =
            sec::cookie(h, &cookie_name(r, Some(purpose))).map(|value| sec::digest(&value))
        else {
            continue;
        };
        let (status, snapshot) = app
            .storage
            .realm_mfa_flow(r, &bearer, &browser, token)
            .await?;
        if status == "csrf" {
            continue;
        }
        return Ok((
            status,
            snapshot.map(|snapshot| MfaAccess {
                bearer,
                browser,
                snapshot,
            }),
        ));
    }
    Ok(("csrf".into(), None))
}

pub(super) fn clear_session(response: &mut Response, r: &str) {
    cookie(response, &cookie_name(r, None), "");
}

async fn apply_choices(
    app: &Application,
    r: &str,
    bearer: &[u8; 32],
    browser: &[u8; 32],
    p: &mut Page,
) -> Result<(), Failure> {
    p.mfa_policy = app
        .storage
        .realm_policy(r, None)
        .await?
        .ok_or(realm_storage::Error::Storage)?
        .mfa;
    let choices = app
        .storage
        .mfa_choices(r, bearer, browser)
        .await?
        .ok_or(realm_storage::Error::Storage)?;
    p.mfa_has_totp = choices.totp;
    p.mfa_has_webauthn = choices.webauthn;
    p.mfa_codes_available = choices.codes;
    p.mfa_default = choices.preferred.unwrap_or_default();
    p.mfa_active_count = choices.active;
    p.purpose = choices.context;
    Ok(())
}
