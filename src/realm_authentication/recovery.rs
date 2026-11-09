use super::*;
use crate::mfa::recovery_storage::{AssistedConfirmation, RecoveryProof};
fn failure(status: &str) -> Failure {
    match status {
        "csrf" => Failure::csrf(),
        "limited" => mfa::limited(),
        "invalid" => Failure::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "We couldn’t verify that proof. Check it and try again.",
        ),
        "link" => Failure::link(),
        _ => Failure::new(
            StatusCode::CONFLICT,
            "This recovery authority changed or expired. Start again with a current recovery method.",
        ),
    }
}
fn strict_cookie(response: &mut Response, r: &str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(&format!(
        "{}={value}; Secure; HttpOnly; SameSite=Strict; Path=/",
        cookie_name(r, Some("mfa-recovery"))
    )) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}
fn fields(form: &Form, allowed: &[&str]) -> Result<(), Failure> {
    if form.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err(Failure::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "This form contains unsupported fields.",
        ))
    } else {
        Ok(())
    }
}
pub(super) async fn handle(
    app: &Application,
    request: Request,
    r: &str,
    route: &str,
    hx: bool,
) -> Result<Response, Failure> {
    let request_source = source(app, &request)?;
    let h = request.headers().clone();
    let query = request.uri().query().unwrap_or("").to_owned();
    let get = matches!(*request.method(), Method::GET | Method::HEAD);
    app.storage
        .mfa_ready(app.config.mfa_keyring.as_ref())
        .await
        .map_err(|_| realm_storage::Error::Storage)?;
    let form = if get {
        Form::new()
    } else {
        post(app, request).await?
    };
    if route == "mfa/recovery-code" {
        return saved(app, r, &h, &request_source, &form, get, hx).await;
    }
    if !query.is_empty() {
        return Err(Failure::link());
    }
    let mut p = Page::new(r, &format!("/realms/{r}/recover-mfa"));
    p.name = app.storage.realm_name(r).await?.unwrap_or_default();
    p.title = "Confirm factor recovery".into();
    let browser = sec::cookie(&h, &cookie_name(r, Some("mfa-recovery"))).map(|v| sec::digest(&v));
    if get {
        if route != "recover-mfa" {
            return Err(Failure::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "Use the recovery form to continue.",
            ));
        }
        if let Some(browser) = browser.as_ref() {
            let stored = app.storage.mfa_assisted_form(r, browser, None).await?;
            if stored.status == "ok" {
                p.state = "mfa-recovery-password";
                p.csrf = sec::encode(
                    stored
                        .csrf
                        .as_deref()
                        .ok_or(realm_storage::Error::Storage)?,
                );
                p.intro = "Confirm your current password to continue.".into();
                return Ok(render(&p, StatusCode::OK, false));
            }
        }
        p.state = "mfa-recovery-entry";
        p.intro = "Enter the recovery link code provided by your administrator.".into();
        let new_browser =
            form_token(app, &mut p, &h, "anonymous", None, None, &request_source).await?;
        let mut response = render(&p, StatusCode::OK, false);
        if let Some(browser) = new_browser {
            cookie(&mut response, &cookie_name(r, Some("anonymous")), &browser);
        }
        return Ok(response);
    }
    if route == "recover-mfa/exchange" {
        fields(&form, &["csrf", "code"])?;
        let anonymous = sec::cookie(&h, &cookie_name(r, Some("anonymous")))
            .map(|v| sec::digest(&v))
            .ok_or_else(Failure::csrf)?;
        let token = sec::decode(val(&form, "csrf")).ok_or_else(Failure::csrf)?;
        reserve(
            app,
            &[
                (
                    "exchange_source",
                    key(app, "realm-link-exchange-source", &request_source)?,
                    1,
                ),
                (
                    "exchange_realm",
                    key(app, "realm-link-exchange-realm", r)?,
                    1,
                ),
            ],
        )
        .await?;
        let code = val(&form, "code");
        if sec::decode(code).is_none() {
            return Err(Failure::link());
        }
        let browser = random()?;
        let csrf = sec::random().map_err(|_| realm_storage::Error::Storage)?;
        let outcome = app
            .storage
            .mfa_assisted_exchange(
                r,
                &anonymous,
                &token,
                &sec::digest(code),
                &sec::digest(&browser),
                &csrf,
            )
            .await?;
        if outcome != "ok" {
            return Err(failure(&outcome));
        }
        let mut response = nav(&format!("/realms/{r}/recover-mfa"), hx);
        strict_cookie(&mut response, r, &browser);
        return Ok(response);
    }
    if route != "recover-mfa/confirm" {
        return Err(Failure::new(
            StatusCode::NOT_FOUND,
            "This recovery page is unavailable.",
        ));
    }
    fields(&form, &["csrf", "current_password"])?;
    let browser = browser.ok_or_else(Failure::csrf)?;
    let token = sec::decode(val(&form, "csrf")).ok_or_else(Failure::csrf)?;
    let stored = app
        .storage
        .mfa_assisted_form(r, &browser, Some(&token))
        .await?;
    if stored.status != "ok" {
        return Err(failure(&stored.status));
    }
    match app
        .storage
        .mfa_assisted_admit(
            r,
            &browser,
            &token,
            &key(app, "realm-mfa-source", &request_source)?,
        )
        .await?
    {
        0 => {}
        -1 => return Err(realm_storage::Error::Capacity.into()),
        -2 => return Err(failure("stale")),
        seconds => {
            return Err(Failure {
                status: StatusCode::TOO_MANY_REQUESTS,
                state: "throttled",
                message: "Too many attempts. Wait before trying again.",
                retry: Some(seconds),
            });
        }
    }
    reserve(
        app,
        &[
            (
                "credential_source",
                key(app, "realm-credential-source", &request_source)?,
                1,
            ),
            ("public_work", [0; 32], 1),
            ("hash_work", [0; 32], 1),
        ],
    )
    .await?;
    let verified = app
        .worker
        .verify(
            val(&form, "current_password").to_owned(),
            stored.phc.ok_or(realm_storage::Error::Storage)?,
        )
        .await?;
    let bearer = random()?;
    let csrf = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let outcome = app
        .storage
        .mfa_assisted_confirm(AssistedConfirmation {
            realm: r,
            browser: &browser,
            token: &token,
            expected: stored.credential.ok_or(realm_storage::Error::Storage)?,
            verified,
            bearer: &sec::digest(&bearer),
            csrf: &csrf,
        })
        .await?;
    if outcome != "ok" {
        return Err(failure(&outcome));
    }
    let mut response = nav(&format!("/realms/{r}/mfa"), hx);
    mfa::clear_session(&mut response, r);
    mfa::flow_cookie(&mut response, r, &bearer);
    Ok(response)
}
async fn saved(
    app: &Application,
    r: &str,
    h: &HeaderMap,
    source: &str,
    form: &Form,
    get: bool,
    hx: bool,
) -> Result<Response, Failure> {
    let token = if get {
        None
    } else {
        Some(sec::decode(val(form, "csrf")).ok_or_else(Failure::csrf)?)
    };
    let (status, access) = mfa::resolve_flow(app, r, h, token.as_ref()).await?;
    if status != "ok" {
        return Err(failure(&status));
    }
    let access = access.ok_or(realm_storage::Error::Storage)?;
    let proof = RecoveryProof {
        realm: r,
        bearer: &access.bearer,
        browser: &access.browser,
        csrf: access
            .snapshot
            .csrf
            .as_slice()
            .try_into()
            .map_err(|_| realm_storage::Error::Storage)?,
    };
    let material = app.storage.mfa_code_material(&proof).await?;
    if material.is_none() {
        return Err(Failure::new(
            StatusCode::NOT_FOUND,
            "Saved-code recovery is unavailable. Contact your administrator.",
        ));
    }
    if get {
        let mut p = Page::new(r, &format!("/realms/{r}/mfa/recovery-code"));
        p.name = app.storage.realm_name(r).await?.unwrap_or_default();
        p.state = "mfa-recovery-code";
        p.title = "Recover your factors".into();
        p.intro = "Use one of your saved recovery codes.".into();
        p.csrf = sec::encode(&access.snapshot.csrf);
        return Ok(render(&p, StatusCode::OK, hx));
    }
    fields(form, &["csrf", "code"])?;
    mfa::admit(
        app,
        r,
        source,
        &access.bearer,
        &access.browser,
        token.as_ref().ok_or_else(Failure::csrf)?,
    )
    .await?;
    let (user, generation) = material.ok_or(realm_storage::Error::Storage)?;
    let digest = crate::mfa::recovery::normalize(val(form, "code"))
        .map(|code| crate::mfa::recovery::code_digest(r, &user, &generation, &code))
        .transpose()
        .map_err(|_| realm_storage::Error::Storage)?;
    let bearer = random()?;
    let csrf = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let outcome = app
        .storage
        .mfa_code_recover(
            &proof,
            Some(&generation),
            digest.as_deref(),
            &sec::digest(&bearer),
            &csrf,
        )
        .await?;
    if outcome != "ok" {
        return Err(failure(&outcome));
    }
    let mut response = nav(&format!("/realms/{r}/mfa"), hx);
    mfa::clear_session(&mut response, r);
    mfa::flow_cookie(&mut response, r, &bearer);
    Ok(response)
}
pub(super) async fn admin(
    app: &Application,
    request: Request,
    path: &str,
    hx: bool,
) -> Result<Response, Failure> {
    if hx {
        return Ok(nav(path, true));
    }
    let request_source = source(app, &request)?;
    let h = request.headers().clone();
    let get = matches!(*request.method(), Method::GET | Method::HEAD);
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    if parts.len() != 6 || !directory::uuid(parts[2]) || !directory::uuid(parts[4]) {
        return Err(Failure::new(
            StatusCode::NOT_FOUND,
            "This user is unavailable.",
        ));
    }
    let r = parts[2];
    let u = parts[4];
    let session = sec::cookie(&h, "__Host-bloc-admin")
        .map(|v| sec::digest(&v))
        .ok_or_else(Failure::csrf)?;
    let owner = app
        .storage
        .authorize(&session)
        .await
        .map_err(|_| realm_storage::Error::Storage)?
        .ok_or_else(Failure::csrf)?;
    let realm = app
        .storage
        .directory_realms(&session, Some(r), None)
        .await
        .map_err(|_| realm_storage::Error::Storage)?
        .into_iter()
        .next()
        .ok_or_else(|| Failure::new(StatusCode::NOT_FOUND, "This realm is unavailable."))?;
    let user = app
        .storage
        .directory_users(&session, r, Some(u), None)
        .await
        .map_err(|_| realm_storage::Error::Storage)?
        .into_iter()
        .next()
        .ok_or_else(|| Failure::new(StatusCode::NOT_FOUND, "This user is unavailable."))?;
    let policy = app
        .storage
        .realm_policy(r, Some(&session))
        .await?
        .ok_or(realm_storage::Error::Storage)?;
    if policy.mfa.mode == crate::mfa::policy::Mode::Disabled || !policy.mfa.assisted {
        return Err(Failure::new(
            StatusCode::FORBIDDEN,
            "Administrator-assisted factor recovery is disabled by this realm’s policy.",
        ));
    }
    let mut p = Page::new(r, path);
    p.admin = true;
    p.protected = true;
    p.workspace = crate::workspace::Workspace::load(&app.storage, &session, realm.clone())
        .await
        .map_err(|_| realm_storage::Error::Storage)?;
    p.name = realm.name;
    p.account.email = owner.email;
    p.title = "Issue factor recovery".into();
    p.intro = format!("{} · {}", user.display_name, user.email);
    p.feedback = "Confirm the person’s identity before continuing. Issuing a new link replaces the previous link; existing factors and sessions remain unchanged.".into();
    p.state = "mfa-admin-recovery";
    p.version = user.version;
    let mut browser = sec::cookie(&h, "__Host-bloc-csrf").map(|v| sec::digest(&v));
    let existing = match browser.as_ref() {
        Some(b) => app
            .storage
            .form(b, Some(&session), None)
            .await
            .map_err(|_| realm_storage::Error::Storage)?,
        None => None,
    };
    let mut browser_cookie = None;
    let token = if let Some(t) = existing {
        t
    } else if get {
        reserve(
            app,
            &[(
                "form_source",
                key(app, "realm-form-source", &request_source)?,
                1,
            )],
        )
        .await?;
        let b = random()?;
        let digest = sec::digest(&b);
        let t = sec::random().map_err(|_| realm_storage::Error::Storage)?;
        let stored = app
            .storage
            .form(&digest, Some(&session), Some(&t))
            .await
            .map_err(|_| realm_storage::Error::Storage)?
            .ok_or(realm_storage::Error::Capacity)?;
        browser = Some(digest);
        browser_cookie = Some(b);
        stored
    } else {
        return Err(Failure::csrf());
    };
    p.csrf = sec::encode(&token);
    if get {
        let mut response = render(&p, StatusCode::OK, false);
        if let Some(b) = browser_cookie {
            crate::administrator::cookie(&mut response, "__Host-bloc-csrf", &b);
        }
        return Ok(response);
    }
    let form = post(app, request).await?;
    fields(
        &form,
        &["csrf", "version", "identity_confirmed", "current_password"],
    )?;
    let submitted = sec::decode(val(&form, "csrf")).ok_or_else(Failure::csrf)?;
    if !bool::from(token.as_slice().ct_eq(&submitted)) {
        return Err(Failure::csrf());
    }
    let wait = app
        .storage
        .reserve(&[
            ("credential_source", key(app, "source", &request_source)?, 1),
            ("hash_work", [0; 32], 1),
            ("password_change", [0; 32], 1),
        ])
        .await
        .map_err(|_| realm_storage::Error::Storage)?;
    if wait == -1 {
        return Err(realm_storage::Error::Capacity.into());
    }
    if wait != 0 {
        return Err(Failure {
            status: StatusCode::TOO_MANY_REQUESTS,
            state: "throttled",
            message: "Too many attempts. Wait before trying again.",
            retry: Some(wait.max(1)),
        });
    }
    reserve(
        app,
        &[(
            "link_issue",
            key(app, "realm-link-issue", &format!("{r}:{u}:mfa-recovery"))?,
            1,
        )],
    )
    .await?;
    if !app
        .worker
        .verify(val(&form, "current_password").to_owned(), owner.phc)
        .await?
    {
        p.error = true;
        p.feedback = "Check your current administrator password.".into();
        return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, false));
    }
    let code = random()?;
    let outcome = app
        .storage
        .mfa_assisted_issue(crate::mfa::recovery_storage::AssistedIssue {
            realm: r,
            user: u,
            session: &session,
            browser: &browser.ok_or_else(Failure::csrf)?,
            csrf: &submitted,
            expected: version(&form),
            admin_version: owner.version,
            confirmed: val(&form, "identity_confirmed") == "true",
            digest: &sec::digest(&code),
        })
        .await?;
    if !outcome.ends_with('Z') {
        return Err(failure(&outcome));
    }
    p.state = "recovery-issued";
    p.intro = "Share the link and the separate code through your approved recovery process.".into();
    p.title = "Recovery link created".into();
    p.link = format!("{}/realms/{r}/recover-mfa#code={code}", app.config.origin);
    p.secret = code;
    p.purpose = "factor recovery".into();
    p.expiry = outcome;
    p.feedback = "This output is shown once. Copy it now; it cannot be retrieved again.".into();
    Ok(render(&p, StatusCode::OK, false))
}
