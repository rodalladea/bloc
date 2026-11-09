//! Own-account display and exact-operation reauthentication.
use super::*;
use crate::mfa::account_storage::{AccountCodes, AccountEdit, AccountReauth, AccountRemove};

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
    if route == "account/security/continue"
        || route == "account/security/recovery-codes/regenerate"
        || route.ends_with("/remove")
    {
        return continuation(app, r, route, &h, &form, get, hx).await;
    }
    let session = sec::cookie(&h, &cookie_name(r, None)).map(|v| sec::digest(&v));
    let mut p = Page::new(r, &format!("/realms/{r}/{route}"));
    p.protected = true;
    p.title = "Account security".into();
    p.intro = "Manage your enrolled factors and recovery options.".into();
    p.name = app.storage.realm_name(r).await?.unwrap_or_default();
    p.account = if let Some(session) = session.as_ref() {
        app.storage.realm_account(r, session, get).await?
    } else {
        None
    }
    .unwrap_or_default();
    if p.account.user.is_empty() {
        if !get {
            return Err(Failure::new(
                StatusCode::FORBIDDEN,
                "Sign in again before changing account security.",
            ));
        }
        if mfa::bearer(&h, r).is_some()
            && let Ok((status, Some(access))) = mfa::resolve_flow(app, r, &h, None).await
            && status == "ok"
            && matches!(
                access.snapshot.purpose.as_str(),
                "initial_enrollment" | "recovery"
            )
        {
            return Ok(nav(&format!("/realms/{r}/mfa"), hx));
        }
        return Ok(nav(&format!("/realms/{r}/login?expired=1"), hx));
    }
    let session = session.ok_or_else(Failure::csrf)?;
    p.mfa_policy = app
        .storage
        .realm_policy(r, None)
        .await?
        .ok_or(realm_storage::Error::Storage)?
        .mfa;
    if p.mfa_policy.mode == crate::mfa::policy::Mode::Disabled {
        p.title = "Protection suspended".into();
    }
    let list = app.storage.mfa_account_factors(r, &session).await?;
    p.mfa_epoch = list.epoch;
    p.mfa_unused_codes = list.unused_codes;
    p.mfa_has_totp = list.factors.iter().any(|f| f.kind == "totp");
    p.mfa_factors = list.factors;
    let pieces: Vec<_> = route.split('/').collect();
    let label_target = if pieces.len() == 5
        && pieces[2] == "factors"
        && pieces[4] == "label"
        && directory::uuid(pieces[3])
    {
        Some(pieces[3])
    } else {
        None
    };
    if route == "account/security" {
        if !get {
            return Err(Failure::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "Open account security to continue.",
            ));
        }
        p.state = "security-list";
    } else if route == "account/security/reauthenticate" {
        p.state = "security-reauthenticate";
        p.title = "Confirm this security change".into();
        p.intro = "Confirm your password, then an existing allowed factor when required.".into();
        p.mfa_operation = if get {
            url::form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "operation")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default()
        } else {
            val(&form, "operation").into()
        };
        if !operation_visible(&p, &p.mfa_operation) {
            return Err(Failure::new(
                StatusCode::NOT_FOUND,
                "This security action is unavailable.",
            ));
        }
    } else if let Some(target) = label_target {
        let factor = p
            .mfa_factors
            .iter()
            .find(|f| f.id == target)
            .ok_or_else(|| Failure::new(StatusCode::NOT_FOUND, "This factor is unavailable."))?;
        let label = if get {
            factor.label.clone()
        } else {
            val(&form, "label").into()
        };
        p.state = "security-label";
        p.title = "Rename factor".into();
        p.intro = "Choose a name that helps you recognize this factor.".into();
        p.field(
            "label",
            "Factor name",
            "text",
            &label,
            "Use 1–64 characters, without control characters.",
        );
    } else if route == "account/security/preferred" {
        if get {
            p.state = "security-preferred";
            p.title = "Preferred verification method".into();
            p.intro="Choose which allowed factor is offered first. This does not change your protection.".into();
        }
    } else {
        return Err(Failure::new(
            StatusCode::NOT_FOUND,
            "This security action is unavailable.",
        ));
    }
    if get {
        let new_browser = form_token(
            app,
            &mut p,
            &h,
            "account",
            Some(&session),
            None,
            &request_source,
        )
        .await?;
        let mut response = render(&p, StatusCode::OK, hx);
        if let Some(browser) = new_browser {
            cookie(&mut response, &cookie_name(r, Some("account")), &browser);
        }
        return Ok(response);
    }
    let browser = sec::cookie(&h, &cookie_name(r, Some("account")))
        .map(|v| sec::digest(&v))
        .ok_or_else(Failure::csrf)?;
    let csrf = sec::decode(val(&form, "csrf")).ok_or_else(Failure::csrf)?;
    let stored = app
        .storage
        .realm_form(Authority {
            realm: r,
            purpose: "account",
            browser: &browser,
            token: None,
            session: Some(&session),
            link: None,
        })
        .await?
        .ok_or_else(Failure::csrf)?;
    if !bool::from(stored.as_slice().ct_eq(&csrf)) {
        return Err(Failure::csrf());
    }
    p.csrf = sec::encode(&csrf);
    if route == "account/security/reauthenticate" {
        fields(&form, &["csrf", "operation", "current_password"])?;
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
                (
                    "password_change",
                    key(
                        app,
                        "realm-password-change",
                        &format!("{r}:{}", p.account.user),
                    )?,
                    1,
                ),
            ],
        )
        .await?;
        if !app
            .worker
            .verify(val(&form, "current_password").into(), p.account.phc.clone())
            .await?
        {
            p.error = true;
            p.feedback = "Check your current password.".into();
            return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
        }
        let bearer = random()?;
        let new_csrf = sec::random().map_err(|_| realm_storage::Error::Storage)?;
        let status = app
            .storage
            .mfa_account_reauthenticate(AccountReauth {
                realm: r,
                session: &session,
                browser: &browser,
                csrf: &csrf,
                credential: p.account.credential,
                operation: &p.mfa_operation,
                bearer: &sec::digest(&bearer),
                new_csrf: &new_csrf,
            })
            .await?;
        if status != "ok" && status != "mfa" {
            return Err(outcome(&status));
        }
        let mut response = nav(
            &format!(
                "/realms/{r}/{}",
                if status == "mfa" {
                    "mfa"
                } else {
                    "account/security/continue"
                }
            ),
            hx,
        );
        mfa::flow_cookie(&mut response, r, &bearer);
        return Ok(response);
    }
    fields(
        &form,
        if label_target.is_some() {
            &["csrf", "epoch", "label"]
        } else {
            &["csrf", "epoch", "factor"]
        },
    )?;
    let target = label_target.or_else(|| {
        let value = val(&form, "factor");
        if value.is_empty() { None } else { Some(value) }
    });
    if target.is_some_and(|target| !directory::uuid(target)) {
        return Err(Failure::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Choose an available factor.",
        ));
    }
    if label_target.is_some() && !valid_label(val(&form, "label")) {
        p.invalid(
            "label",
            "Use 1–64 characters, at most 256 bytes, without control characters.",
        );
        return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
    }
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
    let status = app
        .storage
        .mfa_account_edit(AccountEdit {
            realm: r,
            session: &session,
            browser: &browser,
            csrf: &csrf,
            epoch: val(&form, "epoch").parse().unwrap_or(0),
            factor: target,
            operation: if label_target.is_some() {
                "label"
            } else {
                "preferred"
            },
            value: val(&form, "label"),
        })
        .await?;
    if status != "ok" {
        return Err(outcome(&status));
    }
    Ok(nav(&format!("/realms/{r}/account/security"), hx))
}
fn valid_label(value: &str) -> bool {
    (1..=64).contains(&value.chars().count())
        && value.len() <= 256
        && !value.chars().any(char::is_control)
}
fn operation_visible(p: &Page, op: &str) -> bool {
    if op == "password" {
        return true;
    }
    let enabled = p.mfa_policy.mode != crate::mfa::policy::Mode::Disabled;
    match op {
        "totp_enroll" => enabled && p.mfa_policy.allows("totp") && !p.mfa_has_totp,
        "webauthn_enroll" => {
            enabled
                && p.mfa_policy.allows("webauthn")
                && p.mfa_factors
                    .iter()
                    .filter(|f| f.kind == "webauthn")
                    .count()
                    < 10
        }
        "recovery_codes_regenerate" => enabled && p.mfa_policy.codes && !p.mfa_factors.is_empty(),
        _ => op.split_once(':').is_some_and(|(kind, id)| {
            p.mfa_factors.iter().any(|f| {
                f.id == id
                    && (kind == "factor_remove"
                        || (enabled && f.allowed && kind == format!("{}_replace", f.kind)))
            })
        }),
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
fn outcome(status: &str) -> Failure {
    match status {
        "csrf" => Failure::csrf(),
        "missing" => Failure::new(
            StatusCode::NOT_FOUND,
            "This factor or security action is unavailable.",
        ),
        "authority" => Failure::new(
            StatusCode::FORBIDDEN,
            "Sign in again before changing account security.",
        ),
        "invalid" => Failure::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Check the submitted factor name.",
        ),
        _ => Failure::new(
            StatusCode::CONFLICT,
            "Account security changed or this verification was consumed. Restart this action.",
        ),
    }
}
async fn continuation(
    app: &Application,
    r: &str,
    route: &str,
    h: &HeaderMap,
    form: &Form,
    get: bool,
    hx: bool,
) -> Result<Response, Failure> {
    if (route == "account/security/continue") != get {
        return Err(Failure::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "Use the security page form to continue.",
        ));
    }
    let csrf = if get {
        None
    } else {
        Some(sec::decode(val(form, "csrf")).ok_or_else(Failure::csrf)?)
    };
    let (status, access) = mfa::resolve_flow(app, r, h, csrf.as_ref()).await?;
    if status != "ok" {
        return Err(outcome(&status));
    }
    let access = access.ok_or(realm_storage::Error::Storage)?;
    let (status, details) = app
        .storage
        .mfa_account_continue(r, &access.bearer, &access.browser)
        .await?;
    if status != "ok" {
        return Err(outcome(&status));
    }
    let (operation, epoch) = details.ok_or(realm_storage::Error::Storage)?;
    if get {
        let mut p = Page::new(r, &format!("/realms/{r}/account/security/continue"));
        p.protected = true;
        p.state = "security-continue";
        p.title = "Continue your security change".into();
        p.intro = "Verification applies only to this action.".into();
        p.name = app.storage.realm_name(r).await?.unwrap_or_default();
        let session = sec::cookie(h, &cookie_name(r, None))
            .map(|value| sec::digest(&value))
            .ok_or_else(Failure::csrf)?;
        p.account = app
            .storage
            .realm_account(r, &session, false)
            .await?
            .ok_or_else(|| outcome("stale"))?;
        let shell_token = app
            .storage
            .realm_form(Authority {
                realm: r,
                purpose: "account",
                browser: &access.browser,
                token: None,
                session: Some(&session),
                link: None,
            })
            .await?
            .ok_or_else(Failure::csrf)?;
        p.shell_csrf = sec::encode(&shell_token);
        p.mfa_policy = app
            .storage
            .realm_policy(r, None)
            .await?
            .ok_or(realm_storage::Error::Storage)?
            .mfa;
        p.mfa_factors = app.storage.mfa_account_factors(r, &session).await?.factors;
        if operation.starts_with("factor_remove:") {
            p.title = if p.mfa_factors.len() == 1
                && p.mfa_policy.mode == crate::mfa::policy::Mode::Optional
            {
                "Remove your last factor?"
            } else {
                "Remove factor"
            }
            .into();
        }
        p.csrf = sec::encode(&access.snapshot.csrf);
        p.mfa_epoch = epoch;
        if let Some(target) = operation.strip_prefix("factor_remove:") {
            p.purpose = target.into();
        }
        p.mfa_operation = operation;
        return Ok(render(&p, StatusCode::OK, hx));
    }
    let session = sec::cookie(h, &cookie_name(r, None))
        .map(|v| sec::digest(&v))
        .ok_or_else(Failure::csrf)?;
    let csrf = csrf.ok_or_else(Failure::csrf)?;
    if route == "account/security/recovery-codes/regenerate" {
        fields(form, &["csrf"])?;
        if operation != "recovery_codes_regenerate" {
            return Err(outcome("stale"));
        }
        return regenerate(app, r, &access, &session, &csrf, hx).await;
    }
    fields(form, &["csrf", "epoch", "confirmed"])?;
    let pieces: Vec<_> = route.split('/').collect();
    if pieces.len() != 5
        || pieces[2] != "factors"
        || pieces[4] != "remove"
        || !directory::uuid(pieces[3])
    {
        return Err(outcome("missing"));
    }
    let factor = pieces[3];
    if operation != format!("factor_remove:{factor}") {
        return Err(outcome("stale"));
    }
    let fresh_session = random()?;
    let fresh_browser = random()?;
    let fresh_csrf = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let status = app
        .storage
        .mfa_account_remove(AccountRemove {
            proof: realm_storage::MfaVerification {
                realm: r,
                bearer: &access.bearer,
                browser: &access.browser,
                token: &csrf,
                factor: None,
                step: None,
                session: &sec::digest(&fresh_session),
                new_browser: &sec::digest(&fresh_browser),
                new_token: &fresh_csrf,
                device: device(h),
            },
            current_session: &session,
            epoch: val(form, "epoch").parse().unwrap_or(0),
            factor,
            confirmed: val(form, "confirmed") == "true",
        })
        .await?;
    if status == "required" {
        let mut p = Page::new(r, &format!("/realms/{r}/account/security"));
        p.protected = true;
        p.name = app.storage.realm_name(r).await?.unwrap_or_default();
        p.account = app
            .storage
            .realm_account(r, &session, false)
            .await?
            .ok_or_else(|| outcome("stale"))?;
        let shell_token = app
            .storage
            .realm_form(Authority {
                realm: r,
                purpose: "account",
                browser: &access.browser,
                token: None,
                session: Some(&session),
                link: None,
            })
            .await?
            .ok_or_else(Failure::csrf)?;
        p.shell_csrf = sec::encode(&shell_token);
        p.state = "security-required-remove";
        p.title = "Keep an active factor".into();
        return Ok(render(&p, StatusCode::CONFLICT, hx));
    }
    if status == "login" {
        let mut response = nav(&format!("/realms/{r}/login"), hx);
        clear(&mut response, r);
        mfa::flow_cookie(&mut response, r, "");
        return Ok(response);
    }
    if status != "ok" {
        return Err(outcome(&status));
    }
    let mut response = nav(&format!("/realms/{r}/account/security"), hx);
    cookie(&mut response, &cookie_name(r, None), &fresh_session);
    cookie(
        &mut response,
        &cookie_name(r, Some("account")),
        &fresh_browser,
    );
    mfa::flow_cookie(&mut response, r, "");
    Ok(response)
}
async fn regenerate(
    app: &Application,
    r: &str,
    access: &mfa::MfaAccess,
    session: &[u8; 32],
    csrf: &[u8; 32],
    hx: bool,
) -> Result<Response, Failure> {
    let keys = app
        .storage
        .mfa_keys()
        .await
        .map_err(|_| realm_storage::Error::Storage)?;
    let active = keys
        .iter()
        .find(|k| k.state.as_deref() == Some("active"))
        .ok_or(realm_storage::Error::Storage)?;
    let key = active.id.clone().ok_or(realm_storage::Error::Storage)?;
    let key_generation = active.generation;
    let generation = uuid::Uuid::new_v4().to_string();
    let handoff = uuid::Uuid::new_v4().to_string();
    let binding = crate::mfa::Binding {
        installation: mfa::uuid(&access.snapshot.installation)?,
        realm: mfa::uuid(r)?,
        user: mfa::uuid(&access.snapshot.user)?,
        record: mfa::uuid(&handoff)?,
        purpose: crate::mfa::Purpose::RecoveryHandoff,
        payload_version: 1,
    };
    let ring = app
        .config
        .mfa_keyring
        .clone()
        .ok_or(realm_storage::Error::Storage)?;
    let owned_realm = r.to_owned();
    let owned_user = access.snapshot.user.clone();
    let owned_generation = generation.clone();
    let key_bytes = mfa::uuid(&key)?;
    let (digests, envelope) = app
        .worker
        .factor(move || {
            let codes =
                crate::mfa::recovery::generate(&owned_realm, &owned_user, &owned_generation)?;
            let envelope = ring.encrypt(key_bytes, &binding, &codes.payload)?;
            Ok::<_, crate::mfa::Error>((codes.digests, envelope))
        })
        .await?
        .map_err(|_| realm_storage::Error::Storage)?;
    let bearer = random()?;
    let new_csrf = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let status = app
        .storage
        .mfa_account_regenerate(AccountCodes {
            realm: r,
            bearer: &access.bearer,
            browser: &access.browser,
            csrf,
            session,
            generation: &generation,
            digests,
            handoff: &handoff,
            envelope: &envelope,
            key: &key,
            key_generation,
            new_bearer: &sec::digest(&bearer),
            new_csrf: &new_csrf,
        })
        .await?;
    if status != "handoff" {
        return Err(outcome(&status));
    }
    let mut response = nav(&format!("/realms/{r}/account/security/recovery-codes"), hx);
    mfa::flow_cookie(&mut response, r, &bearer);
    mfa::clear_session(&mut response, r);
    Ok(response)
}
