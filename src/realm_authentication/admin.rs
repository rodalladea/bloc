use super::*;
fn settings_fields(p: &mut Page, policy: &Policy) {
    p.mfa_policy = policy.mfa.clone();
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
        let a = if path.ends_with("mfa-recovery") {
            "mfa_recovery"
        } else if path.ends_with("authentication") {
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
    if path.ends_with("/mfa-recovery") {
        return super::recovery::admin(app, request, path, hx).await;
    }
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
    if !hx {
        p.workspace = crate::workspace::Workspace::load(&app.storage, &session, realm.clone())
            .await
            .map_err(|_| realm_storage::Error::Storage)?;
    }
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
        p.action = "Review changes";
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
        crate::administrator::cookie(&mut response, crate::workspace::COOKIE, r);
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
        "mfa_mode",
        "mfa_totp_allowed",
        "mfa_webauthn_allowed",
        "mfa_preferred_method",
        "mfa_recovery_codes_enabled",
        "mfa_admin_recovery_enabled",
        "mfa_flow_ttl_seconds",
        "mfa_admin_recovery_ttl_seconds",
        "administrator_password",
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
    if version(&form) != policy.version {
        return Ok(settings_conflict(p, hx));
    }
    let mut values = match settings_values(&form) {
        Ok(v) => v,
        Err(field) => {
            p.invalid(&field, "Enter a complete value within the allowed range.");
            p.state = "settings-invalid";
            return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
        }
    };
    let submitted_policy = match parse_mfa_policy(&form, &policy.mfa) {
        Ok(policy) => policy,
        Err(_) => {
            p.error = true;
            p.state = "settings-mfa-invalid";
            p.title = "Choose an allowed method".into();
            p.feedback="Allow at least one method when two-factor authentication is optional or required. Your policy has not changed.".into();
            return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
        }
    };
    let mfa_values = submitted_policy.values();
    let mfa_changed = mfa_values != policy.mfa.values();
    if mfa_changed
        && submitted_policy.mode != crate::mfa::policy::Mode::Disabled
        && submitted_policy.allows("webauthn")
        && !crate::mfa::webauthn::origin_supported(&app.config.origin)
    {
        p.error = true;
        p.state = "settings-mfa-invalid";
        p.title = "Passkeys are unavailable".into();
        p.feedback = "Passkeys and security keys require an HTTPS origin with a domain name. Clear that method before saving this policy.".into();
        return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
    }
    values.extend(mfa_values);
    if mfa_changed && val(&form, "confirmed") == "true" {
        let wait = app
            .storage
            .reserve(&[
                ("credential_source", key(app, "source", &source)?, 1),
                ("hash_work", [0; 32], 1),
                ("password_change", [0; 32], 1),
            ])
            .await
            .map_err(|_| realm_storage::Error::Storage)?;
        if wait != 0 {
            return Err(Failure {
                status: StatusCode::TOO_MANY_REQUESTS,
                state: "throttled",
                message: "Too many attempts. Wait before trying again.",
                retry: Some(wait.max(1)),
            });
        }
        if !app
            .worker
            .verify(
                val(&form, "administrator_password").into(),
                owner.phc.clone(),
            )
            .await?
        {
            p.error = true;
            p.feedback = "Check your current administrator password.".into();
            return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, hx));
        }
    }
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
            policy.version,
            &values,
            val(&form, "confirmed") == "true",
        )
        .await?;
    match out.as_str() {
        "mfa_confirm" => {
            let (enrollment, stranded) = app
                .storage
                .realm_mfa_policy_impact(r, &session, &values[11], &values[12])
                .await?;
            p.state = "settings-mfa-confirm";
            p.title = "Review policy change".into();
            p.confirm = "Apply two-factor authentication policy?".into();
            p.confirm_values = vec![
                (
                    "Accounts requiring enrollment".into(),
                    enrollment.to_string(),
                ),
                (
                    "Accounts with no allowed factor".into(),
                    stranded.to_string(),
                ),
            ];
            p.hidden_fields = form
                .into_iter()
                .filter(|(k, _)| {
                    !matches!(k.as_str(), "csrf" | "confirmed" | "administrator_password")
                })
                .collect();
            p.action = "Apply policy";
            Ok(render(&p, StatusCode::OK, hx))
        }
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
        _ => Ok(settings_conflict(p, hx)),
    }
}

fn settings_conflict(mut p: Page, hx: bool) -> Response {
    p.state = "settings-conflict";
    p.title = "This page is out of date".into();
    p.error = true;
    p.feedback = "These settings changed. Reload before continuing. Review the current values before saving again.".into();
    render(&p, StatusCode::CONFLICT, hx)
}

fn parse_mfa_policy(
    form: &Form,
    current: &crate::mfa::policy::Policy,
) -> Result<crate::mfa::policy::Policy, ()> {
    if !form.contains_key("mfa_mode") {
        return Ok(current.clone());
    }
    let mode = crate::mfa::policy::Mode::parse(val(form, "mfa_mode")).ok_or(())?;
    let checkbox = |name: &str| -> Result<bool, ()> {
        match val(form, name) {
            "true" | "on" => Ok(true),
            "" | "false" => Ok(false),
            _ => Err(()),
        }
    };
    let mut methods = vec![];
    for (name, method) in [
        ("mfa_totp_allowed", "totp"),
        ("mfa_webauthn_allowed", "webauthn"),
    ] {
        if checkbox(name)? {
            methods.push(method.to_owned());
        }
    }
    if mode != crate::mfa::policy::Mode::Disabled && methods.is_empty() {
        return Err(());
    }
    let preferred = match val(form, "mfa_preferred_method") {
        "" => None,
        value if methods.iter().any(|m| m == value) => Some(value.to_owned()),
        _ => return Err(()),
    };
    let ttl = val(form, "mfa_flow_ttl_seconds")
        .parse::<i32>()
        .map_err(|_| ())?;
    let recovery_ttl = val(form, "mfa_admin_recovery_ttl_seconds")
        .parse::<i32>()
        .map_err(|_| ())?;
    if !(120..=600).contains(&ttl) || !(300..=3600).contains(&recovery_ttl) {
        return Err(());
    }
    Ok(crate::mfa::policy::Policy {
        mode,
        methods,
        preferred,
        codes: checkbox("mfa_recovery_codes_enabled")?,
        assisted: checkbox("mfa_admin_recovery_enabled")?,
        ttl,
        recovery_ttl,
    })
}
