use super::*;
struct Proof {
    browser: [u8; 32],
    token: [u8; 32],
}
struct Prepared {
    values: Vec<String>,
    expected: i64,
    policy_version: i64,
    user: Option<String>,
}
enum Preparation {
    Ready(Prepared),
    Respond(Response),
}
pub(super) async fn respond(
    app: &Application,
    mut flow: Flow,
    operation: &str,
    hx: bool,
) -> Result<Response, Failure> {
    if flow.get {
        return page(app, &mut flow, hx).await;
    }
    let proof = authorize(app, &mut flow, operation).await?;
    if operation == "exchange" {
        return access::exchange(app, &flow, &proof.browser, &proof.token, hx).await;
    }
    if matches!(operation, "activation" | "reset") && flow.link.is_none() {
        return Err(Failure::csrf());
    }
    let prepared = match prepare(app, &mut flow, operation, hx).await? {
        Preparation::Ready(p) => p,
        Preparation::Respond(r) => return Ok(r),
    };
    commit(app, flow, operation, proof, prepared, hx).await
}
async fn page(app: &Application, flow: &mut Flow, hx: bool) -> Result<Response, Failure> {
    let Flow {
        source,
        h,
        realm,
        p,
        session,
        link,
        form_purpose,
        ..
    } = flow;
    let r = realm.as_str();
    let form_purpose = *form_purpose;
    let protected = p.protected;
    let b = form_token(
        app,
        p,
        h,
        form_purpose,
        session.as_ref().filter(|_| protected),
        link.as_ref(),
        source,
    )
    .await?;
    let mut response = render(p, StatusCode::OK, hx);
    if let Some(b) = b {
        cookie(&mut response, &cookie_name(r, Some(form_purpose)), &b)
    }
    Ok(response)
}
async fn authorize(app: &Application, flow: &mut Flow, operation: &str) -> Result<Proof, Failure> {
    let Flow {
        h,
        realm,
        p,
        session,
        form,
        link,
        form_purpose,
        ..
    } = flow;
    let r = realm.as_str();
    let form_purpose = *form_purpose;
    let browser = sec::cookie(h, &cookie_name(r, Some(form_purpose)))
        .map(|x| sec::digest(&x))
        .ok_or_else(Failure::csrf)?;
    let token = sec::decode(val(form, "csrf")).ok_or_else(Failure::csrf)?;
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
    let allowed: &[&str] = if operation == "register" {
        &[
            "csrf",
            "email",
            "display_name",
            "password",
            "password_confirmation",
        ]
    } else if operation == "login" {
        &["csrf", "email", "password"]
    } else if operation == "exchange" {
        &["csrf", "code"]
    } else if operation == "profile" {
        &["csrf", "version", "display_name"]
    } else if operation == "password" {
        &[
            "csrf",
            "current_password",
            "password",
            "password_confirmation",
        ]
    } else if matches!(operation, "activation" | "reset") {
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
    Ok(Proof { browser, token })
}
async fn prepare(
    app: &Application,
    flow: &mut Flow,
    operation: &str,
    hx: bool,
) -> Result<Preparation, Failure> {
    let Flow {
        source,
        h,
        realm,
        policy,
        p,
        form,
        link,
        purpose,
        ..
    } = flow;
    let r = realm.as_str();
    let purpose = *purpose;
    let mut values = vec![];
    let mut expected = 0;
    let mut policy_version = policy.version;
    let mut user = None;
    if matches!(operation, "revoke" | "revoke_others") && val(form, "confirmed") != "true" {
        return Ok(Preparation::Respond(render(p, StatusCode::OK, hx)));
    }
    if operation == "profile" {
        match directory::name(val(form, "display_name"), true) {
            Ok(n) => values.push(n),
            Err(_) => {
                p.invalid(
                    "display_name",
                    "Use at most 128 characters and 512 bytes, without control characters.",
                );
                return Ok(Preparation::Respond(render(
                    p,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    hx,
                )));
            }
        }
        expected = version(form);
    }
    let email = if matches!(operation, "login" | "register") {
        match credentials::normalize_email(val(form, "email")) {
            Ok(e) => e,
            Err(_) => {
                p.invalid("email", "Enter an email address.");
                return Ok(Preparation::Respond(render(
                    p,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    hx,
                )));
            }
        }
    } else {
        String::new()
    };
    if operation == "register" {
        let display = match directory::name(val(form, "display_name"), true) {
            Ok(n) => n,
            Err(_) => {
                p.invalid(
                    "display_name",
                    "Use at most 128 characters and 512 bytes, without control characters.",
                );
                return Ok(Preparation::Respond(render(
                    p,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    hx,
                )));
            }
        };
        values = vec![email.clone(), display];
    }
    if matches!(operation, "register" | "activation" | "reset" | "password")
        && !policy.accepts(val(form, "password"), val(form, "password_confirmation"))
    {
        if operation == "register" {
            p.state = "policy-error";
        }
        p.invalid(
            "password",
            "Follow the current password requirements and enter matching confirmation.",
        );
        return Ok(Preparation::Respond(render(
            p,
            StatusCode::UNPROCESSABLE_ENTITY,
            hx,
        )));
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
                key(app, "realm-credential-source", source)?,
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
                    val(form, "password").into(),
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
                return Ok(Preparation::Respond(render(
                    p,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    hx,
                )));
            }
            if let Some(c) = credential {
                expected = c.version;
                policy_version = c.user_version;
                user = Some(c.user);
            }
            values.push(device(h));
        } else {
            if operation == "password" {
                if !app
                    .worker
                    .verify(val(form, "current_password").into(), p.account.phc.clone())
                    .await?
                {
                    p.invalid("current_password", "Check your current password.");
                    return Ok(Preparation::Respond(render(
                        p,
                        StatusCode::UNPROCESSABLE_ENTITY,
                        hx,
                    )));
                }
                expected = p.account.credential;
            }
            values.push(app.worker.hash(val(form, "password").into()).await?);
            if operation == "password" {
                values.push(device(h))
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
    Ok(Preparation::Ready(Prepared {
        values,
        expected,
        policy_version,
        user,
    }))
}
async fn commit(
    app: &Application,
    flow: Flow,
    operation: &str,
    proof: Proof,
    prepared: Prepared,
    hx: bool,
) -> Result<Response, Failure> {
    let Flow {
        realm,
        mut p,
        session,
        link,
        form_purpose,
        target,
        ..
    } = flow;
    let r = realm.as_str();
    let target = target.as_deref();
    let Proof { browser, token } = proof;
    let Prepared {
        values,
        expected,
        policy_version,
        user,
    } = prepared;
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
