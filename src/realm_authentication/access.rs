use super::*;
pub(super) async fn handle(
    app: &Application,
    mut flow: Flow,
    hx: bool,
) -> Result<Response, Failure> {
    populate(
        &mut flow.p,
        &flow.policy,
        &flow.form,
        &flow.query,
        flow.purpose,
        &flow.path,
    );
    let operation = match flow.route.as_str() {
        "register" => "register",
        "login" => "login",
        _ if flow.route.ends_with("/exchange") => "exchange",
        _ => flow.purpose,
    };
    submission::respond(app, flow, operation, hx).await
}
fn populate(p: &mut Page, policy: &Policy, form: &Form, query: &str, purpose: &str, path: &str) {
    match p.state {
        "registration" => {
            p.title = "Create your account".into();
            p.intro = format!("Create an account in {}.", p.name);
            p.field(
                "display_name",
                "Display name",
                "text",
                val(form, "display_name"),
                "Optional. You can change this later.",
            );
            p.field(
                "email",
                "Email address",
                "email",
                val(form, "email"),
                "Your email will not be verified yet.",
            );
            p.passwords(policy);
            p.action = "Create account";
        }
        "login" => {
            p.title = format!("Sign in to {}", p.name);
            p.intro = "Use your realm account to continue.".into();
            p.field("email", "Email address", "email", val(form, "email"), "");
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
            p.passwords(policy);
            p.action = "Save password";
        }
        _ => {}
    }
}

pub(super) async fn exchange(
    app: &Application,
    flow: &Flow,
    browser: &[u8; 32],
    token: &[u8; 32],
    hx: bool,
) -> Result<Response, Failure> {
    let Flow {
        source,
        realm,
        form,
        purpose,
        path,
        ..
    } = flow;
    let r = realm.as_str();
    let purpose = *purpose;
    reserve(
        app,
        &[
            (
                "exchange_source",
                key(app, "realm-exchange-source", source)?,
                1,
            ),
            ("exchange_realm", key(app, "realm-exchange-realm", r)?, 1),
        ],
    )
    .await?;
    if sec::decode(val(form, "code")).is_none() {
        return Err(Failure::link());
    }
    let digest = sec::digest(val(form, "code"));
    let b = random()?;
    let t = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let out = app
        .storage
        .realm_exchange(
            Authority {
                realm: r,
                purpose,
                browser,
                token: Some(token),
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
    Ok(response)
}
