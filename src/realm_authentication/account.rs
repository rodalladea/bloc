use super::*;
pub(super) async fn handle(
    app: &Application,
    mut flow: Flow,
    hx: bool,
) -> Result<Response, Failure> {
    populate(app, &mut flow).await?;
    let operation = match flow.route.as_str() {
        "account/profile" => "profile",
        "account/password" => "password",
        "logout" => "logout",
        "account/sessions/revoke-others" => "revoke_others",
        _ => "revoke",
    };
    submission::respond(app, flow, operation, hx).await
}
async fn populate(app: &Application, flow: &mut Flow) -> Result<(), Failure> {
    let Flow {
        p,
        policy,
        form,
        query,
        get,
        session,
        target,
        ..
    } = flow;
    let get = *get;
    let target = target.as_deref();
    match p.state {
        "profile" => {
            p.title = "Profile".into();
            p.intro = format!("Manage your personal information in {}.", p.name);
            let display = if get {
                p.account.display.clone()
            } else {
                val(form, "display_name").into()
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
            p.passwords(policy);
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
                .realm_sessions(&p.realm, session.as_ref().ok_or_else(Failure::csrf)?)
                .await?;
            if p.path.ends_with("revoke-others") {
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
    Ok(())
}
