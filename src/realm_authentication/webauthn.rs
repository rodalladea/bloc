//! HTTP orchestration around the maintained verifier and guarded ceremony authority.
use super::*;
use crate::mfa::{webauthn as verifier, webauthn_storage as store};

fn stale() -> Failure {
    Failure::new(
        StatusCode::CONFLICT,
        "This verification flow changed or was consumed. Sign in again to continue.",
    )
}
fn proof() -> Failure {
    Failure::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "We couldn’t verify that proof. Try again or choose another available method.",
    )
}
fn verifier_error(error: verifier::Failure) -> Failure {
    match error {
        verifier::Failure::Stored => realm_storage::Error::BeforeCommit.into(),
        verifier::Failure::Proof => proof(),
        verifier::Failure::Stale => stale(),
    }
}
async fn form(app: &Application, request: Request, finish: bool) -> Result<Form, Failure> {
    if !sec::origin(&app.config, request.headers()) && !native_origin(request.headers()) {
        return Err(Failure::csrf());
    }
    if sec::one(request.headers(), "content-type").and_then(|v| v.split(';').next())
        != Some("application/x-www-form-urlencoded")
    {
        return Err(Failure::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Submit this form using the supported format.",
        ));
    }
    let bytes = to_bytes(request.into_body(), if finish { 65536 } else { 16384 })
        .await
        .map_err(|_| {
            Failure::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "The submitted form is too large.",
            )
        })?;
    sec::form_fields_bounded(&bytes, if finish { 65536 } else { 16384 })
        .map_err(|s| Failure::new(s, "The request could not be read."))
}
pub(super) async fn handle(
    app: &Application,
    request: Request,
    r: &str,
    route: &str,
    hx: bool,
) -> Result<Response, Failure> {
    let source = source(app, &request)?;
    let headers = request.headers().clone();
    let get = matches!(*request.method(), Method::GET | Method::HEAD);
    let registration = route.starts_with("account/");
    let finish = route.ends_with("/finish");
    let page = matches!(route, "account/security/webauthn/setup" | "mfa/webauthn");
    if (page && !get) || (!page && request.method() != Method::POST) {
        return Err(Failure::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "Use the page link or form to continue.",
        ));
    }
    app.storage
        .mfa_ready(app.config.mfa_keyring.as_ref())
        .await
        .map_err(|_| realm_storage::Error::Storage)?;
    let form = if get {
        Form::new()
    } else {
        form(app, request, finish).await?
    };
    let token = if get {
        None
    } else {
        Some(sec::decode(val(&form, "csrf")).ok_or_else(Failure::csrf)?)
    };
    let (status, access) = mfa::resolve_flow(app, r, &headers, token.as_ref()).await?;
    if status == "expired" {
        let mut response = nav(&format!("/realms/{r}/login?expired=mfa"), false);
        mfa::flow_cookie(&mut response, r, "");
        return Ok(response);
    }
    if status != "ok" {
        return Err(if status == "csrf" {
            Failure::csrf()
        } else {
            stale()
        });
    }
    let access = access.ok_or(realm_storage::Error::Storage)?;
    let token: [u8; 32] = token.unwrap_or(
        access
            .snapshot
            .csrf
            .as_slice()
            .try_into()
            .map_err(|_| realm_storage::Error::Storage)?,
    );
    let authority = store::Authority {
        realm: r,
        bearer: &access.bearer,
        browser: &access.browser,
        token: &token,
        registration,
    };
    if page {
        app.storage
            .webauthn_material(
                &authority,
                &sec::random().map_err(|_| realm_storage::Error::Storage)?,
            )
            .await?
            .ok_or_else(stale)?;
        if hx {
            return Ok(nav(&format!("/realms/{r}/{route}"), true));
        }
        let mut p = Page::new(r, &format!("/realms/{r}/{route}"));
        p.state = if registration {
            "mfa-webauthn-register"
        } else {
            "mfa-webauthn-authenticate"
        };
        p.title = if registration {
            "Add a passkey or security key"
        } else {
            "Use your passkey"
        }
        .into();
        p.intro = if registration {
            ""
        } else {
            "Your browser will ask you to verify using your passkey or security key."
        }
        .into();
        p.mfa_policy = app
            .storage
            .realm_policy(r, None)
            .await?
            .ok_or(realm_storage::Error::BeforeCommit)?
            .mfa;
        let choices = app
            .storage
            .mfa_choices(r, &access.bearer, &access.browser)
            .await?
            .ok_or(realm_storage::Error::BeforeCommit)?;
        p.mfa_has_totp = choices.totp
            || (matches!(choices.context.as_str(), "initial_enrollment" | "recovery")
                && p.mfa_policy.allows("totp"));
        p.csrf = sec::encode(&token);
        p.name = app.storage.realm_name(r).await?.unwrap_or_default();
        return Ok(render(&p, StatusCode::OK, false));
    }
    if !finish {
        if !form.keys().all(|k| matches!(k.as_str(), "csrf" | "label")) {
            return Err(proof());
        }
        let label = val(&form, "label");
        if registration
            && (label.chars().count() == 0
                || label.chars().count() > 64
                || label.len() > 256
                || label.chars().any(char::is_control))
        {
            return Err(proof());
        }
        reserve(
            app,
            &[(
                "form_source",
                key(app, "realm-mfa-enrollment-source", &source)?,
                1,
            )],
        )
        .await?;
        let material = app
            .storage
            .webauthn_material(
                &authority,
                &sec::random().map_err(|_| realm_storage::Error::Storage)?,
            )
            .await?
            .ok_or_else(stale)?;
        let origin = app.config.origin.clone();
        let output = app
            .worker
            .factor(move || {
                if registration {
                    verifier::register_start(&origin, &material.handle, &material.ids)
                } else {
                    verifier::authentication_start(&origin, &material.records)
                }
            })
            .await?
            .map_err(verifier_error)?;
        let ceremony = random_uuid()?;
        let private_bearer = sec::random().map_err(|_| realm_storage::Error::Storage)?;
        let outcome = app
            .storage
            .webauthn_start(
                &authority,
                &ceremony,
                &sec::digest(&sec::encode(&private_bearer)),
                output.state,
                label,
            )
            .await?;
        if outcome != "ok" {
            return Err(if outcome == "invalid" {
                proof()
            } else {
                stale()
            });
        }
        let mut options = output.options;
        options
            .as_object_mut()
            .ok_or(realm_storage::Error::Storage)?
            .insert("ceremony_id".into(), ceremony.into());
        return Ok(axum::Json(options).into_response());
    }
    mfa::admit(app, r, &source, &access.bearer, &access.browser, &token).await?;
    let ceremony = val(&form, "ceremony_id");
    if !directory::uuid(ceremony) {
        return reject_reference(app, &authority, proof()).await;
    }
    let material = match app.storage.webauthn_ceremony(&authority, ceremony).await? {
        Some(material) => material,
        None => return reject_reference(app, &authority, stale()).await,
    };
    let origin = app.config.origin.clone();
    let bytes = val(&form, "credential").as_bytes().to_vec();
    let fields_valid = form
        .keys()
        .all(|k| matches!(k.as_str(), "csrf" | "ceremony_id" | "credential"));
    let result = app
        .worker
        .factor(move || {
            if !fields_valid {
                return Err(verifier::Failure::Proof);
            }
            if registration {
                verifier::register_finish(&origin, &material.state, &bytes)
                    .map(|v| (v.credential_id, vec![], v.public_record, v.transports))
            } else {
                verifier::authentication_finish(
                    &origin,
                    &material.state,
                    &bytes,
                    &material.handle,
                    &material.records,
                )
                .map(|v| (v.credential_id, v.original_record, v.updated_record, vec![]))
            }
        })
        .await?;
    let (verified, credential, original, updated, transports) = match result {
        Ok((credential, original, updated, transports)) => {
            (true, credential, original, updated, transports)
        }
        Err(verifier::Failure::Proof) => (false, vec![], vec![], vec![], vec![]),
        Err(e) => return Err(verifier_error(e)),
    };
    complete(
        app,
        r,
        &headers,
        authority,
        ceremony,
        &access.snapshot,
        verified,
        credential,
        original,
        updated,
        transports,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn complete(
    app: &Application,
    r: &str,
    h: &HeaderMap,
    authority: store::Authority<'_>,
    ceremony: &str,
    snapshot: &realm_storage::MfaFlow,
    verified: bool,
    credential: Vec<u8>,
    original: Vec<u8>,
    updated: Vec<u8>,
    transports: Vec<String>,
) -> Result<Response, Failure> {
    let factor = random_uuid()?;
    let generation = random_uuid()?;
    let handoff = random_uuid()?;
    let handoff_bearer = random()?;
    let handoff_csrf = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let session = random()?;
    let browser = random()?;
    let token = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    for _ in 0..2 {
        let (key_id, key_generation) = app
            .storage
            .mfa_write_key()
            .await
            .map_err(|_| realm_storage::Error::Storage)?;
        let key_id = key_id.as_str();
        let binding = crate::mfa::Binding {
            installation: mfa::uuid(&snapshot.installation)?,
            realm: mfa::uuid(r)?,
            user: mfa::uuid(&snapshot.user)?,
            record: mfa::uuid(&handoff)?,
            purpose: crate::mfa::Purpose::RecoveryHandoff,
            payload_version: 1,
        };
        let ring = app
            .config
            .mfa_keyring
            .clone()
            .ok_or(realm_storage::Error::Storage)?;
        let owner = snapshot.user.clone();
        let realm = r.to_owned();
        let gen_id = generation.clone();
        let key = mfa::uuid(key_id)?;
        let (digests, envelope) = app
            .worker
            .factor(move || {
                let codes = crate::mfa::recovery::generate(&realm, &owner, &gen_id)?;
                Ok::<_, crate::mfa::Error>((
                    codes.digests,
                    ring.encrypt(key, &binding, &codes.payload)?,
                ))
            })
            .await?
            .map_err(|_| realm_storage::Error::Storage)?;
        let outcome = app
            .storage
            .webauthn_finish(store::Completion {
                authority: store::Authority {
                    realm: authority.realm,
                    bearer: authority.bearer,
                    browser: authority.browser,
                    token: authority.token,
                    registration: authority.registration,
                },
                ceremony,
                verified,
                credential: credential.clone(),
                original: original.clone(),
                updated: updated.clone(),
                transports: transports.clone(),
                factor: &factor,
                key: key_id,
                key_generation,
                generation: &generation,
                digests,
                handoff: &handoff,
                envelope,
                new_bearer: &sec::digest(&handoff_bearer),
                new_csrf: &handoff_csrf,
                session: &sec::digest(&session),
                session_browser: &sec::digest(&browser),
                session_token: &token,
                device: device(h),
            })
            .await?;
        match outcome.as_str() {
            "key_conflict" => continue,
            "handoff" => {
                let mut response = nav(
                    &format!("/realms/{r}/account/security/recovery-codes"),
                    false,
                );
                mfa::clear_session(&mut response, r);
                mfa::flow_cookie(&mut response, r, &handoff_bearer);
                return Ok(response);
            }
            "ok" => return Ok(mfa::issued(r, &session, &browser, false)),
            "reauthenticated" => {
                return Ok(nav(
                    &format!("/realms/{r}/account/security/continue"),
                    false,
                ));
            }
            "invalid" => return Err(proof()),
            "limited" => return Err(mfa::limited()),
            _ => return Err(stale()),
        }
    }
    Err(realm_storage::Error::Storage.into())
}

fn random_uuid() -> Result<String, Failure> {
    let random = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&random[..16]);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}

async fn reject_reference(
    app: &Application,
    authority: &store::Authority<'_>,
    failure: Failure,
) -> Result<Response, Failure> {
    match app.storage.webauthn_reject(authority).await?.as_str() {
        "limited" => Err(mfa::limited()),
        "invalid" => Err(failure),
        _ => Err(stale()),
    }
}
