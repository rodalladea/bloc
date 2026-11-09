use super::*;
use zeroize::Zeroizing;

pub(super) async fn show(
    app: &Application,
    r: &str,
    bearer: &[u8; 32],
    browser: &[u8; 32],
    snapshot: &realm_storage::MfaFlow,
    hx: bool,
) -> Result<Response, Failure> {
    let path = format!("/realms/{r}/account/security/recovery-codes");
    if hx {
        return Ok(nav(&path, true));
    }
    let name = app.storage.realm_name(r).await?.unwrap_or_default();
    let (status, material) = app.storage.realm_mfa_handoff(r, bearer, browser).await?;
    let mut p = Page::new(r, &path);
    p.name = name;
    p.csrf = sec::encode(&snapshot.csrf);
    p.state = "mfa-codes";
    p.title = "Save your recovery codes".into();
    p.intro="Each code can replace your factors once, after password verification. Store these somewhere safe.".into();
    if status == "lost" {
        p.state = "mfa-codes-lost";
        p.title = "Replace unsaved codes".into();
        p.feedback="Create a new set only while setup authority is still valid. Every code in the previous set will stop working.".into();
        return Ok(render(&p, StatusCode::OK, false));
    }
    let material = material.ok_or_else(|| {
        Failure::new(
            StatusCode::CONFLICT,
            "This code handoff changed. Sign in again.",
        )
    })?;
    let binding = crate::mfa::Binding {
        installation: uuid(&material.installation)?,
        realm: uuid(r)?,
        user: uuid(&material.user)?,
        record: uuid(&material.payload)?,
        purpose: crate::mfa::Purpose::RecoveryHandoff,
        payload_version: 1,
    };
    let ring = app
        .config
        .mfa_keyring
        .clone()
        .ok_or(realm_storage::Error::Storage)?;
    p.mfa_codes = app
        .worker
        .factor(move || {
            let plaintext = ring.decrypt(&binding, &material.envelope)?;
            let codes = crate::mfa::decode_handoff(&plaintext)?;
            Ok::<_, crate::mfa::Error>(Zeroizing::new(codes.join("\n")))
        })
        .await?
        .map_err(|_| realm_storage::Error::Storage)?;
    Ok(render(&p, StatusCode::OK, false))
}
pub(super) async fn acknowledge(
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
    let session = random()?;
    let new_browser = random()?;
    let new_token = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let saved = val(form, "saved") == "true"
        && form
            .keys()
            .all(|key| matches!(key.as_str(), "csrf" | "saved"));
    let outcome = app
        .storage
        .realm_mfa_ack(
            realm_storage::MfaVerification {
                realm: r,
                bearer,
                browser,
                token,
                factor: None,
                step: None,
                session: &sec::digest(&session),
                new_browser: &sec::digest(&new_browser),
                new_token: &new_token,
                device: device(h),
            },
            saved,
        )
        .await?;
    match outcome.as_str() {
        "ok" => Ok(super::issued(r, &session, &new_browser, hx)),
        "invalid" => {
            let mut p = Page::new(r, &format!("/realms/{r}/account/security/recovery-codes"));
            p.state = "mfa-codes-lost";
            p.title = "Confirm that you saved your codes".into();
            p.csrf = sec::encode(&snapshot.csrf);
            p.error = true;
            p.feedback="Confirm that you saved your recovery codes before continuing. If you lost the response, replace the unsaved set.".into();
            Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, false))
        }
        "expired" => Ok(nav(&format!("/realms/{r}/login?expired=mfa"), hx)),
        _ => Err(Failure::new(
            StatusCode::CONFLICT,
            "This code handoff changed. Sign in again.",
        )),
    }
}
pub(super) async fn replace(
    app: &Application,
    r: &str,
    h: &HeaderMap,
    access: &MfaAccess,
    token: &[u8; 32],
    hx: bool,
) -> Result<Response, Failure> {
    let MfaAccess {
        bearer,
        browser,
        snapshot,
    } = access;
    let generation = super::enrollment::random_uuid()?;
    let handoff = super::enrollment::random_uuid()?;
    let new_bearer = random()?;
    let new_csrf = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let session = random()?;
    let session_browser = random()?;
    let session_token = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    for _ in 0..2 {
        let keys = app
            .storage
            .mfa_keys()
            .await
            .map_err(|_| realm_storage::Error::Storage)?;
        let active = keys
            .iter()
            .find(|k| k.state.as_deref() == Some("active"))
            .ok_or(realm_storage::Error::Storage)?;
        let key_id = active.id.as_deref().ok_or(realm_storage::Error::Storage)?;
        let binding = crate::mfa::Binding {
            installation: uuid(&snapshot.installation)?,
            realm: uuid(r)?,
            user: uuid(&snapshot.user)?,
            record: uuid(&handoff)?,
            purpose: crate::mfa::Purpose::RecoveryHandoff,
            payload_version: 1,
        };
        let ring = app
            .config
            .mfa_keyring
            .clone()
            .ok_or(realm_storage::Error::Storage)?;
        let key = uuid(key_id)?;
        let realm = r.to_owned();
        let user = snapshot.user.clone();
        let gen_id = generation.clone();
        let (digests, envelope) = app
            .worker
            .factor(move || {
                let set = crate::mfa::recovery::generate(&realm, &user, &gen_id)?;
                Ok::<_, crate::mfa::Error>((
                    set.digests,
                    ring.encrypt(key, &binding, &set.payload)?,
                ))
            })
            .await?
            .map_err(|_| realm_storage::Error::Storage)?;
        let outcome = app
            .storage
            .realm_mfa_replace_handoff(realm_storage::HandoffReplacement {
                realm: r,
                bearer,
                browser,
                token,
                generation: &generation,
                digests,
                handoff: &handoff,
                envelope,
                key: key_id,
                key_generation: active.generation,
                new_bearer: &sec::digest(&new_bearer),
                new_csrf: &new_csrf,
                session: &sec::digest(&session),
                session_browser: &sec::digest(&session_browser),
                session_token: &session_token,
                device: device(h),
            })
            .await?;
        match outcome.as_str() {
            "key_conflict" => continue,
            "handoff" => {
                let mut response = nav(&format!("/realms/{r}/account/security/recovery-codes"), hx);
                super::clear_session(&mut response, r);
                flow_cookie(&mut response, r, &new_bearer);
                return Ok(response);
            }
            "ok" => return Ok(super::issued(r, &session, &session_browser, hx)),
            "expired" => return Ok(nav(&format!("/realms/{r}/login?expired=mfa"), hx)),
            _ => {
                return Err(Failure::new(
                    StatusCode::CONFLICT,
                    "This code handoff changed. Sign in again to continue.",
                ));
            }
        }
    }
    Err(realm_storage::Error::Storage.into())
}
