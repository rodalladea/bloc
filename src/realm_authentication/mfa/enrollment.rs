use super::*;
use zeroize::Zeroizing;

pub(super) async fn start(
    app: &Application,
    r: &str,
    bearer: &[u8; 32],
    browser: &[u8; 32],
    token: &[u8; 32],
    snapshot: &realm_storage::MfaFlow,
    hx: bool,
) -> Result<Response, Failure> {
    let secret =
        Zeroizing::new(sec::random().map_err(|_| realm_storage::Error::Storage)?[..20].to_vec());
    let record = random_uuid()?;
    let new_bearer = random()?;
    let new_csrf = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    for _ in 0..2 {
        let (key_id, key_generation) = app
            .storage
            .mfa_write_key()
            .await
            .map_err(|_| realm_storage::Error::Storage)?;
        let key_id = key_id.as_str();
        let binding = crate::mfa::Binding {
            installation: uuid(&snapshot.installation)?,
            realm: uuid(r)?,
            user: uuid(&snapshot.user)?,
            record: uuid(&record)?,
            purpose: crate::mfa::Purpose::PendingTotp,
            payload_version: 1,
        };
        let ring = app
            .config
            .mfa_keyring
            .clone()
            .ok_or(realm_storage::Error::Storage)?;
        let plaintext = secret.clone();
        let key = uuid(key_id)?;
        let envelope = app
            .worker
            .factor(move || ring.encrypt(key, &binding, &plaintext))
            .await?
            .map_err(|_| realm_storage::Error::Storage)?;
        let result = app
            .storage
            .realm_mfa_totp_start(realm_storage::MfaEnrollment {
                realm: r,
                bearer,
                browser,
                token,
                payload: &record,
                envelope,
                key: key_id,
                generation: key_generation,
                new_bearer: &sec::digest(&new_bearer),
                new_token: &new_csrf,
            })
            .await?;
        if result == "key_conflict" {
            continue;
        }
        if result != "ok" {
            return Err(Failure::new(
                StatusCode::CONFLICT,
                "This enrollment authority changed. Sign in again to continue.",
            ));
        }
        let mut response = nav(&format!("/realms/{r}/account/security/totp/setup"), hx);
        flow_cookie(&mut response, r, &new_bearer);
        return Ok(response);
    }
    Err(realm_storage::Error::Storage.into())
}
pub(super) async fn setup(
    app: &Application,
    r: &str,
    bearer: &[u8; 32],
    browser: &[u8; 32],
    snapshot: &realm_storage::MfaFlow,
    qr: bool,
    hx: bool,
) -> Result<Response, Failure> {
    let path = format!("/realms/{r}/account/security/totp/setup");
    if hx {
        return Ok(nav(&path, true));
    }
    let material = app
        .storage
        .realm_mfa_pending_totp(r, bearer, browser, None)
        .await?
        .ok_or_else(|| {
            Failure::new(
                StatusCode::CONFLICT,
                "This setup changed. Sign in again to continue.",
            )
        })?;
    let binding = crate::mfa::Binding {
        installation: uuid(&material.installation)?,
        realm: uuid(r)?,
        user: uuid(&material.user)?,
        record: uuid(&material.factor)?,
        purpose: crate::mfa::Purpose::PendingTotp,
        payload_version: 1,
    };
    let ring = app
        .config
        .mfa_keyring
        .clone()
        .ok_or(realm_storage::Error::Storage)?;
    let name = app.storage.realm_name(r).await?.unwrap_or_default();
    let realm = r.to_owned();
    let label = name.clone();
    let (key, image) = app
        .worker
        .factor(move || {
            let secret = ring.decrypt(&binding, &material.envelope)?;
            crate::mfa::totp::presentation(&secret, &label, &realm)
        })
        .await?
        .map_err(|_| realm_storage::Error::Storage)?;
    let key = Zeroizing::new(key);
    if qr {
        return Ok((
            [
                (header::CONTENT_TYPE, "image/png"),
                (header::REFERRER_POLICY, "no-referrer"),
            ],
            image,
        )
            .into_response());
    }
    let mut p = Page::new(r, &path);
    p.state = "mfa-totp";
    p.title = "Set up an authenticator app".into();
    p.intro =
        "Scan the setup code with your authenticator app, or enter the setup key manually.".into();
    p.name = name;
    p.csrf = sec::encode(&snapshot.csrf);
    p.mfa_setup_key = key;
    Ok(render(&p, StatusCode::OK, false))
}
pub(super) fn random_uuid() -> Result<String, Failure> {
    let random = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&random[..16]);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}
struct ActivationMaterial {
    step: Option<i64>,
    active: Vec<u8>,
    digests: Vec<Vec<u8>>,
    handoff: Vec<u8>,
}
pub(super) async fn confirm(
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
    let material = app
        .storage
        .realm_mfa_pending_totp(r, bearer, browser, Some(token))
        .await?
        .ok_or_else(|| Failure::new(StatusCode::CONFLICT, "This setup changed. Sign in again."))?;
    let generation = random_uuid()?;
    let handoff = random_uuid()?;
    let handoff_bearer = random()?;
    let handoff_csrf = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    let session = random()?;
    let session_browser = random()?;
    let session_token = sec::random().map_err(|_| realm_storage::Error::Storage)?;
    for _ in 0..2 {
        let (key_id, key_generation) = app
            .storage
            .mfa_write_key()
            .await
            .map_err(|_| realm_storage::Error::Storage)?;
        let key_id = key_id.as_str();
        let pending = crate::mfa::Binding {
            installation: uuid(&material.installation)?,
            realm: uuid(r)?,
            user: uuid(&material.user)?,
            record: uuid(&material.factor)?,
            purpose: crate::mfa::Purpose::PendingTotp,
            payload_version: 1,
        };
        let installed = crate::mfa::Binding {
            installation: pending.installation,
            realm: pending.realm,
            user: pending.user,
            record: pending.record,
            purpose: crate::mfa::Purpose::ActiveTotp,
            payload_version: 1,
        };
        let delivery = crate::mfa::Binding {
            installation: pending.installation,
            realm: pending.realm,
            user: pending.user,
            record: uuid(&handoff)?,
            purpose: crate::mfa::Purpose::RecoveryHandoff,
            payload_version: 1,
        };
        let ring = app
            .config
            .mfa_keyring
            .clone()
            .ok_or(realm_storage::Error::Storage)?;
        let envelope = material.envelope.clone();
        let key = uuid(key_id)?;
        let code = val(form, "code").to_owned();
        let now = material.now;
        let owner = material.user.clone();
        let realm = r.to_owned();
        let gen_id = generation.clone();
        let output = app
            .worker
            .factor(move || -> Result<ActivationMaterial, crate::mfa::Error> {
                let secret = ring.decrypt(&pending, &envelope)?;
                let step = crate::mfa::totp::accepted_step(&secret, &code, now, -1)?;
                if step.is_none() {
                    return Ok(ActivationMaterial {
                        step,
                        active: vec![],
                        digests: vec![],
                        handoff: vec![],
                    });
                }
                let codes = crate::mfa::recovery::generate(&realm, &owner, &gen_id)?;
                Ok(ActivationMaterial {
                    step,
                    active: ring.encrypt(key, &installed, &secret)?,
                    handoff: ring.encrypt(key, &delivery, &codes.payload)?,
                    digests: codes.digests,
                })
            })
            .await?
            .map_err(|_| realm_storage::Error::Storage)?;
        let outcome = app
            .storage
            .realm_mfa_activate_totp(realm_storage::MfaActivation {
                realm: r,
                bearer,
                browser,
                token,
                step: output.step,
                active_envelope: output.active,
                key: key_id,
                key_generation,
                generation: &generation,
                digests: output.digests,
                handoff: &handoff,
                handoff_envelope: output.handoff,
                new_bearer: &sec::digest(&handoff_bearer),
                new_csrf: &handoff_csrf,
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
                flow_cookie(&mut response, r, &handoff_bearer);
                return Ok(response);
            }
            "ok" => return Ok(super::issued(r, &session, &session_browser, hx)),
            "invalid" => {
                let mut p = Page::new(r, &format!("/realms/{r}/account/security/totp/setup"));
                p.name = app.storage.realm_name(r).await?.unwrap_or_default();
                p.state = "mfa-totp";
                p.title = "Check your code".into();
                p.csrf = sec::encode(&snapshot.csrf);
                p.error = true;
                p.feedback =
                    "We couldn’t verify that proof. Try a new code before this setup expires."
                        .into();
                return Ok(render(&p, StatusCode::UNPROCESSABLE_ENTITY, false));
            }
            "limited" => return Err(super::limited()),
            "expired" => return Ok(nav(&format!("/realms/{r}/login?expired=mfa"), hx)),
            _ => {
                return Err(Failure::new(
                    StatusCode::CONFLICT,
                    "This setup changed. Sign in again to continue.",
                ));
            }
        }
    }
    Err(realm_storage::Error::Storage.into())
}
