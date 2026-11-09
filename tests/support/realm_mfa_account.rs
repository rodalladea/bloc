async fn account_flow_token(b: &mut Browser, path: &str) -> String {
    let (status, html, _) = b.request("GET", path, &[]).await;
    assert_eq!(status, 200, "{html}");
    html.split("<main id=\"content\"")
        .nth(1)
        .unwrap()
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .into()
}
// Account-factor acceptance outcomes exercise the production router and guarded storage.
async fn account_security_start(name: &str) -> (Fixture, Browser, MfaOperator) {
    let (f, _, mut browser, op) = mfa_configured(name).await;
    contract_seed(&f).await;
    assert_eq!(
        contract_login(&mut browser, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    (f, browser, op)
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c49() {
    let (_, mut b, _op) = account_security_start("mfac49").await;
    let (status, html, _) = b
        .request("GET", &format!("/realms/{REALM}/account/security"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("No second factor enrolled"));
    assert!(html.contains("Set up authenticator app"));
    assert!(html.contains("Add passkey or security key"));
    assert!(!html.contains("setup-key"));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c52() {
    let (f, mut b, _op) = account_security_start("mfac52").await;
    let path = format!("/realms/{REALM}/account/security");
    let csrf = b.token(&path).await;
    assert_eq!(
        b.request("POST", &format!("{path}/totp/start"), &[("csrf", &csrf)])
            .await
            .0,
        403
    );
    let reauth = format!("{path}/reauthenticate");
    let (status, _, _) = b
        .request(
            "POST",
            &reauth,
            &[
                ("csrf", &csrf),
                ("operation", "totp_enroll"),
                ("current_password", "wrong"),
            ],
        )
        .await;
    assert_eq!(status, 422);
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_mfa_flow").await,
        0
    );
    contract_clear_rates(&f).await;
    let (status, html, headers) = b
        .request(
            "POST",
            &reauth,
            &[
                ("csrf", &csrf),
                ("operation", "totp_enroll"),
                ("current_password", CONTRACT_PASSWORD),
            ],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("{path}/continue"));
    let csrf = account_flow_token(&mut b, &format!("{path}/continue")).await;
    assert_eq!(
        b.request("POST", &format!("{path}/totp/start"), &[("csrf", &csrf)])
            .await
            .0,
        303
    );
    let csrf = b.token(&format!("{path}/totp/setup")).await;
    assert_eq!(
        b.request(
            "POST",
            &format!("{path}/recovery-codes/regenerate"),
            &[("csrf", &csrf)]
        )
        .await
        .0,
        409
    );
    // An ordinary session plus a new password proof cannot mutate established factors.
    let (f, mut protected, _protected_op, secret) = account_protected("mfac52existing").await;
    let factor: String =
        sqlx::query_scalar("SELECT id::text FROM bloc.realm_user_factor WHERE revoked_at IS NULL")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let epoch: String =
        sqlx::query_scalar("SELECT factor_epoch::text FROM bloc.realm_user_mfa_state")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let generation: String = sqlx::query_scalar(
        "SELECT id::text FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    for (operation, mutation) in [
        (
            format!("totp_replace:{factor}"),
            format!("{path}/totp/start"),
        ),
        (
            "webauthn_enroll".into(),
            format!("{path}/webauthn/register/options"),
        ),
        (
            format!("factor_remove:{factor}"),
            format!("{path}/factors/{factor}/remove"),
        ),
        (
            "recovery_codes_regenerate".into(),
            format!("{path}/recovery-codes/regenerate"),
        ),
    ] {
        let csrf = protected.token(&path).await;
        let (status, html, headers) = protected
            .request(
                "POST",
                &format!("{path}/reauthenticate"),
                &[
                    ("csrf", &csrf),
                    ("operation", &operation),
                    ("current_password", CONTRACT_PASSWORD),
                ],
            )
            .await;
        assert_eq!(status, 303, "{html}");
        assert_eq!(headers["location"], format!("/realms/{REALM}/mfa"));
        let csrf = protected.token(&format!("/realms/{REALM}/mfa")).await;
        let mut fields = vec![("csrf", csrf.as_str())];
        if operation.starts_with("factor_remove:") {
            fields.extend([("epoch", epoch.as_str()), ("confirmed", "true")]);
        }
        if operation == "webauthn_enroll" {
            fields.push(("label", "Unproved factor"));
        }
        let (status, html, _) = protected.request("POST", &mutation, &fields).await;
        assert_eq!(status, 409, "{operation}: {html}");
    }
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    let unchanged: String = sqlx::query_scalar(
        "SELECT id::text FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(unchanged, generation);

    let csrf = account_begin_proof(&f, &mut protected, "recovery_codes_regenerate", &secret).await;
    let before = account_security_rows(&f).await;
    let (status, html, _) = protected
        .request("POST", &format!("{path}/totp/start"), &[("csrf", &csrf)])
        .await;
    assert_eq!(status, 409, "{html}");
    assert!(
        account_security_rows(&f).await == before,
        "wrong operation changed proof or security rows"
    );
    let (status, html, headers) = protected
        .request(
            "POST",
            &format!("{path}/recovery-codes/regenerate"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("{path}/recovery-codes"));
    assert_ne!(account_live_generation(&f).await, generation);

    account_expired_exact_proof("mfac52expired").await;
}
const ACCOUNT_FACTOR: &str = "99999999-1111-4111-8111-111111111111";
const ACCOUNT_SECOND_FACTOR: &str = "99999999-2222-4222-8222-222222222222";
async fn account_seed_factor(f: &Fixture, id: &str, label: &str) {
    sqlx::query("INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,'webauthn',$4)")
        .bind(id).bind(REALM).bind(USER).bind(label).execute(&f.admin).await.unwrap();
}
async fn account_seed_foreign_factor(f: &Fixture) {
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES('44444444-4444-4444-8444-444444444444',$1::text::uuid,'Foreign@example.test',clock_timestamp(),clock_timestamp())").bind(REALM).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label) VALUES($1::text::uuid,$2::text::uuid,'44444444-4444-4444-8444-444444444444','webauthn','Foreign factor')").bind(ACCOUNT_SECOND_FACTOR).bind(REALM).execute(&f.admin).await.unwrap();
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c50() {
    let (f, mut b, _op, secret) = account_protected("mfac50").await;
    // Give the two rendered fields distinct values even when enrollment and verification share a second.
    sqlx::query("UPDATE bloc.realm_user_factor SET label='Used authenticator',created_at='2020-01-02 03:04:05+00' WHERE kind='totp'")
        .execute(&f.admin)
        .await
        .unwrap();
    account_begin_password_proof(&mut b, "recovery_codes_regenerate").await;
    account_complete_totp_proof(&f, &mut b, &secret).await;
    let (created, used, matches_proof): (String, String, bool) = sqlx::query_as(
        "SELECT to_char(f.created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS'),to_char(f.last_used_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS'),f.last_used_at=q.proof_verified_at FROM bloc.realm_user_factor f JOIN bloc.realm_mfa_flow q ON q.factor_id=f.id WHERE f.kind='totp' AND q.purpose='reauthenticate'",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert!(matches_proof);
    assert_eq!(created, "2020-01-02 03:04:05");
    assert_ne!(used, created);
    account_seed_factor(&f, ACCOUNT_FACTOR, "Personal laptop").await;
    account_seed_foreign_factor(&f).await;
    sqlx::query("UPDATE bloc.realm_user_mfa_state SET preferred_factor_id=$1::text::uuid WHERE realm_id=$2::text::uuid AND user_id=$3::text::uuid")
        .bind(ACCOUNT_FACTOR)
        .bind(REALM)
        .bind(USER)
        .execute(&f.admin)
        .await
        .unwrap();
    let (status, html, _) = b
        .request("GET", &format!("/realms/{REALM}/account/security"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    for expected in [
        "Personal laptop",
        "Passkey",
        "Created",
        "Last successful use",
        "Never used",
        "preferred",
    ] {
        assert!(html.contains(expected), "missing {expected}: {html}");
    }
    let row = html
        .split("<tr>")
        .find(|row| row.starts_with("<td>Used authenticator<br>"))
        .unwrap();
    assert!(row.contains("Authenticator app"));
    assert!(row.contains(&format!("<td>{created}<br>{used}</td>")));
    let passkey_row = html
        .split("<tr>")
        .find(|row| row.starts_with("<td>Personal laptop<br>"))
        .unwrap();
    assert!(passkey_row.contains("Passkey or security key · preferred"));
    assert!(passkey_row.contains("<br>Never used</td>"));
    assert!(!html.contains("Foreign factor"));
    assert!(!html.contains(ACCOUNT_SECOND_FACTOR));
    assert!(!html.contains("public_credential"));
    assert!(!html.contains("setup-key"));
    assert!(!html.contains(&secret));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c57() {
    let (f, mut b, _op) = account_security_start("mfac57").await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='disabled'")
        .execute(&f.admin)
        .await
        .unwrap();
    account_seed_factor(&f, ACCOUNT_FACTOR, "Old name").await;
    let before: (i64, i64) = sqlx::query_as("SELECT factor_epoch,(SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL) FROM bloc.realm_user_mfa_state").fetch_one(&f.admin).await.unwrap();
    let path = format!("/realms/{REALM}/account/security");
    let csrf = b.token(&path).await;
    let edit = format!("{path}/factors/{ACCOUNT_FACTOR}/label");
    let (status, html, _) = b
        .request(
            "POST",
            &edit,
            &[
                ("csrf", &csrf),
                ("epoch", "1"),
                ("label", "Personal laptop"),
            ],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(
        b.request(
            "POST",
            &format!("{path}/preferred"),
            &[("csrf", &csrf), ("epoch", "1"), ("factor", ACCOUNT_FACTOR)]
        )
        .await
        .0,
        303
    );
    let after: (i64, i64, String, String) = sqlx::query_as("SELECT factor_epoch,(SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL),preferred_factor_id::text,(SELECT label FROM bloc.realm_user_factor WHERE id=$1::text::uuid) FROM bloc.realm_user_mfa_state").bind(ACCOUNT_FACTOR).fetch_one(&f.admin).await.unwrap();
    assert_eq!((after.0, after.1), before);
    assert_eq!(after.2, ACCOUNT_FACTOR);
    assert_eq!(after.3, "Personal laptop");
    assert_eq!(
        b.request(
            "POST",
            &edit,
            &[("csrf", "invalid"), ("epoch", "1"), ("label", "Bad")]
        )
        .await
        .0,
        403
    );
    for label in ["", "\n", &"x".repeat(65)] {
        assert_eq!(
            b.request(
                "POST",
                &edit,
                &[("csrf", &csrf), ("epoch", "1"), ("label", label)]
            )
            .await
            .0,
            422
        );
    }
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c58() {
    let (f, mut b, _op) = account_security_start("mfac58").await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='disabled'")
        .execute(&f.admin)
        .await
        .unwrap();
    account_seed_factor(&f, ACCOUNT_FACTOR, "Unchanged").await;
    account_seed_foreign_factor(&f).await;
    let foreign_row = "SELECT label,xmin::text,revoked_at::text FROM bloc.realm_user_factor WHERE id=$1::text::uuid";
    let foreign_before: (String, String, Option<String>) = sqlx::query_as(foreign_row)
        .bind(ACCOUNT_SECOND_FACTOR)
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(foreign_before.0, "Foreign factor");
    assert!(foreign_before.2.is_none());
    let path = format!("/realms/{REALM}/account/security");
    let csrf = b.token(&path).await;
    for (id, epoch, expected) in [
        (ACCOUNT_FACTOR, "2", 409),
        (ACCOUNT_SECOND_FACTOR, "1", 404),
    ] {
        let (status, html, _) = b
            .request(
                "POST",
                &format!("{path}/factors/{id}/label"),
                &[("csrf", &csrf), ("epoch", epoch), ("label", "Changed")],
            )
            .await;
        assert_eq!(status, expected, "{html}");
    }
    let label: String =
        sqlx::query_scalar("SELECT label FROM bloc.realm_user_factor WHERE id=$1::text::uuid")
            .bind(ACCOUNT_FACTOR)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(label, "Unchanged");
    let foreign_after: (String, String, Option<String>) = sqlx::query_as(foreign_row)
        .bind(ACCOUNT_SECOND_FACTOR)
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(foreign_after, foreign_before);
}
async fn account_protected(name: &str) -> (Fixture, Browser, MfaOperator, String) {
    let (f, mut b, op, csrf, code) = mfa_pending_setup(name).await;
    let (status, html, _) = b
        .request(
            "GET",
            &format!("/realms/{REALM}/account/security/totp/setup"),
            &[],
        )
        .await;
    assert_eq!(status, 200);
    let secret = html
        .split("id=\"setup-key\"")
        .nth(1)
        .unwrap()
        .split('>')
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap()
        .to_owned();
    let (status, html, _) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/account/security/totp/confirm"),
            &[("csrf", &csrf), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    let path = format!("/realms/{REALM}/account/security/recovery-codes");
    let csrf = b.token(&path).await;
    assert_eq!(
        b.request(
            "POST",
            &format!("{path}/acknowledge"),
            &[("csrf", &csrf), ("saved", "true")]
        )
        .await
        .0,
        303
    );
    (f, b, op, secret)
}
async fn account_begin_password_proof(b: &mut Browser, operation: &str) {
    let path = format!("/realms/{REALM}/account/security");
    let csrf = b.token(&path).await;
    let (status, html, headers) = b
        .request(
            "POST",
            &format!("{path}/reauthenticate"),
            &[
                ("csrf", &csrf),
                ("operation", operation),
                ("current_password", CONTRACT_PASSWORD),
            ],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/mfa"));
}
async fn account_complete_totp_proof(f: &Fixture, b: &mut Browser, secret: &str) {
    let path = format!("/realms/{REALM}/account/security");
    let csrf = b.token(&format!("/realms/{REALM}/mfa")).await;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let code = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(secret).unwrap())
        .build()
        .unwrap()
        .generate((now + 30) as u64)
        .to_string();
    let (status, html, headers) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("{path}/continue"));
}
async fn account_begin_proof(
    f: &Fixture,
    b: &mut Browser,
    operation: &str,
    secret: &str,
) -> String {
    account_begin_password_proof(b, operation).await;
    account_complete_totp_proof(f, b, secret).await;
    let path = format!("/realms/{REALM}/account/security");
    account_flow_token(
        b,
        &format!(
            "{path}/{}",
            if operation.starts_with("webauthn_") {
                "webauthn/setup"
            } else {
                "continue"
            }
        ),
    )
    .await
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c51() {
    let (f, mut b, _op, _secret) = account_protected("mfac51").await;
    account_seed_factor(&f, ACCOUNT_SECOND_FACTOR, "Unavailable passkey").await;
    sqlx::query("UPDATE bloc.realm_user_mfa_state SET preferred_factor_id=$1::text::uuid")
        .bind(ACCOUNT_SECOND_FACTOR)
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_allowed_methods=ARRAY['totp'],mfa_preferred_method='totp'").execute(&f.admin).await.unwrap();
    let (status, html, _) = b
        .request("GET", &format!("/realms/{REALM}/account/security"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("unavailable under current policy"));
    assert!(html.contains("Replace"));
    assert!(!html.contains(&format!(
        "operation=webauthn_replace:{ACCOUNT_SECOND_FACTOR}"
    )));
    assert!(!html.contains("operation=webauthn_enroll"));
    let mut login = Browser {
        app: b.app.clone(),
        cookies: BTreeMap::new(),
    };
    assert_eq!(
        contract_login(&mut login, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let (status, html, _) = login
        .request("GET", &format!("/realms/{REALM}/mfa"), &[])
        .await;
    assert_eq!(status, 200);
    assert!(html.contains("Authentication code"));
    assert!(!html.contains(&format!("/realms/{REALM}/mfa/webauthn")));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c53() {
    let (f, mut b, _op, secret) = account_protected("mfac53").await;
    account_seed_factor(&f, ACCOUNT_SECOND_FACTOR, "Spare passkey").await;
    let current = b.cookies[&format!("__Host-bloc-realm-{REALM}")].clone();
    sqlx::query("INSERT INTO bloc.realm_user_session(realm_id,user_id,session_digest,credential_version,created_at,last_activity_at,expires_at,device_label,factor_epoch,password_verified_at,mfa_method,mfa_factor_id,mfa_verified_at) SELECT realm_id,user_id,$1,credential_version,created_at,last_activity_at,expires_at,'Other device',factor_epoch,password_verified_at,mfa_method,mfa_factor_id,mfa_verified_at FROM bloc.realm_user_session WHERE revoked_at IS NULL").bind(vec![66u8;32]).execute(&f.admin).await.unwrap();
    let epoch: String =
        sqlx::query_scalar("SELECT factor_epoch::text FROM bloc.realm_user_mfa_state")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let totp_factor: String =
        sqlx::query_scalar("SELECT id::text FROM bloc.realm_user_factor WHERE kind='totp'")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let operation = format!("factor_remove:{totp_factor}");
    let csrf = account_begin_proof(&f, &mut b, &operation, &secret).await;
    let (status, html, _) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/account/security/factors/{totp_factor}/remove"),
            &[("csrf", &csrf), ("epoch", &epoch), ("confirmed", "true")],
        )
        .await;
    assert_eq!(status, 409, "{html}");
    assert!(html.contains("Verify with a factor you’re keeping"));
    assert!(html.contains(&format!("reauthenticate?operation={operation}")));
    assert_eq!(b.cookies[&format!("__Host-bloc-realm-{REALM}")], current);
    let unchanged: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL),(SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL),(SELECT factor_epoch FROM bloc.realm_user_mfa_state)")
        .fetch_one(&f.admin).await.unwrap();
    assert_eq!(unchanged, (2, 2, epoch.parse::<i64>().unwrap()));
    account_begin_password_proof(&mut b, &operation).await;
    // Seed the passkey verification result to isolate removal from the WebAuthn ceremony.
    let bearer = &b.cookies[&format!("__Host-bloc-realm-mfa-{REALM}")];
    sqlx::query("UPDATE bloc.realm_mfa_flow SET proof_verified_at=clock_timestamp(),verified_method='webauthn',factor_id=$1::text::uuid WHERE bearer_digest=$2")
        .bind(ACCOUNT_SECOND_FACTOR).bind(sec::digest(bearer).as_slice()).execute(&f.admin).await.unwrap();
    let csrf = account_flow_token(&mut b, &format!("/realms/{REALM}/account/security/continue")).await;
    let path = format!("/realms/{REALM}/account/security/factors/{totp_factor}/remove");
    let (status, html, headers) = b
        .request(
            "POST",
            &path,
            &[("csrf", &csrf), ("epoch", &epoch), ("confirmed", "true")],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(
        headers["location"],
        format!("/realms/{REALM}/account/security")
    );
    assert_ne!(b.cookies[&format!("__Host-bloc-realm-{REALM}")], current);
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL),(SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL),(SELECT factor_epoch FROM bloc.realm_user_mfa_state)").fetch_one(&f.admin).await.unwrap();
    assert_eq!(counts, (1, 1, epoch.parse::<i64>().unwrap() + 1));
    let session_factor: String = sqlx::query_scalar(
        "SELECT mfa_factor_id::text FROM bloc.realm_user_session WHERE revoked_at IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(session_factor, ACCOUNT_SECOND_FACTOR);
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/security"), &[])
            .await
            .0,
        200
    );
    assert_ne!(
        b.request(
            "POST",
            &path,
            &[("csrf", &csrf), ("epoch", &epoch), ("confirmed", "true")]
        )
        .await
        .0,
        303
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c54() {
    let (f, mut b, _op, secret) = account_protected("mfac54").await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='optional'")
        .execute(&f.admin)
        .await
        .unwrap();
    let factor: String =
        sqlx::query_scalar("SELECT id::text FROM bloc.realm_user_factor WHERE revoked_at IS NULL")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let csrf = account_begin_proof(&f, &mut b, &format!("factor_remove:{factor}"), &secret).await;
    let epoch: String =
        sqlx::query_scalar("SELECT factor_epoch::text FROM bloc.realm_user_mfa_state")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let path = format!("/realms/{REALM}/account/security/factors/{factor}/remove");
    assert_eq!(
        b.request("POST", &path, &[("csrf", &csrf), ("epoch", &epoch)])
            .await
            .0,
        409
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    let (status, html, _) = b
        .request(
            "POST",
            &path,
            &[("csrf", &csrf), ("epoch", &epoch), ("confirmed", "true")],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL"
        )
        .await,
        0
    );
    let evidence:(bool,bool,bool)=sqlx::query_as("SELECT mfa_method IS NULL,mfa_factor_id IS NULL,mfa_verified_at IS NULL FROM bloc.realm_user_session WHERE revoked_at IS NULL").fetch_one(&f.admin).await.unwrap();
    assert_eq!(evidence, (true, true, true));
    let (status, html, _) = b
        .request("GET", &format!("/realms/{REALM}/account/security"), &[])
        .await;
    assert_eq!(status, 200);
    assert!(html.contains("password-only protection"));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c55() {
    let (f, mut b, _op, secret) = account_protected("mfac55").await;
    let factor: String =
        sqlx::query_scalar("SELECT id::text FROM bloc.realm_user_factor WHERE revoked_at IS NULL")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let csrf = account_begin_proof(&f, &mut b, &format!("factor_remove:{factor}"), &secret).await;
    let epoch: String =
        sqlx::query_scalar("SELECT factor_epoch::text FROM bloc.realm_user_mfa_state")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let (status, html, _) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/account/security/factors/{factor}/remove"),
            &[("csrf", &csrf), ("epoch", &epoch), ("confirmed", "true")],
        )
        .await;
    assert_eq!(status, 409, "{html}");
    assert!(html.contains("Confirm a replacement first"));
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c56() {
    let (f, mut b, _op) = account_security_start("mfac56").await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='disabled'")
        .execute(&f.admin)
        .await
        .unwrap();
    account_seed_factor(&f, ACCOUNT_FACTOR, "Retained passkey").await;
    let path = format!("/realms/{REALM}/account/security");
    let (status, html, _) = b.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    assert!(html.contains("Existing factors are retained but do not protect sign-in"));
    assert!(!html.contains("operation=webauthn_enroll"));
    assert!(!html.contains("operation=recovery_codes_regenerate"));
    account_disabled_mutations(&f, &mut b, false).await;
    let csrf = b.token(&path).await;
    let (status, html, _) = b
        .request(
            "POST",
            &format!("{path}/reauthenticate"),
            &[
                ("csrf", &csrf),
                ("operation", &format!("factor_remove:{ACCOUNT_FACTOR}")),
                ("current_password", CONTRACT_PASSWORD),
            ],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    let csrf = account_flow_token(&mut b, &format!("{path}/continue")).await;
    let (status, html, _) = b
        .request(
            "POST",
            &format!("{path}/factors/{ACCOUNT_FACTOR}/remove"),
            &[("csrf", &csrf), ("epoch", "1"), ("confirmed", "true")],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        0
    );
    assert_eq!(b.request("GET", &path, &[]).await.0, 200);
}

async fn account_browser_proof() {
    let (f, _admin, _public, op) = mfa_configured("mfaaccountbrowser").await;
    contract_seed(&f).await;
    let directory = op.dir.join("services");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("runtime"), f.url("runtime_user")).unwrap();
    std::fs::write(directory.join("operator"), f.url("operator_user")).unwrap();
    std::fs::write(directory.join("abuse"), [7; 32]).unwrap();
    let mut services = Services {
        children: vec![],
        directory,
    };
    for port in [31001, 31002] {
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_bloc"))
            .env("BLOC_DATABASE_URL_FILE", services.directory.join("runtime"))
            .env("BLOC_DATABASE_CA_FILE", &f.ca)
            .env("BLOC_ABUSE_KEY_FILE", services.directory.join("abuse"))
            .env("BLOC_MFA_KEYRING_FILE", op.dir.join("keys"))
            .env("BLOC_CANONICAL_ORIGIN", "https://bloc.example.test:4443")
            .env("BLOC_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
            .env("BLOC_BIND_ADDR", format!("127.0.0.1:{port}"))
            .stdout(
                std::fs::File::create(services.directory.join(format!("service-{port}.stdout")))
                    .unwrap(),
            )
            .stderr(
                std::fs::File::create(services.directory.join(format!("service-{port}.stderr")))
                    .unwrap(),
            )
            .spawn()
            .unwrap();
        services.children.push(child);
    }
    for port in [31001, 31002] {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    let mut command = std::process::Command::new(
        std::env::var("BLOC_BROWSER_PYTHON").expect("real browser required"),
    );
    command
        .arg("tests/support/realm_mfa_account_browser.py")
        .env("BLOC_TEST_ORIGIN", "https://bloc.example.test:4443")
        .env(
            "BLOC_DATABASE_URL_FILE",
            services.directory.join("operator"),
        )
        .env(
            "BLOC_TEST_SPKI",
            std::env::var("BLOC_TEST_SPKI").expect("synthetic TLS pin required"),
        )
        .env("BLOC_REALM_SERVICE_LOGS", &services.directory);
    let output = tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}

#[tokio::test]
#[ignore = "real TLS browser"]
async fn realm_mfa_account_browser() {
    account_browser_proof().await;
}

async fn account_pending_handoff(name: &str) -> (Fixture, Browser, MfaOperator, String) {
    let (f, mut b, op, csrf, code) = mfa_pending_setup(name).await;
    let (_, html, _) = b
        .request(
            "GET",
            &format!("/realms/{REALM}/account/security/totp/setup"),
            &[],
        )
        .await;
    let secret = totp_manual_key(&html);
    let (status, html, headers) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/account/security/totp/confirm"),
            &[("csrf", &csrf), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(
        headers["location"],
        format!("/realms/{REALM}/account/security/recovery-codes")
    );
    (f, b, op, secret)
}
fn account_handoff_codes(html: &str) -> Vec<String> {
    let codes: Vec<String> = html
        .split("id=\"recovery-codes\"")
        .nth(1)
        .unwrap()
        .split('>')
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(codes.len(), 10);
    let distinct: std::collections::BTreeSet<_> = codes.iter().collect();
    assert_eq!(distinct.len(), 10);
    for code in &codes {
        assert_eq!(code.len(), 26);
        assert!(
            code.bytes()
                .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
        );
    }
    codes
}
async fn account_live_generation(f: &Fixture) -> String {
    sqlx::query_scalar(
        "SELECT id::text FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap()
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c36() {
    let (f, mut b, op, secret) = account_pending_handoff("mfac36").await;
    let path = format!("/realms/{REALM}/account/security/recovery-codes");
    let (status, body, _) = b.request("HEAD", &path, &[]).await;
    assert_eq!(status, 200);
    assert!(body.is_empty());
    let (status, html, headers) = b.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    let codes = account_handoff_codes(&html);
    assert!(
        html.contains("Copy codes")
            && html.contains("Download codes")
            && html.contains("I saved my recovery codes.")
    );
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        b.request("POST", &format!("{path}/acknowledge"), &[("csrf", &csrf)])
            .await
            .0,
        422
    );
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
    assert!(
        !b.cookies
            .contains_key(&format!("__Host-bloc-realm-{REALM}"))
    );
    let generation = account_live_generation(&f).await;
    sqlx::query("UPDATE bloc.realm_mfa_flow SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute'").execute(&f.admin).await.unwrap();
    let mut resumed = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    assert_eq!(
        contract_login(&mut resumed, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let csrf = resumed.token(&format!("/realms/{REALM}/mfa")).await;
    let code = totp_code_for_secret(&f, &secret, true).await;
    let (status, html, headers) = resumed
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], path);
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
    assert_ne!(account_live_generation(&f).await, generation);
    let (status, html, _) = resumed.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    let replacement = account_handoff_codes(&html);
    assert!(replacement.iter().all(|code| !codes.contains(code)));
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let (status, html, _) = resumed
        .request(
            "POST",
            &format!("{path}/acknowledge"),
            &[("csrf", &csrf), ("saved", "true")],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL AND acknowledged_at IS NOT NULL").await,1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c37() {
    let (f, mut b, op, _secret) = account_pending_handoff("mfac37").await;
    let path = format!("/realms/{REALM}/account/security/recovery-codes");
    let (status, html, _) = b.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    let codes = account_handoff_codes(&html);
    let old = account_live_generation(&f).await;
    let mut stale = policy_flow_replica(&f, &op, b.cookies.clone()).await;
    let (status, html, _) = b.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    assert!(html.contains("Replace unsaved codes"));
    assert!(codes.iter().all(|code| !html.contains(code)));
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.mfa_encrypted_payload WHERE purpose=3"
        )
        .await,
        0
    );
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let (status, html, headers) = b
        .request("POST", &format!("{path}/replace"), &[("csrf", &csrf)])
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], path);
    assert_ne!(account_live_generation(&f).await, old);
    let active_old:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.realm_mfa_recovery_code c JOIN bloc.realm_mfa_recovery_generation g ON g.id=c.generation_id WHERE g.id=$1::text::uuid AND g.invalidated_at IS NULL").bind(&old).fetch_one(&f.admin).await.unwrap();
    assert_eq!(active_old, 0);
    assert_eq!(
        stale
            .request("POST", &format!("{path}/replace"), &[("csrf", &csrf)])
            .await
            .0,
        409
    );
    let (status, html, _) = b.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    let replacement = account_handoff_codes(&html);
    assert!(replacement.iter().all(|code| !codes.contains(code)));
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        b.request(
            "POST",
            &format!("{path}/acknowledge"),
            &[("csrf", &csrf), ("saved", "true")]
        )
        .await
        .0,
        303
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c38() {
    let (f, mut b, _op, secret) = account_protected("mfac38").await;
    let old = account_live_generation(&f).await;
    let before: i64 = sqlx::query_scalar("SELECT factor_epoch FROM bloc.realm_user_mfa_state")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    let csrf = account_begin_proof(&f, &mut b, "recovery_codes_regenerate", &secret).await;
    let path = format!("/realms/{REALM}/account/security/recovery-codes");
    sqlx::raw_sql("CREATE FUNCTION bloc.test_code_atomicity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic code audit failure'; END $$; CREATE TRIGGER test_code_atomicity BEFORE INSERT ON bloc.security_audit_event FOR EACH ROW WHEN (NEW.action='realm_mfa_code_issue') EXECUTE FUNCTION bloc.test_code_atomicity();").execute(&f.admin).await.unwrap();
    assert_eq!(
        b.request("POST", &format!("{path}/regenerate"), &[("csrf", &csrf)])
            .await
            .0,
        503
    );
    assert_eq!(account_live_generation(&f).await, old);
    let unchanged: i64 = sqlx::query_scalar("SELECT factor_epoch FROM bloc.realm_user_mfa_state")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(unchanged, before);
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    sqlx::query("DROP TRIGGER test_code_atomicity ON bloc.security_audit_event")
        .execute(&f.admin)
        .await
        .unwrap();
    let (status, html, headers) = b
        .request("POST", &format!("{path}/regenerate"), &[("csrf", &csrf)])
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], path);
    assert_ne!(account_live_generation(&f).await, old);
    let epoch: i64 = sqlx::query_scalar("SELECT factor_epoch FROM bloc.realm_user_mfa_state")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(epoch, before + 1);
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        0
    );
    let active_old:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.realm_mfa_recovery_generation WHERE id=$1::text::uuid AND invalidated_at IS NULL").bind(&old).fetch_one(&f.admin).await.unwrap();
    assert_eq!(active_old, 0);
    let (status, html, _) = b.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    account_handoff_codes(&html);
    let (status, lost, _) = b.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    assert!(lost.contains("Replace unsaved codes"));
    let csrf = lost
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        b.request("POST", &format!("{path}/replace"), &[("csrf", &csrf)])
            .await
            .0,
        303
    );
    let (status, html, _) = b.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    account_handoff_codes(&html);
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        b.request(
            "POST",
            &format!("{path}/acknowledge"),
            &[("csrf", &csrf), ("saved", "true")]
        )
        .await
        .0,
        303
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
}

async fn account_security_rows(f: &Fixture) -> String {
    sqlx::query_scalar("SELECT jsonb_build_object(
        'factors', (SELECT jsonb_agg(f ORDER BY id) FROM bloc.realm_user_factor f),
        'totp', (SELECT jsonb_agg(t ORDER BY factor_id) FROM bloc.realm_totp_factor t),
        'state', (SELECT jsonb_agg(s ORDER BY realm_id,user_id) FROM bloc.realm_user_mfa_state s),
        'payloads', (SELECT jsonb_agg(p ORDER BY id) FROM bloc.mfa_encrypted_payload p),
        'flows', (SELECT jsonb_agg(f ORDER BY id) FROM bloc.realm_mfa_flow f),
        'generations', (SELECT jsonb_agg(g ORDER BY id) FROM bloc.realm_mfa_recovery_generation g),
        'codes', (SELECT jsonb_agg(c ORDER BY generation_id,ordinal) FROM bloc.realm_mfa_recovery_code c)
    )::text")
        .fetch_one(&f.admin)
        .await
        .unwrap()
}

async fn account_disabled_mutations(f: &Fixture, b: &mut Browser, has_totp: bool) {
    let path = format!("/realms/{REALM}/account/security");
    let csrf = b.token(&path).await;
    let before = account_security_rows(f).await;
    let mut operations = vec!["webauthn_enroll", "recovery_codes_regenerate"];
    if !has_totp {
        operations.push("totp_enroll");
    }
    for operation in operations {
        let (status, html, _) = b
            .request(
                "POST",
                &format!("{path}/reauthenticate"),
                &[
                    ("csrf", &csrf),
                    ("operation", operation),
                    ("current_password", CONTRACT_PASSWORD),
                ],
            )
            .await;
        assert_eq!(status, 404, "{operation}: {html}");
        assert!(
            html.contains("This security action is unavailable."),
            "{html}"
        );
        assert!(
            account_security_rows(f).await == before,
            "{operation} changed security rows under disabled policy"
        );
    }
    assert!(
        !b.cookies
            .contains_key(&format!("__Host-bloc-realm-mfa-{REALM}"))
    );
}

async fn account_expired_exact_proof(name: &str) {
    let (f, mut b, _op, secret) = account_protected(name).await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_flow_ttl_seconds=600 WHERE realm_id=$1::text::uuid")
        .bind(REALM)
        .execute(&f.admin)
        .await
        .unwrap();
    let operation = "recovery_codes_regenerate";
    account_begin_password_proof(&mut b, operation).await;
    let cookie = format!("__Host-bloc-realm-mfa-{REALM}");
    let bearer = b.cookies[&cookie].clone();
    let digest = sec::digest(&bearer).to_vec();
    let times = "SELECT id::text,created_at::text,expires_at::text,
        expires_at=created_at+interval '300 seconds' AND password_verified_at=created_at,
        proof_verified_at IS NOT NULL FROM bloc.realm_mfa_flow
        WHERE bearer_digest=$1 AND realm_id=$2::text::uuid AND user_id=$3::text::uuid
        AND purpose='reauthenticate' AND operation=$4 AND consumed_at IS NULL";
    let before: (String, String, String, bool, bool) = sqlx::query_as(sqlx::AssertSqlSafe(times))
        .bind(&digest)
        .bind(REALM)
        .bind(USER)
        .bind(operation)
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert!(
        before.3,
        "password reauthentication did not persist an exact 300-second deadline"
    );
    assert!(!before.4);
    account_complete_totp_proof(&f, &mut b, &secret).await;
    let after: (String, String, String, bool, bool) = sqlx::query_as(sqlx::AssertSqlSafe(times))
        .bind(&digest)
        .bind(REALM)
        .bind(USER)
        .bind(operation)
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        (&after.0, &after.1, &after.2, after.3, after.4),
        (&before.0, &before.1, &before.2, true, true)
    );
    let path = format!("/realms/{REALM}/account/security");
    let csrf = account_flow_token(&mut b, &format!("{path}/continue")).await;
    assert_eq!(b.cookies[&cookie], bearer);

    // Move this fixture proof to 100 ms beyond its actual deadline. Translate its
    // times together so its 300-second lifetime and proof offset remain intact.
    // The browser/token, TOTP replay floor, and admission history stay as issued.
    let expired: bool = sqlx::query_scalar("WITH boundary AS (
        SELECT id,expires_at-statement_timestamp()+interval '100 milliseconds' AS shift
        FROM bloc.realm_mfa_flow WHERE bearer_digest=$1
    ) UPDATE bloc.realm_mfa_flow f SET created_at=f.created_at-boundary.shift,
      expires_at=f.expires_at-boundary.shift,password_verified_at=f.password_verified_at-boundary.shift,
      proof_verified_at=f.proof_verified_at-boundary.shift
      FROM boundary WHERE f.id=boundary.id
      RETURNING f.expires_at=statement_timestamp()-interval '100 milliseconds'
        AND f.expires_at=f.created_at+interval '300 seconds'")
        .bind(&digest).fetch_one(&f.admin).await.unwrap();
    assert!(expired);
    let unchanged = account_security_rows(&f).await;
    let (status, html, _) = b
        .request(
            "POST",
            &format!("{path}/recovery-codes/regenerate"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(status, 409, "{html}");
    assert!(
        account_security_rows(&f).await == unchanged,
        "expired proof changed security rows"
    );
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
}
