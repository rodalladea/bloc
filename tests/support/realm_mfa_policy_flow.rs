fn policy_flow_fields<'a>(
    csrf: &'a str,
    version: &'a str,
    mode: &'a str,
    methods: &[&str],
) -> Vec<(&'a str, &'a str)> {
    let mut fields = contract_settings(csrf, version);
    fields.extend([
        ("registration_enabled", "true"),
        ("mfa_mode", mode),
        ("mfa_recovery_codes_enabled", "true"),
        ("mfa_admin_recovery_enabled", "true"),
        ("mfa_flow_ttl_seconds", "300"),
        ("mfa_admin_recovery_ttl_seconds", "1800"),
    ]);
    for method in methods {
        fields.push((
            if *method == "totp" {
                "mfa_totp_allowed"
            } else {
                "mfa_webauthn_allowed"
            },
            "true",
        ));
    }
    fields
}
async fn policy_flow_no_success(f: &Fixture) {
    let (sessions, audits): (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM bloc.realm_user_session),(SELECT count(*) FROM bloc.security_audit_event WHERE action IN('realm_sign_in','realm_mfa_sign_in'))")
        .fetch_one(&f.admin).await.unwrap();
    assert_eq!((sessions, audits), (0, 0));
}
async fn policy_flow_replica(
    f: &Fixture,
    op: &MfaOperator,
    cookies: BTreeMap<String, String>,
) -> Browser {
    let config = Config::new("https://bloc.example.test", "127.0.0.1/32", [7; 32])
        .unwrap()
        .with_mfa_keyring(&op.dir.join("keys"))
        .unwrap();
    Browser {
        app: router(
            Application::new(
                bloc::storage::Storage::connect(&f.url("runtime_user"), &f.ca)
                    .await
                    .unwrap(),
                config,
            )
            .await
            .unwrap(),
        ),
        cookies,
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c01() {
    let (f, mut admin, mut public, _op) = mfa_configured("mfac01").await;
    create_realm(&mut admin, OTHER, "Other realm").await;
    type PolicyDefaults = (String, Vec<String>, Option<String>, bool, bool, i32, i32);
    let rows: Vec<PolicyDefaults> = sqlx::query_as("SELECT mfa_mode,mfa_allowed_methods,mfa_preferred_method,mfa_recovery_codes_enabled,mfa_admin_recovery_enabled,mfa_flow_ttl_seconds,mfa_admin_recovery_ttl_seconds FROM bloc.realm_authentication_settings ORDER BY realm_id")
        .fetch_all(&f.admin).await.unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(
            row,
            (
                "optional".into(),
                vec!["totp".into(), "webauthn".into()],
                Some("webauthn".into()),
                true,
                true,
                300,
                1800
            )
        );
    }
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_factor").await,
        0
    );
    contract_seed(&f).await;
    let (status, html, headers) =
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/account"));
    let epoch: i64 = sqlx::query_scalar("SELECT factor_epoch FROM bloc.realm_user_mfa_state")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(epoch, 1);
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c02() {
    let (f, mut admin, mut public, _op) = mfa_configured("mfac02").await;
    contract_seed(&f).await;
    mfa_secret_fixture(&f).await;
    let (status, html, _) = mfa_policy_post(
        &mut admin,
        "disabled",
        &["totp", "webauthn"],
        true,
        CONTRACT_PASSWORD,
    )
    .await;
    assert_eq!(status, 303, "{html}");
    let (status, html, headers) =
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/account"));
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    let (status, html, _) = public
        .request("GET", &format!("/realms/{REALM}/account/security"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("Protection suspended"), "{html}");
    assert!(!html.contains("value=\"totp_enroll\""));
    assert!(!html.contains("value=\"webauthn_enroll\""));
    let evidence: (bool, bool) = sqlx::query_as("SELECT password_verified_at IS NOT NULL,mfa_method IS NULL AND mfa_factor_id IS NULL AND mfa_verified_at IS NULL FROM bloc.realm_user_session").fetch_one(&f.admin).await.unwrap();
    assert_eq!(evidence, (true, true));
    account_disabled_mutations(&f, &mut public, true).await;
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c03() {
    let (f, _admin, mut public, _op) = mfa_configured("mfac03").await;
    contract_seed(&f).await;
    assert_eq!(
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let (status, html, _) = public
        .request("GET", &format!("/realms/{REALM}/account/security"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(html.to_lowercase().contains("password-only"), "{html}");
    assert!(html.to_lowercase().contains("authenticator"), "{html}");
    assert!(html.to_lowercase().contains("passkey"), "{html}");
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_factor").await,
        0
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c04_disallowed() {
    let (f, mut admin, mut public, _op) = mfa_configured("mfac04disallowed").await;
    contract_seed(&f).await;
    mfa_secret_fixture(&f).await;
    assert_eq!(
        mfa_policy_post(
            &mut admin,
            "optional",
            &["webauthn"],
            true,
            CONTRACT_PASSWORD
        )
        .await
        .0,
        303
    );
    let (status, html, headers) =
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/mfa"));
    let csrf = public.token(&format!("/realms/{REALM}/mfa")).await;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let code = totp_rs::Builder::new()
        .with_secret([9u8; 20])
        .build()
        .unwrap()
        .generate(now as u64)
        .to_string();
    let (status, html, _) = public
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 422, "{html}");
    policy_flow_no_success(&f).await;
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
async fn realm_mfa_c05() {
    let (f, _admin, mut public, _op) = mfa_configured("mfac05").await;
    contract_seed(&f).await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='required'")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let (status, html, _) = public
        .request("GET", &format!("/realms/{REALM}/mfa"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("Set up two-factor authentication"), "{html}");
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let (status, _, headers) = public
        .request("GET", &format!("/realms/{REALM}/account"), &[])
        .await;
    assert_eq!(status, 303);
    assert!(headers["location"].to_str().unwrap().contains("/login"));
    let (status, _, _) = public
        .request(
            "POST",
            &format!("/realms/{REALM}/account/profile"),
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("display_name", "Forbidden change"),
            ],
        )
        .await;
    assert_eq!(status, 403);
    let display: String = sqlx::query_scalar("SELECT display_name FROM bloc.realm_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(display, "Alice");
    policy_flow_no_success(&f).await;
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c06() {
    let (f, _admin, mut public, _op) = mfa_configured("mfac06").await;
    contract_seed(&f).await;
    mfa_secret_fixture(&f).await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='required',mfa_allowed_methods=ARRAY['webauthn'],mfa_preferred_method='webauthn'").execute(&f.admin).await.unwrap();
    assert_eq!(
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let purpose: String =
        sqlx::query_scalar("SELECT purpose FROM bloc.realm_mfa_flow WHERE parent_id IS NULL")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(purpose, "login");
    let (status, html, _) = public
        .request("GET", &format!("/realms/{REALM}/mfa"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(!html.contains("Set up two-factor authentication"));
    assert!(
        html.to_lowercase().contains("recovery") || html.to_lowercase().contains("administrator"),
        "{html}"
    );
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let (status, _, _) = public
        .request(
            "POST",
            &format!("/realms/{REALM}/account/security/totp/start"),
            &[("csrf", &csrf)],
        )
        .await;
    assert!(
        status.is_client_error(),
        "enrolled owner must use recovery, got {status}"
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_mfa_flow WHERE purpose='totp_enrollment'"
        )
        .await,
        0
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    policy_flow_no_success(&f).await;
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c09() {
    let (f, mut admin, _, _op) = mfa_configured("mfac09").await;
    let path = format!("/admin/realms/{REALM}/authentication");
    let csrf = admin.token(&path).await;
    assert_eq!(
        mfa_policy_post(
            &mut admin,
            "required",
            &["totp", "webauthn"],
            true,
            CONTRACT_PASSWORD
        )
        .await
        .0,
        303
    );
    let fields = policy_flow_fields(&csrf, "1", "optional", &["totp", "webauthn"]);
    let (status, html, _) = admin.request("POST", &path, &fields).await;
    assert_eq!(status, 409, "{html}");
    let row: (String, i64) =
        sqlx::query_as("SELECT mfa_mode,version FROM bloc.realm_authentication_settings")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(row, ("required".into(), 2));
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c10() {
    let (f, mut admin, mut public, _op) = mfa_configured("mfac10").await;
    contract_seed(&f).await;
    mfa_secret_fixture(&f).await;
    assert_eq!(
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let csrf = public.token(&format!("/realms/{REALM}/mfa")).await;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let code = totp_rs::Builder::new()
        .with_secret([9u8; 20])
        .build()
        .unwrap()
        .generate(now as u64)
        .to_string();
    assert_eq!(
        mfa_policy_post(&mut admin, "required", &["totp"], true, CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let (status, html, _) = public
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 409, "{html}");
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    policy_flow_no_success(&f).await;
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c11() {
    let (f, _admin, mut public, _op) = mfa_configured("mfac11").await;
    contract_seed(&f).await;
    let (status, html, headers) =
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/account"));
    let evidence: (bool, bool, i64) = sqlx::query_as("SELECT password_verified_at>=created_at AND password_verified_at<=clock_timestamp(),mfa_method IS NULL AND mfa_factor_id IS NULL AND mfa_verified_at IS NULL,factor_epoch FROM bloc.realm_user_session").fetch_one(&f.admin).await.unwrap();
    assert_eq!(evidence, (true, true, 1));
    assert!(
        public
            .cookies
            .contains_key(&format!("__Host-bloc-realm-{REALM}"))
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c13() {
    let (f, mut admin, mut public, op) = mfa_configured("mfac13").await;
    contract_seed(&f).await;
    assert_eq!(
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let csrf = public
        .token(&format!("/realms/{REALM}/account/profile"))
        .await;
    let mut post_browser = policy_flow_replica(&f, &op, public.cookies.clone()).await;
    assert_eq!(
        mfa_policy_post(&mut admin, "required", &["totp"], true, CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let (status, _, headers) = public
        .request("GET", &format!("/realms/{REALM}/account"), &[])
        .await;
    assert_eq!(status, 303);
    assert!(headers["location"].to_str().unwrap().contains("/login"));
    let (status, html, _) = post_browser
        .request(
            "POST",
            &format!("/realms/{REALM}/account/profile"),
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("display_name", "Forbidden change"),
            ],
        )
        .await;
    assert_eq!(status, 403, "{html}");
    assert!(html.to_lowercase().contains("sign in"), "{html}");
    let display: String = sqlx::query_scalar("SELECT display_name FROM bloc.realm_user")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(display, "Alice");
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c14() {
    let (f, mut public, _op, csrf, code) = mfa_challenge("mfac14").await;
    let deadline: String = sqlx::query_scalar(
        "SELECT expires_at::text FROM bloc.realm_mfa_flow WHERE parent_id IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let totp = totp_rs::Builder::new()
        .with_secret([9u8; 20])
        .build()
        .unwrap();
    let nearby: Vec<String> = [-60i64, -30, 0, 30, 60]
        .into_iter()
        .map(|offset| totp.generate((now + offset) as u64).to_string())
        .collect();
    let expired = (4..10)
        .map(|steps| totp.generate((now - steps * 30) as u64).to_string())
        .find(|candidate| !nearby.contains(candidate))
        .unwrap();
    for invalid in ["!!!!!!", expired.as_str()] {
        let (status, html, _) = public
            .request(
                "POST",
                &format!("/realms/{REALM}/mfa/verify"),
                &[("csrf", &csrf), ("method", "totp"), ("code", invalid)],
            )
            .await;
        assert_eq!(status, 422, "{html}");
    }
    sqlx::query("UPDATE bloc.realm_totp_factor SET last_accepted_step=floor(extract(epoch FROM clock_timestamp())/30)::bigint").execute(&f.admin).await.unwrap();
    let (status, html, _) = public
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 422, "{html}");
    let after: String = sqlx::query_scalar(
        "SELECT expires_at::text FROM bloc.realm_mfa_flow WHERE parent_id IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(after, deadline);
    policy_flow_no_success(&f).await;
    sqlx::query("UPDATE bloc.realm_mfa_flow SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute'").execute(&f.admin).await.unwrap();
    let (status, html, headers) = public
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert!(
        headers["location"]
            .to_str()
            .unwrap()
            .starts_with(&format!("/realms/{REALM}/login"))
    );
    policy_flow_no_success(&f).await;
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c15() {
    use base64::Engine;
    let (f, _admin, mut public, _op) = mfa_configured("mfac15").await;
    contract_seed(&f).await;
    mfa_secret_fixture(&f).await;
    let id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    // This public record is used only to exercise method options, never to claim a signed proof.
    let record = serde_json::to_vec(&serde_json::json!({"format_version":1,"library":"webauthn-rs","library_version":"0.6.2","kind":"credential","payload":{"cred":{
        "cred_id":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([44;32]),
        "cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":vec![1;32],"y":vec![2;32]}}},
        "counter":0,"transports":["internal"],"user_verified":true,"backup_eligible":true,"backup_state":true,"registration_policy":"required","extensions":{},"attestation":{"data":"None","metadata":"None"},"attestation_format":"none"}}})).unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,'webauthn','Options-only passkey')").bind(id).bind(REALM).bind(USER).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_webauthn_identity(realm_id,user_id,user_handle) VALUES($1::text::uuid,$2::text::uuid,$3)").bind(REALM).bind(USER).bind(vec![37u8;32]).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_webauthn_factor(factor_id,realm_id,user_id,credential_id,public_credential) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4,$5)").bind(id).bind(REALM).bind(USER).bind(vec![44u8;32]).bind(record).execute(&f.admin).await.unwrap();
    assert_eq!(
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let csrf = public.token(&format!("/realms/{REALM}/mfa")).await;
    assert_eq!(
        public
            .request(
                "POST",
                &format!("/realms/{REALM}/mfa/verify"),
                &[("csrf", &csrf), ("method", "totp"), ("code", "!!!!!!")]
            )
            .await
            .0,
        422
    );
    let before: (String, String, i16) = sqlx::query_as("SELECT id::text,expires_at::text,failed_attempts FROM bloc.realm_mfa_flow WHERE parent_id IS NULL").fetch_one(&f.admin).await.unwrap();
    assert_eq!(before.2, 1);
    let (status, html, _) = public
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/webauthn/options"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(status, 200, "{html}");
    let options: serde_json::Value = serde_json::from_str(&html).unwrap();
    assert_eq!(options["publicKey"]["userVerification"], "required");
    let (status, html, _) = public
        .request("GET", &format!("/realms/{REALM}/mfa/methods"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("Choose a verification method"), "{html}");
    assert!(html.to_lowercase().contains("authenticator"));
    assert!(html.to_lowercase().contains("passkey"));
    let after: (String, String, i16) = sqlx::query_as("SELECT id::text,expires_at::text,failed_attempts FROM bloc.realm_mfa_flow WHERE parent_id IS NULL").fetch_one(&f.admin).await.unwrap();
    assert_eq!(after, before);
    let bounded: bool = sqlx::query_scalar("SELECT bool_and(child.expires_at<=parent.expires_at AND child.expires_at<=child.created_at+interval '300 seconds') FROM bloc.realm_mfa_flow child JOIN bloc.realm_mfa_flow parent ON parent.id=child.parent_id").fetch_one(&f.admin).await.unwrap();
    assert!(bounded);
    policy_flow_no_success(&f).await;
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c16() {
    let (f, mut public, _op, csrf, _code) = mfa_challenge("mfac16").await;
    let (status, html, headers) = public
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/cancel"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(
        headers["location"],
        format!("/realms/{REALM}/login?mfa-canceled=1")
    );
    let (status, html, _) = public
        .request("GET", &format!("/realms/{REALM}/login?mfa-canceled=1"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(
        html.contains("You have left the verification flow. Existing factors have not changed."),
        "{html}"
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_mfa_flow WHERE consumed_at IS NULL"
        )
        .await,
        0
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    policy_flow_no_success(&f).await;
    let (f, mut public, _op, _, _) = mfa_challenge("mfac16abandoned").await;
    sqlx::query("UPDATE bloc.realm_mfa_flow SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute'").execute(&f.admin).await.unwrap();
    let (status, html, headers) = public
        .request("GET", &format!("/realms/{REALM}/mfa"), &[])
        .await;
    assert_eq!(status, 303, "{html}");
    assert!(
        headers["location"]
            .to_str()
            .unwrap()
            .starts_with(&format!("/realms/{REALM}/login"))
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    policy_flow_no_success(&f).await;
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c18() {
    for (name, statement, expected) in [
        (
            "mfac18policy",
            "UPDATE bloc.realm_authentication_settings SET version=version+1",
            409,
        ),
        (
            "mfac18credential",
            "UPDATE bloc.realm_user_credential SET credential_version=credential_version+1",
            409,
        ),
        (
            "mfac18epoch",
            "UPDATE bloc.realm_user_mfa_state SET factor_epoch=factor_epoch+1",
            409,
        ),
        (
            "mfac18lifecycle",
            "UPDATE bloc.realm_user SET status='suspended'",
            404,
        ),
    ] {
        let (f, mut public, _op, csrf, code) = mfa_challenge(name).await;
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&f.admin)
            .await
            .unwrap();
        let (status, html, _) = public
            .request(
                "POST",
                &format!("/realms/{REALM}/mfa/verify"),
                &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
            )
            .await;
        assert_eq!(status.as_u16(), expected, "{name}: {html}");
        policy_flow_no_success(&f).await;
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c19() {
    let (f, mut first, op, csrf, code) = mfa_challenge("mfac19").await;
    let mut second = policy_flow_replica(&f, &op, first.cookies.clone()).await;
    let path = format!("/realms/{REALM}/mfa/verify");
    let fields = [
        ("csrf", csrf.as_str()),
        ("method", "totp"),
        ("code", code.as_str()),
    ];
    let (a, b) = tokio::join!(
        first.request("POST", &path, &fields),
        second.request("POST", &path, &fields)
    );
    let mut statuses = [a.0.as_u16(), b.0.as_u16()];
    statuses.sort();
    assert_eq!(statuses, [303, 409], "{} {}", a.1, b.1);
    let (sessions, audits): (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM bloc.realm_user_session),(SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in')").fetch_one(&f.admin).await.unwrap();
    assert_eq!((sessions, audits), (1, 1));
    let loser = if a.0 == StatusCode::SEE_OTHER {
        second
    } else {
        first
    };
    assert!(
        !loser
            .cookies
            .contains_key(&format!("__Host-bloc-realm-{REALM}"))
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c20() {
    let session_cookie = format!("__Host-bloc-realm-{REALM}=");
    let (f, mut public, _op, csrf, code) = mfa_challenge("mfac20audit").await;
    sqlx::raw_sql("CREATE FUNCTION bloc.test_mfa_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='realm_mfa_sign_in' THEN RAISE EXCEPTION 'synthetic audit outage'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_mfa_audit_failure BEFORE INSERT ON bloc.security_audit_event FOR EACH ROW EXECUTE FUNCTION bloc.test_mfa_audit_failure();").execute(&f.admin).await.unwrap();
    let (status, html, headers) = public
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 503, "{html}");
    assert!(html.contains("No authentication success was recorded."));
    assert!(
        headers
            .get_all("set-cookie")
            .iter()
            .all(|cookie| { !cookie.to_str().unwrap().starts_with(&session_cookie) })
    );
    assert!(!html.contains("synthetic audit outage"));
    assert!(!html.contains(&code));
    policy_flow_no_success(&f).await;
    let (floor, consumed): (i64, bool) = sqlx::query_as("SELECT t.last_accepted_step,f.consumed_at IS NOT NULL FROM bloc.realm_totp_factor t CROSS JOIN bloc.realm_mfa_flow f WHERE f.parent_id IS NULL").fetch_one(&f.admin).await.unwrap();
    assert_eq!((floor, consumed), (12345, false));
    let (f, mut public, _op, csrf, code) = mfa_challenge("mfac20storage").await;
    sqlx::query("REVOKE USAGE ON SCHEMA bloc FROM bloc_runtime")
        .execute(&f.admin)
        .await
        .unwrap();
    let (status, html, headers) = public
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 503, "{html}");
    assert!(html.contains("bloc cannot confirm the outcome"));
    assert!(html.contains("this response granted no new access"));
    assert!(!html.contains("No authentication success was recorded."));
    assert!(
        headers
            .get_all("set-cookie")
            .iter()
            .all(|cookie| { !cookie.to_str().unwrap().starts_with(&session_cookie) })
    );
    policy_flow_no_success(&f).await;
}
