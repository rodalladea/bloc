async fn totp_active_factor(f: &Fixture) -> String {
    sqlx::query_scalar("SELECT factor_id::text FROM bloc.realm_totp_factor t JOIN bloc.realm_user_factor f ON f.id=t.factor_id WHERE f.revoked_at IS NULL")
        .fetch_one(&f.admin).await.unwrap()
}
async fn totp_code_for_secret(f: &Fixture, secret: &str, next: bool) -> String {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(secret).unwrap())
        .build()
        .unwrap()
        .generate((now + if next { 30 } else { 0 }) as u64)
        .to_string()
}
fn totp_manual_key(html: &str) -> String {
    html.split("id=\"setup-key\"")
        .nth(1)
        .unwrap()
        .split('>')
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c22() {
    let (f, mut browser, _op, csrf, _code) = mfa_pending_setup("mfac22").await;
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        0
    );
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_totp_factor").await,
        0
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.mfa_encrypted_payload WHERE purpose=2"
        )
        .await,
        1
    );
    let (status, html, _) = browser
        .request(
            "GET",
            &format!("/realms/{REALM}/account/security/totp/setup"),
            &[],
        )
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(
        html.contains("Your factor becomes active only after confirmation"),
        "{html}"
    );
    let (status, html, headers) = browser
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
    let (status, html, _) = browser
        .request("GET", &format!("/realms/{REALM}/login?mfa-canceled=1"), &[])
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(
        html.contains("You have left the verification flow. Existing factors have not changed."),
        "{html}"
    );
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_factor").await,
        0
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
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c24() {
    let (f, mut browser, _op, csrf, code) = mfa_pending_setup("mfac24").await;
    let before: Vec<(String, String)> =
        sqlx::query_as("SELECT id::text,expires_at::text FROM bloc.realm_mfa_flow ORDER BY id")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    let (status, html, _) = browser
        .request(
            "POST",
            &format!("/realms/{REALM}/account/security/totp/confirm"),
            &[("csrf", &csrf), ("code", "!!!!!!")],
        )
        .await;
    assert_eq!(status, 422, "{html}");
    let after: Vec<(String, String)> =
        sqlx::query_as("SELECT id::text,expires_at::text FROM bloc.realm_mfa_flow ORDER BY id")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    assert_eq!(after, before);
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_factor").await,
        0
    );
    sqlx::query("UPDATE bloc.realm_mfa_flow SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute'").execute(&f.admin).await.unwrap();
    let expired: Vec<(String, String)> =
        sqlx::query_as("SELECT id::text,expires_at::text FROM bloc.realm_mfa_flow ORDER BY id")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    let (status, html, headers) = browser
        .request(
            "POST",
            &format!("/realms/{REALM}/account/security/totp/confirm"),
            &[("csrf", &csrf), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert!(
        headers["location"]
            .to_str()
            .unwrap()
            .starts_with(&format!("/realms/{REALM}/login"))
    );
    let after: Vec<(String, String)> =
        sqlx::query_as("SELECT id::text,expires_at::text FROM bloc.realm_mfa_flow ORDER BY id")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    assert_eq!(after, expired);
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_factor").await,
        0
    );
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c25() {
    let (f, mut browser, op, csrf, code) = mfa_pending_setup("mfac25setup").await;
    assert_eq!(
        browser
            .request(
                "POST",
                &format!("/realms/{REALM}/account/security/totp/confirm"),
                &[("csrf", &csrf), ("code", &code)]
            )
            .await
            .0,
        303
    );
    let path = format!("/realms/{REALM}/account/security/recovery-codes");
    let csrf = browser.token(&path).await;
    assert_eq!(
        browser
            .request(
                "POST",
                &format!("{path}/acknowledge"),
                &[("csrf", &csrf), ("saved", "true")]
            )
            .await
            .0,
        303
    );
    let before: (i64, i64) = sqlx::query_as("SELECT (SELECT last_accepted_step FROM bloc.realm_totp_factor),(SELECT count(*) FROM bloc.realm_user_session)").fetch_one(&f.admin).await.unwrap();
    assert_eq!(before.1, 1);
    let mut login = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    assert_eq!(
        contract_login(&mut login, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let csrf = login.token(&format!("/realms/{REALM}/mfa")).await;
    let (status, html, _) = login
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 422, "{html}");
    assert!(
        !login
            .cookies
            .contains_key(&format!("__Host-bloc-realm-{REALM}"))
    );
    let after: (i64, i64) = sqlx::query_as("SELECT (SELECT last_accepted_step FROM bloc.realm_totp_factor),(SELECT count(*) FROM bloc.realm_user_session)").fetch_one(&f.admin).await.unwrap();
    assert_eq!(after, before);

    let (f, mut first, op, csrf1, code) = mfa_challenge("mfac25parallel").await;
    let mut second = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    assert_eq!(
        contract_login(&mut second, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let csrf2 = second.token(&format!("/realms/{REALM}/mfa")).await;
    let path = format!("/realms/{REALM}/mfa/verify");
    let fields1 = [
        ("csrf", csrf1.as_str()),
        ("method", "totp"),
        ("code", code.as_str()),
    ];
    let fields2 = [
        ("csrf", csrf2.as_str()),
        ("method", "totp"),
        ("code", code.as_str()),
    ];
    let (a, b) = tokio::join!(
        first.request("POST", &path, &fields1),
        second.request("POST", &path, &fields2)
    );
    let mut statuses = [a.0.as_u16(), b.0.as_u16()];
    statuses.sort();
    assert_eq!(statuses, [303, 422], "{} {}", a.1, b.1);
    let (sessions, audits): (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM bloc.realm_user_session),(SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in')").fetch_one(&f.admin).await.unwrap();
    assert_eq!((sessions, audits), (1, 1));
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c26() {
    let (f, mut browser, op, old_secret) = account_protected("mfac26").await;
    let old = totp_active_factor(&f).await;
    let operation = format!("totp_replace:{old}");
    let csrf = account_begin_proof(&f, &mut browser, &operation, &old_secret).await;
    let (status, html, _) = browser
        .request(
            "POST",
            &format!("/realms/{REALM}/account/security/totp/start"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    let path = format!("/realms/{REALM}/account/security/totp/setup");
    let (status, html, _) = browser.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    let candidate_secret = totp_manual_key(&html);
    let csrf = html
        .split("<main id=\"content\"")
        .nth(1)
        .unwrap()
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(totp_active_factor(&f).await, old);
    let epoch: i64 = sqlx::query_scalar("SELECT factor_epoch FROM bloc.realm_user_mfa_state")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(35);
    loop {
        let eligible: bool = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint >= last_accepted_step FROM bloc.realm_totp_factor WHERE factor_id=$1::text::uuid").bind(&old).fetch_one(&f.admin).await.unwrap();
        if eligible {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "next real TOTP window did not arrive"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let mut old_login = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    assert_eq!(
        contract_login(
            &mut old_login,
            REALM,
            "Alice@example.test",
            CONTRACT_PASSWORD
        )
        .await
        .0,
        303
    );
    let login_csrf = old_login.token(&format!("/realms/{REALM}/mfa")).await;
    let old_code = totp_code_for_secret(&f, &old_secret, true).await;
    let (status, html, headers) = old_login
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[
                ("csrf", &login_csrf),
                ("method", "totp"),
                ("code", &old_code),
            ],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/account"));
    assert_eq!(totp_active_factor(&f).await, old);
    sqlx::raw_sql("CREATE FUNCTION bloc.test_totp_atomicity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic enrollment audit failure'; END $$; CREATE TRIGGER test_totp_atomicity BEFORE INSERT ON bloc.security_audit_event FOR EACH ROW WHEN (NEW.realm_id IS NOT NULL) EXECUTE FUNCTION bloc.test_totp_atomicity();").execute(&f.admin).await.unwrap();
    let code = totp_code_for_secret(&f, &candidate_secret, false).await;
    let (status, html, _) = browser
        .request(
            "POST",
            &format!("/realms/{REALM}/account/security/totp/confirm"),
            &[("csrf", &csrf), ("code", &code)],
        )
        .await;
    assert_eq!(status, 503, "{html}");
    assert_eq!(totp_active_factor(&f).await, old);
    let unchanged: i64 = sqlx::query_scalar("SELECT factor_epoch FROM bloc.realm_user_mfa_state")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(unchanged, epoch);
    sqlx::query("DROP TRIGGER test_totp_atomicity ON bloc.security_audit_event")
        .execute(&f.admin)
        .await
        .unwrap();
    let code = totp_code_for_secret(&f, &candidate_secret, false).await;
    let (status, html, headers) = browser
        .request(
            "POST",
            &format!("/realms/{REALM}/account/security/totp/confirm"),
            &[("csrf", &csrf), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/account"));
    let current = totp_active_factor(&f).await;
    assert_ne!(current, old);
    let (revoked, count, epoch_after): (bool, i64, i64) = sqlx::query_as("SELECT (SELECT revoked_at IS NOT NULL FROM bloc.realm_user_factor WHERE id=$1::text::uuid),(SELECT count(*) FROM bloc.realm_user_factor WHERE kind='totp' AND revoked_at IS NULL),(SELECT factor_epoch FROM bloc.realm_user_mfa_state)").bind(&old).fetch_one(&f.admin).await.unwrap();
    assert!(revoked);
    assert_eq!(count, 1);
    assert_eq!(epoch_after, epoch + 1);
    let evidence: String = sqlx::query_scalar(
        "SELECT mfa_factor_id::text FROM bloc.realm_user_session WHERE revoked_at IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(evidence, current);
    let (status, _, headers) = old_login
        .request("GET", &format!("/realms/{REALM}/account"), &[])
        .await;
    assert_eq!(status, 303);
    assert!(headers["location"].to_str().unwrap().contains("/login"));
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c27() {
    let (f, mut browser, _op, _) = account_protected("mfac27").await;
    let factor = totp_active_factor(&f).await;
    let path = format!("/realms/{REALM}/account/security");
    let (status, html, _) = browser.request("GET", &path, &[]).await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains(&format!("totp_replace:{factor}")), "{html}");
    assert!(!html.contains("operation=totp_enroll"));
    assert!(!html.contains("value=\"totp_enroll\""));
    let csrf = browser.token(&path).await;
    let (status, _, _) = browser
        .request(
            "POST",
            &format!("{path}/reauthenticate"),
            &[
                ("csrf", &csrf),
                ("operation", "totp_enroll"),
                ("current_password", CONTRACT_PASSWORD),
            ],
        )
        .await;
    assert!(status.is_client_error());
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE kind='totp' AND revoked_at IS NULL"
        )
        .await,
        1
    );
    let error = sqlx::query("INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label) VALUES('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',$1::text::uuid,$2::text::uuid,'totp','Forbidden second authenticator')").bind(REALM).bind(USER).execute(&f.admin).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23505")
    );
    assert_eq!(totp_active_factor(&f).await, factor);
}
