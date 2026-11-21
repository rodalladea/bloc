async fn recovery_saved_fixture(name: &str) -> (Fixture, Browser, MfaOperator, String) {
    let (f, mut b, op, _) = account_protected(name).await;
    let code = "A".repeat(26);
    let generation: String = sqlx::query_scalar(
        "SELECT id::text FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"bloc:mfa:recovery-code:v1");
    for id in [REALM, USER, &generation] {
        digest.update(uuid::Uuid::parse_str(id).unwrap().as_bytes());
    }
    digest.update(code.as_bytes());
    sqlx::query("UPDATE bloc.realm_mfa_recovery_code SET code_digest=$1 WHERE generation_id=$2::text::uuid AND ordinal=1").bind(digest.finalize().to_vec()).bind(&generation).execute(&f.admin).await.unwrap();
    b.cookies.clear();
    let (status, html, _) =
        contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    (f, b, op, code)
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c39() {
    let (f, mut b, _op, code) = recovery_saved_fixture("mfac39").await;
    let path = format!("/realms/{REALM}/mfa/recovery-code");
    let csrf = b.token(&path).await;
    let (status, html, h) = b
        .request("POST", &path, &[("csrf", &csrf), ("code", &code)])
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(h["location"], format!("/realms/{REALM}/mfa"));
    assert!(
        !b.cookies
            .contains_key(&format!("__Host-bloc-realm-{REALM}"))
    );
    let(kind,used,oldlive,sessions):(String,bool,i64,i64)=sqlx::query_as("SELECT (SELECT purpose FROM bloc.realm_mfa_flow WHERE consumed_at IS NULL AND parent_id IS NULL),(SELECT consumed_at IS NOT NULL FROM bloc.realm_mfa_recovery_code WHERE ordinal=1 LIMIT 1),(SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL),(SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL)").fetch_one(&f.admin).await.unwrap();
    assert_eq!(kind, "recovery");
    assert!(used);
    assert_eq!(oldlive, 1);
    assert_eq!(sessions, 0);
    let (status, _, _) = b
        .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
        .await;
    assert_eq!(status, 303);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_saved_code_race() {
    let (f, mut b, op, code) = recovery_saved_fixture("mfasavedrace").await;
    let path = format!("/realms/{REALM}/mfa/recovery-code");
    let csrf = b.token(&path).await;
    let mut other = policy_flow_replica(&f, &op, b.cookies.clone()).await;
    let fields = [("csrf", csrf.as_str()), ("code", code.as_str())];
    let (one, two) = tokio::join!(
        b.request("POST", &path, &fields),
        other.request("POST", &path, &fields)
    );
    let mut statuses = vec![one.0.as_u16(), two.0.as_u16()];
    statuses.sort();
    assert_eq!(statuses, vec![303, 409]);
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bloc.realm_mfa_flow WHERE purpose='recovery' AND consumed_at IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(n, 1);
}
async fn recovery_issue(f: &Fixture, b: &mut Browser) -> String {
    b.login().await;
    let path = format!("/admin/realms/{REALM}/users/{USER}/mfa-recovery");
    let csrf = b.token(&path).await;
    let version: i64 =
        sqlx::query_scalar("SELECT version FROM bloc.realm_user WHERE id=$1::text::uuid")
            .bind(USER)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let (status, html, _) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", &version.to_string()),
                ("identity_confirmed", "true"),
                ("current_password", CONTRACT_PASSWORD),
            ],
        )
        .await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("#code="));
    assert!(html.contains("Expires"));
    html.split("id=\"access-code\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c40() {
    let (f, mut b, _op, _secret) = account_protected("mfac40").await;
    b.login().await;
    let path = format!("/admin/realms/{REALM}/users/{USER}/mfa-recovery");
    let csrf = b.token(&path).await;
    for (confirmed, password) in [("false", CONTRACT_PASSWORD), ("true", "wrong password")] {
        let (status, _, _) = b
            .request(
                "POST",
                &path,
                &[
                    ("csrf", &csrf),
                    ("version", "1"),
                    ("identity_confirmed", confirmed),
                    ("current_password", password),
                ],
            )
            .await;
        assert_eq!(status, 422);
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.realm_mfa_recovery_link")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let code = recovery_issue(&f, &mut b).await;
    assert_eq!(sec::decode(&code).unwrap().len(), 32);
    let (stored, actor): (Vec<u8>, bool) = sqlx::query_as(
        "SELECT token_digest,issued_by IS NOT NULL FROM bloc.realm_mfa_recovery_link",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(stored, sec::digest(&code));
    assert!(actor);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c41() {
    let (f, mut b, _op, _secret) = account_protected("mfac41").await;
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let first = recovery_issue(&f, &mut b).await;
    let second = recovery_issue(&f, &mut b).await;
    assert_ne!(first, second);
    let(n,factors,sessions,digest):(i64,i64,i64,Vec<u8>)=sqlx::query_as("SELECT (SELECT count(*) FROM bloc.realm_mfa_recovery_link),(SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL),(SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL),token_digest FROM bloc.realm_mfa_recovery_link").fetch_one(&f.admin).await.unwrap();
    assert_eq!(n, 1);
    assert_eq!(factors, 1);
    assert_eq!(sessions, before);
    assert_eq!(digest, sec::digest(&second));
}
async fn recovery_exchange(f: &Fixture, b: &mut Browser, code: &str) -> String {
    let path = format!("/realms/{REALM}/recover-mfa");
    let csrf = b.token(&path).await;
    let (status, html, _) = b
        .request(
            "POST",
            &format!("{path}/exchange"),
            &[("csrf", &csrf), ("code", code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    let consumed: bool =
        sqlx::query_scalar("SELECT consumed_at IS NOT NULL FROM bloc.realm_mfa_recovery_link")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert!(!consumed);
    b.token(&path).await
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c42() {
    let (f, mut b, _op, _secret) = account_protected("mfac42").await;
    let code = recovery_issue(&f, &mut b).await;
    let path = format!("/realms/{REALM}/recover-mfa");
    assert_eq!(
        b.request("GET", &format!("{path}?code={code}"), &[])
            .await
            .0,
        403
    );
    assert_eq!(
        b.request("POST", &format!("{path}/exchange"), &[("code", &code)])
            .await
            .0,
        403
    );
    let csrf = recovery_exchange(&f, &mut b, &code).await;
    assert!(!csrf.is_empty());
    let (status, html, _) = b.request("GET", &path, &[]).await;
    assert_eq!(status, 200);
    assert!(html.contains("Current password"));
    assert!(!html.contains(&code));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c43() {
    let (f, mut b, _op, _secret) = account_protected("mfac43").await;
    let code = recovery_issue(&f, &mut b).await;
    let csrf = recovery_exchange(&f, &mut b, &code).await;
    let path = format!("/realms/{REALM}/recover-mfa/confirm");
    assert_eq!(
        b.request(
            "POST",
            &path,
            &[("csrf", &csrf), ("current_password", "wrong")]
        )
        .await
        .0,
        422
    );
    let (status, html, h) = b
        .request(
            "POST",
            &path,
            &[("csrf", &csrf), ("current_password", CONTRACT_PASSWORD)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(h["location"], format!("/realms/{REALM}/mfa"));
    let(used,factors,sessions):(bool,i64,i64)=sqlx::query_as("SELECT consumed_at IS NOT NULL,(SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL),(SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL) FROM bloc.realm_mfa_recovery_link").fetch_one(&f.admin).await.unwrap();
    assert!(used);
    assert_eq!(factors, 1);
    assert_eq!(sessions, 0);
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        303
    );
}
async fn recovery_enter_saved(f: &Fixture, b: &mut Browser, code: &str) {
    let path = format!("/realms/{REALM}/mfa/recovery-code");
    let csrf = b.token(&path).await;
    let (status, html, _) = b
        .request("POST", &path, &[("csrf", &csrf), ("code", code)])
        .await;
    assert_eq!(status, 303, "{html}");
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bloc.realm_mfa_flow WHERE purpose='recovery' AND consumed_at IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(n, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c44() {
    let (f, mut b, _op, code) = recovery_saved_fixture("mfac44").await;
    recovery_enter_saved(&f, &mut b, &code).await;
    sqlx::query("UPDATE bloc.realm_mfa_flow SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE purpose='recovery'").execute(&f.admin).await.unwrap();
    let (status, _, h) = b.request("GET", &format!("/realms/{REALM}/mfa"), &[]).await;
    assert_eq!(status, 303);
    assert!(h["location"].to_str().unwrap().contains("login"));
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(n, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c45() {
    let (f, mut b, op, code) = recovery_saved_fixture("mfac45").await;
    let(old,epoch):(String,i64)=sqlx::query_as("SELECT f.id::text,s.factor_epoch FROM bloc.realm_user_factor f JOIN bloc.realm_user_mfa_state s USING(realm_id,user_id) WHERE f.revoked_at IS NULL").fetch_one(&f.admin).await.unwrap();
    let mut admin = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    let assisted_code = recovery_issue(&f, &mut admin).await;
    let assisted_digest = sec::digest(&assisted_code).to_vec();
    let live_link = "SELECT count(*) FROM bloc.realm_mfa_recovery_link WHERE token_digest=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()";
    let before: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(live_link))
        .bind(&assisted_digest)
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(before, 1);
    recovery_enter_saved(&f, &mut b, &code).await;
    let pending: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(live_link))
        .bind(&assisted_digest)
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(pending, 1);

    let csrf = b.token(&format!("/realms/{REALM}/mfa")).await;
    let path = format!("/realms/{REALM}/account/security/totp");
    assert_eq!(
        b.request("POST", &format!("{path}/start"), &[("csrf", &csrf)])
            .await
            .0,
        303
    );
    let (status, html, _) = b.request("GET", &format!("{path}/setup"), &[]).await;
    assert_eq!(status, 200);
    let key = html
        .split("id=\"setup-key\"")
        .nth(1)
        .unwrap()
        .split('>')
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let proof = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(key).unwrap())
        .build()
        .unwrap()
        .generate(now as u64)
        .to_string();
    let csrf = b.token(&format!("{path}/setup")).await;
    let (status, html, h) = b
        .request(
            "POST",
            &format!("{path}/confirm"),
            &[("csrf", &csrf), ("code", &proof)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert!(h["location"].to_str().unwrap().ends_with("recovery-codes"));
    let(revoked,active,new_epoch,oldcodes):(bool,i64,i64,i64)=sqlx::query_as("SELECT (SELECT revoked_at IS NOT NULL FROM bloc.realm_user_factor WHERE id=$1::text::uuid),(SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL),(SELECT factor_epoch FROM bloc.realm_user_mfa_state),(SELECT count(*) FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NOT NULL)").bind(old).fetch_one(&f.admin).await.unwrap();
    assert!(revoked);
    assert_eq!(active, 1);
    assert_eq!(new_epoch, epoch + 1);
    assert_eq!(oldcodes, 1);
    let after: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(live_link))
        .bind(&assisted_digest)
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(after, 0);
    let mut other = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    let recovery = format!("/realms/{REALM}/recover-mfa");
    let exchange_csrf = other.token(&recovery).await;
    let (status, html, _) = other
        .request(
            "POST",
            &format!("{recovery}/exchange"),
            &[("csrf", &exchange_csrf), ("code", &assisted_code)],
        )
        .await;
    assert_eq!(status, 403, "{html}");
    assert!(html.contains("This link can’t be used"), "{html}");

    assert!(
        !b.cookies
            .contains_key(&format!("__Host-bloc-realm-{REALM}"))
    );
    let handoff = format!("/realms/{REALM}/account/security/recovery-codes");
    let (status, html, _) = b.request("GET", &handoff, &[]).await;
    assert_eq!(status, 200);
    assert_eq!(
        html.split("readonly rows=\"10\">")
            .nth(1)
            .unwrap()
            .split("</textarea>")
            .next()
            .unwrap()
            .lines()
            .count(),
        10
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
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
        .unwrap();
    let (status, html, _) = b
        .request(
            "POST",
            &format!("{handoff}/acknowledge"),
            &[("csrf", csrf), ("saved", "true")],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c46() {
    let (f, mut b, _op, _code) = recovery_saved_fixture("mfac46").await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_allowed_methods=ARRAY['webauthn'],mfa_recovery_codes_enabled=false,mfa_admin_recovery_enabled=false").execute(&f.admin).await.unwrap();
    let (status, html, _) = b.request("GET", &format!("/realms/{REALM}/mfa"), &[]).await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("administrator"));
    assert!(!html.contains("name=\"code\""));
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/mfa/recovery-code"), &[])
            .await
            .0,
        404
    );

    for assisted in [false, true] {
        let name = if assisted {
            "mfac46assisted"
        } else {
            "mfac46stranded"
        };
        let (f, mut b, _op, code) = recovery_saved_fixture(name).await;
        let changed =
            sqlx::query("UPDATE bloc.realm_mfa_recovery_code SET consumed_at=clock_timestamp()")
                .execute(&f.admin)
                .await
                .unwrap();
        assert_eq!(changed.rows_affected(), 10);
        sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_allowed_methods=ARRAY['webauthn'],mfa_admin_recovery_enabled=$1 WHERE mfa_recovery_codes_enabled")
            .bind(assisted).execute(&f.admin).await.unwrap();
        let base = format!("/realms/{REALM}");
        let (status, html, _) = b.request("GET", &format!("{base}/mfa"), &[]).await;
        assert_eq!(status, 200, "{html}");
        assert!(!html.contains(&format!("href=\"{base}/mfa/recovery-code\"")));
        assert!(!html.contains("name=\"code\""));
        assert!(!html.contains("/account/security/webauthn/setup"));
        assert!(!html.contains("/account/security/totp/start"));
        assert_eq!(
            html.contains(&format!("href=\"{base}/recover-mfa\"")),
            assisted
        );
        if !assisted {
            assert!(
                html.contains("No allowed factor or enabled recovery path is available. An administrator must change the policy before you can continue.")
            );
        }
        let saved = format!("{base}/mfa/recovery-code");
        let csrf = b.token(&saved).await;
        let (status, html, _) = b
            .request("POST", &saved, &[("csrf", &csrf), ("code", &code)])
            .await;
        assert_eq!(status, 422, "{html}");
        assert_eq!(
            contract_count(
                &f,
                "SELECT count(*) FROM bloc.realm_mfa_flow WHERE purpose='recovery'"
            )
            .await,
            0
        );
        assert_eq!(contract_count(&f, "SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_code_consume'").await, 0);
        assert!(
            !b.cookies
                .contains_key(&format!("__Host-bloc-realm-{REALM}"))
        );
        if assisted {
            let link = recovery_issue(&f, &mut b).await;
            let csrf = recovery_exchange(&f, &mut b, &link).await;
            let (status, html, headers) = b
                .request(
                    "POST",
                    &format!("{base}/recover-mfa/confirm"),
                    &[("csrf", &csrf), ("current_password", CONTRACT_PASSWORD)],
                )
                .await;
            assert_eq!(status, 303, "{html}");
            assert_eq!(headers["location"], format!("{base}/mfa"));
            let (status, html, _) = b.request("GET", &format!("{base}/mfa"), &[]).await;
            assert_eq!(status, 200);
            assert!(html.contains("Replace your factors"));
            assert!(html.contains("Create a replacement passkey"));
            assert!(!html.contains("/account/security/totp/start"));
            assert_eq!(
                b.request("GET", &format!("{base}/account/profile"), &[])
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
                0
            );
        }
    }
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c48() {
    let (f, mut b, op, code) = recovery_saved_fixture("mfac48").await;
    let path = format!("/realms/{REALM}/mfa/recovery-code");
    let old_csrf = b.token(&path).await;
    let mut admin = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    admin.login().await;
    let policy = format!("/admin/realms/{REALM}/authentication");
    let snapshot = || {
        sqlx::query_as::<_, (String, Vec<u8>, i64, i64, i64)>("SELECT g.id::text,c.code_digest,(SELECT count(*) FROM bloc.realm_mfa_recovery_generation),(SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_code_issue'),(SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_code_consume') FROM bloc.realm_mfa_recovery_generation g JOIN bloc.realm_mfa_recovery_code c ON c.generation_id=g.id WHERE g.invalidated_at IS NULL AND c.ordinal=1 AND c.consumed_at IS NULL")
        .fetch_one(&f.admin)
    };
    let before = snapshot().await.unwrap();
    for (version, enabled) in [("1", false), ("2", true)] {
        let csrf = admin.token(&policy).await;
        let mut fields = policy_flow_fields(&csrf, version, "required", &["totp", "webauthn"]);
        fields.push(("mfa_preferred_method", "webauthn"));
        fields.extend([
            ("confirmed", "true"),
            ("administrator_password", CONTRACT_PASSWORD),
        ]);
        if !enabled {
            fields.retain(|(key, _)| *key != "mfa_recovery_codes_enabled");
        }
        let (status, html, _) = admin.request("POST", &policy, &fields).await;
        assert_eq!(status, 303, "{html}");
        let active: bool = sqlx::query_scalar(
            "SELECT mfa_recovery_codes_enabled FROM bloc.realm_authentication_settings",
        )
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert_eq!(active, enabled);
        if !enabled {
            let (status, html, _) = b
                .request("POST", &path, &[("csrf", &old_csrf), ("code", &code)])
                .await;
            assert_eq!(status, 409, "{html}");
        }
        b.cookies.clear();
        let (status, html, headers) =
            contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
        assert_eq!(status, 303, "{html}");
        let challenge = format!("/realms/{REALM}/mfa");
        assert_eq!(headers["location"], challenge);
        if !enabled {
            assert_eq!(b.request("GET", &path, &[]).await.0, 404);
            let csrf = b.token(&challenge).await;
            let (status, html, headers) = b
                .request("POST", &path, &[("csrf", &csrf), ("code", &code)])
                .await;
            assert_eq!(status, 404, "{html}");
            assert!(!headers.contains_key("set-cookie"));
            assert!(
                !b.cookies
                    .contains_key(&format!("__Host-bloc-realm-{REALM}"))
            );
            assert_eq!(
                contract_count(
                    &f,
                    "SELECT count(*) FROM bloc.realm_mfa_flow WHERE purpose='recovery'"
                )
                .await,
                0
            );
        }
        assert_eq!(snapshot().await.unwrap(), before);
        assert_eq!(
            contract_count(
                &f,
                "SELECT count(*) FROM bloc.realm_mfa_recovery_code WHERE consumed_at IS NOT NULL"
            )
            .await,
            0
        );
    }
    recovery_enter_saved(&f, &mut b, &code).await;
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_mfa_recovery_code WHERE consumed_at IS NOT NULL"
        )
        .await,
        1
    );
}
