#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_cleanup_categories() {
    let (f, mut browser, op, csrf, code) = mfa_challenge("mfacleanupcategories").await;
    // Disposable owner fixtures exercise cleanup cardinality, not proof validity.
    // The original live flow below still completes through the real HTTP verifier.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(r#"
        INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at)
        SELECT ('88888888-8888-4888-8888-'||lpad(n::text,12,'0'))::uuid,
          '{REALM}','cleanup'||n||'@example.test',clock_timestamp(),clock_timestamp()
        FROM generate_series(1,1002) n;
        INSERT INTO bloc.realm_user_session(id,realm_id,user_id,session_digest,credential_version,
          created_at,last_activity_at,expires_at,device_label)
        VALUES('99999999-9999-4999-8999-999999999999','{REALM}','{USER}',
          sha256('expired-session-fixture'::bytea),1,clock_timestamp()-interval '20 minutes',
          clock_timestamp()-interval '10 minutes',clock_timestamp()-interval '1 minute','Expired fixture');
        INSERT INTO bloc.realm_user_credential(realm_id,user_id,password_hash,credential_version,password_changed_at)
        SELECT '{REALM}','88888888-8888-4888-8888-000000001002',password_hash,1,clock_timestamp()
        FROM bloc.realm_user_credential WHERE realm_id='{REALM}' AND user_id='{USER}';
        INSERT INTO bloc.realm_mfa_recovery_link(realm_id,user_id,token_digest,issued_by,
          credential_version,user_version,factor_epoch,issued_at,expires_at)
        SELECT u.realm_id,u.id,sha256(uuid_send(u.id)),a.id,1,1,1,
          clock_timestamp()-interval '19 minutes',
          CASE WHEN u.email='cleanup1002@example.test' THEN clock_timestamp()+interval '10 minutes'
               ELSE clock_timestamp()-interval '1 minute' END
        FROM bloc.realm_user u CROSS JOIN bloc.installation_administrator a
        WHERE u.email LIKE 'cleanup%@example.test';
        INSERT INTO bloc.realm_mfa_recovery_form(realm_id,user_id,link_digest,browser_digest,
          csrf_token,credential_version,user_version,policy_version,factor_epoch,created_at,expires_at)
        SELECT realm_id,user_id,token_digest,token_digest,token_digest,1,1,1,1,issued_at,expires_at
        FROM bloc.realm_mfa_recovery_link;
        INSERT INTO bloc.realm_mfa_recovery_issue_bucket
        SELECT realm_id,user_id,ARRAY[issued_at],expires_at FROM bloc.realm_mfa_recovery_link;
        INSERT INTO bloc.mfa_admission_bucket
        SELECT 'account',token_digest,ARRAY[issued_at],expires_at FROM bloc.realm_mfa_recovery_link;
        INSERT INTO bloc.realm_mfa_flow(realm_id,user_id,bearer_digest,browser_digest,purpose,
          credential_version,factor_epoch,policy_version,user_version,password_verified_at,
          csrf_token,created_at,expires_at,session_id)
        SELECT realm_id,'{USER}',token_digest,token_digest,'login',1,1,1,1,
          clock_timestamp()-interval '10 minutes',token_digest,
          clock_timestamp()-interval '5 minutes',clock_timestamp()-interval '1 minute',
          '99999999-9999-4999-8999-999999999999'::uuid
        FROM bloc.realm_mfa_recovery_link WHERE expires_at<clock_timestamp();
        INSERT INTO bloc.mfa_encrypted_payload(id,realm_id,user_id,purpose,encryption_key_id,encrypted_payload)
        SELECT gen_random_uuid(),'{REALM}','{USER}',2,'{MFA_KEY_A}',
          decode('424d46410101','hex')||uuid_send('{MFA_KEY_A}'::uuid)||decode(repeat('00',40),'hex')
        FROM generate_series(1,1002);
        UPDATE bloc.realm_mfa_flow SET payload_id=(SELECT id FROM bloc.mfa_encrypted_payload
          WHERE purpose=2 LIMIT 1) WHERE user_id='{USER}' AND expires_at>clock_timestamp();
    "#))).execute(&f.admin).await.unwrap();
    let mut password_only = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    let (status, html, headers) = contract_login(
        &mut password_only,
        REALM,
        "cleanup1002@example.test",
        CONTRACT_PASSWORD,
    )
    .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/account"));
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_mfa_flow").await,
        1002,
        "password-only session pruning must not cascade-delete retained MFA flows"
    );
    assert_eq!(contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session WHERE id='99999999-9999-4999-8999-999999999999'").await, 1);
    let categories = [
        "realm_mfa_flow",
        "realm_mfa_recovery_form",
        "mfa_encrypted_payload",
        "realm_mfa_recovery_link",
        "realm_mfa_recovery_issue_bucket",
        "mfa_admission_bucket",
    ];
    let maintenance = f.pool("maintenance_user").await;
    for (round, expected) in [(0, 1002), (1, 2), (2, 1)] {
        if round != 0 {
            sqlx::query("SELECT bloc.maintain_access()")
                .execute(&maintenance)
                .await
                .unwrap();
        }
        if round == 1 {
            assert_eq!(contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session WHERE id='99999999-9999-4999-8999-999999999999'").await, 1,
                "maintenance must retain a session while an MFA flow still references it");
        }
        for table in categories {
            let predicate = if table == "mfa_encrypted_payload" {
                " WHERE purpose=2"
            } else {
                ""
            };
            let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) FROM bloc.{table}{predicate}"
            )))
            .fetch_one(&f.admin)
            .await
            .unwrap();
            assert_eq!(
                count, expected,
                "{table}: cleanup round {round} must remove at most 1000 and retain the live row"
            );
        }
    }
    let (status, html, _) = browser
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(
        status, 303,
        "cleanup must preserve live factor and flow authority: {html}"
    );
}
