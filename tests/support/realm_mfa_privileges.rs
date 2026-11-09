async fn mfa_all_privileges(f: &Fixture) {
    for role in ["runtime_user", "operator_user", "maintenance_user"] {
        let pool = f.pool(role).await;
        for table in [
            "mfa_encrypted_payload",
            "mfa_encryption_key_registry",
            "mfa_encryption_control",
            "realm_user_mfa_state",
            "realm_user_factor",
            "realm_totp_factor",
            "realm_webauthn_identity",
            "realm_webauthn_factor",
            "realm_mfa_flow",
            "realm_mfa_recovery_generation",
            "realm_mfa_recovery_code",
            "realm_mfa_recovery_link",
            "realm_mfa_recovery_form",
            "realm_mfa_recovery_issue_bucket",
            "mfa_admission_bucket",
        ] {
            for statement in [
                format!("SELECT * FROM bloc.{table}"),
                format!("DELETE FROM bloc.{table}"),
            ] {
                let error = sqlx::query(sqlx::AssertSqlSafe(statement))
                    .execute(&pool)
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.as_database_error().and_then(|e| e.code()).as_deref(),
                    Some("42501"),
                    "{role}/{table}: {error}"
                );
            }
        }
        for statement in [
            "SELECT bloc.mfa_reserve_proof('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',decode(repeat('00',32),'hex'))",
            "SELECT bloc.mfa_take_proof('11111111-1111-4111-8111-111111111111',decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),'password')",
        ] {
            let error = sqlx::query(statement).execute(&pool).await.unwrap_err();
            assert_eq!(
                error.as_database_error().and_then(|e| e.code()).as_deref(),
                Some("42501"),
                "private proof authority callable by {role}: {error}"
            );
        }
    }
    let(public,unsafe_path):(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl WHERE n.nspname='bloc' AND p.proname LIKE 'mfa_%' AND acl.grantee=0 AND acl.privilege_type='EXECUTE'),(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='bloc' AND p.proname LIKE 'mfa_%' AND p.prosecdef AND NOT coalesce(p.proconfig @> ARRAY['search_path=pg_catalog, bloc, pg_temp'],false))").fetch_one(&f.admin).await.unwrap();
    assert_eq!((public, unsafe_path), (0, 0));
}
async fn mfa_recovery_audit_assertions() {
    let (f, mut b, _op, code) = recovery_saved_fixture("mfaauditrecovery").await;
    let path = format!("/realms/{REALM}/mfa/recovery-code");
    let csrf = b.token(&path).await;
    assert_eq!(
        b.request("POST", &path, &[("csrf", &csrf), ("code", "bad")])
            .await
            .0,
        422
    );
    let denials:i64=sqlx::query_scalar("SELECT coalesce(sum(count),0)::bigint FROM bloc.realm_denial_aggregate WHERE action='mfa_recovery' AND reason='credentials'").fetch_one(&f.admin).await.unwrap();
    assert_eq!(denials, 1);
    recovery_enter_saved(&f, &mut b, &code).await;
    let bad:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.security_audit_event WHERE action IN('realm_mfa_sign_in','realm_mfa_factor_enroll','realm_mfa_code_issue','realm_mfa_code_consume','realm_mfa_factor_remove','realm_mfa_factor_label','realm_mfa_preference') AND (realm_id IS NULL OR realm_user_id IS NULL OR actor_realm_id IS DISTINCT FROM realm_id OR actor_user_id IS DISTINCT FROM realm_user_id OR administrator_id IS NOT NULL)").fetch_one(&f.admin).await.unwrap();
    assert_eq!(bad, 0);
    let actor:bool=sqlx::query_scalar("SELECT actor_realm_id=$1::text::uuid AND actor_user_id=$2::text::uuid FROM bloc.security_audit_event WHERE action='realm_mfa_code_consume'").bind(REALM).bind(USER).fetch_one(&f.admin).await.unwrap();
    assert!(actor);
    let expired = uuid::Uuid::new_v4().to_string();
    let retained = uuid::Uuid::new_v4().to_string();
    for (id, days) in [(&expired, 91i32), (&retained, 89i32)] {
        sqlx::query("INSERT INTO bloc.security_audit_event(id,occurred_at,installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id) VALUES($1::text::uuid,clock_timestamp()-make_interval(days=>$2),1,'realm_mfa_code_consume','success',$3::text::uuid,$4::text::uuid,$3::text::uuid,$4::text::uuid)").bind(id).bind(days).bind(REALM).bind(USER).execute(&f.admin).await.unwrap();
    }
    sqlx::query("INSERT INTO bloc.realm_denial_aggregate VALUES(date_trunc('minute',clock_timestamp()-interval '8 days'),'mfa_recovery','credentials',3),(date_trunc('minute',clock_timestamp()-interval '6 days'),'mfa_recovery','credentials',4)").execute(&f.admin).await.unwrap();
    let maintenance = f.pool("maintenance_user").await;
    sqlx::query("SELECT bloc.maintain_access()")
        .execute(&maintenance)
        .await
        .unwrap();
    let(old,new):(bool,bool)=sqlx::query_as("SELECT EXISTS(SELECT FROM bloc.security_audit_event WHERE id=$1::text::uuid),EXISTS(SELECT FROM bloc.security_audit_event WHERE id=$2::text::uuid)").bind(expired).bind(retained).fetch_one(&f.admin).await.unwrap();
    assert!(!old && new);
    let counts: Vec<i64> = sqlx::query_scalar(
        "SELECT count FROM bloc.realm_denial_aggregate WHERE action='mfa_recovery' AND minute<clock_timestamp()-interval '1 day' ORDER BY minute",
    )
    .fetch_all(&f.admin)
    .await
    .unwrap();
    assert_eq!(counts, vec![4]);
    let audit: String = sqlx::query_scalar(
        "SELECT coalesce(json_agg(e)::text,'[]') FROM bloc.security_audit_event e",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert!(!audit.contains(&code));
    assert!(!audit.contains(CONTRACT_PASSWORD));
    assert!(!audit.contains("BMFA"));
    mfa_all_privileges(&f).await;
}
