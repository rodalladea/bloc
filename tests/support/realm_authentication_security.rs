const REALM_PASSWORD: &str = "a realm synthetic password";
async fn realm_fixture(name: &str) -> (Fixture, Browser) {
    let f = Fixture::new(name).await;
    sqlx::query("INSERT INTO bloc.realm(id,name,created_at,updated_at) VALUES($1::text::uuid,'Acme',clock_timestamp(),clock_timestamp()),($2::text::uuid,'Other',clock_timestamp(),clock_timestamp())").bind(REALM).bind(OTHER).execute(&f.admin).await.unwrap();
    let hash = bloc::credentials::PasswordWorker::new()
        .hash(REALM_PASSWORD.into())
        .await
        .unwrap();
    for r in [REALM, OTHER] {
        sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,display_name,created_at,updated_at) VALUES(gen_random_uuid(),$1::text::uuid,'person@example.test','Person',clock_timestamp(),clock_timestamp())").bind(r).execute(&f.admin).await.unwrap();
        sqlx::query("INSERT INTO bloc.realm_user_credential SELECT realm_id,id,$2,1,clock_timestamp() FROM bloc.realm_user WHERE realm_id=$1::text::uuid").bind(r).bind(&hash).execute(&f.admin).await.unwrap();
    }
    let b = Browser::new(&f).await;
    (f, b)
}
async fn realm_login(b: &mut Browser, r: &str) {
    let path = format!("/realms/{r}/login");
    let csrf = b.token(&path).await;
    let (s, h, _) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("email", "person@example.test"),
                ("password", REALM_PASSWORD),
            ],
        )
        .await;
    assert_eq!(s, 303, "{h}");
}
async fn realm_clear_budgets(f: &Fixture) {
    sqlx::raw_sql(
        "DELETE FROM bloc.realm_admission_bucket; DELETE FROM bloc.administrator_admission_bucket;",
    )
    .execute(&f.admin)
    .await
    .unwrap();
}
async fn realm_count(f: &Fixture, query: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(query.to_owned()))
        .fetch_one(&f.admin)
        .await
        .unwrap()
}
async fn realm_audit(f: &Fixture, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM bloc.security_audit_event WHERE action=$1")
        .bind(action)
        .fetch_one(&f.admin)
        .await
        .unwrap()
}
async fn realm_link_fixture(name: &str) -> (Fixture, Browser, String, String) {
    let (f, mut admin) = signed(name).await;
    create_realm(&mut admin, REALM, "Acme").await;
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES($1::text::uuid,$2::text::uuid,'person@example.test',clock_timestamp(),clock_timestamp())").bind(USER).bind(REALM).execute(&f.admin).await.unwrap();
    let path = format!("/admin/realms/{REALM}/users/{USER}/access-links");
    let csrf = admin.token(&path).await;
    let (s, h, _) = admin
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("purpose", "activation"),
                ("identity_confirmed", "true"),
            ],
        )
        .await;
    assert_eq!(s, 200, "{h}");
    let code = h
        .split("id=\"access-code\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    (f, admin, path, code)
}
async fn realm_exchange(
    b: &mut Browser,
    code: &str,
    purpose: &str,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let path = format!("/realms/{REALM}/{purpose}");
    let csrf = b.token(&path).await;
    b.request(
        "POST",
        &format!("{path}/exchange"),
        &[("csrf", &csrf), ("code", code)],
    )
    .await
}
async fn realm_consume(
    b: &mut Browser,
    purpose: &str,
    password: &str,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let path = format!("/realms/{REALM}/{purpose}");
    let csrf = b.token(&path).await;
    b.request(
        "POST",
        &path,
        &[
            ("csrf", &csrf),
            ("password", password),
            ("password_confirmation", password),
        ],
    )
    .await
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c09() {
    prove_protected_refusals("refusals_c09").await;
    realm_private_proof("realm_request_order_contract").await;
    realm_private_proof("realm_native_origin_contract").await;
    administrator_native_logout().await;
    let (f, mut b) = realm_fixture("rac09").await;
    let path = format!("/realms/{REALM}/login");
    let (s, h, _) = b
        .request(
            "POST",
            &path,
            &[
                ("email", "person@example.test"),
                ("password", REALM_PASSWORD),
            ],
        )
        .await;
    assert_eq!(s, 403, "{h}");
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
    let token = b.token(&path).await;
    let (s, _, _) = b
        .request(
            "POST",
            &format!("/realms/{OTHER}/login"),
            &[
                ("csrf", &token),
                ("email", "person@example.test"),
                ("password", REALM_PASSWORD),
            ],
        )
        .await;
    assert_eq!(s, 403);
    let huge = "x".repeat(17000);
    let (s, _, _) = b
        .request("POST", &path, &[("csrf", &token), ("password", &huge)])
        .await;
    assert_eq!(s, 413);
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c10() {
    realm_private_proof("realm_worker_contract").await;
    let (f, mut b) = realm_fixture("rac10").await;
    realm_login(&mut b, REALM).await;
    let phc: String =
        sqlx::query_scalar("SELECT password_hash FROM bloc.realm_user_credential LIMIT 1")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
    let encoded = phc.rsplit('$').next().unwrap();
    assert_eq!(encoded.len(), 43);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c11() {
    prove_http_allowances().await;
    let (f, _) = realm_fixture("rac11").await;
    let pool = f.pool("runtime_user").await;
    for (scope, allowance) in [
        ("form_source", 10),
        ("credential_source", 10),
        ("login_identifier", 5),
        ("registration_realm", 10),
        ("registration_identifier", 3),
        ("exchange_source", 10),
        ("exchange_realm", 10),
        ("link", 5),
        ("password_change", 5),
        ("link_issue", 5),
        ("public_work", 20),
        ("account_mutation", 30),
        ("hash_work", 30),
    ] {
        realm_clear_budgets(&f).await;
        for _ in 0..allowance {
            let n: i32 = sqlx::query_scalar("SELECT bloc.realm_reserve($1,$2,$3)")
                .bind(vec![scope])
                .bind(vec![vec![0u8; 32]])
                .bind(vec![1])
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(n, 0, "{scope}");
        }
        let n: i32 = sqlx::query_scalar("SELECT bloc.realm_reserve($1,$2,$3)")
            .bind(vec![scope])
            .bind(vec![vec![0u8; 32]])
            .bind(vec![1])
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!((1..=60).contains(&n), "{scope}");
    }
    realm_clear_budgets(&f).await;
    sqlx::query("INSERT INTO bloc.realm_admission_bucket VALUES('login_identifier',$1,array_fill(clock_timestamp()-interval '50 seconds',ARRAY[5]),clock_timestamp()+interval '1 minute'),('credential_source',$2,array_fill(clock_timestamp()-interval '10 seconds',ARRAY[10]),clock_timestamp()+interval '2 minutes')").bind(vec![0u8;32]).bind(vec![1u8;32]).execute(&f.admin).await.unwrap();
    let before: String = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(b) ORDER BY scope)::text FROM bloc.realm_admission_bucket b",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    let retry: i32 = sqlx::query_scalar("SELECT bloc.realm_reserve($1,$2,$3)")
        .bind(vec![
            "login_identifier",
            "credential_source",
            "registration_realm",
        ])
        .bind(vec![vec![0u8; 32], vec![1u8; 32], vec![2u8; 32]])
        .bind(vec![1, 1, 1])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!((49..=50).contains(&retry));
    let after: String = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(b) ORDER BY scope)::text FROM bloc.realm_admission_bucket b",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(before, after);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c12() {
    prove_replica_last_slot().await;
    realm_private_proof("realm_password_admission_contract").await;
    let (f, _) = realm_fixture("rac12").await;
    let a = f.pool("runtime_user").await;
    let b = f.pool("runtime_user").await;
    sqlx::query("INSERT INTO bloc.administrator_admission_bucket VALUES('hash_work',$1,array_fill(clock_timestamp(),ARRAY[29]),clock_timestamp()+interval '2 minutes')").bind(vec![0u8;32]).execute(&f.admin).await.unwrap();
    let reserve = |p: sqlx::PgPool| async move {
        sqlx::query_scalar::<_, i32>(
            "SELECT bloc.realm_reserve(ARRAY['public_work','hash_work'],$1,ARRAY[1,1])",
        )
        .bind(vec![vec![0u8; 32], vec![0u8; 32]])
        .fetch_one(&p)
        .await
        .unwrap()
    };
    let (x, y) = tokio::join!(reserve(a.clone()), reserve(b));
    assert_eq!(usize::from(x == 0) + usize::from(y == 0), 1);
    realm_clear_budgets(&f).await;
    sqlx::query("INSERT INTO bloc.administrator_admission_bucket VALUES('hash_work',$1,array_fill(clock_timestamp(),ARRAY[29]),clock_timestamp()+interval '2 minutes')").bind(vec![0u8;32]).execute(&f.admin).await.unwrap();
    let n: i32 = sqlx::query_scalar(
        "SELECT bloc.realm_reserve(ARRAY['public_work','hash_work'],$1,ARRAY[2,2])",
    )
    .bind(vec![vec![0u8; 32], vec![0u8; 32]])
    .fetch_one(&a)
    .await
    .unwrap();
    assert!(n > 0);
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_admission_bucket").await,
        0
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c13() {
    realm_private_proof("realm_registration_duplicate_hash_contract").await;
    let (f, mut b) = realm_fixture("rac13").await;
    let path = format!("/realms/{REALM}/login");
    let mut outcomes = vec![];
    for email in ["unknown@example.test", "person@example.test"] {
        let csrf = b.token(&path).await;
        let (s, h, _) = b
            .request(
                "POST",
                &path,
                &[
                    ("csrf", &csrf),
                    ("email", email),
                    ("password", "incorrect password"),
                ],
            )
            .await;
        outcomes.push((s, h.contains("Email or password is incorrect.")));
    }
    assert_eq!(outcomes, vec![(StatusCode::UNPROCESSABLE_ENTITY, true); 2]);
    assert_eq!(realm_count(&f,"SELECT cardinality(admitted_at)::bigint FROM bloc.realm_admission_bucket WHERE scope='public_work'").await,2);
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c14() {
    prove_bounded_insertion_cleanup().await;
    let (f, mut b) = realm_fixture("rac14").await;
    sqlx::query("INSERT INTO bloc.realm_form_state SELECT decode(lpad(to_hex(n),64,'0'),'hex'),$1::text::uuid,'anonymous',NULL,NULL,decode(repeat('01',32),'hex'),statement_timestamp(),statement_timestamp()+interval '30 minutes' FROM generate_series(1,1000)n").bind(REALM).execute(&f.admin).await.unwrap();
    let (s, _, h) = b
        .request("GET", &format!("/realms/{REALM}/login"), &[])
        .await;
    assert_eq!(s, 503);
    assert_eq!(h["retry-after"], "60");
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_form_state").await,
        1000
    );
    sqlx::query("DELETE FROM bloc.realm_admission_bucket")
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO bloc.realm_admission_bucket SELECT 'form_source',decode(lpad(to_hex(n),64,'0'),'hex'),ARRAY[clock_timestamp()],clock_timestamp()+interval '2 minutes' FROM generate_series(1,10000)n").execute(&f.admin).await.unwrap();
    let (s, _, h) = b
        .request("GET", &format!("/realms/{OTHER}/login"), &[])
        .await;
    assert_eq!(s, 503);
    assert_eq!(h["retry-after"], "60");
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.administrator_form_state").await,
        0
    );
    // Global form capacity is independent of the per-realm1000 ceiling.
    sqlx::raw_sql("DELETE FROM bloc.realm_form_state;DELETE FROM bloc.realm_admission_bucket;")
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO bloc.realm(id,name,created_at,updated_at) SELECT ('aaaaaaaa-aaaa-4aaa-8aaa-'||lpad(n::text,12,'0'))::uuid,'Capacity realm',clock_timestamp(),clock_timestamp() FROM generate_series(1,10)n").execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_form_state SELECT decode(lpad(to_hex(n),64,'0'),'hex'),('aaaaaaaa-aaaa-4aaa-8aaa-'||lpad(((n-1)/1000+1)::text,12,'0'))::uuid,'anonymous',NULL,NULL,decode(repeat('01',32),'hex'),statement_timestamp(),statement_timestamp()+interval '30 minutes' FROM generate_series(1,10000)n").execute(&f.admin).await.unwrap();
    let (status, _, headers) = b
        .request("GET", &format!("/realms/{REALM}/login"), &[])
        .await;
    assert_eq!(status, 503);
    assert_eq!(headers["retry-after"], "60");
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_form_state").await,
        10000
    );
    sqlx::raw_sql("DELETE FROM bloc.realm_form_state;DELETE FROM bloc.realm_admission_bucket;")
        .execute(&f.admin)
        .await
        .unwrap();
    let token = b.token(&format!("/realms/{REALM}/login")).await;
    sqlx::query("INSERT INTO bloc.realm_user_session(realm_id,user_id,session_digest,credential_version,created_at,last_activity_at,expires_at,device_label) SELECT u.realm_id,u.id,decode(lpad(to_hex(n),64,'0'),'hex'),1,statement_timestamp(),statement_timestamp(),statement_timestamp()+interval '30 minutes','Unknown device' FROM bloc.realm_user u CROSS JOIN generate_series(1,100000)n WHERE u.realm_id=$1::text::uuid").bind(REALM).execute(&f.admin).await.unwrap();
    let (status, _, headers) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/login"),
            &[
                ("csrf", &token),
                ("email", "person@example.test"),
                ("password", REALM_PASSWORD),
            ],
        )
        .await;
    assert_eq!(status, 503);
    assert_eq!(headers["retry-after"], "60");
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        100000
    );
    // Issuance cleanup removes at most1000 expired forms in one operation.
    sqlx::query("INSERT INTO bloc.realm_form_state SELECT decode(lpad(to_hex(n+20000),64,'0'),'hex'),$1::text::uuid,'anonymous',NULL,NULL,decode(repeat('01',32),'hex'),statement_timestamp()-interval '1 hour',statement_timestamp()-interval '30 minutes' FROM generate_series(1,1001)n").bind(OTHER).execute(&f.admin).await.unwrap();
    let mut fresh = Browser::new(&f).await;
    assert_eq!(
        fresh
            .request("GET", &format!("/realms/{OTHER}/login"), &[])
            .await
            .0,
        200
    );
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_form_state WHERE expires_at<=clock_timestamp()"
        )
        .await,
        1
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c15() {
    prove_account_form_binding().await;
    prove_link_form_bindings().await;
    let (f, mut b) = realm_fixture("rac15").await;
    let path = format!("/realms/{REALM}/login");
    let a = b.token(&path).await;
    let cookies = b.cookies.clone();
    assert_eq!(b.token(&path).await, a);
    assert_eq!(b.cookies, cookies);
    assert_eq!(realm_count(&f,"SELECT count(*) FROM bloc.realm_form_state WHERE expires_at=created_at+interval '30 minutes'").await,1);
    realm_login(&mut b, REALM).await;
    let csrf = b.token(&format!("/realms/{REALM}/account/profile")).await;
    assert_ne!(a, csrf);
    let (s, _, _) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/logout"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(s, 303);
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_form_state WHERE purpose='account'"
        )
        .await,
        0
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c16() {
    contract_rollback_matrix().await;
    let (f, mut b) = realm_fixture("rac16").await;
    let path = format!("/realms/{REALM}/login");
    let csrf = b.token(&path).await;
    f.fail_audit(true).await;
    let (s, _, _) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("email", "person@example.test"),
                ("password", REALM_PASSWORD),
            ],
        )
        .await;
    assert_eq!(s, 503);
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
    f.fail_audit(false).await;
    sqlx::query("UPDATE bloc.installation SET recovery_required=true")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(b.request("GET", &path, &[]).await.0, 503);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c17() {
    realm_private_proof("realm_suspension_verify_race_contract").await;
    let (f, mut b) = realm_fixture("rac17").await;
    realm_login(&mut b, REALM).await;
    let path = format!("/realms/{REALM}/account/password");
    let csrf = b.token(&path).await;
    sqlx::query("UPDATE bloc.realm_user SET status='suspended' WHERE realm_id=$1::text::uuid")
        .bind(REALM)
        .execute(&f.admin)
        .await
        .unwrap();
    let (s, _, h) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("current_password", REALM_PASSWORD),
                ("password", "a replaced synthetic password"),
                ("password_confirmation", "a replaced synthetic password"),
            ],
        )
        .await;
    assert_eq!(s, 303);
    assert!(h["location"].to_str().unwrap().contains("/login"));
    assert_eq!(
        realm_count(
            &f,
            "SELECT max(credential_version) FROM bloc.realm_user_credential"
        )
        .await,
        1
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c18() {
    contract_audit_matrix().await;
    let (f, mut b) = realm_fixture("rac18").await;
    realm_login(&mut b, REALM).await;
    assert_eq!(realm_audit(&f, "realm_sign_in").await, 1);
    assert_eq!(realm_count(&f,"SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_sign_in' AND administrator_id IS NULL AND actor_realm_id=realm_id AND actor_user_id=realm_user_id").await,1);
    assert!(sqlx::query("INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id) SELECT 1,'realm_sign_in','success',realm_id,id,realm_id FROM bloc.realm_user LIMIT 1").execute(&f.admin).await.is_err());
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c19() {
    realm_browser("transport19").await;
    let (f, _) = realm_fixture("rac19").await;
    let pool = f.pool("runtime_user").await;
    for action in [
        "form_issue",
        "registration",
        "sign_in",
        "sign_out",
        "link_exchange",
        "link_issue",
        "activation",
        "reset",
        "profile",
        "password_change",
        "session_revoke",
        "settings",
    ] {
        for reason in [
            "origin",
            "csrf",
            "malformed",
            "oversized",
            "media_type",
            "admission",
            "capacity",
            "authority",
            "credentials",
            "conflict",
            "storage",
        ] {
            sqlx::query("SELECT bloc.realm_denial($1,$2)")
                .bind(action)
                .bind(reason)
                .execute(&pool)
                .await
                .unwrap();
        }
    }
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_denial_aggregate").await,
        132
    );
    assert!(
        sqlx::query("SELECT bloc.realm_denial('person@example.test','credentials')")
            .execute(&pool)
            .await
            .is_err()
    );
    sqlx::query("UPDATE bloc.realm_denial_aggregate SET count=9223372036854775807 WHERE action='sign_in' AND reason='credentials'").execute(&f.admin).await.unwrap();
    sqlx::query("SELECT bloc.realm_denial('sign_in','credentials')")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(realm_count(&f,"SELECT count FROM bloc.realm_denial_aggregate WHERE action='sign_in' AND reason='credentials'").await,i64::MAX);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c20() {
    let (f, mut administrator) = realm_fixture("rac20").await;
    administrator.setup(&f).await;
    sqlx::query("INSERT INTO bloc.realm_form_state SELECT decode(lpad(to_hex(n),64,'0'),'hex'),$1::text::uuid,'anonymous',NULL,NULL,decode(repeat('01',32),'hex'),statement_timestamp()-interval '1 hour',statement_timestamp()-interval '30 minutes' FROM generate_series(1,1001)n").bind(REALM).execute(&f.admin).await.unwrap();
    let m = f.pool("maintenance_user").await;
    sqlx::query("SELECT bloc.maintain_access()")
        .execute(&m)
        .await
        .unwrap();
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_form_state").await,
        1
    );
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user").await,
        2
    );
    sqlx::query("INSERT INTO bloc.realm_admission_bucket SELECT 'form_source',decode(lpad(to_hex(n),64,'0'),'hex'),ARRAY[statement_timestamp()-interval '1 hour'],statement_timestamp()-interval '1 minute' FROM generate_series(1,1001)n").execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_denial_aggregate SELECT date_trunc('minute',statement_timestamp())-interval '8 days'-n*interval '1 minute','sign_in','credentials',1 FROM generate_series(1,1001)n").execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.security_audit_event(installation_id,action,outcome,occurred_at) SELECT 1,'restore','success',statement_timestamp()-interval '91 days' FROM generate_series(1,1001)").execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_session(realm_id,user_id,session_digest,credential_version,created_at,last_activity_at,expires_at,device_label) SELECT u.realm_id,u.id,decode(lpad(to_hex(n),64,'0'),'hex'),1,statement_timestamp()-interval '1 hour',statement_timestamp()-interval '1 hour',statement_timestamp()-interval '30 minutes','Unknown device' FROM bloc.realm_user u CROSS JOIN generate_series(1,1001)n WHERE u.realm_id=$1::text::uuid").bind(REALM).execute(&f.admin).await.unwrap();
    sqlx::query("SELECT bloc.maintain_access()")
        .execute(&m)
        .await
        .unwrap();
    for query in [
        "SELECT count(*) FROM bloc.realm_admission_bucket",
        "SELECT count(*) FROM bloc.realm_denial_aggregate",
        "SELECT count(*) FROM bloc.security_audit_event WHERE occurred_at<clock_timestamp()-interval '90 days'",
        "SELECT count(*) FROM bloc.realm_user_session",
    ] {
        assert_eq!(realm_count(&f, query).await, 1, "{query}");
    }
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user").await,
        2
    );
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) SELECT gen_random_uuid(),$1::text::uuid,'cleanup'||n||'@example.test',statement_timestamp(),statement_timestamp() FROM generate_series(1,1001)n").bind(REALM).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_access_link(realm_id,user_id,purpose,token_digest,user_version,issued_by,issued_at,expires_at) SELECT u.realm_id,u.id,'activation',decode(md5(u.id::text)||md5(u.email),'hex'),1,a.id,statement_timestamp()-interval '2 hours',statement_timestamp()-interval '1 hour' FROM bloc.realm_user u CROSS JOIN bloc.installation_administrator a WHERE u.email LIKE 'cleanup%@example.test'").execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_form_state SELECT token_digest,realm_id,'activation',NULL,token_digest,decode(repeat('01',32),'hex'),statement_timestamp()-interval '90 minutes',statement_timestamp()-interval '1 hour' FROM bloc.realm_user_access_link").execute(&f.admin).await.unwrap();
    sqlx::query("SELECT bloc.maintain_access()")
        .execute(&m)
        .await
        .unwrap();
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_access_link").await,
        1
    );
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_form_state WHERE purpose='activation'"
        )
        .await,
        1
    );
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user").await,
        1003
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c27() {
    prove_suspended_issuance().await;
    let (f, mut b, path, _) = realm_link_fixture("rac27").await;
    let csrf = b.token(&path).await;
    let (s, h, _) = b
        .request(
            "POST",
            &path,
            &[("csrf", &csrf), ("version", "1"), ("purpose", "activation")],
        )
        .await;
    assert_eq!(s, 422, "{h}");
    for (version, purpose) in [("2", "activation"), ("1", "reset")] {
        let (s, _, _) = b
            .request(
                "POST",
                &path,
                &[
                    ("csrf", &csrf),
                    ("version", version),
                    ("purpose", purpose),
                    ("identity_confirmed", "true"),
                ],
            )
            .await;
        assert_eq!(s, 409);
    }
    assert_eq!(realm_audit(&f, "realm_activation_link_issue").await, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c28() {
    prove_link_expiry_output().await;
    let (f, mut b, path, code) = realm_link_fixture("rac28").await;
    assert!(sec::decode(&code).is_some());
    let (s, h, _) = b.request("GET", &path, &[]).await;
    assert_eq!(s, 200);
    assert!(!h.contains(&code));
    assert!(h.contains("Lost output cannot be retrieved"));
    let digest: Vec<u8> =
        sqlx::query_scalar("SELECT token_digest FROM bloc.realm_user_access_link")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(digest, sec::digest(&code));
    assert_eq!(realm_audit(&f, "realm_activation_link_issue").await, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c29() {
    prove_reset_replacement().await;
    let (f, mut admin, path, code) = realm_link_fixture("rac29").await;
    let mut b = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
    let csrf = admin.token(&path).await;
    assert_eq!(
        admin
            .request(
                "POST",
                &path,
                &[
                    ("csrf", &csrf),
                    ("version", "1"),
                    ("purpose", "activation"),
                    ("identity_confirmed", "true")
                ]
            )
            .await
            .0,
        200
    );
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_form_state WHERE purpose='activation'"
        )
        .await,
        0
    );
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 403);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c30() {
    realm_browser("transport30").await;
    let (f, _, _, code) = realm_link_fixture("rac30").await;
    let mut b = Browser::new(&f).await;
    let (s, h, _) = b
        .request("GET", &format!("/realms/{REALM}/activate"), &[])
        .await;
    assert_eq!(s, 200);
    assert!(h.contains("name=\"code\" type=\"password\""));
    assert!(h.contains("method=\"post\""));
    assert!(!h.contains(&code));
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c31() {
    let (f, _, _, code) = realm_link_fixture("rac31").await;
    let mut b = Browser::new(&f).await;
    for route in ["activate", "reset-password"] {
        let (s, _, _) = b
            .request("GET", &format!("/realms/{REALM}/{route}"), &[])
            .await;
        assert_eq!(s, 200);
        let (s, _, _) = b
            .request("GET", &format!("/realms/{REALM}/{route}?code={code}"), &[])
            .await;
        assert_eq!(s, 403);
    }
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_credential").await,
        0
    );
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_access_link WHERE consumed_at IS NULL"
        )
        .await,
        1
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c32() {
    prove_exchange_refusals().await;
    let (f, _, _, code) = realm_link_fixture("rac32").await;
    let mut b = Browser::new(&f).await;
    for route in ["activate/exchange", "reset-password/exchange", "logout"] {
        let (status, _, headers) = b
            .request("GET", &format!("/realms/{REALM}/{route}"), &[])
            .await;
        assert_eq!(status, 405);
        assert_eq!(headers["allow"], "POST");
    }
    let (s, h, headers) = realm_exchange(&mut b, &code, "activate").await;
    assert_eq!(s, 303, "{h}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/activate"));
    assert!(
        headers
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().contains("HttpOnly"))
    );
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_access_link WHERE consumed_at IS NULL"
        )
        .await,
        1
    );
    assert_eq!(realm_count(&f,"SELECT count(*) FROM bloc.realm_form_state WHERE purpose='activation' AND link_digest IS NOT NULL AND session_id IS NULL").await,1);
    assert_eq!(realm_count(&f,"SELECT count(*) FROM bloc.realm_form_state WHERE purpose='activation' AND expires_at=created_at+interval '30 minutes'").await,1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c33() {
    prove_generic_link_failures().await;
    let (f, mut admin, _, code) = realm_link_fixture("rac33").await;
    create_realm(&mut admin, OTHER, "Other").await;
    let mut b = Browser::new(&f).await;
    let invalid = sec::encode(&[99; 32]);
    let (s, h, _) = realm_exchange(&mut b, &invalid, "activate").await;
    assert_eq!(s, 403);
    assert!(h.contains("This link can’t be used"));
    assert!(!h.contains("person@example.test"));
    let (s, h2, _) = realm_exchange(&mut b, &code, "reset-password").await;
    assert_eq!(s, 403);
    assert_eq!(h, h2.replace("reset-password", "activate"));
    let other_path = format!("/realms/{OTHER}/activate");
    let csrf = b.token(&other_path).await;
    let (status, unavailable, _) = b
        .request(
            "POST",
            &format!("{other_path}/exchange"),
            &[("csrf", &csrf), ("code", &code)],
        )
        .await;
    assert_eq!(status, 403);
    assert_eq!(h, unavailable.replace(OTHER, REALM));
    sqlx::query("UPDATE bloc.realm_user_access_link SET expires_at=clock_timestamp()")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 403);
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_credential").await,
        0
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c34() {
    prove_original_link_cutoff("reexchange_cutoff", false).await;
    let (f, _, _, code) = realm_link_fixture("rac34").await;
    let mut b = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
    let path = format!("/realms/{REALM}/activate");
    let csrf = b.token(&path).await;
    sqlx::query(
        "UPDATE bloc.realm_form_state SET expires_at=clock_timestamp() WHERE purpose='activation'",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    let (s, h, _) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("password", REALM_PASSWORD),
                ("password_confirmation", REALM_PASSWORD),
            ],
        )
        .await;
    assert_eq!(s, 403);
    assert!(!h.contains(REALM_PASSWORD));
    assert!(h.contains("reopen the original link"));
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c35() {
    realm_private_proof("realm_link_lifecycle_race_contract").await;
    let (f, _, _, code) = realm_link_fixture("rac35").await;
    let mut a = Browser::new(&f).await;
    let mut b = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut a, &code, "activate").await.0, 303);
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
    let (x, y) = tokio::join!(
        realm_consume(&mut a, "activate", REALM_PASSWORD),
        realm_consume(&mut b, "activate", REALM_PASSWORD)
    );
    assert_eq!(usize::from(x.0 == 303) + usize::from(y.0 == 303), 1);
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_credential").await,
        1
    );
    assert_eq!(realm_audit(&f, "realm_activation").await, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c36() {
    let (f, _, _, code) = realm_link_fixture("rac36").await;
    let mut b = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
    let (s, h, headers) = realm_consume(&mut b, "activate", REALM_PASSWORD).await;
    assert_eq!(s, 303, "{h}");
    assert!(headers["location"].to_str().unwrap().contains("/login"));
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
    realm_login(&mut b, REALM).await;
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c37() {
    prove_credential_invalidation(true).await;
    let (f, mut admin, path, code) = realm_link_fixture("rac37").await;
    let mut b = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
    assert_eq!(
        realm_consume(&mut b, "activate", REALM_PASSWORD).await.0,
        303
    );
    realm_login(&mut b, REALM).await;
    realm_clear_budgets(&f).await;
    let csrf = admin.token(&path).await;
    let (s, h, _) = admin
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("purpose", "reset"),
                ("identity_confirmed", "true"),
            ],
        )
        .await;
    assert_eq!(s, 200, "{h}");
    let code = h
        .split("id=\"access-code\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    assert_eq!(realm_exchange(&mut b, code, "reset-password").await.0, 303);
    let replacement = "a new realm synthetic password";
    assert_eq!(
        realm_consume(&mut b, "reset-password", replacement).await.0,
        303
    );
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        0
    );
    assert_eq!(realm_audit(&f, "realm_password_reset").await, 1);
    let login = format!("/realms/{REALM}/login");
    let csrf = b.token(&login).await;
    assert_eq!(
        b.request(
            "POST",
            &login,
            &[
                ("csrf", &csrf),
                ("email", "person@example.test"),
                ("password", REALM_PASSWORD)
            ]
        )
        .await
        .0,
        422
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c38() {
    prove_original_link_cutoff("policy_cutoff", true).await;
    let (f, _, _, code) = realm_link_fixture("rac38").await;
    let mut b = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
    let (s, h, _) = realm_consume(&mut b, "activate", "short").await;
    assert_eq!(s, 422);
    assert!(!h.contains("value=\"short\""));
    sqlx::query("UPDATE bloc.realm_user SET display_name='Updated',version=version+1")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        realm_consume(&mut b, "activate", REALM_PASSWORD).await.0,
        303
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c39() {
    realm_browser("transport39").await;
    let (f, _, _, code) = realm_link_fixture("rac39").await;
    let mut b = Browser::new(&f).await;
    let (s, h, headers) = realm_exchange(&mut b, &code, "activate").await;
    assert_eq!(s, 303);
    assert!(!h.contains(&code));
    for (_, v) in &headers {
        assert!(!v.to_str().unwrap().contains(&code));
    }
    let (_, h, headers) = b
        .request("GET", &format!("/realms/{REALM}/activate"), &[])
        .await;
    assert!(!h.contains(&code));
    assert_eq!(headers["referrer-policy"], "no-referrer");
    assert_eq!(headers["cache-control"], "no-store");
    assert!(headers.contains_key("content-security-policy"));
    assert!(b.cookies.values().all(|v| v != &code));
    let audit: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(row_to_json(e)::text,''),'') FROM bloc.security_audit_event e",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert!(!audit.contains(&code));
    assert!(!audit.contains("person@example.test"));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c49() {
    prove_lifecycle_link_invalidation().await;
    let (f, mut b) = realm_fixture("rac49").await;
    realm_login(&mut b, REALM).await;
    realm_login(&mut b, OTHER).await;
    b.setup(&f).await;
    b.login().await;
    let user: String =
        sqlx::query_scalar("SELECT id::text FROM bloc.realm_user WHERE realm_id=$1::text::uuid")
            .bind(REALM)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let password_hash: String = sqlx::query_scalar(
        "SELECT password_hash FROM bloc.realm_user_credential WHERE realm_id=$1::text::uuid",
    )
    .bind(REALM)
    .fetch_one(&f.admin)
    .await
    .unwrap();
    let issue_path = format!("/admin/realms/{REALM}/users/{user}/access-links");
    let csrf = b.token(&issue_path).await;
    let (status, html, _) = b
        .request(
            "POST",
            &issue_path,
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("purpose", "reset"),
                ("identity_confirmed", "true"),
            ],
        )
        .await;
    assert_eq!(status, 200, "{html}");
    let code = html
        .split("id=\"access-code\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let mut recipient = Browser::new(&f).await;
    assert_eq!(
        realm_exchange(&mut recipient, code, "reset-password")
            .await
            .0,
        303
    );
    let path = format!("/admin/realms/{REALM}/users/{user}");
    let csrf = b.token(&path).await;
    let values = [
        ("csrf", csrf.as_str()),
        ("version", "1"),
        ("email", "replacement@example.test"),
        ("display_name", "Person"),
    ];
    let (status, html, _) = b.request("POST", &path, &values).await;
    assert_eq!(status, 422, "{html}");
    assert!(html.contains("Confirm the email change"));
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_access_link").await,
        1
    );
    let mut confirmed = values.to_vec();
    confirmed.push(("email_confirmed", "true"));
    assert_eq!(b.request("POST", &path, &confirmed).await.0, 303);
    let same:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM bloc.realm_user u JOIN bloc.realm_user_credential c ON (c.realm_id,c.user_id)=(u.realm_id,u.id) WHERE u.id=$1::text::uuid AND u.email='replacement@example.test' AND c.password_hash=$2)").bind(&user).bind(password_hash).fetch_one(&f.admin).await.unwrap();
    assert!(same);
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_access_link").await,
        0
    );
    assert_eq!(realm_count(&f,"SELECT count(*) FROM bloc.realm_form_state WHERE realm_id='11111111-1111-4111-8111-111111111111' AND purpose<>'anonymous'").await,0);

    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        303
    );
    assert_eq!(
        b.request("GET", &format!("/realms/{OTHER}/account/profile"), &[])
            .await
            .0,
        200
    );
    sqlx::query("UPDATE bloc.realm SET status='suspended' WHERE id=$1::text::uuid")
        .bind(OTHER)
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("UPDATE bloc.realm SET status='active' WHERE id=$1::text::uuid")
        .bind(OTHER)
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        b.request("GET", &format!("/realms/{OTHER}/account/profile"), &[])
            .await
            .0,
        303
    );
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_credential").await,
        2
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c50() {
    prove_restore_link_invalidation().await;
    let (f, mut b) = realm_fixture("rac50").await;
    b.setup(&f).await;
    realm_login(&mut b, REALM).await;
    let mut replica = Browser::new(&f).await;
    replica.cookies = b.cookies.clone();
    f.operator.invalidate_access().await.unwrap();
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_form_state").await,
        0
    );
    for client in [&mut b, &mut replica] {
        assert_eq!(
            client
                .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
                .await
                .0,
            503
        );
    }
    sqlx::query("UPDATE bloc.installation SET recovery_required=false")
        .execute(&f.admin)
        .await
        .unwrap();
    for client in [&mut b, &mut replica] {
        let (status, _, headers) = client
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await;
        assert_eq!(status, 303);
        assert_eq!(
            headers["location"],
            format!("/realms/{REALM}/login?expired=1")
        );
    }
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c51() {
    let (f, mut b) = realm_fixture("rac51").await;
    realm_login(&mut b, REALM).await;
    let (s, h, _) = b
        .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
        .await;
    assert_eq!(s, 200);
    assert!(h.contains("person@example.test"));
    assert!(h.contains("Not verified"));
    assert!(!h.contains("name=\"email\""));
    assert!(!h.contains("name=\"user_id\""));
    assert!(!h.contains("href=\"/admin"));
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user").await,
        2
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c52() {
    prove_profile_boundaries().await;
    let (f, mut b) = realm_fixture("rac52").await;
    realm_login(&mut b, REALM).await;
    let path = format!("/realms/{REALM}/account/profile");
    let csrf = b.token(&path).await;
    let (s, h, _) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("display_name", "  New name  "),
            ],
        )
        .await;
    assert_eq!(s, 303, "{h}");
    let name: String = sqlx::query_scalar(
        "SELECT display_name FROM bloc.realm_user WHERE realm_id=$1::text::uuid",
    )
    .bind(REALM)
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(name, "New name");
    assert_eq!(realm_audit(&f, "realm_profile_update").await, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c53() {
    prove_profile_conflicts().await;
    let (f, mut b) = realm_fixture("rac53").await;
    realm_login(&mut b, REALM).await;
    let path = format!("/realms/{REALM}/account/profile");
    let csrf = b.token(&path).await;
    sqlx::query("UPDATE bloc.realm_user SET version=2 WHERE realm_id=$1::text::uuid")
        .bind(REALM)
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        b.request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("display_name", "Must not win")
            ]
        )
        .await
        .0,
        409
    );
    assert_eq!(
        b.request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", "2"),
                ("display_name", "control\nname")
            ]
        )
        .await
        .0,
        422
    );
    assert_eq!(realm_audit(&f, "realm_profile_update").await, 0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c54() {
    prove_credential_invalidation(false).await;
    let (f, mut b) = realm_fixture("rac54").await;
    realm_login(&mut b, REALM).await;
    let old = b.cookies.clone();
    let path = format!("/realms/{REALM}/account/password");
    let csrf = b.token(&path).await;
    let replacement = "a replacement realm password";
    let (s, h, headers) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("current_password", REALM_PASSWORD),
                ("password", replacement),
                ("password_confirmation", replacement),
            ],
        )
        .await;
    assert_eq!(s, 303, "{h}");
    assert_eq!(
        headers["location"],
        format!("/realms/{REALM}/account?password-saved=1")
    );
    assert_ne!(
        b.cookies.get(&format!("__Host-bloc-realm-{REALM}")),
        old.get(&format!("__Host-bloc-realm-{REALM}"))
    );
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
    b.cookies = old;
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        303
    );
    assert_eq!(realm_audit(&f, "realm_password_change").await, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c55() {
    prove_protected_refusals("refusals_c55").await;
    realm_private_proof("realm_profile_authority_race_contract").await;
    realm_private_proof("realm_password_authority_race_contract").await;
    let (f, mut b) = realm_fixture("rac55").await;
    realm_login(&mut b, REALM).await;
    let path = format!("/realms/{REALM}/account/password");
    let csrf = b.token(&path).await;
    let (s, h, _) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("current_password", "wrong current password"),
                ("password", "a replacement realm password"),
                ("password_confirmation", "a replacement realm password"),
            ],
        )
        .await;
    assert_eq!(s, 422);
    assert!(!h.contains("value=\"wrong current"));
    assert_eq!(
        realm_count(
            &f,
            "SELECT max(credential_version) FROM bloc.realm_user_credential"
        )
        .await,
        1
    );
    assert_eq!(realm_audit(&f, "realm_password_change").await, 0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c56() {
    prove_session_inventory().await;
    let (f, mut b) = realm_fixture("rac56").await;
    realm_login(&mut b, REALM).await;
    let (s, h, _) = b
        .request("GET", &format!("/realms/{REALM}/account/sessions"), &[])
        .await;
    assert_eq!(s, 200);
    for text in [
        "directory-page",
        "table-wrap ui-table-scroll",
        "class=\"ui-table\"",
        "Device",
        "Status",
        "Created (UTC)",
        "Last active",
        "Actions",
        "Current session",
        "End all other sessions",
    ] {
        assert!(h.contains(text), "{text}");
    }
    assert!(!h.contains(OTHER));
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        1
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c57() {
    prove_device_labels().await;
    let (f, mut b) = realm_fixture("rac57").await;
    realm_login(&mut b, REALM).await;
    let label: String = sqlx::query_scalar("SELECT device_label FROM bloc.realm_user_session")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(label, "Unknown device");
    let columns:Vec<String>=sqlx::query_scalar("SELECT column_name FROM information_schema.columns WHERE table_schema='bloc' AND table_name='realm_user_session'").fetch_all(&f.admin).await.unwrap();
    assert!(
        !columns
            .iter()
            .any(|c| c.contains("agent") || c.contains("ip_address"))
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c58() {
    prove_owned_revocation().await;
    let (f, mut b) = realm_fixture("rac58").await;
    realm_login(&mut b, REALM).await;
    let mut other = Browser::new(&f).await;
    realm_login(&mut other, REALM).await;
    let path = format!("/realms/{REALM}/account/sessions/revoke-others");
    let csrf = b.token(&path).await;
    let (s, h, _) = b.request("POST", &path, &[("csrf", &csrf)]).await;
    assert_eq!(s, 200);
    assert!(h.contains("End all other"));
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        2
    );
    assert_eq!(
        b.request("POST", &path, &[("csrf", &csrf), ("confirmed", "true")])
            .await
            .0,
        303
    );
    assert_eq!(
        other
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        303
    );
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
    assert_eq!(realm_audit(&f, "realm_session_revoke").await, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c59() {
    prove_foreign_revocation().await;
    let (f, mut b) = realm_fixture("rac59").await;
    realm_login(&mut b, REALM).await;
    realm_login(&mut b, OTHER).await;
    let foreign: String = sqlx::query_scalar(
        "SELECT id::text FROM bloc.realm_user_session WHERE realm_id=$1::text::uuid",
    )
    .bind(OTHER)
    .fetch_one(&f.admin)
    .await
    .unwrap();
    let csrf = b.token(&format!("/realms/{REALM}/account/sessions")).await;
    assert_eq!(
        b.request(
            "POST",
            &format!("/realms/{REALM}/account/sessions/{foreign}/revoke"),
            &[("csrf", &csrf), ("confirmed", "true")]
        )
        .await
        .0,
        404
    );
    let current: String = sqlx::query_scalar(
        "SELECT id::text FROM bloc.realm_user_session WHERE realm_id=$1::text::uuid",
    )
    .bind(REALM)
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(
        b.request(
            "POST",
            &format!("/realms/{REALM}/account/sessions/{current}/revoke"),
            &[("csrf", &csrf), ("confirmed", "true")]
        )
        .await
        .0,
        303
    );
    assert_eq!(
        b.request("GET", &format!("/realms/{OTHER}/account/profile"), &[])
            .await
            .0,
        200
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c60() {
    let (f, mut b) = realm_fixture("rac60").await;
    realm_login(&mut b, REALM).await;
    let mut other = Browser::new(&f).await;
    realm_login(&mut other, REALM).await;
    let bearer = other
        .cookies
        .get(&format!("__Host-bloc-realm-{REALM}"))
        .unwrap();
    let id: String =
        sqlx::query_scalar("SELECT id::text FROM bloc.realm_user_session WHERE session_digest=$1")
            .bind(sec::digest(bearer).as_slice())
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let csrf = b.token(&format!("/realms/{REALM}/account/sessions")).await;
    for _ in 0..2 {
        assert_eq!(
            b.request(
                "POST",
                &format!("/realms/{REALM}/account/sessions/{id}/revoke"),
                &[("csrf", &csrf), ("confirmed", "true")]
            )
            .await
            .0,
            303
        );
    }
    assert_eq!(realm_audit(&f, "realm_session_revoke").await, 1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c61() {
    let (f, mut b) = realm_fixture("rac61").await;
    sqlx::query("UPDATE bloc.realm_user SET display_name=NULL")
        .execute(&f.admin)
        .await
        .unwrap();
    realm_login(&mut b, REALM).await;
    let (s, h, _) = b
        .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
        .await;
    assert_eq!(s, 200);
    assert!(h.contains("name=\"display_name\" type=\"text\" value=\"\""));
    assert!(
        include_str!("../../assets/realm.css")
            .lines()
            .all(|l| !l.contains("td") && !l.contains("th{"))
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c63() {
    prove_public_exhaustion_logout().await;
    let (f, mut b) = realm_fixture("rac63").await;
    realm_login(&mut b, REALM).await;
    let path = format!("/realms/{REALM}/account/profile");
    let csrf = b.token(&path).await;
    for _ in 0..30 {
        assert_eq!(
            b.request(
                "POST",
                &path,
                &[
                    ("csrf", &csrf),
                    ("version", "1"),
                    ("display_name", "Person")
                ]
            )
            .await
            .0,
            303
        );
    }
    let (s, _, h) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("display_name", "Person"),
            ],
        )
        .await;
    assert_eq!(s, 429);
    assert!(h.contains_key("retry-after"));
    assert_eq!(realm_count(&f,"SELECT cardinality(admitted_at)::bigint FROM bloc.realm_admission_bucket WHERE scope='public_work'").await,1);
}

async fn realm_private_proof(name: &str) {
    let name = format!("realm_authentication::tests::{name}");
    let command_name = name.clone();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("cargo")
            .args([
                "test",
                "--locked",
                "--lib",
                &command_name,
                "--",
                "--ignored",
                "--exact",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{output_text}");
    assert!(
        output_text.contains(&format!("test {name} ... ok")),
        "{output_text}"
    );
}

include!("realm_authentication_extended.rs");

async fn administrator_native_logout() {
    let (f, mut b, access_path, _) = realm_link_fixture("admin_native_logout").await;
    let native = [
        ("origin", "null"),
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
    ];
    for path in [
        format!("/admin/realms/{REALM}/authentication"),
        access_path,
    ] {
        let (_, html, headers) = b.request("GET", &path, &[]).await;
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert!(html.contains("action=\"/admin/logout\""));
        let csrf = b.token(&path).await;
        let old_session = sec::digest(&b.cookies["__Host-bloc-admin"]);
        for (name, value) in [
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-site", "same-site"),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-dest", "iframe"),
            ("origin", "https://foreign.example"),
        ] {
            let mut invalid = native.to_vec();
            invalid.retain(|(key, _)| *key != name);
            invalid.push((name, value));
            assert_eq!(b.request_headers("POST", "/admin/logout", &[("csrf", &csrf)], &invalid).await.0, 403);
        }
        assert_eq!(b.request_headers("POST", "/admin/logout", &[("csrf", "invalid")], &native).await.0, 403);
        // The exception belongs only to logout; other administrator forms retain strict origin checks.
        assert_eq!(b.request_headers("POST", "/admin/password", &[("csrf", &csrf)], &native).await.0, 403);
        let (status, _, headers) = b.request_headers("POST", "/admin/logout", &[("csrf", &csrf)], &native).await;
        assert_eq!(status, 303);
        assert_eq!(headers["location"], "/admin/login");
        assert!(!b.cookies.contains_key("__Host-bloc-admin"));
        assert!(f.runtime.authorize(&old_session).await.unwrap().is_none());
        b.login().await;
    }
}
