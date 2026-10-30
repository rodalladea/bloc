const CONTRACT_PASSWORD: &str = "a synthetic password";

fn contract_settings<'a>(csrf: &'a str, version: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("csrf", csrf),
        ("version", version),
        ("password_min_length", "16"),
        ("activation_ttl_seconds", "86400"),
        ("reset_ttl_seconds", "1800"),
        ("session_idle_seconds", "1800"),
        ("session_absolute_seconds", "43200"),
        ("session_limit", "10"),
    ]
}
fn contract_replace<'a>(fields: &mut Vec<(&'a str, &'a str)>, key: &'a str, value: &'a str) {
    fields.retain(|(name, _)| *name != key);
    fields.push((key, value));
}
async fn contract_count(f: &Fixture, query: &'static str) -> i64 {
    sqlx::query_scalar(query).fetch_one(&f.admin).await.unwrap()
}
async fn contract_start(name: &str, enrolled: bool) -> (Fixture, Browser, Browser) {
    let (f, mut admin) = signed(name).await;
    create_realm(&mut admin, REALM, "Acme").await;
    if enrolled {
        sqlx::query("UPDATE bloc.realm_authentication_settings SET registration_enabled=true WHERE realm_id=$1::text::uuid").bind(REALM).execute(&f.admin).await.unwrap();
    }
    let public = Browser::new(&f).await;
    (f, admin, public)
}
async fn contract_seed(f: &Fixture) {
    let phc = bloc::credentials::PasswordWorker::new()
        .hash(CONTRACT_PASSWORD.into())
        .await
        .unwrap();
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,display_name,created_at,updated_at) VALUES($1::text::uuid,$2::text::uuid,'Alice@example.test','Alice',clock_timestamp(),clock_timestamp())").bind(USER).bind(REALM).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_credential(realm_id,user_id,password_hash,credential_version,password_changed_at) VALUES($1::text::uuid,$2::text::uuid,$3,1,clock_timestamp())").bind(REALM).bind(USER).bind(phc).execute(&f.admin).await.unwrap();
}
async fn contract_seed_other(f: &Fixture) {
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES('44444444-4444-4444-8444-444444444444',$1::text::uuid,'Alice@example.test',clock_timestamp(),clock_timestamp())").bind(OTHER).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_credential(realm_id,user_id,password_hash,credential_version,password_changed_at) SELECT $1::text::uuid,'44444444-4444-4444-8444-444444444444',password_hash,1,clock_timestamp() FROM bloc.realm_user_credential WHERE realm_id=$2::text::uuid").bind(OTHER).bind(REALM).execute(&f.admin).await.unwrap();
}
async fn contract_register(
    b: &mut Browser,
    email: &str,
    password: &str,
    confirmation: &str,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let path = format!("/realms/{REALM}/register");
    let csrf = b.token(&path).await;
    b.request(
        "POST",
        &path,
        &[
            ("csrf", &csrf),
            ("email", email),
            ("display_name", "Alice"),
            ("password", password),
            ("password_confirmation", confirmation),
        ],
    )
    .await
}
async fn contract_login(
    b: &mut Browser,
    realm: &str,
    email: &str,
    password: &str,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let path = format!("/realms/{realm}/login");
    let csrf = b.token(&path).await;
    b.request(
        "POST",
        &path,
        &[("csrf", &csrf), ("email", email), ("password", password)],
    )
    .await
}
async fn contract_clear_rates(f: &Fixture) {
    sqlx::raw_sql("TRUNCATE bloc.realm_admission_bucket,bloc.administrator_admission_bucket")
        .execute(&f.admin)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c02() {
    let (f, mut admin, _) = contract_start("realmauthc02", false).await;
    let path = format!("/admin/realms/{REALM}/authentication");
    let csrf = admin.token(&path).await;
    let mut fields = contract_settings(&csrf, "1");
    fields.push(("registration_enabled", "true"));
    let (s, h, r) = admin.request("POST", &path, &fields).await;
    assert_eq!(s, 303, "{h}");
    assert!(r["location"].to_str().unwrap().starts_with(&path));
    assert_eq!(
        contract_count(&f, "SELECT version FROM bloc.realm_authentication_settings").await,
        2
    );
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_authentication_update'").await,1);
    let (s, h, _) = admin
        .request("GET", r["location"].to_str().unwrap(), &[])
        .await;
    assert_eq!(s, 200);
    assert!(h.to_lowercase().contains("saved"), "{h}");
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c03() {
    let (f, mut admin, _) = contract_start("realmauthc03", false).await;
    let path = format!("/admin/realms/{REALM}/authentication");
    let csrf = admin.token(&path).await;
    for (key, value) in [
        ("password_min_length", "15"),
        ("password_min_length", "129"),
        ("activation_ttl_seconds", "299"),
        ("activation_ttl_seconds", "604801"),
        ("reset_ttl_seconds", "299"),
        ("reset_ttl_seconds", "86401"),
        ("session_idle_seconds", "59"),
        ("session_idle_seconds", "86401"),
        ("session_absolute_seconds", "299"),
        ("session_absolute_seconds", "2592001"),
        ("session_idle_seconds", "43201"),
        ("session_limit", "0"),
        ("session_limit", "101"),
    ] {
        let mut fields = contract_settings(&csrf, "1");
        contract_replace(&mut fields, key, value);
        fields.push(("confirmed", "true"));
        let (s, h, _) = admin.request("POST", &path, &fields).await;
        assert_eq!(s, 422, "{key}={value}: {h}");
        assert!(h.contains("aria-invalid=\"true\""), "{h}");
        assert_eq!(
            contract_count(&f, "SELECT version FROM bloc.realm_authentication_settings").await,
            1
        );
    }
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_authentication_update'").await,0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c04() {
    realm_private_proof("realm_policy_hash_race_contract").await;
    let (f, mut admin, _) = contract_start("realmauthc04", false).await;
    let path = format!("/admin/realms/{REALM}/authentication");
    let csrf = admin.token(&path).await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET version=2, password_min_length=20")
        .execute(&f.admin)
        .await
        .unwrap();
    let (s, h, _) = admin
        .request("POST", &path, &contract_settings(&csrf, "1"))
        .await;
    assert_eq!(s, 409, "{h}");
    assert!(h.to_lowercase().contains("reload"), "{h}");
    assert_eq!(
        contract_count(
            &f,
            "SELECT password_min_length::bigint FROM bloc.realm_authentication_settings"
        )
        .await,
        20
    );
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_authentication_update'").await,0);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c05() {
    contract_lifetime_units().await;
    let (f, mut admin, _) = contract_start("realmauthc05", false).await;
    let path = format!("/admin/realms/{REALM}/authentication");
    let csrf = admin.token(&path).await;
    let mut fields = contract_settings(&csrf, "1");
    contract_replace(&mut fields, "session_limit", "5");
    let (s, h, _) = admin.request("POST", &path, &fields).await;
    assert_eq!(s, 200, "{h}");
    assert!(h.contains("Review session changes"), "{h}");
    assert!(h.contains("Apply new session limits?"), "{h}");
    assert_eq!(
        contract_count(&f, "SELECT version FROM bloc.realm_authentication_settings").await,
        1
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT session_limit::bigint FROM bloc.realm_authentication_settings"
        )
        .await,
        10
    );
    let _ = admin.request("GET", &path, &[]).await;
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_authentication_update'").await,0);
    fields.push(("confirmed", "true"));
    let (s, h, _) = admin.request("POST", &path, &fields).await;
    assert_eq!(s, 303, "{h}");
    assert_eq!(
        contract_count(
            &f,
            "SELECT session_limit::bigint FROM bloc.realm_authentication_settings"
        )
        .await,
        5
    );
    contract_replace(&mut fields, "version", "2");
    contract_replace(&mut fields, "session_idle_seconds", "2");
    fields.push(("session_idle_seconds_unit", "hours"));
    assert_eq!(admin.request("POST", &path, &fields).await.0, 303);
    assert_eq!(
        contract_count(
            &f,
            "SELECT session_idle_seconds::bigint FROM bloc.realm_authentication_settings"
        )
        .await,
        7200
    );
    let (_, markup, _) = admin.request("GET", &path, &[]).await;
    for control in [
        "require_uppercase",
        "require_lowercase",
        "require_number",
        "require_special",
    ] {
        assert!(markup.contains(&format!("name=\"{control}\" type=\"checkbox\"")));
    }
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c06() {
    contract_shortened_policy().await;
    let (f, mut admin, mut public) = contract_start("realmauthc06", false).await;
    contract_seed(&f).await;
    assert_eq!(
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    sqlx::query("UPDATE bloc.realm_user_session SET created_at=clock_timestamp()-interval '2 hours',last_activity_at=clock_timestamp()-interval '31 minutes',expires_at=clock_timestamp()-interval '1 minute'").execute(&f.admin).await.unwrap();
    let path = format!("/admin/realms/{REALM}/authentication");
    let csrf = admin.token(&path).await;
    let mut fields = contract_settings(&csrf, "1");
    contract_replace(&mut fields, "session_idle_seconds", "3600");
    fields.push(("confirmed", "true"));
    assert_eq!(admin.request("POST", &path, &fields).await.0, 303);
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        0
    );
    contract_replace(&mut fields, "version", "2");
    contract_replace(&mut fields, "session_idle_seconds", "7200");
    assert_eq!(admin.request("POST", &path, &fields).await.0, 303);
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        0
    );
    let (s, _, r) = public
        .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
        .await;
    assert_eq!(s, 303);
    assert!(
        r["location"]
            .to_str()
            .unwrap()
            .starts_with(&format!("/realms/{REALM}/login"))
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c07() {
    contract_link_lifetimes().await;
    let (f, mut admin, mut public) = contract_start("realmauthc07", false).await;
    contract_seed(&f).await;
    for _ in 0..3 {
        contract_clear_rates(&f).await;
        assert_eq!(
            contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD)
                .await
                .0,
            303
        );
    }
    sqlx::query(
        "UPDATE bloc.realm_user_session SET created_at=transaction_timestamp()-interval '1 minute'",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    let newest: String = sqlx::query_scalar(
        "SELECT id::text FROM bloc.realm_user_session ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    let path = format!("/admin/realms/{REALM}/authentication");
    let csrf = admin.token(&path).await;
    let mut fields = contract_settings(&csrf, "1");
    contract_replace(&mut fields, "session_limit", "1");
    fields.push(("confirmed", "true"));
    assert_eq!(admin.request("POST", &path, &fields).await.0, 303);
    let active: Vec<String> =
        sqlx::query_scalar("SELECT id::text FROM bloc.realm_user_session WHERE revoked_at IS NULL")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    assert_eq!(active, vec![newest]);
    let issue = format!("/admin/realms/{REALM}/users/{USER}/access-links");
    let csrf = admin
        .token(&format!("/admin/realms/{REALM}/authentication"))
        .await;
    assert_eq!(
        admin
            .request(
                "POST",
                &issue,
                &[
                    ("csrf", &csrf),
                    ("version", "1"),
                    ("purpose", "reset"),
                    ("identity_confirmed", "true")
                ]
            )
            .await
            .0,
        200
    );
    let expiry: String =
        sqlx::query_scalar("SELECT expires_at::text FROM bloc.realm_user_access_link")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let mut fields = contract_settings(&csrf, "2");
    contract_replace(&mut fields, "session_limit", "1");
    contract_replace(&mut fields, "reset_ttl_seconds", "3600");
    assert_eq!(admin.request("POST", &path, &fields).await.0, 303);
    let after: String =
        sqlx::query_scalar("SELECT expires_at::text FROM bloc.realm_user_access_link")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(expiry, after);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c08() {
    contract_policy_transitions().await;
    contract_password_boundaries().await;
    let (f, _, mut public) = contract_start("realmauthc08", true).await;
    for (i, password) in ["a".repeat(15), "a".repeat(129)].iter().enumerate() {
        let email = format!("invalid{i}@example.test");
        let (s, h, _) = contract_register(&mut public, &email, password, password).await;
        assert_eq!(s, 422, "{h}");
        assert!(!h.contains(&format!("value=\"{password}\"")));
    }
    sqlx::query("UPDATE bloc.realm_authentication_settings SET require_uppercase=true,require_lowercase=true,require_number=true,require_special=true").execute(&f.admin).await.unwrap();
    for password in [
        "abcdefghijklmnop1!",
        "ABCDEFGHIJKLMNOP1!",
        "Abcdefghijklmnop١!",
        "Abcdefghijklmnop1 ",
    ] {
        contract_clear_rates(&f).await;
        assert_eq!(
            contract_register(&mut public, "invalid@example.test", password, password)
                .await
                .0,
            422
        );
    }
    contract_clear_rates(&f).await;
    let password = " Éé 123! unchanged whitespace ";
    assert_eq!(
        contract_register(&mut public, "unicode@example.test", password, password)
            .await
            .0,
        303
    );
    contract_clear_rates(&f).await;
    assert_eq!(
        contract_login(&mut public, REALM, "unicode@example.test", password)
            .await
            .0,
        303
    );
    for changed in [
        password.trim().to_owned(),
        password.replace("Éé", "E\u{301}e\u{301}"),
    ] {
        contract_clear_rates(&f).await;
        assert_eq!(
            contract_login(&mut public, REALM, "unicode@example.test", &changed)
                .await
                .0,
            422
        );
    }
    sqlx::query(
        "UPDATE bloc.realm_authentication_settings SET password_min_length=128,version=version+1",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    contract_clear_rates(&f).await;
    assert_eq!(
        contract_login(&mut public, REALM, "unicode@example.test", password)
            .await
            .0,
        303
    );
}

async fn contract_issue(admin: &mut Browser, path: &str, purpose: &str, version: &str) -> String {
    let csrf = admin.token(path).await;
    let (s, h, _) = admin
        .request(
            "POST",
            path,
            &[
                ("csrf", &csrf),
                ("version", version),
                ("purpose", purpose),
                ("identity_confirmed", "true"),
            ],
        )
        .await;
    assert_eq!(s, 200, "{h}");
    h.split("id=\"access-code\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}
async fn contract_policy_transitions() {
    let (f, mut admin, issue, code) = realm_link_fixture("policytransitions").await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET password_min_length=24,require_uppercase=true,require_lowercase=true,require_number=true,require_special=true").execute(&f.admin).await.unwrap();
    let mut b = Browser::new(&f).await;
    let mut current = String::new();
    for purpose in ["activate", "reset-password", "account/password"] {
        contract_clear_rates(&f).await;
        if purpose == "activate" {
            assert_eq!(realm_exchange(&mut b, &code, purpose).await.0, 303);
        }
        if purpose == "reset-password" {
            let code = contract_issue(&mut admin, &issue, "reset", "1").await;
            assert_eq!(realm_exchange(&mut b, &code, purpose).await.0, 303);
        }
        let path = format!("/realms/{REALM}/{purpose}");
        for invalid in [
            "Éé1! too short".to_owned(),
            "Éé1!".to_owned() + &"x".repeat(125),
            "Éé١!".to_owned() + &"x".repeat(24),
            "éé1!".to_owned() + &"x".repeat(24),
            "ÉÉ1!".to_owned() + &"X".repeat(24),
            "Éé1 ".to_owned() + &"x".repeat(24),
        ] {
            contract_clear_rates(&f).await;
            let csrf = b.token(&path).await;
            let mut fields = vec![
                ("csrf", csrf.as_str()),
                ("password", invalid.as_str()),
                ("password_confirmation", invalid.as_str()),
            ];
            if purpose == "account/password" {
                fields.push(("current_password", current.as_str()));
            }
            let (s, h, _) = b.request("POST", &path, &fields).await;
            assert_eq!(s, 422, "{purpose}: {h}");
            assert!(!h.contains(&format!("value=\"{invalid}\"")));
        }
        contract_clear_rates(&f).await;
        let csrf = b.token(&path).await;
        let replacement = format!(" Éé1! preserved {purpose} whitespace ");
        let mut fields = vec![
            ("csrf", csrf.as_str()),
            ("password", replacement.as_str()),
            ("password_confirmation", replacement.as_str()),
        ];
        if purpose == "account/password" {
            fields.push(("current_password", current.as_str()));
        }
        let (s, h, _) = b.request("POST", &path, &fields).await;
        assert_eq!(s, 303, "{purpose}: {h}");
        current = replacement;
        contract_clear_rates(&f).await;
        assert_eq!(
            contract_login(&mut b, REALM, "person@example.test", current.trim())
                .await
                .0,
            422
        );
        contract_clear_rates(&f).await;
        let decomposed = current.replace("Éé", "E\u{301}e\u{301}");
        assert_eq!(
            contract_login(&mut b, REALM, "person@example.test", &decomposed)
                .await
                .0,
            422
        );
        contract_clear_rates(&f).await;
        assert_eq!(
            contract_login(&mut b, REALM, "person@example.test", &current)
                .await
                .0,
            303
        );
    }
}

async fn contract_snapshot(f: &Fixture) -> String {
    sqlx::query_scalar("SELECT jsonb_build_object('users',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM bloc.realm_user t),'credentials',(SELECT jsonb_agg(to_jsonb(t) ORDER BY user_id) FROM bloc.realm_user_credential t),'settings',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id) FROM bloc.realm_authentication_settings t),'links',(SELECT jsonb_agg(to_jsonb(t) ORDER BY token_digest) FROM bloc.realm_user_access_link t),'sessions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM bloc.realm_user_session t),'forms',(SELECT jsonb_agg(to_jsonb(t) ORDER BY browser_digest) FROM bloc.realm_form_state t),'events',(SELECT count(*) FROM bloc.security_audit_event))::text").fetch_one(&f.admin).await.unwrap()
}
async fn contract_transition(
    f: &Fixture,
    b: &mut Browser,
    path: &str,
    fields: &[(&str, &str)],
    expected: u16,
    rollback: bool,
) -> String {
    if rollback {
        let before = contract_snapshot(f).await;
        let cookies = b.cookies.clone();
        f.fail_audit(true).await;
        let (s, h, _) = b.request("POST", path, fields).await;
        assert_eq!(s, 503, "{path}: {h}");
        assert_eq!(
            contract_snapshot(f).await,
            before,
            "audit failure mutated {path}"
        );
        f.fail_audit(false).await;
        b.cookies = cookies;
        contract_clear_rates(f).await;
    }
    let (s, h, _) = b.request("POST", path, fields).await;
    assert_eq!(s, expected, "{path}: {h}");
    h
}
async fn contract_audit_matrix() {
    contract_transitions(false).await;
}
async fn contract_rollback_matrix() {
    contract_transitions(true).await;
}
async fn contract_transitions(rollback: bool) {
    let (f, mut admin, mut b) = contract_start(
        if rollback {
            "rollbackmatrix"
        } else {
            "auditmatrix"
        },
        false,
    )
    .await;
    let path = format!("/admin/realms/{REALM}/authentication");
    let csrf = admin.token(&path).await;
    let mut fields = contract_settings(&csrf, "1");
    fields.push(("registration_enabled", "true"));
    contract_transition(&f, &mut admin, &path, &fields, 303, rollback).await;
    let path = format!("/realms/{REALM}/register");
    let csrf = b.token(&path).await;
    contract_transition(
        &f,
        &mut b,
        &path,
        &[
            ("csrf", &csrf),
            ("email", "registered@example.test"),
            ("display_name", "Registered"),
            ("password", CONTRACT_PASSWORD),
            ("password_confirmation", CONTRACT_PASSWORD),
        ],
        303,
        rollback,
    )
    .await;
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES($1::text::uuid,$2::text::uuid,'person@example.test',clock_timestamp(),clock_timestamp())").bind(USER).bind(REALM).execute(&f.admin).await.unwrap();
    for (purpose, route) in [("activation", "activate"), ("reset", "reset-password")] {
        contract_clear_rates(&f).await;
        let path = format!("/admin/realms/{REALM}/users/{USER}/access-links");
        let csrf = admin.token(&path).await;
        let h = contract_transition(
            &f,
            &mut admin,
            &path,
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("purpose", purpose),
                ("identity_confirmed", "true"),
            ],
            200,
            rollback,
        )
        .await;
        let code = h
            .split("id=\"access-code\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert_eq!(realm_exchange(&mut b, code, route).await.0, 303);
        let path = format!("/realms/{REALM}/{route}");
        let csrf = b.token(&path).await;
        contract_transition(
            &f,
            &mut b,
            &path,
            &[
                ("csrf", &csrf),
                ("password", CONTRACT_PASSWORD),
                ("password_confirmation", CONTRACT_PASSWORD),
            ],
            303,
            rollback,
        )
        .await;
    }
    contract_clear_rates(&f).await;
    let path = format!("/realms/{REALM}/login");
    let csrf = b.token(&path).await;
    contract_transition(
        &f,
        &mut b,
        &path,
        &[
            ("csrf", &csrf),
            ("email", "person@example.test"),
            ("password", CONTRACT_PASSWORD),
        ],
        303,
        rollback,
    )
    .await;
    let path = format!("/realms/{REALM}/account/profile");
    let csrf = b.token(&path).await;
    contract_transition(
        &f,
        &mut b,
        &path,
        &[
            ("csrf", &csrf),
            ("version", "1"),
            ("display_name", "Updated"),
        ],
        303,
        rollback,
    )
    .await;
    contract_clear_rates(&f).await;
    let path = format!("/realms/{REALM}/account/password");
    let csrf = b.token(&path).await;
    contract_transition(
        &f,
        &mut b,
        &path,
        &[
            ("csrf", &csrf),
            ("current_password", CONTRACT_PASSWORD),
            ("password", "replacement synthetic password"),
            ("password_confirmation", "replacement synthetic password"),
        ],
        303,
        rollback,
    )
    .await;
    contract_clear_rates(&f).await;
    let mut other = Browser::new(&f).await;
    assert_eq!(
        contract_login(
            &mut other,
            REALM,
            "person@example.test",
            "replacement synthetic password"
        )
        .await
        .0,
        303
    );
    let path = format!("/realms/{REALM}/account/sessions/revoke-others");
    let csrf = b.token(&format!("/realms/{REALM}/account/sessions")).await;
    contract_transition(
        &f,
        &mut b,
        &path,
        &[("csrf", &csrf), ("confirmed", "true")],
        303,
        rollback,
    )
    .await;
    let path = format!("/realms/{REALM}/logout");
    let csrf = b.token(&format!("/realms/{REALM}/account/profile")).await;
    contract_transition(&f, &mut b, &path, &[("csrf", &csrf)], 303, rollback).await;
    for action in [
        "realm_authentication_update",
        "realm_registration",
        "realm_activation_link_issue",
        "realm_reset_link_issue",
        "realm_activation",
        "realm_password_reset",
        "realm_sign_in",
        "realm_sign_out",
        "realm_profile_update",
        "realm_password_change",
        "realm_session_revoke",
    ] {
        assert_eq!(
            realm_audit(&f, action).await,
            if action == "realm_sign_in" { 2 } else { 1 },
            "event count for {action}"
        );
    }
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.security_audit_event WHERE action IN('realm_authentication_update','realm_activation_link_issue','realm_reset_link_issue') AND (administrator_id IS NULL OR actor_user_id IS NOT NULL OR actor_realm_id IS NOT NULL)").await,0);
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.security_audit_event WHERE action IN('realm_registration','realm_activation','realm_password_reset') AND (administrator_id IS NOT NULL OR actor_user_id IS NOT NULL OR actor_realm_id IS NOT NULL)").await,0);
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.security_audit_event WHERE action IN('realm_sign_in','realm_sign_out','realm_profile_update','realm_password_change','realm_session_revoke') AND (administrator_id IS NOT NULL OR actor_user_id IS DISTINCT FROM realm_user_id OR actor_realm_id IS DISTINCT FROM realm_id)").await,0);
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c21() {
    let (f, _, mut b) = contract_start("realmauthc21", false).await;
    let path = format!("/realms/{REALM}/register");
    let (s, h, _) = b.request("GET", &path, &[]).await;
    assert_eq!(s, 403);
    assert!(h.contains("Registration is unavailable"));
    sqlx::query("UPDATE bloc.realm_authentication_settings SET registration_enabled=true")
        .execute(&f.admin)
        .await
        .unwrap();
    let (s, h, _) = b.request("GET", &path, &[]).await;
    assert_eq!(s, 200);
    for field in ["email", "display_name", "password", "password_confirmation"] {
        assert!(h.contains(&format!("name=\"{field}\"")), "{field}");
    }
    sqlx::query("UPDATE bloc.realm SET status='suspended'")
        .execute(&f.admin)
        .await
        .unwrap();
    let (s, h, _) = b.request("GET", &path, &[]).await;
    assert_eq!(s, 404);
    assert!(h.contains("This realm is unavailable"));
    assert_eq!(
        b.request("GET", &format!("/realms/{OTHER}/register"), &[])
            .await
            .0,
        404
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c22() {
    let (f, _, mut b) = contract_start("realmauthc22", true).await;
    let (s, h, r) = contract_register(
        &mut b,
        "Alice@EXAMPLE.test",
        CONTRACT_PASSWORD,
        CONTRACT_PASSWORD,
    )
    .await;
    assert_eq!(s, 303, "{h}");
    assert!(
        r["location"]
            .to_str()
            .unwrap()
            .starts_with(&format!("/realms/{REALM}/login"))
    );
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.realm_user WHERE email='Alice@example.test' AND status='active'").await,1);
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_credential").await,
        1
    );
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_registration' AND administrator_id IS NULL").await,1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c23() {
    let (f, _, mut b) = contract_start("realmauthc23", true).await;
    contract_seed(&f).await;
    for credential in [true, false] {
        if !credential {
            sqlx::query("DELETE FROM bloc.realm_user_credential")
                .execute(&f.admin)
                .await
                .unwrap();
        }
        for status in ["active", "suspended"] {
            sqlx::query("UPDATE bloc.realm_user SET status=$1")
                .bind(status)
                .execute(&f.admin)
                .await
                .unwrap();
            contract_clear_rates(&f).await;
            let (s, h, _) = contract_register(
                &mut b,
                "Alice@example.test",
                CONTRACT_PASSWORD,
                CONTRACT_PASSWORD,
            )
            .await;
            assert_eq!(s, 422, "{h}");
            assert!(h.to_lowercase().contains("administrator"));
            assert!(!h.to_lowercase().contains("already exists"));
            assert!(!h.to_lowercase().contains("already registered"));
            assert!(!h.to_lowercase().contains("sign in"), "{h}");
            assert!(!h.contains(&format!("href=\"/realms/{REALM}/login")), "{h}");
            assert_eq!(
                contract_count(&f, "SELECT count(*) FROM bloc.realm_user").await,
                1
            );
            assert_eq!(
                contract_count(&f, "SELECT count(*) FROM bloc.realm_user_credential").await,
                i64::from(credential)
            );
        }
    }
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_registration'"
        )
        .await,
        0
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c24() {
    let (f, _, mut b) = contract_start("realmauthc24", true).await;
    for (email, password, confirmation) in [
        ("invalid", "a synthetic password", "a synthetic password"),
        ("Alice@example.test", "short", "short"),
        (
            "Alice@example.test",
            "a synthetic password",
            "different password",
        ),
    ] {
        let (s, h, _) = contract_register(&mut b, email, password, confirmation).await;
        assert_eq!(s, 422, "{h}");
        assert!(h.contains("aria-invalid=\"true\""));
        assert!(
            h.contains(&format!("value=\"{email}\"")),
            "safe email retained: {h}"
        );
        assert!(h.contains("value=\"Alice\""), "safe name retained: {h}");
        assert!(!h.contains(&format!("value=\"{password}\"")));
        assert!(!h.contains(&format!("value=\"{confirmation}\"")));
    }
    for invalid_name in ["x".repeat(129), "name\ncontrol".into()] {
        let path = format!("/realms/{REALM}/register");
        let csrf = b.token(&path).await;
        let (status, html, _) = b
            .request(
                "POST",
                &path,
                &[
                    ("csrf", &csrf),
                    ("email", "Safe@example.test"),
                    ("display_name", &invalid_name),
                    ("password", CONTRACT_PASSWORD),
                    ("password_confirmation", CONTRACT_PASSWORD),
                ],
            )
            .await;
        assert_eq!(status, 422, "{html}");
        assert!(html.contains("value=\"Safe@example.test\""));
        assert!(html.contains("aria-invalid=\"true\""));
        assert!(!html.contains(&format!("value=\"{CONTRACT_PASSWORD}\"")));
    }
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user").await,
        0
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c25() {
    let (f, _, mut a) = contract_start("realmauthc25", true).await;
    let mut b = Browser::new(&f).await;
    let (a_result, b_result) = tokio::join!(
        contract_register(
            &mut a,
            "Race@example.test",
            CONTRACT_PASSWORD,
            CONTRACT_PASSWORD
        ),
        contract_register(
            &mut b,
            "Race@example.test",
            CONTRACT_PASSWORD,
            CONTRACT_PASSWORD
        )
    );
    assert_eq!(
        [a_result.0, b_result.0]
            .iter()
            .filter(|s| **s == 303)
            .count(),
        1
    );
    assert_eq!(
        [a_result.0, b_result.0]
            .iter()
            .filter(|s| **s == 422)
            .count(),
        1
    );
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_credential").await,
        1
    );
    contract_clear_rates(&f).await;
    assert_eq!(
        contract_register(
            &mut a,
            "Race@example.test",
            CONTRACT_PASSWORD,
            CONTRACT_PASSWORD
        )
        .await
        .0,
        422
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_registration'"
        )
        .await,
        1
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c26() {
    realm_private_proof("realm_registration_state_race_contract").await;
    contract_registration_history().await;
    let (f, _, mut b) = contract_start("realmauthc26", true).await;
    let path = format!("/realms/{REALM}/register");
    let csrf = b.token(&path).await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET registration_enabled=false")
        .execute(&f.admin)
        .await
        .unwrap();
    let fields = [
        ("csrf", csrf.as_str()),
        ("email", "Alice@example.test"),
        ("password", CONTRACT_PASSWORD),
        ("password_confirmation", CONTRACT_PASSWORD),
    ];
    assert_eq!(b.request("POST", &path, &fields).await.0, 403);
    sqlx::query("UPDATE bloc.realm SET status='suspended'")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(b.request("POST", &path, &fields).await.0, 404);
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user").await,
        0
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c40() {
    let (f, _, mut b) = contract_start("realmauthc40", false).await;
    let path = format!("/realms/{REALM}/login");
    let (s, h, _) = b.request("GET", &path, &[]).await;
    assert_eq!(s, 200);
    assert!(h.contains("Sign in to Acme"));
    assert!(h.contains("administrator"));
    assert!(!h.contains(&format!("href=\"/realms/{REALM}/register\"")));
    sqlx::query("UPDATE bloc.realm_authentication_settings SET registration_enabled=true")
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(
        b.request("GET", &path, &[])
            .await
            .1
            .contains(&format!("href=\"/realms/{REALM}/register\""))
    );
    sqlx::query("UPDATE bloc.realm SET status='suspended'")
        .execute(&f.admin)
        .await
        .unwrap();
    let (s, h, _) = b.request("GET", &path, &[]).await;
    sqlx::raw_sql("DELETE FROM bloc.realm_form_state; DELETE FROM bloc.realm_authentication_settings; DELETE FROM bloc.security_audit_event WHERE realm_id IS NOT NULL; DELETE FROM bloc.realm").execute(&f.admin).await.unwrap();
    let (t, j, _) = b.request("GET", &path, &[]).await;
    assert_eq!((s, t), (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND));
    assert_eq!(h, j);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c41() {
    let (f, _, mut b) = contract_start("realmauthc41", false).await;
    contract_seed(&f).await;
    let (s, h, r) = contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    assert_eq!(s, 303, "{h}");
    assert_eq!(r["location"], format!("/realms/{REALM}/account"));
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_sign_in'"
        )
        .await,
        1
    );
    let (s, _, r) = b
        .request("GET", &format!("/realms/{REALM}/account"), &[])
        .await;
    assert_eq!(s, 303);
    assert_eq!(r["location"], format!("/realms/{REALM}/account/profile"));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c42() {
    let (f, _, mut b) = contract_start("realmauthc42", false).await;
    contract_seed(&f).await;
    for (email, password) in [
        ("Unknown@example.test", CONTRACT_PASSWORD),
        ("Alice@example.test", "incorrect password"),
    ] {
        contract_clear_rates(&f).await;
        let (s, h, _) = contract_login(&mut b, REALM, email, password).await;
        assert_eq!(s, 422, "{h}");
    }
    sqlx::query("UPDATE bloc.realm_user SET status='suspended'")
        .execute(&f.admin)
        .await
        .unwrap();
    contract_clear_rates(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        422
    );
    sqlx::raw_sql(
        "UPDATE bloc.realm_user SET status='active'; DELETE FROM bloc.realm_user_credential",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    contract_clear_rates(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        422
    );
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
    let (s, h, r) = b
        .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
        .await;
    assert_eq!(s, 303);
    assert!(!h.contains("Alice@example.test"));
    assert!(r["location"].to_str().unwrap().contains("/login"));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c43() {
    let (f, mut admin, _) = contract_start("realmauthc43", false).await;
    contract_seed(&f).await;
    create_realm(&mut admin, OTHER, "Independent").await;
    let (_, _, r) =
        contract_login(&mut admin, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    let name = format!("__Host-bloc-realm-{REALM}");
    let cookie = r
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .unwrap();
    for attr in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(cookie.contains(attr), "{cookie}");
    }
    assert!(!cookie.contains("Domain="));
    assert!(admin.cookies.contains_key("__Host-bloc-admin"));
    assert!(admin.cookies.contains_key(&name));
    assert_eq!(admin.request("GET", "/admin?installation=1", &[]).await.0, 200);
    assert_eq!(
        admin
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
    assert_eq!(
        admin
            .request("GET", &format!("/realms/{OTHER}/account/profile"), &[])
            .await
            .0,
        303
    );
    let bearer = admin.cookies.get(&name).unwrap().clone();
    admin
        .cookies
        .insert(name.clone(), format!("{bearer}; {name}={bearer}"));
    assert_eq!(
        admin
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        303
    );
    admin.cookies.insert(name.clone(), bearer);
    contract_seed_other(&f).await;
    assert_eq!(
        contract_login(&mut admin, OTHER, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    assert_eq!(
        admin
            .request("GET", &format!("/realms/{OTHER}/account/profile"), &[])
            .await
            .0,
        200
    );
    assert_eq!(
        admin
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
    admin.cookies.insert(name, "malformed".into());
    assert_eq!(
        admin
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        303
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c44() {
    contract_expiry_equality().await;
    let (f, _, mut b) = contract_start("realmauthc44", false).await;
    contract_seed(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    sqlx::query("UPDATE bloc.realm_user_session SET expires_at=clock_timestamp()")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        303
    );
    sqlx::query("UPDATE bloc.realm_authentication_settings SET session_idle_seconds=86400,session_absolute_seconds=2592000").execute(&f.admin).await.unwrap();
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
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
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c45() {
    let (f, _, mut b) = contract_start("realmauthc45", false).await;
    contract_seed(&f).await;
    for _ in 0..10 {
        contract_clear_rates(&f).await;
        assert_eq!(
            contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD)
                .await
                .0,
            303
        );
    }
    let oldest: String = sqlx::query_scalar(
        "SELECT id::text FROM bloc.realm_user_session ORDER BY created_at,id LIMIT 1",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    contract_clear_rates(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD)
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
        10
    );
    let ended: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM bloc.realm_user_session WHERE id=$1::text::uuid",
    )
    .bind(oldest)
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert!(ended);
    contract_clear_rates(&f).await;
    let mut other = Browser::new(&f).await;
    let (a, z) = tokio::join!(
        contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD),
        contract_login(&mut other, REALM, "Alice@example.test", CONTRACT_PASSWORD)
    );
    assert_eq!(a.0, 303);
    assert_eq!(z.0, 303);
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        10
    );
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c46() {
    contract_logout_other_realm().await;
    let (f, mut b, _) = contract_start("realmauthc46", false).await;
    contract_seed(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let csrf = b.token(&format!("/realms/{REALM}/account/profile")).await;
    let (s, h, r) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/logout"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(s, 303, "{h}");
    assert!(
        r["location"]
            .to_str()
            .unwrap()
            .starts_with(&format!("/realms/{REALM}/login"))
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        0
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_form_state WHERE purpose='account'"
        )
        .await,
        0
    );
    assert_eq!(b.request("GET", "/admin?installation=1", &[]).await.0, 200);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_auth_c47() {
    let (f, _, mut b) = contract_start("realmauthc47", false).await;
    contract_seed(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let csrf = b.token(&format!("/realms/{REALM}/account/profile")).await;
    f.fail_audit(true).await;
    let (s, h, r) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/logout"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(s, 503, "{h}");
    assert!(r.get_all("set-cookie").iter().any(|v| {
        v.to_str()
            .unwrap()
            .starts_with(&format!("__Host-bloc-realm-{REALM}=;"))
    }));
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
}

#[tokio::test]
#[ignore = "TLS fixture and retained baseline binary"]
async fn realm_auth_upgrade_roles() {
    let f = Fixture::new("realmauthupgrade").await;
    for role in [
        "runtime_user",
        "operator_user",
        "maintenance_user",
        "public_user",
    ] {
        let pool = f.pool(role).await;
        for table in [
            "realm_authentication_settings",
            "realm_user_credential",
            "realm_user_session",
            "realm_user_access_link",
            "realm_form_state",
            "realm_admission_bucket",
            "realm_denial_aggregate",
        ] {
            let query = format!("SELECT * FROM bloc.{table}");
            let error = sqlx::query(sqlx::AssertSqlSafe(query))
                .fetch_all(&pool)
                .await
                .unwrap_err();
            assert_eq!(
                error.as_database_error().unwrap().code().as_deref(),
                Some("42501"),
                "{role}/{table}"
            );
            let writable: bool = sqlx::query_scalar(
                "SELECT has_table_privilege($1,$2,'INSERT,UPDATE,DELETE,TRUNCATE')",
            )
            .bind(role)
            .bind(format!("bloc.{table}"))
            .fetch_one(&f.admin)
            .await
            .unwrap();
            assert!(!writable, "{role} may mutate {table} directly");
        }
        let invalidates: bool = sqlx::query_scalar(
            "SELECT has_function_privilege($1,'bloc.realm_invalidate(uuid,uuid)','EXECUTE')",
        )
        .bind(role)
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert!(!invalidates, "{role} may bypass guarded revocation");
        pool.close().await;
    }
    let legacy = std::env::var("BLOC_REALM_LEGACY_BINARY")
        .expect("retain the pre-0005 binary and set BLOC_REALM_LEGACY_BINARY");
    let output = std::env::temp_dir().join(format!(
        "bloc-realm-upgrade-{}-{}",
        std::process::id(),
        sec::encode(&sec::random().unwrap())
    ));
    let run = std::process::Command::new("python3")
        .args([
            "tests/realm_authentication_binary_compatibility.py",
            "--legacy-binary",
            &legacy,
            "--current-binary",
            env!("CARGO_BIN_EXE_bloc"),
            "--major",
            &std::env::var("BLOC_SETUP_MAJOR").unwrap(),
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
#[ignore = "source-matched native Linux amd64 and arm64 capacity evidence"]
fn realm_auth_native_capacity() {
    let records=std::env::var("BLOC_REALM_NATIVE_SERVICE_EVIDENCE").expect("run native_service_capacity.py --realm-auth on native amd64 and arm64 and supply the combined records");
    let output = std::process::Command::new("python3")
        .args([
            "tests/support/native_service_evidence.py",
            &records,
            "--realm-auth",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn contract_password_boundaries() {
    let (f, mut admin, issue, code) = realm_link_fixture("passwordboundaries").await;
    let mut b = Browser::new(&f).await;
    let boundary = "🦀".repeat(128);
    assert_eq!(boundary.chars().count(), 128);
    assert_eq!(boundary.len(), 512);
    sqlx::query("UPDATE bloc.realm_authentication_settings SET registration_enabled=true")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        contract_register(&mut b, "Boundary@example.test", &boundary, &boundary)
            .await
            .0,
        303
    );
    contract_clear_rates(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "Boundary@example.test", &boundary)
            .await
            .0,
        303
    );
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
    assert_eq!(realm_consume(&mut b, "activate", &boundary).await.0, 303);
    contract_clear_rates(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "person@example.test", &boundary)
            .await
            .0,
        303
    );
    let code = contract_issue(&mut admin, &issue, "reset", "1").await;
    assert_eq!(realm_exchange(&mut b, &code, "reset-password").await.0, 303);
    assert_eq!(
        realm_consume(&mut b, "reset-password", &boundary).await.0,
        303
    );
    contract_clear_rates(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "person@example.test", &boundary)
            .await
            .0,
        303
    );
    let path = format!("/realms/{REALM}/account/password");
    let csrf = b.token(&path).await;
    let replacement = "🐚".repeat(128);
    assert_eq!(replacement.len(), 512);
    assert_eq!(
        b.request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("current_password", &boundary),
                ("password", &replacement),
                ("password_confirmation", &replacement)
            ]
        )
        .await
        .0,
        303
    );
    contract_clear_rates(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "person@example.test", &replacement)
            .await
            .0,
        303
    );
}

async fn contract_shortened_policy() {
    for (label, field, value) in [
        ("shortidle", "session_idle_seconds", "60"),
        ("shortabsolute", "session_absolute_seconds", "300"),
    ] {
        let (f, mut admin, mut b) = contract_start(label, false).await;
        contract_seed(&f).await;
        assert_eq!(
            contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD)
                .await
                .0,
            303
        );
        sqlx::query("UPDATE bloc.realm_user_session SET created_at=clock_timestamp()-interval '10 minutes', last_activity_at=clock_timestamp()-interval '2 minutes', expires_at=clock_timestamp()+interval '20 minutes'").execute(&f.admin).await.unwrap();
        assert_eq!(contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL AND expires_at>clock_timestamp()").await, 1);
        let path = format!("/admin/realms/{REALM}/authentication");
        let csrf = admin.token(&path).await;
        let mut fields = contract_settings(&csrf, "1");
        contract_replace(&mut fields, "session_idle_seconds", "300");
        contract_replace(&mut fields, field, value);
        fields.push(("confirmed", "true"));
        assert_eq!(admin.request("POST", &path, &fields).await.0, 303);
        assert_eq!(
            contract_count(
                &f,
                "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
            )
            .await,
            0
        );
        let mut larger = contract_settings(&csrf, "2");
        contract_replace(&mut larger, "session_idle_seconds", "86400");
        contract_replace(&mut larger, "session_absolute_seconds", "2592000");
        larger.push(("confirmed", "true"));
        assert_eq!(admin.request("POST", &path, &larger).await.0, 303);
        assert_eq!(
            contract_count(
                &f,
                "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
            )
            .await,
            0
        );
        assert_eq!(
            b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
                .await
                .0,
            303
        );
    }
}

async fn contract_logout_other_realm() {
    let (f, mut b, _) = contract_start("logoutotherrealm", false).await;
    contract_seed(&f).await;
    create_realm(&mut b, OTHER, "Other").await;
    contract_seed_other(&f).await;
    for realm in [REALM, OTHER] {
        assert_eq!(
            contract_login(&mut b, realm, "Alice@example.test", CONTRACT_PASSWORD)
                .await
                .0,
            303
        );
    }
    let other_cookie = b.cookies[&format!("__Host-bloc-realm-{OTHER}")].clone();
    let csrf = b.token(&format!("/realms/{REALM}/account/profile")).await;
    assert_eq!(
        b.request(
            "POST",
            &format!("/realms/{REALM}/logout"),
            &[("csrf", &csrf)]
        )
        .await
        .0,
        303
    );
    assert_eq!(
        b.cookies[&format!("__Host-bloc-realm-{OTHER}")],
        other_cookie
    );
    assert_eq!(
        b.request("GET", &format!("/realms/{OTHER}/account/profile"), &[])
            .await
            .0,
        200
    );
    assert_eq!(b.request("GET", "/admin?installation=1", &[]).await.0, 200);
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        303
    );
    let alive: Vec<String> = sqlx::query_scalar(
        "SELECT realm_id::text FROM bloc.realm_user_session WHERE revoked_at IS NULL",
    )
    .fetch_all(&f.admin)
    .await
    .unwrap();
    assert_eq!(alive, vec![OTHER]);
}

async fn contract_lifetime_units() {
    let (f, mut admin, _) = contract_start("lifetimeunits", false).await;
    let path = format!("/admin/realms/{REALM}/authentication");
    let csrf = admin.token(&path).await;
    for (version, value, unit, expected) in [
        ("1", "17", "minutes", 1020),
        ("2", "2", "hours", 7200),
        ("3", "3", "days", 259200),
    ] {
        let mut fields = contract_settings(&csrf, version);
        contract_replace(&mut fields, "activation_ttl_seconds", value);
        fields.push(("activation_ttl_seconds_unit", unit));
        assert_eq!(admin.request("POST", &path, &fields).await.0, 303);
        assert_eq!(
            contract_count(
                &f,
                "SELECT activation_ttl_seconds::bigint FROM bloc.realm_authentication_settings"
            )
            .await,
            expected
        );
    }
    for invalid in ["1.5", "0.00001", "2147483647"] {
        let mut fields = contract_settings(&csrf, "4");
        contract_replace(&mut fields, "activation_ttl_seconds", invalid);
        fields.push(("activation_ttl_seconds_unit", "days"));
        assert_eq!(admin.request("POST", &path, &fields).await.0, 422);
        assert_eq!(
            contract_count(
                &f,
                "SELECT activation_ttl_seconds::bigint FROM bloc.realm_authentication_settings"
            )
            .await,
            259200
        );
    }
    let mut pending = contract_settings(&csrf, "4");
    contract_replace(&mut pending, "session_limit", "5");
    assert_eq!(admin.request("POST", &path, &pending).await.0, 200);
    let mut competing = contract_settings(&csrf, "4");
    contract_replace(&mut competing, "password_min_length", "17");
    assert_eq!(admin.request("POST", &path, &competing).await.0, 303);
    pending.push(("confirmed", "true"));
    let (status, html, _) = admin.request("POST", &path, &pending).await;
    assert_eq!(status, 409, "{html}");
    assert!(html.to_lowercase().contains("reload"));
    assert_eq!(
        contract_count(
            &f,
            "SELECT session_limit::bigint FROM bloc.realm_authentication_settings"
        )
        .await,
        10
    );
    for control in [
        "require_uppercase",
        "require_lowercase",
        "require_number",
        "require_special",
    ] {
        let version = contract_count(&f, "SELECT version FROM bloc.realm_authentication_settings")
            .await
            .to_string();
        let mut fields = contract_settings(&csrf, &version);
        fields.push((control, "true"));
        assert_eq!(admin.request("POST", &path, &fields).await.0, 303);
        let flags: (bool, bool, bool, bool) = sqlx::query_as("SELECT require_uppercase,require_lowercase,require_number,require_special FROM bloc.realm_authentication_settings").fetch_one(&f.admin).await.unwrap();
        assert_eq!(
            flags,
            (
                control == "require_uppercase",
                control == "require_lowercase",
                control == "require_number",
                control == "require_special"
            )
        );
    }
}

async fn contract_link_lifetimes() {
    let (f, mut admin, activation_path, _) = realm_link_fixture("linklifetimes").await;
    let reset_user = "55555555-5555-4555-8555-555555555555";
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES($1::text::uuid,$2::text::uuid,'Reset@example.test',clock_timestamp(),clock_timestamp())").bind(reset_user).bind(REALM).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_credential VALUES($1::text::uuid,$2::text::uuid,$3,1,clock_timestamp())").bind(REALM).bind(reset_user).bind(common::HASH).execute(&f.admin).await.unwrap();
    let reset_path = format!("/admin/realms/{REALM}/users/{reset_user}/access-links");
    contract_issue(&mut admin, &reset_path, "reset", "1").await;
    let before: Vec<(String, String)> = sqlx::query_as(
        "SELECT purpose,expires_at::text FROM bloc.realm_user_access_link ORDER BY purpose",
    )
    .fetch_all(&f.admin)
    .await
    .unwrap();
    let original: Vec<(String, i64)> = sqlx::query_as("SELECT purpose,extract(epoch FROM expires_at-issued_at)::bigint FROM bloc.realm_user_access_link ORDER BY purpose").fetch_all(&f.admin).await.unwrap();
    assert_eq!(
        original,
        vec![("activation".into(), 86400), ("reset".into(), 1800)]
    );
    let path = format!("/admin/realms/{REALM}/authentication");
    let csrf = admin.token(&path).await;
    let mut fields = contract_settings(&csrf, "1");
    contract_replace(&mut fields, "activation_ttl_seconds", "604800");
    contract_replace(&mut fields, "reset_ttl_seconds", "86400");
    assert_eq!(admin.request("POST", &path, &fields).await.0, 303);
    let after: Vec<(String, String)> = sqlx::query_as(
        "SELECT purpose,expires_at::text FROM bloc.realm_user_access_link ORDER BY purpose",
    )
    .fetch_all(&f.admin)
    .await
    .unwrap();
    assert_eq!(before, after);
    contract_clear_rates(&f).await;
    contract_issue(&mut admin, &activation_path, "activation", "1").await;
    contract_issue(&mut admin, &reset_path, "reset", "1").await;
    let subsequent: Vec<(String, i64)> = sqlx::query_as("SELECT purpose,extract(epoch FROM expires_at-issued_at)::bigint FROM bloc.realm_user_access_link ORDER BY purpose").fetch_all(&f.admin).await.unwrap();
    assert_eq!(
        subsequent,
        vec![("activation".into(), 604800), ("reset".into(), 86400)]
    );
}

async fn contract_expiry_equality() {
    let (f, _, mut b) = contract_start("expiryequality", false).await;
    contract_seed(&f).await;
    assert_eq!(
        contract_login(&mut b, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let digest = sec::digest(&b.cookies[&format!("__Host-bloc-realm-{REALM}")]);
    for boundary in ["stored", "idle", "absolute"] {
        let mut tx = f.admin.begin().await.unwrap();
        let definition: String =
            sqlx::query_scalar("SELECT pg_get_functiondef('bloc.realm_lock()'::regprocedure)")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert!(definition.contains("RETURN clock_timestamp()"));
        let fixed =
            definition.replace("RETURN clock_timestamp()", "RETURN transaction_timestamp()");
        sqlx::raw_sql(sqlx::AssertSqlSafe(fixed))
            .execute(&mut *tx)
            .await
            .unwrap();
        let fixture = match boundary {
            "stored" => {
                "UPDATE bloc.realm_user_session SET created_at=transaction_timestamp()-interval '1 minute',last_activity_at=transaction_timestamp(),expires_at=transaction_timestamp()"
            }
            "idle" => {
                "UPDATE bloc.realm_user_session SET created_at=transaction_timestamp()-interval '1 hour',last_activity_at=transaction_timestamp()-interval '1800 seconds',expires_at=transaction_timestamp()+interval '1 hour'"
            }
            _ => {
                "UPDATE bloc.realm_user_session SET created_at=transaction_timestamp()-interval '43200 seconds',last_activity_at=transaction_timestamp(),expires_at=transaction_timestamp()+interval '1 hour'"
            }
        };
        sqlx::raw_sql(fixture).execute(&mut *tx).await.unwrap();
        let before: String = sqlx::query_scalar("SELECT jsonb_build_array(created_at,last_activity_at,expires_at)::text FROM bloc.realm_user_session").fetch_one(&mut *tx).await.unwrap();
        let absent: bool =
            sqlx::query_scalar("SELECT (bloc.realm_session($1::text::uuid,$2,true)).id IS NULL")
                .bind(REALM)
                .bind(digest.as_slice())
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert!(absent, "{boundary} equality must expire before refresh");
        let revoked: bool = sqlx::query_scalar(
            "SELECT revoked_at=transaction_timestamp() FROM bloc.realm_user_session",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert!(revoked);
        let after: String = sqlx::query_scalar("SELECT jsonb_build_array(created_at,last_activity_at,expires_at)::text FROM bloc.realm_user_session").fetch_one(&mut *tx).await.unwrap();
        assert_eq!(before, after, "expired session timestamps must not refresh");
        sqlx::query("UPDATE bloc.realm_authentication_settings SET session_idle_seconds=86400,session_absolute_seconds=2592000").execute(&mut *tx).await.unwrap();
        let still_absent: bool =
            sqlx::query_scalar("SELECT (bloc.realm_session($1::text::uuid,$2,true)).id IS NULL")
                .bind(REALM)
                .bind(digest.as_slice())
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert!(still_absent, "{boundary} expiry must never revive");
        let forms: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM bloc.realm_form_state WHERE purpose='account'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(forms, 0);
        tx.rollback().await.unwrap();
        let restored: String =
            sqlx::query_scalar("SELECT pg_get_functiondef('bloc.realm_lock()'::regprocedure)")
                .fetch_one(&f.admin)
                .await
                .unwrap();
        assert_eq!(restored, definition);
    }
}

async fn contract_registration_history() {
    let (f, _, mut b) = contract_start("registrationhistory", true).await;
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,status,created_at,updated_at) SELECT gen_random_uuid(),$1::text::uuid,'Historical'||n||'@example.test','suspended',clock_timestamp(),clock_timestamp() FROM generate_series(1,10001) n").bind(REALM).execute(&f.admin).await.unwrap();
    assert_eq!(
        contract_register(
            &mut b,
            "New@example.test",
            CONTRACT_PASSWORD,
            CONTRACT_PASSWORD
        )
        .await
        .0,
        303
    );
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user").await,
        10002
    );
    let missing = "66666666-6666-4666-8666-666666666666";
    let (status, _, _) = b
        .request(
            "POST",
            &format!("/realms/{missing}/register"),
            &[
                ("csrf", "invalid"),
                ("email", "Never@example.test"),
                ("password", CONTRACT_PASSWORD),
                ("password_confirmation", CONTRACT_PASSWORD),
            ],
        )
        .await;
    assert_eq!(status, 404);
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user").await,
        10002
    );
}

include!("realm_authentication_account_contracts.rs");
