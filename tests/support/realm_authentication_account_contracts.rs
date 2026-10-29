async fn prove_profile_boundaries() {
    let (f, mut b) = realm_fixture("profileboundaries").await;
    realm_login(&mut b, REALM).await;
    let path = format!("/realms/{REALM}/account/profile");
    let csrf = b.token(&path).await;
    let boundary = "🦀".repeat(128);
    assert_eq!(boundary.len(), 512);
    for (version, value, expected) in [
        ("1", boundary.as_str(), Some(boundary.as_str())),
        ("2", "  ", None),
    ] {
        let (status, html, headers) = b
            .request(
                "POST",
                &path,
                &[
                    ("csrf", &csrf),
                    ("version", version),
                    ("display_name", value),
                ],
            )
            .await;
        assert_eq!(status, 303, "{html}");
        assert_eq!(headers["location"], format!("{path}?saved=1"));
        let actual: Option<String> = sqlx::query_scalar(
            "SELECT display_name FROM bloc.realm_user WHERE realm_id=$1::text::uuid",
        )
        .bind(REALM)
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert_eq!(actual.as_deref(), expected);
    }
    assert_eq!(realm_audit(&f, "realm_profile_update").await, 2);
    let (status, html, _) = b.request("GET", &format!("{path}?saved=1"), &[]).await;
    assert_eq!(status, 200);
    assert!(html.contains("Your profile was saved."), "{html}");
    for value in ["a".repeat(129), "🦀".repeat(129), "control\nname".into()] {
        let before = contract_snapshot(&f).await;
        let (status, html, _) = b
            .request(
                "POST",
                &path,
                &[("csrf", &csrf), ("version", "3"), ("display_name", &value)],
            )
            .await;
        assert_eq!(status, 422, "{html}");
        assert!(html.contains("id=\"display_name-error\""));
        assert!(html.contains("aria-invalid=\"true\""));
        assert_eq!(contract_snapshot(&f).await, before);
    }
}

async fn prove_profile_conflicts() {
    let (f, mut b) = realm_fixture("profileconflicts").await;
    realm_login(&mut b, REALM).await;
    let path = format!("/realms/{REALM}/account/profile");
    let csrf = b.token(&path).await;
    sqlx::query("UPDATE bloc.realm_user SET display_name='Administrator edit',version=version+1 WHERE realm_id=$1::text::uuid").bind(REALM).execute(&f.admin).await.unwrap();
    let before = contract_snapshot(&f).await;
    let (status, html, _) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("display_name", "Stale overwrite"),
            ],
        )
        .await;
    assert_eq!(status, 409);
    assert!(html.to_lowercase().contains("reload"));
    assert_eq!(contract_snapshot(&f).await, before);
    let (status, html, _) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", "2"),
                ("display_name", "control\nname"),
            ],
        )
        .await;
    assert_eq!(status, 422);
    assert!(html.contains("id=\"display_name-error\""));
    assert!(html.contains("aria-describedby=\"display_name-help display_name-error\""));
    assert_eq!(contract_snapshot(&f).await, before);
}

async fn account_session_id(f: &Fixture, b: &Browser) -> String {
    let digest = sec::digest(&b.cookies[&format!("__Host-bloc-realm-{REALM}")]);
    sqlx::query_scalar("SELECT id::text FROM bloc.realm_user_session WHERE session_digest=$1")
        .bind(digest.as_slice())
        .fetch_one(&f.admin)
        .await
        .unwrap()
}

async fn prove_owned_revocation() {
    let (f, mut current) = realm_fixture("ownedrevocation").await;
    realm_login(&mut current, REALM).await;
    let mut one = Browser::new(&f).await;
    let mut two = Browser::new(&f).await;
    realm_login(&mut one, REALM).await;
    realm_login(&mut two, REALM).await;
    let one_id = account_session_id(&f, &one).await;
    let two_id = account_session_id(&f, &two).await;
    let current_id = account_session_id(&f, &current).await;
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_form_state WHERE purpose='account'"
        )
        .await,
        3
    );
    let base = format!("/realms/{REALM}/account/sessions");
    for (path, targets, event_count) in [
        (format!("{base}/{one_id}/revoke"), vec![one_id.as_str()], 1),
        (format!("{base}/revoke-others"), vec![two_id.as_str()], 2),
    ] {
        let csrf = current.token(&base).await;
        let before = contract_snapshot(&f).await;
        let (status, html, _) = current.request("POST", &path, &[("csrf", &csrf)]).await;
        assert_eq!(status, 200);
        assert!(html.contains("End "));
        assert!(html.contains("name=\"confirmed\" value=\"true\""));
        assert_eq!(
            contract_snapshot(&f).await,
            before,
            "confirmation must not mutate authority"
        );
        f.fail_audit(true).await;
        assert_eq!(
            current
                .request("POST", &path, &[("csrf", &csrf), ("confirmed", "true")])
                .await
                .0,
            503
        );
        assert_eq!(
            contract_snapshot(&f).await,
            before,
            "revoke and audit are atomic"
        );
        f.fail_audit(false).await;
        let (status, html, headers) = current
            .request("POST", &path, &[("csrf", &csrf), ("confirmed", "true")])
            .await;
        assert_eq!(status, 303, "{html}");
        assert!(headers["location"].to_str().unwrap().starts_with(&base));
        for target in targets {
            let ended:bool=sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM bloc.realm_user_session WHERE id=$1::text::uuid").bind(target).fetch_one(&f.admin).await.unwrap();
            assert!(ended);
            let forms: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM bloc.realm_form_state WHERE session_id=$1::text::uuid",
            )
            .bind(target)
            .fetch_one(&f.admin)
            .await
            .unwrap();
            assert_eq!(forms, 0);
        }
        assert_eq!(realm_audit(&f, "realm_session_revoke").await, event_count);
        assert_eq!(
            current
                .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
                .await
                .0,
            200
        );
    }
    let active: Vec<String> =
        sqlx::query_scalar("SELECT id::text FROM bloc.realm_user_session WHERE revoked_at IS NULL")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    assert_eq!(active, vec![current_id]);
    for ended in [&mut one, &mut two] {
        assert_eq!(
            ended
                .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
                .await
                .0,
            303
        );
    }
}

async fn prove_foreign_revocation() {
    let (f, mut b) = realm_fixture("foreignrevocation").await;
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES('77777777-7777-4777-8777-777777777777',$1::text::uuid,'Foreign@example.test',clock_timestamp(),clock_timestamp())").bind(REALM).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_credential SELECT realm_id,'77777777-7777-4777-8777-777777777777',password_hash,1,clock_timestamp() FROM bloc.realm_user_credential WHERE realm_id=$1::text::uuid").bind(REALM).execute(&f.admin).await.unwrap();
    realm_login(&mut b, REALM).await;
    let mut foreign = Browser::new(&f).await;
    assert_eq!(
        contract_login(&mut foreign, REALM, "Foreign@example.test", REALM_PASSWORD)
            .await
            .0,
        303
    );
    let foreign_id = account_session_id(&f, &foreign).await;
    let current_id = account_session_id(&f, &b).await;
    let csrf = b.token(&format!("/realms/{REALM}/account/sessions")).await;
    let before = contract_snapshot(&f).await;
    let (status, html, _) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/account/sessions/{foreign_id}/revoke"),
            &[("csrf", &csrf), ("confirmed", "true")],
        )
        .await;
    assert_eq!(status, 404);
    assert!(!html.contains("Foreign@example.test"));
    assert_eq!(contract_snapshot(&f).await, before);
    assert_eq!(
        foreign
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
    let (status, _, headers) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/account/sessions/{current_id}/revoke"),
            &[("csrf", &csrf), ("confirmed", "true")],
        )
        .await;
    assert_eq!(status, 303);
    assert!(
        headers["location"]
            .to_str()
            .unwrap()
            .starts_with(&format!("/realms/{REALM}/login"))
    );
    assert_eq!(
        b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        303
    );
    assert_eq!(
        foreign
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
}

async fn prove_session_inventory() {
    let (f, mut current) = realm_fixture("sessioninventory").await;
    realm_login(&mut current, REALM).await;
    let mut expired = Browser::new(&f).await;
    realm_login(&mut expired, REALM).await;
    let expired_id = account_session_id(&f, &expired).await;
    sqlx::query("UPDATE bloc.realm_user_session SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1::text::uuid").bind(&expired_id).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES('88888888-8888-4888-8888-888888888888',$1::text::uuid,'OtherPerson@example.test',clock_timestamp(),clock_timestamp())").bind(REALM).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_credential SELECT realm_id,'88888888-8888-4888-8888-888888888888',password_hash,1,clock_timestamp() FROM bloc.realm_user_credential WHERE realm_id=$1::text::uuid").bind(REALM).execute(&f.admin).await.unwrap();
    let mut foreign = Browser::new(&f).await;
    assert_eq!(
        contract_login(
            &mut foreign,
            REALM,
            "OtherPerson@example.test",
            REALM_PASSWORD
        )
        .await
        .0,
        303
    );
    let foreign_id = account_session_id(&f, &foreign).await;
    let current_id = account_session_id(&f, &current).await;
    let (status, html, _) = current
        .request("GET", &format!("/realms/{REALM}/account/sessions"), &[])
        .await;
    assert_eq!(status, 200);
    assert!(html.contains(&format!("/sessions/{current_id}/revoke")));
    assert!(!html.contains(&format!("/sessions/{expired_id}/revoke")));
    assert!(!html.contains(&format!("/sessions/{foreign_id}/revoke")));
    assert!(!html.contains("OtherPerson@example.test"));
    assert_eq!(html.matches("Current session").count(), 1);
    let heading = html
        .split("<div class=\"heading\">")
        .nth(1)
        .unwrap()
        .split("<div class=\"table-wrap")
        .next()
        .unwrap();
    assert!(heading.contains("End all other sessions"));
    let body = html
        .split("<tbody>")
        .nth(1)
        .unwrap()
        .split("</tbody>")
        .next()
        .unwrap();
    assert_eq!(body.matches("<tr>").count(), 1);
    assert!(!body.contains("End all other sessions"));
}

async fn prove_device_labels() {
    let (f, _) = realm_fixture("devicelabels").await;
    for (user_agent, expected) in [
        ("opaque-client-no-fingerprint".to_owned(), "Unknown device"),
        (
            "Mozilla/5.0 (iPhone) Safari/605.1".to_owned(),
            "Safari · iPhone",
        ),
        (
            format!("Firefox/150 Linux\t<script>{}", "x".repeat(4096)),
            "Firefox · Linux",
        ),
    ] {
        contract_clear_rates(&f).await;
        let mut b = Browser::new(&f).await;
        let path = format!("/realms/{REALM}/login");
        let csrf = b.token(&path).await;
        let (status, _, headers) = realm_raw(
            &b,
            "POST",
            &path,
            realm_encoded(&[
                ("csrf", &csrf),
                ("email", "person@example.test"),
                ("password", REALM_PASSWORD),
            ]),
            &[("user-agent", &user_agent)],
        )
        .await;
        assert_eq!(status, 303);
        for cookie in headers.get_all("set-cookie") {
            let (key, value) = cookie
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .split_once('=')
                .unwrap();
            b.cookies.insert(key.into(), value.into());
        }
        let id = account_session_id(&f, &b).await;
        let label: String = sqlx::query_scalar(
            "SELECT device_label FROM bloc.realm_user_session WHERE id=$1::text::uuid",
        )
        .bind(&id)
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert_eq!(label, expected);
        assert!(label.chars().count() <= 128 && label.len() <= 512);
        assert!(!label.chars().any(char::is_control));
        assert!(!label.contains("<script>"));
        let (status, html, _) = b
            .request("GET", &format!("/realms/{REALM}/account/sessions"), &[])
            .await;
        assert_eq!(status, 200);
        let(created,active):(String,String)=sqlx::query_as("SELECT to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS'),to_char(last_activity_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') FROM bloc.realm_user_session WHERE id=$1::text::uuid").bind(&id).fetch_one(&f.admin).await.unwrap();
        let row = html
            .split("<tr>")
            .find(|row| row.contains(&format!("/sessions/{id}/revoke")))
            .unwrap();
        assert!(row.contains(&format!("<td>{expected}</td>")));
        assert!(row.contains(&format!("<td>{created}</td>")));
        assert!(row.contains(&format!("<td>{active}</td>")));
        assert!(!html.contains(&user_agent));
    }
}

async fn prove_lifecycle_link_invalidation() {
    for scope in ["user", "realm"] {
        let (f, mut admin, issue, activation) =
            realm_link_fixture(&format!("lifecyclelinks{scope}")).await;
        let mut b = Browser::new(&f).await;
        assert_eq!(realm_exchange(&mut b, &activation, "activate").await.0, 303);
        assert_eq!(
            realm_consume(&mut b, "activate", REALM_PASSWORD).await.0,
            303
        );
        realm_login(&mut b, REALM).await;
        let code = contract_issue(&mut admin, &issue, "reset", "1").await;
        let mut link = Browser::new(&f).await;
        assert_eq!(
            realm_exchange(&mut link, &code, "reset-password").await.0,
            303
        );
        let link_path = format!("/realms/{REALM}/reset-password");
        let link_csrf = link.token(&link_path).await;
        assert_eq!(
            realm_count(&f, "SELECT count(*) FROM bloc.realm_user_access_link").await,
            1
        );
        assert_eq!(
            realm_count(
                &f,
                "SELECT count(*) FROM bloc.realm_form_state WHERE purpose IN('account','reset')"
            )
            .await,
            2
        );
        let target = if scope == "user" {
            format!("/admin/realms/{REALM}/users/{USER}")
        } else {
            format!("/admin/realms/{REALM}")
        };
        let csrf = admin.token(&target).await;
        let path = format!("{target}/status");
        let fields = [
            ("csrf", csrf.as_str()),
            ("version", "1"),
            ("status", "suspended"),
        ];
        let before = contract_snapshot(&f).await;
        f.fail_audit(true).await;
        assert_eq!(admin.request("POST", &path, &fields).await.0, 503);
        assert_eq!(contract_snapshot(&f).await, before);
        f.fail_audit(false).await;
        assert_eq!(admin.request("POST", &path, &fields).await.0, 303);
        assert_eq!(
            realm_count(&f, "SELECT count(*) FROM bloc.realm_user_access_link").await,
            0
        );
        assert_eq!(
            realm_count(
                &f,
                "SELECT count(*) FROM bloc.realm_form_state WHERE purpose IN('account','reset')"
            )
            .await,
            0
        );
        assert_eq!(
            realm_count(
                &f,
                "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
            )
            .await,
            0
        );
        assert_eq!(
            admin
                .request(
                    "POST",
                    &path,
                    &[("csrf", &csrf), ("version", "2"), ("status", "active")]
                )
                .await
                .0,
            303
        );
        assert_eq!(
            b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
                .await
                .0,
            303
        );
        assert_eq!(
            link.request(
                "POST",
                &link_path,
                &[
                    ("csrf", &link_csrf),
                    ("password", REALM_PASSWORD),
                    ("password_confirmation", REALM_PASSWORD)
                ]
            )
            .await
            .0,
            403
        );
        assert_eq!(
            realm_exchange(&mut link, &code, "reset-password").await.0,
            403
        );
        assert_eq!(
            realm_count(&f, "SELECT count(*) FROM bloc.realm_user_credential").await,
            1
        );
    }
}

async fn prove_restore_link_invalidation() {
    let (f, mut admin, issue, activation) = realm_link_fixture("restorelinks").await;
    let mut b = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut b, &activation, "activate").await.0, 303);
    assert_eq!(
        realm_consume(&mut b, "activate", REALM_PASSWORD).await.0,
        303
    );
    realm_login(&mut b, REALM).await;
    let code = contract_issue(&mut admin, &issue, "reset", "1").await;
    assert_eq!(realm_exchange(&mut b, &code, "reset-password").await.0, 303);
    let link_path = format!("/realms/{REALM}/reset-password");
    let csrf = b.token(&link_path).await;
    let mut replica = Browser::new(&f).await;
    replica.cookies = b.cookies.clone();
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_access_link").await,
        1
    );
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        1
    );
    assert!(realm_count(&f, "SELECT count(*) FROM bloc.realm_form_state").await >= 3);
    f.operator.invalidate_access().await.unwrap();
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_access_link").await,
        0
    );
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_form_state").await,
        0
    );
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        0
    );
    let fields = [
        ("csrf", csrf.as_str()),
        ("password", REALM_PASSWORD),
        ("password_confirmation", REALM_PASSWORD),
    ];
    for browser in [&mut b, &mut replica] {
        assert_eq!(
            browser
                .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
                .await
                .0,
            503
        );
        assert_eq!(browser.request("POST", &link_path, &fields).await.0, 503);
    }
    sqlx::query("UPDATE bloc.installation SET recovery_required=false")
        .execute(&f.admin)
        .await
        .unwrap();
    for browser in [&mut b, &mut replica] {
        assert_eq!(
            browser
                .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
                .await
                .0,
            303
        );
        assert_eq!(browser.request("POST", &link_path, &fields).await.0, 403);
        assert_eq!(
            realm_exchange(browser, &code, "reset-password").await.0,
            403
        );
    }
    assert_eq!(realm_audit(&f, "realm_password_reset").await, 0);
}

async fn prove_clean_signin_recovery() {
    let (f, mut original, _) = contract_start("cleansigninrecovery", false).await;
    contract_seed(&f).await;
    create_realm(&mut original, OTHER, "Other").await;
    contract_seed_other(&f).await;
    assert_eq!(
        contract_login(
            &mut original,
            OTHER,
            "Alice@example.test",
            CONTRACT_PASSWORD
        )
        .await
        .0,
        303
    );
    let cookies = original.cookies.clone();
    let mut clean = Browser::new(&f).await;
    let (status, html, headers) = clean
        .request("GET", &format!("/realms/{REALM}/login"), &[])
        .await;
    assert_eq!(status, 200);
    assert!(html.contains("try a private window"));
    assert!(html.contains("Your other realm and administrator sessions stay unchanged"));
    for value in headers.get_all("set-cookie") {
        let value = value.to_str().unwrap();
        assert!(!value.starts_with("__Host-bloc-admin="));
        assert!(!value.starts_with(&format!("__Host-bloc-realm-{OTHER}=")));
    }
    assert_eq!(
        contract_login(&mut clean, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    assert_eq!(
        clean
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
    assert_eq!(original.cookies, cookies);
    assert_eq!(original.request("GET", "/admin", &[]).await.0, 200);
    assert_eq!(
        original
            .request("GET", &format!("/realms/{OTHER}/account/profile"), &[])
            .await
            .0,
        200
    );
}
