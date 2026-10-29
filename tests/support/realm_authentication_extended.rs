async fn realm_raw(
    b: &Browser,
    method: &str,
    path: &str,
    body: String,
    extra: &[(&str, &str)],
) -> (StatusCode, String, axum::http::HeaderMap) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "bloc.example.test")
        .header("origin", "https://bloc.example.test")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "192.0.2.4")
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "cookie",
            b.cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
        .body(Body::from(body))
        .unwrap();
    for name in extra
        .iter()
        .map(|(k, _)| *k)
        .collect::<std::collections::BTreeSet<_>>()
    {
        request.headers_mut().remove(name);
    }
    for (name, value) in extra {
        request.headers_mut().append(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = b.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 200000).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap(), headers)
}
fn realm_encoded(fields: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish()
}
async fn realm_authority_snapshot(f: &Fixture) -> String {
    sqlx::query_scalar("SELECT jsonb_build_object('users',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM bloc.realm_user t),'credentials',(SELECT jsonb_agg(to_jsonb(t) ORDER BY user_id) FROM bloc.realm_user_credential t),'sessions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM bloc.realm_user_session t),'forms',(SELECT jsonb_agg(to_jsonb(t) ORDER BY browser_digest) FROM bloc.realm_form_state t),'links',(SELECT jsonb_agg(to_jsonb(t) ORDER BY token_digest) FROM bloc.realm_user_access_link t),'events',(SELECT count(*) FROM bloc.security_audit_event))::text").fetch_one(&f.admin).await.unwrap()
}
async fn prove_protected_refusals(name: &str) {
    let (f, mut b) = realm_fixture(name).await;
    realm_login(&mut b, REALM).await;
    let path = format!("/realms/{REALM}/account/profile");
    let csrf = b.token(&path).await;
    let valid = realm_encoded(&[
        ("csrf", &csrf),
        ("version", "1"),
        ("display_name", "Refused"),
    ]);
    let before = realm_authority_snapshot(&f).await;
    for (body, headers, status) in [
        (
            valid.clone(),
            vec![("origin", "https://foreign.example")],
            403,
        ),
        (
            valid.clone(),
            vec![("content-type", "application/json")],
            415,
        ),
        ("csrf=%GG".into(), vec![], 400),
        (format!("csrf={}", "x".repeat(16385)), vec![], 413),
        (
            realm_encoded(&[
                ("csrf", "invalid"),
                ("version", "1"),
                ("display_name", "Refused"),
            ]),
            vec![],
            403,
        ),
        (valid.clone(), vec![("cookie", "")], 303),
    ] {
        let (s, _, _) = realm_raw(&b, "POST", &path, body, &headers).await;
        assert_eq!(s, status);
        assert_eq!(realm_authority_snapshot(&f).await, before);
    }
    let password = format!("/realms/{REALM}/account/password");
    for (current, replacement) in [
        (
            "incorrect current password",
            "a compliant replacement password",
        ),
        (REALM_PASSWORD, "short"),
    ] {
        let (s, h, _) = b
            .request(
                "POST",
                &password,
                &[
                    ("csrf", &csrf),
                    ("current_password", current),
                    ("password", replacement),
                    ("password_confirmation", replacement),
                ],
            )
            .await;
        assert_eq!(s, 422);
        assert!(h.contains("aria-invalid=\"true\""));
        for field in ["current_password", "password", "password_confirmation"] {
            assert!(h.contains(&format!("name=\"{field}\" type=\"password\" value=\"\"")));
        }
        for secret in [current, replacement] {
            assert!(!h.contains(&format!("value=\"{secret}\"")));
        }
        assert_eq!(realm_authority_snapshot(&f).await, before);
    }
    let (s, h, _) = b
        .request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", "999"),
                ("display_name", "Refused"),
            ],
        )
        .await;
    assert_eq!(s, 409);
    assert!(h.contains("Reload"));
    assert_eq!(realm_authority_snapshot(&f).await, before);
}
async fn prove_http_allowances() {
    for (scope, limit) in [
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
        let (f, mut b, path, code) = if matches!(scope, "link" | "link_issue") {
            realm_link_fixture(&format!("http_budget_{scope}")).await
        } else {
            let (f, b) = realm_fixture(&format!("http_budget_{scope}")).await;
            (f, b, String::new(), String::new())
        };
        let route = match scope {
            "form_source" => "login",
            "registration_realm" | "registration_identifier" => "register",
            "exchange_source" | "exchange_realm" => "activate",
            "link" => "activate",
            "password_change" => "account/password",
            "account_mutation" => "account/profile",
            _ => "login",
        };
        if scope.starts_with("registration") {
            sqlx::query("UPDATE bloc.realm_authentication_settings SET registration_enabled=true")
                .execute(&f.admin)
                .await
                .unwrap();
        }
        if matches!(scope, "password_change" | "account_mutation") {
            realm_login(&mut b, REALM).await;
        }
        if scope == "link" {
            b = Browser::new(&f).await;
            assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
            f.fail_audit(true).await;
        }
        let route_path = if scope == "link_issue" {
            path
        } else {
            format!("/realms/{REALM}/{route}")
        };
        let csrf = if scope == "form_source" {
            String::new()
        } else {
            b.token(&route_path).await
        };
        realm_clear_budgets(&f).await;
        for i in 0..=limit {
            // Isolate this named allowance while preserving its real HTTP-derived key and events.
            sqlx::query("DELETE FROM bloc.realm_admission_bucket WHERE scope<>$1")
                .bind(scope)
                .execute(&f.admin)
                .await
                .unwrap();
            sqlx::query("DELETE FROM bloc.administrator_admission_bucket WHERE scope<>$1")
                .bind(scope)
                .execute(&f.admin)
                .await
                .unwrap();
            let mut fields = vec![("csrf", csrf.as_str())];
            match scope {
                "registration_realm" | "registration_identifier" => fields.extend([
                    ("email", "person@example.test"),
                    ("display_name", "Person"),
                    ("password", REALM_PASSWORD),
                    ("password_confirmation", REALM_PASSWORD),
                ]),
                "exchange_source" | "exchange_realm" => fields.push(("code", "invalid")),
                "link" => fields.extend([
                    ("password", REALM_PASSWORD),
                    ("password_confirmation", REALM_PASSWORD),
                ]),
                "password_change" => fields.extend([
                    ("current_password", "wrong current password"),
                    ("password", REALM_PASSWORD),
                    ("password_confirmation", REALM_PASSWORD),
                ]),
                "link_issue" => fields.extend([
                    ("version", "1"),
                    ("purpose", "activation"),
                    ("identity_confirmed", "true"),
                ]),
                "account_mutation" => fields.extend([("version", "1"), ("display_name", "Person")]),
                _ => fields.extend([
                    ("email", "unknown@example.test"),
                    ("password", "wrong password"),
                ]),
            }
            let exchange = scope.starts_with("exchange_");
            let target = if exchange {
                format!("{route_path}/exchange")
            } else {
                route_path.clone()
            };
            if scope == "form_source" {
                b.cookies.clear();
            }
            let (s, _, headers) = b
                .request(
                    if scope == "form_source" {
                        "GET"
                    } else {
                        "POST"
                    },
                    &target,
                    &fields,
                )
                .await;
            if i == limit {
                assert_eq!(s, 429, "{scope}");
                let retry: i32 = headers["retry-after"].to_str().unwrap().parse().unwrap();
                assert!((1..=60).contains(&retry));
            } else {
                let expected = match scope {
                    "form_source" | "link_issue" => 200,
                    "exchange_source" | "exchange_realm" => 403,
                    "link" => 503,
                    "account_mutation" => 303,
                    _ => 422,
                };
                assert_eq!(s, expected, "{scope} request {i}");
            }
            let sql = if scope == "hash_work" {
                "SELECT coalesce(sum(cardinality(admitted_at)),0)::bigint FROM bloc.administrator_admission_bucket WHERE scope=$1"
            } else {
                "SELECT coalesce(sum(cardinality(admitted_at)),0)::bigint FROM bloc.realm_admission_bucket WHERE scope=$1"
            };
            let actual: i64 = sqlx::query_scalar(sql)
                .bind(scope)
                .fetch_one(&f.admin)
                .await
                .unwrap();
            assert_eq!(actual, i64::from((i + 1).min(limit)), "{scope}");
        }
    }
}
async fn prove_replica_last_slot() {
    let (f, mut a) = realm_fixture("http_replica_last_slot").await;
    let mut b = Browser::new(&f).await;
    let path = format!("/realms/{REALM}/login");
    let ca = a.token(&path).await;
    let cb = b.token(&path).await;
    realm_clear_budgets(&f).await;
    sqlx::query("INSERT INTO bloc.administrator_admission_bucket VALUES('hash_work',$1,array_fill(clock_timestamp(),ARRAY[29]),clock_timestamp()+interval '2 minutes')").bind(vec![0u8;32]).execute(&f.admin).await.unwrap();
    let fa = [
        ("csrf", ca.as_str()),
        ("email", "a@example.test"),
        ("password", "wrong password"),
    ];
    let fb = [
        ("csrf", cb.as_str()),
        ("email", "b@example.test"),
        ("password", "wrong password"),
    ];
    let (x, y) = tokio::join!(a.request("POST", &path, &fa), b.request("POST", &path, &fb));
    let mut statuses = vec![x.0.as_u16(), y.0.as_u16()];
    statuses.sort();
    assert_eq!(statuses, [422, 429]);
    let rejected = if x.0 == 429 { x } else { y };
    assert!(
        (1..=60).contains(
            &rejected.2["retry-after"]
                .to_str()
                .unwrap()
                .parse::<i32>()
                .unwrap()
        )
    );
    assert_eq!(realm_count(&f,"SELECT cardinality(admitted_at)::bigint FROM bloc.administrator_admission_bucket WHERE scope='hash_work'").await,30);
    assert_eq!(realm_count(&f,"SELECT cardinality(admitted_at)::bigint FROM bloc.realm_admission_bucket WHERE scope='public_work'").await,1);
}
async fn prove_suspended_issuance() {
    for kind in ["user", "realm"] {
        let (f, mut admin, path, _) = realm_link_fixture(&format!("issue_suspended_{kind}")).await;
        let csrf = admin.token(&path).await;
        let update = if kind == "user" {
            "UPDATE bloc.realm_user SET status='suspended'"
        } else {
            "UPDATE bloc.realm SET status='suspended'"
        };
        sqlx::query(update).execute(&f.admin).await.unwrap();
        let before = realm_authority_snapshot(&f).await;
        for method in ["GET", "POST"] {
            let (s, html, _) = admin
                .request(
                    method,
                    &path,
                    &[
                        ("csrf", &csrf),
                        ("version", "1"),
                        ("purpose", "activation"),
                        ("identity_confirmed", "true"),
                    ],
                )
                .await;
            assert_eq!(s, if method == "GET" { 200 } else { 409 });
            if method == "GET" {
                assert!(html.contains("Activate the realm and user"));
                assert!(!html.contains("name=\"identity_confirmed\""));
            }
            assert_eq!(realm_authority_snapshot(&f).await, before);
        }
    }
}
async fn prove_link_expiry_output() {
    let (f, mut admin, path, _) = realm_link_fixture("link_output_expiry").await;
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
    assert_eq!(s, 200);
    let deadline:String=sqlx::query_scalar("SELECT to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM bloc.realm_user_access_link WHERE consumed_at IS NULL").fetch_one(&f.admin).await.unwrap();
    assert!(
        h.contains(&deadline),
        "output must show its stored immutable expiry"
    );
    let before: String =
        sqlx::query_scalar("SELECT expires_at::text FROM bloc.realm_user_access_link")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    sqlx::query("UPDATE bloc.realm_authentication_settings SET activation_ttl_seconds=172800,version=version+1").execute(&f.admin).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT expires_at::text FROM bloc.realm_user_access_link")
            .fetch_one(&f.admin)
            .await
            .unwrap(),
        before
    );
}
async fn issue_reset(f: &Fixture, admin: &mut Browser, user: &str) -> String {
    let path = format!("/admin/realms/{REALM}/users/{user}/access-links");
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
        .unwrap()
        .to_owned();
    assert_eq!(realm_count(f,"SELECT count(*) FROM bloc.realm_user_access_link WHERE purpose='reset' AND consumed_at IS NULL").await,1);
    code
}
async fn prove_reset_replacement() {
    let (f, mut admin, path, code) = realm_link_fixture("reset_replacement").await;
    let mut recipient = Browser::new(&f).await;
    assert_eq!(
        realm_exchange(&mut recipient, &code, "activate").await.0,
        303
    );
    assert_eq!(
        realm_consume(&mut recipient, "activate", REALM_PASSWORD)
            .await
            .0,
        303
    );
    realm_login(&mut recipient, REALM).await;
    let before: String =
        sqlx::query_scalar("SELECT row_to_json(c)::text FROM bloc.realm_user_credential c")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let first = issue_reset(&f, &mut admin, USER).await;
    let mut bound = Browser::new(&f).await;
    assert_eq!(
        realm_exchange(&mut bound, &first, "reset-password").await.0,
        303
    );
    let second = issue_reset(&f, &mut admin, USER).await;
    assert_ne!(first, second);
    assert_eq!(
        realm_exchange(&mut bound, &first, "reset-password").await.0,
        403
    );
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_form_state WHERE purpose='reset'"
        )
        .await,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT row_to_json(c)::text FROM bloc.realm_user_credential c"
        )
        .fetch_one(&f.admin)
        .await
        .unwrap(),
        before
    );
    assert_eq!(
        recipient
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
    realm_clear_budgets(&f).await;
    let mut fresh = Browser::new(&f).await;
    realm_login(&mut fresh, REALM).await;
    assert_eq!(realm_audit(&f, "realm_password_reset").await, 0);
    assert!(!path.is_empty());
}
async fn prove_exchange_refusals() {
    let (f, _, _, code) = realm_link_fixture("exchange_refusals").await;
    let mut b = Browser::new(&f).await;
    let path = format!("/realms/{REALM}/activate");
    let csrf = b.token(&path).await;
    let before = realm_authority_snapshot(&f).await;
    for (token, headers) in [
        (csrf.as_str(), vec![("origin", "https://foreign.example")]),
        ("invalid", vec![]),
        (csrf.as_str(), vec![("cookie", "")]),
    ] {
        let (s, _, _) = realm_raw(
            &b,
            "POST",
            &format!("{path}/exchange"),
            realm_encoded(&[("csrf", token), ("code", &code)]),
            &headers,
        )
        .await;
        assert_eq!(s, 403);
        assert_eq!(realm_authority_snapshot(&f).await, before);
    }
    for route in ["account", "account/sessions"] {
        let (s, _, h) = b
            .request("POST", &format!("/realms/{REALM}/{route}"), &[])
            .await;
        assert_eq!(s, 405);
        assert_eq!(h["allow"], "GET, HEAD");
    }
}
async fn prove_link_form_bindings() {
    let (f, mut admin, path, code) = realm_link_fixture("link_form_bindings").await;
    create_realm(&mut admin, OTHER, "Other").await;
    sqlx::query(
        "UPDATE bloc.realm_user_access_link SET expires_at=clock_timestamp()+interval '5 minutes'",
    )
    .execute(&f.admin)
    .await
    .unwrap();
    let mut b = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
    assert_eq!(realm_count(&f,"SELECT count(*) FROM bloc.realm_form_state f JOIN bloc.realm_user_access_link l ON l.token_digest=f.link_digest WHERE f.expires_at=l.expires_at AND f.purpose='activation'").await,1);
    let csrf = b.token(&format!("/realms/{REALM}/activate")).await;
    let snapshot = realm_authority_snapshot(&f).await;
    let activation_name = format!("__Host-bloc-realm-{REALM}-activation");
    let bearer = b.cookies.get(&activation_name).unwrap().clone();
    for route in [
        format!("/realms/{OTHER}/activate"),
        format!("/realms/{REALM}/reset-password"),
        format!("/realms/{REALM}/login"),
    ] {
        let original = b.cookies.clone();
        b.cookies.insert(
            format!("__Host-bloc-realm-{OTHER}-activation"),
            bearer.clone(),
        );
        b.cookies
            .insert(format!("__Host-bloc-realm-{REALM}-reset"), bearer.clone());
        b.cookies.insert(
            format!("__Host-bloc-realm-{REALM}-anonymous"),
            bearer.clone(),
        );
        let (s, _, _) = b
            .request(
                "POST",
                &route,
                &[
                    ("csrf", &csrf),
                    ("password", REALM_PASSWORD),
                    ("password_confirmation", REALM_PASSWORD),
                ],
            )
            .await;
        assert_eq!(s, 403);
        b.cookies = original;
        assert_eq!(realm_authority_snapshot(&f).await, snapshot);
    }
    let mut other = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut other, &code, "activate").await.0, 303);
    let other_csrf = other.token(&format!("/realms/{REALM}/activate")).await;
    let (s, _, _) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/activate"),
            &[
                ("csrf", &other_csrf),
                ("password", REALM_PASSWORD),
                ("password_confirmation", REALM_PASSWORD),
            ],
        )
        .await;
    assert_eq!(s, 403);
    assert!(!path.is_empty());
}
async fn prove_original_link_cutoff(name: &str, policy_failure: bool) {
    let (f, _, _, code) = realm_link_fixture(name).await;
    let mut b = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
    let original: String =
        sqlx::query_scalar("SELECT expires_at::text FROM bloc.realm_user_access_link")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    if policy_failure {
        assert_eq!(realm_consume(&mut b, "activate", "short").await.0, 422);
    } else {
        sqlx::query("UPDATE bloc.realm_form_state SET expires_at=clock_timestamp() WHERE purpose='activation'").execute(&f.admin).await.unwrap();
        assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 303);
    }
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT expires_at::text FROM bloc.realm_user_access_link")
            .fetch_one(&f.admin)
            .await
            .unwrap(),
        original
    );
    // Move the immutable deadline to the present to exercise its terminal boundary without waiting24h.
    sqlx::query("UPDATE bloc.realm_user_access_link SET expires_at=clock_timestamp()")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        realm_consume(&mut b, "activate", REALM_PASSWORD).await.0,
        403
    );
    assert_eq!(realm_exchange(&mut b, &code, "activate").await.0, 403);
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_credential").await,
        0
    );
    assert_eq!(realm_audit(&f, "realm_activation").await, 0);
}
async fn prove_bounded_insertion_cleanup() {
    let (f, mut b) = realm_fixture("bounded_insert_cleanup").await;
    let login = format!("/realms/{REALM}/login");
    let csrf = b.token(&login).await;
    realm_clear_budgets(&f).await;
    sqlx::query("INSERT INTO bloc.realm_admission_bucket SELECT 'exchange_source',decode(lpad(to_hex(n),64,'0'),'hex'),ARRAY[statement_timestamp()-interval '3 minutes'],statement_timestamp()-interval '1 minute' FROM generate_series(1,1001)n").execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_admission_bucket VALUES('exchange_realm',$1,ARRAY[clock_timestamp()],clock_timestamp()+interval '2 minutes')").bind(vec![99u8;32]).execute(&f.admin).await.unwrap();
    let live:String=sqlx::query_scalar("SELECT row_to_json(t)::text FROM bloc.realm_admission_bucket t WHERE scope='exchange_realm'").fetch_one(&f.admin).await.unwrap();
    let (s, _, _) = b
        .request(
            "POST",
            &login,
            &[
                ("csrf", &csrf),
                ("email", "missing@example.test"),
                ("password", "incorrect password"),
            ],
        )
        .await;
    assert_eq!(s, 422);
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_admission_bucket WHERE expires_at<=clock_timestamp()"
        )
        .await,
        1
    );
    assert_eq!(sqlx::query_scalar::<_,String>("SELECT row_to_json(t)::text FROM bloc.realm_admission_bucket t WHERE scope='exchange_realm'").fetch_one(&f.admin).await.unwrap(),live);
    realm_clear_budgets(&f).await;
    sqlx::query("INSERT INTO bloc.realm_user_session(realm_id,user_id,session_digest,credential_version,created_at,last_activity_at,expires_at,device_label) SELECT u.realm_id,u.id,decode(lpad(to_hex(n),64,'0'),'hex'),1,statement_timestamp()-interval '2 hours',statement_timestamp()-interval '2 hours',statement_timestamp()-interval '1 hour','Unknown device' FROM bloc.realm_user u CROSS JOIN generate_series(1,1001)n WHERE u.realm_id=$1::text::uuid").bind(REALM).execute(&f.admin).await.unwrap();
    let mut other = Browser::new(&f).await;
    realm_login(&mut other, OTHER).await;
    // The OTHER login removed1000; restore1000 expired records so the target insertion has1001 to clean.
    sqlx::query("INSERT INTO bloc.realm_user_session(realm_id,user_id,session_digest,credential_version,created_at,last_activity_at,expires_at,device_label) SELECT u.realm_id,u.id,decode(lpad(to_hex(n+2000),64,'0'),'hex'),1,statement_timestamp()-interval '2 hours',statement_timestamp()-interval '2 hours',statement_timestamp()-interval '1 hour','Unknown device' FROM bloc.realm_user u CROSS JOIN generate_series(1,1000)n WHERE u.realm_id=$1::text::uuid").bind(REALM).execute(&f.admin).await.unwrap();
    let live: String = sqlx::query_scalar(
        "SELECT row_to_json(t)::text FROM bloc.realm_user_session t WHERE realm_id=$1::text::uuid",
    )
    .bind(OTHER)
    .fetch_one(&f.admin)
    .await
    .unwrap();
    realm_login(&mut b, REALM).await;
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE expires_at<=clock_timestamp()"
        )
        .await,
        1
    );
    assert_eq!(sqlx::query_scalar::<_,String>("SELECT row_to_json(t)::text FROM bloc.realm_user_session t WHERE realm_id=$1::text::uuid").bind(OTHER).fetch_one(&f.admin).await.unwrap(),live);
}
async fn prove_generic_link_failures() {
    let (f, mut admin, path, code) = realm_link_fixture("generic_link_failures").await;
    let mut b = Browser::new(&f).await;
    let (s, expected, _) = realm_exchange(&mut b, &sec::encode(&[99; 32]), "activate").await;
    assert_eq!(s, 403);
    assert!(expected.contains("administrator"));
    sqlx::query("UPDATE bloc.realm_user_access_link SET expires_at=clock_timestamp()")
        .execute(&f.admin)
        .await
        .unwrap();
    let (s, h, _) = realm_exchange(&mut b, &code, "activate").await;
    assert_eq!(s, 403);
    assert_eq!(h, expected);
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
    assert_eq!(s, 200);
    let replacement = h
        .split("id=\"access-code\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let (s, h, _) = realm_exchange(&mut b, &code, "activate").await;
    assert_eq!(s, 403);
    assert_eq!(h, expected);
    assert_eq!(
        realm_exchange(&mut b, &replacement, "activate").await.0,
        303
    );
    assert_eq!(
        realm_consume(&mut b, "activate", REALM_PASSWORD).await.0,
        303
    );
    let before = realm_authority_snapshot(&f).await;
    let (s, h, _) = realm_exchange(&mut b, &replacement, "activate").await;
    assert_eq!(s, 403);
    assert_eq!(h, expected);
    assert_eq!(realm_authority_snapshot(&f).await, before);
}
async fn prove_account_form_binding() {
    let (f, mut a) = realm_fixture("account_form_binding").await;
    realm_login(&mut a, REALM).await;
    let path = format!("/realms/{REALM}/account/profile");
    let csrf = a.token(&path).await;
    let mut b = Browser::new(&f).await;
    realm_login(&mut b, REALM).await;
    // CSRF plus browser bearer from sessionA cannot authorize sessionB, even for the same immutable user.
    b.cookies.insert(
        format!("__Host-bloc-realm-{REALM}-account"),
        a.cookies[&format!("__Host-bloc-realm-{REALM}-account")].clone(),
    );
    let before = realm_authority_snapshot(&f).await;
    assert_eq!(
        b.request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("version", "1"),
                ("display_name", "Rejected")
            ]
        )
        .await
        .0,
        403
    );
    assert_eq!(realm_authority_snapshot(&f).await, before);
}
async fn prove_public_exhaustion_logout() {
    let (f, mut b) = realm_fixture("public_exhaustion_logout").await;
    realm_login(&mut b, REALM).await;
    let csrf = b.token(&format!("/realms/{REALM}/account/profile")).await;
    realm_clear_budgets(&f).await;
    sqlx::query("INSERT INTO bloc.realm_admission_bucket VALUES('public_work',$1,array_fill(clock_timestamp(),ARRAY[20]),clock_timestamp()+interval '2 minutes')").bind(vec![0u8;32]).execute(&f.admin).await.unwrap();
    let mut stranger = Browser::new(&f).await;
    let login = format!("/realms/{REALM}/login");
    let token = stranger.token(&login).await;
    assert_eq!(
        stranger
            .request(
                "POST",
                &login,
                &[
                    ("csrf", &token),
                    ("email", "stranger@example.test"),
                    ("password", "wrong password")
                ]
            )
            .await
            .0,
        429
    );
    let (s, _, headers) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/logout"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(s, 303);
    assert_eq!(headers["location"], format!("/realms/{REALM}/login"));
    assert_eq!(realm_audit(&f, "realm_sign_out").await, 1);
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        0
    );
}
async fn prove_credential_invalidation(reset: bool) {
    let name = if reset {
        "reset_populated_authority"
    } else {
        "password_populated_authority"
    };
    let (f, mut admin, _, code) = realm_link_fixture(name).await;
    let mut a = Browser::new(&f).await;
    assert_eq!(realm_exchange(&mut a, &code, "activate").await.0, 303);
    assert_eq!(
        realm_consume(&mut a, "activate", REALM_PASSWORD).await.0,
        303
    );
    realm_clear_budgets(&f).await;
    let mut clients = Vec::new();
    for _ in 0..3 {
        let mut b = Browser::new(&f).await;
        realm_login(&mut b, REALM).await;
        b.token(&format!("/realms/{REALM}/account/profile")).await;
        clients.push(b);
    }
    let code = issue_reset(&f, &mut admin, USER).await;
    let mut bound = Browser::new(&f).await;
    assert_eq!(
        realm_exchange(&mut bound, &code, "reset-password").await.0,
        303
    );
    let old_forms: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT browser_digest FROM bloc.realm_form_state WHERE purpose<>'anonymous'",
    )
    .fetch_all(&f.admin)
    .await
    .unwrap();
    assert_eq!(old_forms.len(), 4);
    let old_sessions: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT session_digest FROM bloc.realm_user_session WHERE revoked_at IS NULL",
    )
    .fetch_all(&f.admin)
    .await
    .unwrap();
    assert_eq!(old_sessions.len(), 3);
    let replacement = "a replacement authority password";
    if reset {
        assert_eq!(
            realm_consume(&mut bound, "reset-password", replacement)
                .await
                .0,
            303
        );
    } else {
        let path = format!("/realms/{REALM}/account/password");
        let csrf = clients[0].token(&path).await;
        let old = clients[0].cookies.clone();
        assert_eq!(
            clients[0]
                .request(
                    "POST",
                    &path,
                    &[
                        ("csrf", &csrf),
                        ("current_password", REALM_PASSWORD),
                        ("password", replacement),
                        ("password_confirmation", replacement)
                    ]
                )
                .await
                .0,
            303
        );
        for suffix in ["", "-account"] {
            let key = format!("__Host-bloc-realm-{REALM}{suffix}");
            assert_ne!(clients[0].cookies[&key], old[&key]);
        }
        assert_eq!(
            clients[0]
                .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
                .await
                .0,
            200
        );
        clients[0].cookies = old;
    }
    assert_eq!(
        realm_count(&f, "SELECT count(*) FROM bloc.realm_user_access_link").await,
        0
    );
    for digest in old_forms {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM bloc.realm_form_state WHERE browser_digest=$1"
            )
            .bind(digest)
            .fetch_one(&f.admin)
            .await
            .unwrap(),
            0
        );
    }
    for digest in old_sessions {
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM bloc.realm_user_session WHERE session_digest=$1 AND revoked_at IS NULL").bind(digest).fetch_one(&f.admin).await.unwrap(),0);
    }
    for b in &mut clients {
        assert_eq!(
            b.request("GET", &format!("/realms/{REALM}/account/profile"), &[])
                .await
                .0,
            303
        );
    }
    assert_eq!(
        realm_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL"
        )
        .await,
        if reset { 0 } else { 1 }
    );
    assert_eq!(
        realm_exchange(&mut bound, &code, "reset-password").await.0,
        403
    );
}
