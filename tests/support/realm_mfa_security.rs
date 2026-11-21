async fn security_bad_proof(
    browser: &mut Browser,
    csrf: &str,
) -> (StatusCode, String, axum::http::HeaderMap) {
    browser
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", csrf), ("method", "totp"), ("code", "!!!!!!")],
        )
        .await
}
async fn security_buckets(f: &Fixture) -> Vec<(String, i32)> {
    sqlx::query_as(
        "SELECT scope,cardinality(admitted_at) FROM bloc.mfa_admission_bucket ORDER BY scope",
    )
    .fetch_all(&f.admin)
    .await
    .unwrap()
}

async fn security_raw(
    browser: &Browser,
    method: &str,
    path: &str,
    body: Vec<u8>,
    content_type: &str,
    origin: Option<&str>,
    headers: &[(&str, &str)],
) -> (StatusCode, String, axum::http::HeaderMap) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "bloc.example.test")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "192.0.2.4")
        .header("content-type", content_type)
        .header(
            "cookie",
            browser
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        );
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut request = request.body(Body::from(body)).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:54321".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = browser.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let html = String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, html, headers)
}
fn security_public_record(number: usize, id_size: usize) -> Vec<u8> {
    use base64::Engine;
    serde_json::to_vec(&serde_json::json!({"format_version":1,"library":"webauthn-rs","library_version":"0.6.2","kind":"credential","payload":{"cred":{
        "cred_id":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![number as u8;id_size]),
        "cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":vec![1;32],"y":vec![2;32]}}},
        "counter":0,"transports":["internal"],"user_verified":true,"backup_eligible":true,"backup_state":true,"registration_policy":"required","extensions":{},"attestation":{"data":"None","metadata":"None"},"attestation_format":"none"}}})).unwrap()
}
async fn security_seed_public_factor(f: &Fixture, number: usize) {
    let id = format!("77777777-7777-4777-8777-{number:012}");
    // Count/serialization fixtures only; successful signed ceremonies have their own real browser proofs.
    sqlx::query("INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,'webauthn',$4)").bind(&id).bind(REALM).bind(USER).bind(format!("Boundary passkey {number}")).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_webauthn_identity(realm_id,user_id,user_handle) VALUES($1::text::uuid,$2::text::uuid,$3) ON CONFLICT DO NOTHING").bind(REALM).bind(USER).bind(vec![37u8;32]).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_webauthn_factor(factor_id,realm_id,user_id,credential_id,public_credential) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4,$5)").bind(id).bind(REALM).bind(USER).bind(vec![number as u8;32]).bind(security_public_record(number,32)).execute(&f.admin).await.unwrap();
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_security_contract() {
    let canonical = "https://bloc.example.test";
    let (f, mut browser, _op, csrf, _) = mfa_challenge("mfasecurityheaders").await;
    let (status, html, headers) = browser
        .request("GET", &format!("/realms/{REALM}/mfa"), &[])
        .await;
    assert_eq!(status, 200);
    assert!(
        headers["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    assert_eq!(headers["referrer-policy"], "no-referrer");
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert!(
        !html.contains(
            browser
                .cookies
                .get(&format!("__Host-bloc-realm-mfa-{REALM}"))
                .unwrap()
        )
    );
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("csrf", csrf.as_str()),
            ("method", "totp"),
            ("code", "!!!!!!"),
        ])
        .finish()
        .into_bytes();
    let path = format!("/realms/{REALM}/mfa/verify");
    for (origin, metadata) in [
        (Some("https://wrong.example.test"), vec![]),
        (Some("null"), vec![]),
        (
            None,
            vec![
                ("sec-fetch-site", "cross-site"),
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-dest", "document"),
            ],
        ),
    ] {
        assert_eq!(
            security_raw(
                &browser,
                "POST",
                &path,
                body.clone(),
                "application/x-www-form-urlencoded",
                origin,
                &metadata
            )
            .await
            .0,
            403
        );
    }
    let wrong_csrf = sec::encode(&[0; 32]);
    assert_eq!(
        browser
            .request(
                "POST",
                &path,
                &[
                    ("csrf", &wrong_csrf),
                    ("method", "totp"),
                    ("code", "!!!!!!")
                ]
            )
            .await
            .0,
        403
    );
    assert!(security_buckets(&f).await.is_empty());
    let failed: i16 = sqlx::query_scalar(
        "SELECT failed_attempts FROM bloc.realm_mfa_flow WHERE parent_id IS NULL",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(failed, 0);
    let (status, html, _) = security_raw(
        &browser,
        "POST",
        &path,
        body,
        "application/x-www-form-urlencoded",
        Some("null"),
        &[
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-dest", "document"),
        ],
    )
    .await;
    assert_eq!(
        status, 422,
        "valid native form must reach proof validation: {html}"
    );
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );

    let (f, _admin, mut browser, _op) = mfa_configured("mfasecuritybounds").await;
    contract_seed(&f).await;
    mfa_secret_fixture(&f).await;
    security_seed_public_factor(&f, 1).await;
    let (status, html, headers) =
        contract_login(&mut browser, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    let cookie = headers
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap())
        .find(|value| value.starts_with(&format!("__Host-bloc-realm-mfa-{REALM}=")))
        .unwrap();
    for flag in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(flag), "{flag}");
    }
    assert!(!cookie.contains("Domain="));
    let csrf = browser.token(&format!("/realms/{REALM}/mfa")).await;
    let (status, html, _) = browser
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/webauthn/options"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(status, 200, "{html}");
    let options: serde_json::Value = serde_json::from_str(&html).unwrap();
    let ceremony = options["ceremony_id"].as_str().unwrap();
    assert_eq!(options["publicKey"]["userVerification"], "required");
    let encode = |credential: &serde_json::Value| {
        let credential = credential.to_string();
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("csrf", csrf.as_str()),
                ("ceremony_id", ceremony),
                ("credential", credential.as_str()),
            ])
            .finish()
            .into_bytes()
    };
    let mut response = serde_json::json!({"padding":""});
    let base = encode(&response).len();
    response["padding"] = serde_json::Value::String("a".repeat(65536 - base));
    let exact = encode(&response);
    assert_eq!(exact.len(), 65536);
    let finish = format!("/realms/{REALM}/mfa/webauthn/finish");
    let (status, html, headers) = security_raw(
        &browser,
        "POST",
        &finish,
        exact.clone(),
        "application/x-www-form-urlencoded",
        Some(canonical),
        &[],
    )
    .await;
    assert_eq!(
        status, 422,
        "64KiB must reach credential validation rather than a smaller body cap: {html}"
    );
    assert!(
        headers["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    let mut excess = exact;
    excess.push(b'a');
    assert_eq!(excess.len(), 65537);
    assert_eq!(
        security_raw(
            &browser,
            "POST",
            &finish,
            excess,
            "application/x-www-form-urlencoded",
            Some(canonical),
            &[]
        )
        .await
        .0,
        413
    );
    let mut nested = serde_json::json!(0);
    for _ in 0..17 {
        nested = serde_json::json!([nested]);
    }
    let deep = serde_json::json!({"padding":nested});
    assert_eq!(
        security_raw(
            &browser,
            "POST",
            &finish,
            encode(&deep),
            "application/x-www-form-urlencoded",
            Some(canonical),
            &[]
        )
        .await
        .0,
        422
    );
    assert_eq!(
        contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
        0
    );
    let login = format!("/realms/{REALM}/login");
    let csrf = browser.token(&login).await;
    let mut form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("csrf", csrf.as_str()),
            ("email", "Alice@example.test"),
            ("password", ""),
        ])
        .finish()
        .into_bytes();
    form.extend(vec![b'a'; 16384 - form.len()]);
    assert_eq!(form.len(), 16384);
    assert_eq!(
        security_raw(
            &browser,
            "POST",
            &login,
            form.clone(),
            "application/x-www-form-urlencoded",
            Some(canonical),
            &[]
        )
        .await
        .0,
        422
    );
    form.push(b'a');
    assert_eq!(
        security_raw(
            &browser,
            "POST",
            &login,
            form,
            "application/x-www-form-urlencoded",
            Some(canonical),
            &[]
        )
        .await
        .0,
        413
    );

    let (f, browser, _op, _csrf, _code) = mfa_pending_setup("mfasecuritysecret").await;
    let path = format!("/realms/{REALM}/account/security/totp/setup");
    let before: Vec<(String, String)> =
        sqlx::query_as("SELECT id::text,expires_at::text FROM bloc.realm_mfa_flow ORDER BY id")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    let (status, html, headers) = security_raw(
        &browser,
        "GET",
        &path,
        vec![],
        "application/x-www-form-urlencoded",
        Some(canonical),
        &[("hx-request", "true")],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers["hx-redirect"], path);
    assert!(html.is_empty());
    let after: Vec<(String, String)> =
        sqlx::query_as("SELECT id::text,expires_at::text FROM bloc.realm_mfa_flow ORDER BY id")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    assert_eq!(before, after);

    let (f, mut browser, _op, secret) = account_protected("mfatenpasskeys").await;
    for number in 1..=9 {
        security_seed_public_factor(&f, number).await;
    }
    let csrf = account_begin_proof(&f, &mut browser, "webauthn_enroll", &secret).await;
    let options_path = format!("/realms/{REALM}/account/security/webauthn/register/options");
    for label in [String::new(), "a".repeat(65), "control\nlabel".into()] {
        let (status, html, _) = browser
            .request("POST", &options_path, &[("csrf", &csrf), ("label", &label)])
            .await;
        assert_eq!(status, 422, "{html}");
    }
    for label in ["😀".repeat(64), "Ninth-boundary candidate".into()] {
        let (status, html, _) = browser
            .request("POST", &options_path, &[("csrf", &csrf), ("label", &label)])
            .await;
        assert_eq!(status, 200, "{html}");
    }
    security_seed_public_factor(&f, 10).await;
    let before = contract_count(
        &f,
        "SELECT count(*) FROM bloc.realm_mfa_flow WHERE purpose='webauthn_registration'",
    )
    .await;
    let (status, html, _) = browser
        .request(
            "POST",
            &options_path,
            &[("csrf", &csrf), ("label", "Eleventh passkey")],
        )
        .await;
    assert!(
        status.is_client_error()
            && status != StatusCode::NOT_FOUND
            && status != StatusCode::METHOD_NOT_ALLOWED,
        "{html}"
    );
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_mfa_flow WHERE purpose='webauthn_registration'"
        )
        .await,
        before
    );
    assert_eq!(contract_count(&f,"SELECT count(*) FROM bloc.realm_user_factor WHERE kind='webauthn' AND revoked_at IS NULL").await,10);
    let factor = "77777777-7777-4777-8777-000000000010";
    let mut record = security_public_record(10, 1024);
    record.resize(16384, b' ');
    sqlx::query("UPDATE bloc.realm_webauthn_factor SET credential_id=$2,public_credential=$3 WHERE factor_id=$1::text::uuid").bind(factor).bind(vec![10u8;1024]).bind(record).execute(&f.admin).await.unwrap();
    let error = sqlx::query(
        "UPDATE bloc.realm_webauthn_factor SET credential_id=$2 WHERE factor_id=$1::text::uuid",
    )
    .bind(factor)
    .bind(vec![10u8; 1025])
    .execute(&f.admin)
    .await
    .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    let error = sqlx::query(
        "UPDATE bloc.realm_webauthn_factor SET public_credential=$2 WHERE factor_id=$1::text::uuid",
    )
    .bind(factor)
    .bind(vec![b' '; 16385])
    .execute(&f.admin)
    .await
    .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    account_expired_exact_proof("mfac73expiry").await;
}

async fn security_fill_flows(f: &Fixture, realm: &str, count: i32, children: bool) {
    sqlx::query("INSERT INTO bloc.realm_mfa_flow(realm_id,user_id,bearer_digest,browser_digest,purpose,credential_version,factor_epoch,policy_version,user_version,password_verified_at,parent_id,csrf_token,created_at,expires_at) SELECT f.realm_id,f.user_id,sha256(uuid_send(gen_random_uuid())),f.browser_digest,CASE WHEN $3 THEN 'webauthn_authentication' ELSE f.purpose END,f.credential_version,f.factor_epoch,f.policy_version,f.user_version,f.password_verified_at,CASE WHEN $3 THEN f.id ELSE NULL END,f.csrf_token,clock_timestamp(),f.expires_at FROM bloc.realm_mfa_flow f CROSS JOIN generate_series(1,$2) g WHERE f.id=(SELECT id FROM bloc.realm_mfa_flow WHERE realm_id=$1::text::uuid AND parent_id IS NULL LIMIT 1)")
        .bind(realm).bind(count).bind(children).execute(&f.admin).await.unwrap();
}
async fn security_other_realm(f: &Fixture, number: usize) -> String {
    let realm = format!("55555555-5555-4555-8555-{number:012}");
    let user = format!("66666666-6666-4666-8666-{number:012}");
    sqlx::query("INSERT INTO bloc.realm(id,name,created_at,updated_at) VALUES($1::text::uuid,'Capacity fixture',clock_timestamp(),clock_timestamp())").bind(&realm).execute(&f.admin).await.unwrap();
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='required' WHERE realm_id=$1::text::uuid").bind(&realm).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES($1::text::uuid,$2::text::uuid,'capacity@example.test',clock_timestamp(),clock_timestamp())").bind(&user).bind(&realm).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_credential(realm_id,user_id,password_hash,credential_version,password_changed_at) SELECT $1::text::uuid,$2::text::uuid,password_hash,1,clock_timestamp() FROM bloc.realm_user_credential WHERE realm_id=$3::text::uuid AND user_id=$4::text::uuid").bind(&realm).bind(&user).bind(REALM).bind(USER).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_mfa_state(realm_id,user_id) VALUES($1::text::uuid,$2::text::uuid) ON CONFLICT DO NOTHING").bind(&realm).bind(&user).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_mfa_flow(realm_id,user_id,bearer_digest,browser_digest,purpose,credential_version,factor_epoch,policy_version,user_version,password_verified_at,csrf_token,created_at,expires_at) VALUES($1::text::uuid,$2::text::uuid,sha256(uuid_send(gen_random_uuid())),sha256(uuid_send(gen_random_uuid())),'initial_enrollment',1,1,1,1,clock_timestamp(),sha256(uuid_send(gen_random_uuid())),clock_timestamp(),clock_timestamp()+interval '300 seconds')").bind(&realm).bind(&user).execute(&f.admin).await.unwrap();
    realm
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_admission_contract() {
    // Real submissions across fresh replicas retain account, source and realm budgets.
    let (f, mut browser, op, mut csrf, _) = mfa_challenge("mfaaccountbudget").await;
    for attempt in 1..=10 {
        if attempt == 6 {
            browser = policy_flow_replica(&f, &op, BTreeMap::new()).await;
            assert_eq!(
                contract_login(&mut browser, REALM, "Alice@example.test", CONTRACT_PASSWORD)
                    .await
                    .0,
                303
            );
            csrf = browser.token(&format!("/realms/{REALM}/mfa")).await;
        }
        let (status, html, headers) = security_bad_proof(&mut browser, &csrf).await;
        assert_eq!(
            status.as_u16(),
            if attempt % 5 == 0 { 429 } else { 422 },
            "{html}"
        );
        if attempt % 5 == 0 {
            assert!(
                headers["retry-after"]
                    .to_str()
                    .unwrap()
                    .parse::<u32>()
                    .unwrap()
                    > 0
            );
        }
    }
    assert_eq!(
        security_buckets(&f).await,
        vec![
            ("account".into(), 10),
            ("realm".into(), 10),
            ("source".into(), 10)
        ]
    );
    browser = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    assert_eq!(
        contract_login(&mut browser, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    csrf = browser.token(&format!("/realms/{REALM}/mfa")).await;
    let (status, html, headers) = security_bad_proof(&mut browser, &csrf).await;
    assert_eq!(status, 429, "{html}");
    assert!(headers.contains_key("retry-after"));
    assert_eq!(
        security_buckets(&f).await,
        vec![
            ("account".into(), 10),
            ("realm".into(), 10),
            ("source".into(), 10)
        ]
    );
    policy_flow_no_success(&f).await;

    for (name, scope, maximum, near, old) in [
        ("mfaaccountwindow", "account", 10, 599, 601),
        ("mfasourcewindow", "source", 30, 59, 61),
        ("mfarealmwindow", "realm", 300, 59, 61),
    ] {
        let (f, mut browser, _op, csrf, _) = mfa_challenge(name).await;
        assert_eq!(security_bad_proof(&mut browser, &csrf).await.0, 422);
        sqlx::query("UPDATE bloc.mfa_admission_bucket SET admitted_at=array_fill(clock_timestamp()-make_interval(secs=>$3),ARRAY[$2]),expires_at=clock_timestamp()+interval '11 minutes' WHERE scope=$1")
            .bind(scope).bind(maximum).bind(near as f64).execute(&f.admin).await.unwrap();
        let before = security_buckets(&f).await;
        let (status, html, headers) = security_bad_proof(&mut browser, &csrf).await;
        assert_eq!(status, 429, "{scope}: {html}");
        assert!(headers.contains_key("retry-after"));
        assert_eq!(
            security_buckets(&f).await,
            before,
            "reservation must be all-or-none"
        );
        sqlx::query("UPDATE bloc.mfa_admission_bucket SET admitted_at=array_fill(clock_timestamp()-make_interval(secs=>$3),ARRAY[$2]) WHERE scope=$1")
            .bind(scope).bind(maximum).bind(old as f64).execute(&f.admin).await.unwrap();
        assert_eq!(security_bad_proof(&mut browser, &csrf).await.0, 422);
        let current: i32 = sqlx::query_scalar(
            "SELECT cardinality(admitted_at) FROM bloc.mfa_admission_bucket WHERE scope=$1",
        )
        .bind(scope)
        .fetch_one(&f.admin)
        .await
        .unwrap();
        assert_eq!(current, 1);
        policy_flow_no_success(&f).await;
    }

    for (name, kind) in [
        ("mfausercapacity", "user"),
        ("mfarealmcapacity", "realm"),
        ("mfaglobalcapacity", "installation"),
        ("mfaformcapacity", "forms"),
    ] {
        let (f, mut browser, op, csrf, code) = mfa_challenge(name).await;
        match kind {
            "user" => security_fill_flows(&f, REALM, 4, false).await,
            "realm" => security_fill_flows(&f, REALM, 999, true).await,
            "installation" => {
                for number in 1..=10 {
                    let realm = security_other_realm(&f, number).await;
                    security_fill_flows(&f, &realm, if number == 10 { 998 } else { 999 }, true)
                        .await;
                }
                assert_eq!(
                    contract_count(&f, "SELECT count(*) FROM bloc.realm_mfa_flow").await,
                    10000
                );
                let requested: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM bloc.realm_mfa_flow WHERE realm_id=$1::text::uuid",
                )
                .bind(REALM)
                .fetch_one(&f.admin)
                .await
                .unwrap();
                assert_eq!(requested, 1);
                let largest: i64 = sqlx::query_scalar("SELECT max(n) FROM (SELECT count(*) n FROM bloc.realm_mfa_flow GROUP BY realm_id) x").fetch_one(&f.admin).await.unwrap();
                assert_eq!(largest, 1000);
            }
            _ => {
                sqlx::query(
                    "WITH owned_link AS (
                        INSERT INTO bloc.realm_mfa_recovery_link(realm_id,user_id,token_digest,issued_by,credential_version,user_version,factor_epoch,issued_at,expires_at)
                        SELECT realm_id,user_id,sha256(uuid_send(gen_random_uuid())),(SELECT id FROM bloc.installation_administrator),credential_version,user_version,factor_epoch,clock_timestamp(),expires_at
                        FROM bloc.realm_mfa_flow WHERE parent_id IS NULL
                        RETURNING realm_id,user_id,token_digest
                    )
                    INSERT INTO bloc.realm_mfa_recovery_form(realm_id,user_id,link_digest,browser_digest,csrf_token,credential_version,user_version,policy_version,factor_epoch,created_at,expires_at)
                    SELECT f.realm_id,f.user_id,l.token_digest,sha256(uuid_send(gen_random_uuid())),f.csrf_token,f.credential_version,f.user_version,f.policy_version,f.factor_epoch,clock_timestamp(),f.expires_at
                    FROM bloc.realm_mfa_flow f JOIN owned_link l USING(realm_id,user_id) CROSS JOIN generate_series(1,4)
                    WHERE f.parent_id IS NULL",
                )
                    .execute(&f.admin).await.unwrap();
            }
        }
        let before: Vec<String> =
            sqlx::query_scalar("SELECT id::text FROM bloc.realm_mfa_flow ORDER BY id")
                .fetch_all(&f.admin)
                .await
                .unwrap();
        let mut fresh = policy_flow_replica(&f, &op, BTreeMap::new()).await;
        let (status, html, headers) =
            contract_login(&mut fresh, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
        assert_eq!(status, 503, "{kind}: {html}");
        assert_eq!(headers["retry-after"], "60");
        let after: Vec<String> =
            sqlx::query_scalar("SELECT id::text FROM bloc.realm_mfa_flow ORDER BY id")
                .fetch_all(&f.admin)
                .await
                .unwrap();
        assert_eq!(after, before);
        assert_eq!(
            contract_count(&f, "SELECT count(*) FROM bloc.realm_user_session").await,
            0
        );
        let (status, html, _) = browser
            .request(
                "POST",
                &format!("/realms/{REALM}/mfa/verify"),
                &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
            )
            .await;
        assert_eq!(
            status, 303,
            "live authority was evicted at {kind} capacity: {html}"
        );
    }

    let (f, mut browser, _op, csrf, code) = mfa_challenge("mfaboundedcleanup").await;
    security_fill_flows(&f, REALM, 999, false).await;
    sqlx::query("UPDATE bloc.realm_mfa_flow SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE bearer_digest<>$1")
        .bind(sec::digest(browser.cookies.get(&format!("__Host-bloc-realm-mfa-{REALM}")).unwrap()).as_slice()).execute(&f.admin).await.unwrap();
    let realm = security_other_realm(&f, 99).await;
    security_fill_flows(&f, &realm, 1, true).await;
    sqlx::query("UPDATE bloc.realm_mfa_flow SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE realm_id=$1::text::uuid").bind(&realm).execute(&f.admin).await.unwrap();
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_mfa_flow WHERE expires_at<=clock_timestamp()"
        )
        .await,
        1001
    );
    let maintenance = f.pool("maintenance_user").await;
    sqlx::query("SELECT bloc.maintain_access()")
        .execute(&maintenance)
        .await
        .unwrap();
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_mfa_flow WHERE expires_at<=clock_timestamp()"
        )
        .await,
        1
    );
    assert_eq!(contract_count(&f, "SELECT count(*) FROM bloc.realm_mfa_flow WHERE expires_at>clock_timestamp() AND consumed_at IS NULL").await, 1);
    sqlx::query("SELECT bloc.maintain_access()")
        .execute(&maintenance)
        .await
        .unwrap();
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_mfa_flow WHERE expires_at<=clock_timestamp()"
        )
        .await,
        0
    );
    assert_eq!(
        browser
            .request(
                "POST",
                &format!("/realms/{REALM}/mfa/verify"),
                &[("csrf", &csrf), ("method", "totp"), ("code", &code)]
            )
            .await
            .0,
        303
    );
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c47() {
    let (f, mut admin, mut browser, op) = mfa_configured("mfac47").await;
    contract_seed(&f).await;
    mfa_secret_fixture(&f).await;
    assert_eq!(
        contract_login(&mut browser, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let csrf = browser.token(&format!("/realms/{REALM}/mfa")).await;
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
        browser
            .request(
                "POST",
                &format!("/realms/{REALM}/mfa/verify"),
                &[("csrf", &csrf), ("method", "totp"), ("code", &code)]
            )
            .await
            .0,
        303
    );
    let mut pending = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    assert_eq!(
        contract_login(&mut pending, REALM, "Alice@example.test", CONTRACT_PASSWORD)
            .await
            .0,
        303
    );
    let pending_csrf = pending.token(&format!("/realms/{REALM}/mfa")).await;
    let before: (String, Vec<u8>, i64) = sqlx::query_as("SELECT t.factor_id::text,p.encrypted_payload,t.last_accepted_step FROM bloc.realm_totp_factor t JOIN bloc.mfa_encrypted_payload p ON p.id=t.factor_id").fetch_one(&f.admin).await.unwrap();
    let reset_code = contract_issue(
        &mut admin,
        &format!("/admin/realms/{REALM}/users/{USER}/access-links"),
        "reset",
        "1",
    )
    .await;
    let mut reset = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    assert_eq!(
        realm_exchange(&mut reset, &reset_code, "reset-password")
            .await
            .0,
        303
    );
    let replacement_password = "a different synthetic password";
    assert_eq!(
        realm_consume(&mut reset, "reset-password", replacement_password)
            .await
            .0,
        303
    );
    let after: (String, Vec<u8>, i64) = sqlx::query_as("SELECT t.factor_id::text,p.encrypted_payload,t.last_accepted_step FROM bloc.realm_totp_factor t JOIN bloc.mfa_encrypted_payload p ON p.id=t.factor_id").fetch_one(&f.admin).await.unwrap();
    assert!(before == after);
    assert_eq!(
        contract_count(
            &f,
            "SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL"
        )
        .await,
        1
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
            "SELECT count(*) FROM bloc.realm_mfa_flow WHERE consumed_at IS NULL"
        )
        .await,
        0
    );
    let (status, html, _) = pending
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &pending_csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 409, "{html}");
    let mut login = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    let (status, html, headers) = contract_login(
        &mut login,
        REALM,
        "Alice@example.test",
        replacement_password,
    )
    .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/mfa"));
    assert!(
        !login
            .cookies
            .contains_key(&format!("__Host-bloc-realm-{REALM}"))
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
