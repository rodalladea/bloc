fn mfa_owned_cipher(installation: &str, user: &str, record: &str) -> Vec<u8> {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    let random = sec::random().unwrap();
    let nonce: [u8; 24] = random[..24].try_into().unwrap();
    let mut header = b"BMFA\x01\x01".to_vec();
    header.extend_from_slice(uuid::Uuid::parse_str(MFA_KEY_A).unwrap().as_bytes());
    header.extend_from_slice(&nonce);
    let mut aad = header.clone();
    for id in [installation, REALM, user] {
        aad.extend_from_slice(uuid::Uuid::parse_str(id).unwrap().as_bytes());
    }
    aad.push(1);
    aad.extend_from_slice(uuid::Uuid::parse_str(record).unwrap().as_bytes());
    aad.extend_from_slice(&1u16.to_be_bytes());
    let cipher = XChaCha20Poly1305::new_from_slice(&[7; 32]).unwrap();
    let encrypted = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &[11; 20],
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &encrypted,
                    aad: &aad
                }
            )
            .unwrap(),
        vec![11; 20]
    );
    header.extend(encrypted);
    header
}
async fn mfa_http_foreign_owner_cipher() {
    let (f, mut b, _op, csrf, code) = mfa_challenge("mfac63foreign").await;
    let other = "44444444-4444-4444-8444-444444444444";
    let record = "55555555-5555-4555-8555-555555555555";
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES($1::text::uuid,$2::text::uuid,'Other@example.test',clock_timestamp(),clock_timestamp())").bind(other).bind(REALM).execute(&f.admin).await.unwrap();
    let installation: String =
        sqlx::query_scalar("SELECT security_id::text FROM bloc.installation")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let envelope = mfa_owned_cipher(&installation, other, record);
    sqlx::query("INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,'totp','Other owner')").bind(record).bind(REALM).bind(other).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.mfa_encrypted_payload(id,realm_id,user_id,purpose,encryption_key_id,encrypted_payload) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,1,$4::text::uuid,$5)").bind(record).bind(REALM).bind(other).bind(MFA_KEY_A).bind(&envelope).execute(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_totp_factor(factor_id,realm_id,user_id,last_accepted_step) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,0)").bind(record).bind(REALM).bind(other).execute(&f.admin).await.unwrap();
    sqlx::query(
        "UPDATE bloc.mfa_encrypted_payload SET encrypted_payload=$1 WHERE id=$2::text::uuid",
    )
    .bind(envelope)
    .bind(MFA_FACTOR)
    .execute(&f.admin)
    .await
    .unwrap();
    let (status, html, _) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 503, "{html}");
    assert!(!html.contains(&code));
    assert!(!html.contains("BMFA"));
    let(sessions,audits,floor):(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM bloc.realm_user_session),(SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in'),(SELECT last_accepted_step FROM bloc.realm_totp_factor WHERE factor_id=$1::text::uuid)").bind(MFA_FACTOR).fetch_one(&f.admin).await.unwrap();
    assert_eq!((sessions, audits, floor), (0, 0, 12345));
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_owner_relations() {
    let (f, mut b, _op, csrf, code) = mfa_challenge("mfaownerrelations").await;
    let other = "44444444-4444-4444-8444-444444444444";
    sqlx::query("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES($1::text::uuid,$2::text::uuid,'Other@example.test',clock_timestamp(),clock_timestamp())").bind(other).bind(REALM).execute(&f.admin).await.unwrap();
    let error=sqlx::query("INSERT INTO bloc.realm_mfa_flow(realm_id,user_id,bearer_digest,browser_digest,purpose,credential_version,factor_epoch,policy_version,user_version,password_verified_at,parent_id,csrf_token,created_at,expires_at) SELECT realm_id,$1::text::uuid,sha256(uuid_send(gen_random_uuid())),browser_digest,'login',1,1,1,1,password_verified_at,id,csrf_token,created_at,expires_at FROM bloc.realm_mfa_flow WHERE parent_id IS NULL LIMIT 1").bind(other).execute(&f.admin).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23503")
    );
    let payload = uuid::Uuid::new_v4().to_string();
    let installation: String =
        sqlx::query_scalar("SELECT security_id::text FROM bloc.installation")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    sqlx::query("INSERT INTO bloc.mfa_encrypted_payload(id,realm_id,user_id,purpose,encryption_key_id,encrypted_payload) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,1,$4::text::uuid,$5)").bind(&payload).bind(REALM).bind(other).bind(MFA_KEY_A).bind(mfa_owned_cipher(&installation,other,&payload)).execute(&f.admin).await.unwrap();
    let generation:String=sqlx::query_scalar("INSERT INTO bloc.realm_mfa_recovery_generation(realm_id,user_id) VALUES($1::text::uuid,$2::text::uuid) RETURNING id::text").bind(REALM).bind(other).fetch_one(&f.admin).await.unwrap();
    let session:String=sqlx::query_scalar("INSERT INTO bloc.realm_user_session(realm_id,user_id,session_digest,credential_version,created_at,last_activity_at,expires_at,device_label) VALUES($1::text::uuid,$2::text::uuid,sha256(uuid_send(gen_random_uuid())),1,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '5 minutes','Synthetic other') RETURNING id::text").bind(REALM).bind(other).fetch_one(&f.admin).await.unwrap();
    for (column, id) in [
        ("payload_id", payload),
        ("recovery_generation_id", generation),
        ("session_id", session),
    ] {
        let error = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE bloc.realm_mfa_flow SET {column}=$1::text::uuid WHERE user_id=$2::text::uuid"
        )))
        .bind(id)
        .bind(USER)
        .execute(&f.admin)
        .await
        .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23503"),
            "{column}"
        );
    }
    mfa_recovery_form_owner_relation(&f, other).await;
    let (status, html, _) = b
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
}

async fn mfa_recovery_form_owner_relation(f: &Fixture, other: &str) {
    let digest = sec::random().unwrap();
    sqlx::query("INSERT INTO bloc.realm_mfa_recovery_link(realm_id,user_id,token_digest,issued_by,credential_version,user_version,factor_epoch,issued_at,expires_at,policy_version) SELECT $1::text::uuid,$2::text::uuid,$3,id,1,1,1,clock_timestamp(),clock_timestamp()+interval '5 minutes',1 FROM bloc.installation_administrator LIMIT 1").bind(REALM).bind(other).bind(digest.as_slice()).execute(&f.admin).await.unwrap();
    let error=sqlx::query("INSERT INTO bloc.realm_mfa_recovery_form(realm_id,user_id,link_digest,browser_digest,csrf_token,credential_version,user_version,policy_version,factor_epoch,created_at,expires_at) VALUES($1::text::uuid,$2::text::uuid,$3,$3,$3,1,1,1,1,clock_timestamp(),clock_timestamp()+interval '5 minutes')").bind(REALM).bind(USER).bind(digest.as_slice()).execute(&f.admin).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23503")
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.realm_mfa_recovery_form")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}
