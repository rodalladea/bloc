fn mfa_startup_diagnostics(f: &Fixture, op: &MfaOperator) {
    let runtime = op.dir.join("runtime-diagnostic-url");
    let abuse = op.dir.join("runtime-diagnostic-abuse");
    let invalid = op.dir.join("malformed-mfa-keyring");
    std::fs::write(&runtime, f.url("runtime_user")).unwrap();
    std::fs::write(&abuse, [7; 32]).unwrap();
    std::fs::write(&invalid, b"{\"key\":\"redacted-test-marker\"}").unwrap();
    for keyring in [None, Some(&invalid)] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_bloc"));
        command
            .env_remove("BLOC_MFA_KEYRING_FILE")
            .env("BLOC_DATABASE_URL_FILE", &runtime)
            .env("BLOC_DATABASE_CA_FILE", &f.ca)
            .env("BLOC_ABUSE_KEY_FILE", &abuse)
            .env("BLOC_CANONICAL_ORIGIN", "https://bloc.example.test")
            .env("BLOC_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
            .env("BLOC_BIND_ADDR", "invalid address");
        if let Some(path) = keyring {
            command.env("BLOC_MFA_KEYRING_FILE", path);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"bloc: invalid server configuration\n");
    }
}

#[derive(Clone, Default)]
struct MfaDiagnosticSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for MfaDiagnosticSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn mfa_capture_diagnostics() -> (impl tracing::Subscriber, MfaDiagnosticSink) {
    let sink = MfaDiagnosticSink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .with_level(false)
        .with_target(false)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    (subscriber, sink)
}

fn mfa_redacted_operator_output(output: &std::process::Output) {
    use base64::Engine;
    for material in [[7; 32], [8; 32]] {
        let text = base64::engine::general_purpose::STANDARD.encode(material);
        for stream in [&output.stdout, &output.stderr] {
            assert!(
                !stream
                    .windows(text.len())
                    .any(|part| part == text.as_bytes())
            );
            assert!(!stream.windows(material.len()).any(|part| part == material));
        }
    }
}

fn mfa_operator_assert(f: &Fixture, op: &MfaOperator, args: &[&str], status: i32) -> String {
    let output = op.run(f, args);
    mfa_redacted_operator_output(&output);
    assert_eq!(
        output.status.code(),
        Some(status),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn mfa_pending_fixture_envelope(installation: uuid::Uuid, id: uuid::Uuid) -> Vec<u8> {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    let nonce = {
        let mut bytes = [0; 24];
        getrandom::fill(&mut bytes).unwrap();
        bytes
    };
    let mut header = b"BMFA\x01\x01".to_vec();
    header.extend_from_slice(uuid::Uuid::parse_str(MFA_KEY_A).unwrap().as_bytes());
    header.extend_from_slice(&nonce);
    let mut aad = header.clone();
    for owner in [
        installation,
        uuid::Uuid::parse_str(REALM).unwrap(),
        uuid::Uuid::parse_str(USER).unwrap(),
    ] {
        aad.extend_from_slice(owner.as_bytes());
    }
    aad.push(2);
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&1u16.to_be_bytes());
    let cipher = XChaCha20Poly1305::new_from_slice(&[7; 32]).unwrap();
    header.extend(
        cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &[9; 20],
                    aad: &aad,
                },
            )
            .unwrap(),
    );
    header
}

fn mfa_operator_activate_second(f: &Fixture, op: &MfaOperator) {
    mfa_operator_assert(f, op, &["stage", "--key-id", MFA_KEY_B], 0);
    mfa_operator_assert(
        f,
        op,
        &[
            "activate",
            "--key-id",
            MFA_KEY_B,
            "--expected-generation",
            "1",
            "--confirm-replicas-restarted",
        ],
        0,
    );
}

async fn mfa_operator_reference_contract() {
    let (f, _admin, _public, op) = mfa_configured("mfakeybatchsize").await;
    contract_seed(&f).await;
    let installation: String =
        sqlx::query_scalar("SELECT security_id::text FROM bloc.installation")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let installation = uuid::Uuid::parse_str(&installation).unwrap();
    // Test-owned synthetic rows use valid authenticated payloads and unique nonces.
    for _ in 0..101 {
        let id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO bloc.mfa_encrypted_payload(id,realm_id,user_id,purpose,encryption_key_id,encrypted_payload) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,2,$4::text::uuid,$5)")
            .bind(id.to_string()).bind(REALM).bind(USER).bind(MFA_KEY_A).bind(mfa_pending_fixture_envelope(installation,id)).execute(&f.admin).await.unwrap();
    }
    mfa_operator_activate_second(&f, &op);
    let admin = &f.admin;
    let remaining = |expected| async move {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.mfa_encrypted_payload WHERE encryption_key_id=$1::text::uuid").bind(MFA_KEY_A).fetch_one(admin).await.unwrap();
        assert_eq!(count, expected);
    };
    remaining(101).await;
    assert_eq!(
        mfa_operator_assert(&f, &op, &["reencrypt", "--from", MFA_KEY_A], 0),
        "converted=100\nremaining=1\n"
    );
    remaining(1).await;
    assert_eq!(
        mfa_operator_assert(
            &f,
            &op,
            &["reencrypt", "--from", MFA_KEY_A, "--batch-size", "1"],
            0
        ),
        "converted=1\nremaining=0\n"
    );
    remaining(0).await;
    mfa_operator_assert(
        &f,
        &op,
        &[
            "retire",
            "--key-id",
            MFA_KEY_A,
            "--expected-generation",
            "2",
        ],
        2,
    );
    mfa_operator_assert(
        &f,
        &op,
        &[
            "retire",
            "--key-id",
            MFA_KEY_A,
            "--expected-generation",
            "2",
            "--confirm-backup-escrow",
        ],
        0,
    );
    mfa_operator_assert(&f, &op, &["status"], 0);
    let events: Vec<(String,i64,i64)> = sqlx::query_as("SELECT action,count(*),count(*) FILTER(WHERE installation_id<>1 OR outcome<>'success' OR administrator_id IS NOT NULL OR realm_id IS NOT NULL OR realm_user_id IS NOT NULL OR actor_realm_id IS NOT NULL OR actor_user_id IS NOT NULL OR mfa_factor_id IS NOT NULL) FROM bloc.security_audit_event WHERE action LIKE 'mfa_key_%' GROUP BY action ORDER BY action").fetch_all(&f.admin).await.unwrap();
    assert_eq!(
        events,
        vec![
            ("mfa_key_activate".into(), 1, 0),
            ("mfa_key_initialize".into(), 1, 0),
            ("mfa_key_reencrypt".into(), 2, 0),
            ("mfa_key_retire".into(), 1, 0),
            ("mfa_key_stage".into(), 1, 0),
        ]
    );

    for (name, purpose, flow_purpose) in [
        ("mfakeypendingref", 2i16, "totp_enrollment"),
        ("mfakeyhandoffref", 3, "handoff"),
    ] {
        let (f, mut b, op, csrf, code) = mfa_pending_setup(name).await;
        if purpose == 3 {
            assert_eq!(
                b.request(
                    "POST",
                    &format!("/realms/{REALM}/account/security/totp/confirm"),
                    &[("csrf", &csrf), ("code", &code)]
                )
                .await
                .0,
                303
            );
        }
        mfa_operator_activate_second(&f, &op);
        if purpose == 3 {
            // Keep only the live handoff on the retiring key. The factor remains owned.
            let (factor, installation, old): (String,String,Vec<u8>) = sqlx::query_as("SELECT f.id::text,i.security_id::text,p.encrypted_payload FROM bloc.realm_user_factor f JOIN bloc.mfa_encrypted_payload p ON p.id=f.id CROSS JOIN bloc.installation i WHERE f.kind='totp'").fetch_one(&f.admin).await.unwrap();
            let plaintext =
                zeroize::Zeroizing::new(mfa_fixture_decrypt(&installation, &factor, &old, [7; 32]));
            let reference =
                mfa_fixture_envelope(&installation, &factor, MFA_KEY_B, [8; 32], &plaintext);
            sqlx::query("UPDATE bloc.mfa_encrypted_payload SET encryption_key_id=$1::text::uuid,encrypted_payload=$2 WHERE id=$3::text::uuid")
                .bind(MFA_KEY_B).bind(reference).bind(factor).execute(&f.admin).await.unwrap();
        }
        let (references, live): (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM bloc.mfa_encrypted_payload WHERE encryption_key_id=$1::text::uuid),(SELECT count(*) FROM bloc.realm_mfa_flow f JOIN bloc.mfa_encrypted_payload p ON p.id=f.payload_id WHERE p.encryption_key_id=$1::text::uuid AND p.purpose=$2 AND f.purpose=$3 AND f.consumed_at IS NULL AND f.expires_at>clock_timestamp())")
            .bind(MFA_KEY_A).bind(purpose).bind(flow_purpose).fetch_one(&f.admin).await.unwrap();
        assert_eq!((references, live), (1, 1));
        mfa_operator_assert(
            &f,
            &op,
            &[
                "retire",
                "--key-id",
                MFA_KEY_A,
                "--expected-generation",
                "2",
                "--confirm-backup-escrow",
            ],
            3,
        );
    }
}

async fn mfa_denial_and_audit(f: &Fixture, dimension: &str, actions: &[&str], secrets: &[&str]) {
    let denials: Vec<(String, i64)> = sqlx::query_as("SELECT reason,sum(count)::bigint FROM bloc.realm_denial_aggregate WHERE action=$1 GROUP BY reason ORDER BY reason").bind(dimension).fetch_all(&f.admin).await.unwrap();
    assert_eq!(denials, vec![("credentials".to_owned(), 1)]);
    for &action in actions {
        let (count,bad): (i64,i64) = sqlx::query_as("SELECT count(*),count(*) FILTER(WHERE outcome<>'success' OR realm_id IS DISTINCT FROM $2::text::uuid OR realm_user_id IS DISTINCT FROM $3::text::uuid OR actor_realm_id IS DISTINCT FROM realm_id OR actor_user_id IS DISTINCT FROM realm_user_id OR administrator_id IS NOT NULL) FROM bloc.security_audit_event WHERE action=$1").bind(action).bind(REALM).bind(USER).fetch_one(&f.admin).await.unwrap();
        assert!(
            count > 0,
            "production action {action} did not produce an audit"
        );
        assert_eq!(bad, 0, "incorrect owner or outcome for {action}");
    }
    let redacted: String = sqlx::query_scalar("SELECT json_build_object('audit',(SELECT json_agg(e) FROM bloc.security_audit_event e),'denials',(SELECT json_agg(d) FROM bloc.realm_denial_aggregate d))::text").fetch_one(&f.admin).await.unwrap();
    for secret in secrets {
        assert!(
            !redacted.contains(secret),
            "secret leaked in audit/denial storage"
        );
    }
}

async fn mfa_denial_dimension_contract() {
    let (f, mut b, _op, csrf, code) = mfa_challenge("mfaauditproof").await;
    let path = format!("/realms/{REALM}/mfa/verify");
    assert_eq!(
        b.request(
            "POST",
            &path,
            &[
                ("csrf", &csrf),
                ("method", "totp"),
                ("code", "bad-proof-marker")
            ]
        )
        .await
        .0,
        422
    );
    assert_eq!(
        b.request(
            "POST",
            &path,
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)]
        )
        .await
        .0,
        303
    );
    mfa_denial_and_audit(
        &f,
        "mfa_proof",
        &["realm_mfa_sign_in"],
        &[&csrf, &code, "bad-proof-marker"],
    )
    .await;
    let factor: String = sqlx::query_scalar("SELECT mfa_factor_id::text FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in'").fetch_one(&f.admin).await.unwrap();
    assert_eq!(factor, MFA_FACTOR);

    let (f, mut b, _op, csrf, code) = mfa_pending_setup("mfaauditenrollment").await;
    let path = format!("/realms/{REALM}/account/security/totp/confirm");
    assert_eq!(
        b.request(
            "POST",
            &path,
            &[("csrf", &csrf), ("code", "bad-enrollment-marker")]
        )
        .await
        .0,
        422
    );
    assert_eq!(
        b.request("POST", &path, &[("csrf", &csrf), ("code", &code)])
            .await
            .0,
        303
    );
    mfa_denial_and_audit(
        &f,
        "mfa_enrollment",
        &["realm_mfa_factor_enroll", "realm_mfa_code_issue"],
        &[&csrf, &code, "bad-enrollment-marker"],
    )
    .await;

    let (f, mut b, _op, secret) = account_protected("mfaauditaccount").await;
    let path = format!("/realms/{REALM}/account/security");
    let csrf = b.token(&path).await;
    let (factor, epoch): (String,String) = sqlx::query_as("SELECT f.id::text,m.factor_epoch::text FROM bloc.realm_user_factor f JOIN bloc.realm_user_mfa_state m USING(realm_id,user_id) WHERE f.revoked_at IS NULL").fetch_one(&f.admin).await.unwrap();
    assert_eq!(
        b.request(
            "POST",
            &format!("{path}/reauthenticate"),
            &[
                ("csrf", &csrf),
                ("operation", "recovery_codes_regenerate"),
                ("current_password", "bad-account-marker")
            ]
        )
        .await
        .0,
        422
    );
    assert_eq!(
        b.request(
            "POST",
            &format!("{path}/factors/{factor}/label"),
            &[
                ("csrf", &csrf),
                ("epoch", &epoch),
                ("label", "synthetic-label-marker")
            ]
        )
        .await
        .0,
        303
    );
    assert_eq!(
        b.request(
            "POST",
            &format!("{path}/preferred"),
            &[("csrf", &csrf), ("epoch", &epoch), ("factor", &factor)]
        )
        .await
        .0,
        303
    );
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='optional'")
        .execute(&f.admin)
        .await
        .unwrap();
    let proof = account_begin_proof(&f, &mut b, &format!("factor_remove:{factor}"), &secret).await;
    assert_eq!(
        b.request(
            "POST",
            &format!("{path}/factors/{factor}/remove"),
            &[("csrf", &proof), ("epoch", &epoch), ("confirmed", "true")]
        )
        .await
        .0,
        303
    );
    mfa_denial_and_audit(
        &f,
        "mfa_account",
        &[
            "realm_mfa_factor_label",
            "realm_mfa_preference",
            "realm_mfa_factor_remove",
        ],
        &[
            &csrf,
            &proof,
            &secret,
            "synthetic-label-marker",
            "bad-account-marker",
            CONTRACT_PASSWORD,
        ],
    )
    .await;

    let (f, mut b, _op, _secret) = account_protected("mfaauditassisted").await;
    let code = recovery_issue(&f, &mut b).await;
    let csrf = recovery_exchange(&f, &mut b, &code).await;
    let path = format!("/realms/{REALM}/recover-mfa/confirm");
    assert_eq!(
        b.request(
            "POST",
            &path,
            &[("csrf", &csrf), ("current_password", "bad-assisted-marker")]
        )
        .await
        .0,
        422
    );
    assert_eq!(
        b.request(
            "POST",
            &path,
            &[("csrf", &csrf), ("current_password", CONTRACT_PASSWORD)]
        )
        .await
        .0,
        303
    );
    mfa_denial_and_audit(
        &f,
        "mfa_recovery",
        &["realm_mfa_assisted_consume"],
        &[&code, &csrf, "bad-assisted-marker", CONTRACT_PASSWORD],
    )
    .await;
    let actor: (String,String,bool,bool,bool) = sqlx::query_as("SELECT realm_id::text,realm_user_id::text,administrator_id=(SELECT id FROM bloc.installation_administrator),actor_realm_id IS NULL,actor_user_id IS NULL FROM bloc.security_audit_event WHERE action='realm_mfa_assisted_issue' AND outcome='success'").fetch_one(&f.admin).await.unwrap();
    assert_eq!(actor, (REALM.into(), USER.into(), true, true, true));
}
