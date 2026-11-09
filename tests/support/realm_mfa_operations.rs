const MFA_KEY_A:&str="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const MFA_KEY_B:&str="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
struct MfaOperator {dir:std::path::PathBuf}
impl MfaOperator {
 fn new(f:&Fixture)->Self{
  use base64::Engine;
  let dir=std::env::temp_dir().join(format!("bloc-mfa-{}-{}",std::process::id(),f.database));std::fs::create_dir_all(&dir).unwrap();
  std::fs::write(dir.join("url"),f.url("operator_user")).unwrap();
  std::fs::write(dir.join("keys"),format!(r#"{{"format_version":1,"keys":[{{"id":"{MFA_KEY_A}","key":"{}"}},{{"id":"{MFA_KEY_B}","key":"{}"}}]}}"#,base64::engine::general_purpose::STANDARD.encode([7;32]),base64::engine::general_purpose::STANDARD.encode([8;32]))).unwrap();Self{dir}
 }
 fn run(&self,f:&Fixture,args:&[&str])->std::process::Output{
  std::process::Command::new(env!("CARGO_BIN_EXE_bloc")).args(["mfa","keys"]).args(args).env("BLOC_DATABASE_URL_FILE",self.dir.join("url")).env("BLOC_DATABASE_CA_FILE",&f.ca).env("BLOC_MFA_KEYRING_FILE",self.dir.join("keys")).output().unwrap()
 }
 fn success(&self,f:&Fixture,args:&[&str])->String{let output=self.run(f,args);assert_eq!(output.status.code(),Some(0),"{}",String::from_utf8_lossy(&output.stderr));String::from_utf8(output.stdout).unwrap()}
}
impl Drop for MfaOperator{fn drop(&mut self){let _=std::fs::remove_dir_all(&self.dir);}}
#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_operator_contract(){
 mfa_operator_reference_contract().await;
 let(f,mut browser)=signed("mfaoperator").await;create_realm(&mut browser,REALM,"Acme").await;contract_seed(&f).await;
 let op=MfaOperator::new(&f);
 assert!(op.success(&f,&["status"]).contains("key_id=none"));
 op.success(&f,&["initialize","--key-id",MFA_KEY_A]);
 assert_eq!(op.run(&f,&["initialize","--key-id",MFA_KEY_A]).status.code(),Some(3));
 op.success(&f,&["stage","--key-id",MFA_KEY_B]);
 assert_eq!(op.run(&f,&["activate","--key-id",MFA_KEY_B,"--expected-generation","1"]).status.code(),Some(2));
 op.success(&f,&["activate","--key-id",MFA_KEY_B,"--expected-generation","1","--confirm-replicas-restarted"]);
 assert_eq!(op.run(&f,&["retire","--key-id",MFA_KEY_B,"--expected-generation","2","--confirm-backup-escrow"]).status.code(),Some(3));
 assert_eq!(op.run(&f,&["retire","--key-id",MFA_KEY_A,"--expected-generation","1","--confirm-backup-escrow"]).status.code(),Some(3));
 op.success(&f,&["retire","--key-id",MFA_KEY_A,"--expected-generation","2","--confirm-backup-escrow"]);
 let status=op.success(&f,&["status"]);assert!(status.contains("state=retired"));assert!(status.contains("generation=3"));
 assert_eq!(op.run(&f,&["reencrypt","--from",MFA_KEY_A,"--batch-size","101"]).status.code(),Some(2));
 assert!(op.success(&f,&["reencrypt","--from",MFA_KEY_A]).contains("converted=0"));
 let audit:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.security_audit_event WHERE action LIKE 'mfa_key_%'").fetch_one(&f.admin).await.unwrap();assert_eq!(audit,4);
 for role in ["runtime_user","maintenance_user"]{let pool=f.pool(role).await;assert!(sqlx::query("SELECT bloc.mfa_key_change('stage',gen_random_uuid(),1,true)").execute(&pool).await.is_err());}
 let config=Config::new("https://bloc.example.test","127.0.0.1/32",[7;32]).unwrap().with_mfa_keyring(&op.dir.join("keys")).unwrap();
 let mut ready=Browser{app:router(Application::new(bloc::storage::Storage::connect(&f.url("runtime_user"),&f.ca).await.unwrap(),config).await.unwrap()),cookies:BTreeMap::new()};
 assert_eq!(ready.request("GET","/readyz",&[]).await.0,200);
 assert_eq!(browser.request("GET","/readyz",&[]).await.0,503);
}
fn mfa_fixture_envelope(installation:&str,record:&str,key_id:&str,key:[u8;32],plaintext:&[u8])->Vec<u8>{
 use chacha20poly1305::{XChaCha20Poly1305,XNonce,aead::{Aead,KeyInit,Payload}};
 let mut header=b"BMFA\x01\x01".to_vec();header.extend_from_slice(uuid::Uuid::parse_str(key_id).unwrap().as_bytes());header.extend_from_slice(&[5;24]);
 let mut aad=header.clone();for id in [installation,REALM,USER]{aad.extend_from_slice(uuid::Uuid::parse_str(id).unwrap().as_bytes());}aad.push(1);aad.extend_from_slice(uuid::Uuid::parse_str(record).unwrap().as_bytes());aad.extend_from_slice(&1u16.to_be_bytes());
 let cipher=XChaCha20Poly1305::new_from_slice(&key).unwrap();header.extend(cipher.encrypt(&XNonce::from([5;24]),Payload{msg:plaintext,aad:&aad}).unwrap());header
}
const MFA_FACTOR:&str="cccccccc-cccc-4ccc-8ccc-cccccccccccc";
async fn mfa_secret_fixture(f:&Fixture){
 let installation:String=sqlx::query_scalar("SELECT security_id::text FROM bloc.installation").fetch_one(&f.admin).await.unwrap();
 let envelope=mfa_fixture_envelope(&installation,MFA_FACTOR,MFA_KEY_A,[7;32],&[9;20]);
 sqlx::query("INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,'totp','Authenticator')").bind(MFA_FACTOR).bind(REALM).bind(USER).execute(&f.admin).await.unwrap();
 sqlx::query("INSERT INTO bloc.mfa_encrypted_payload(id,realm_id,user_id,purpose,encryption_key_id,encrypted_payload) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,1,$4::text::uuid,$5)").bind(MFA_FACTOR).bind(REALM).bind(USER).bind(MFA_KEY_A).bind(envelope).execute(&f.admin).await.unwrap();
 sqlx::query("INSERT INTO bloc.realm_totp_factor(factor_id,realm_id,user_id,last_accepted_step) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,12345)").bind(MFA_FACTOR).bind(REALM).bind(USER).execute(&f.admin).await.unwrap();
 sqlx::query("INSERT INTO bloc.realm_user_mfa_state(realm_id,user_id) VALUES($1::text::uuid,$2::text::uuid) ON CONFLICT DO NOTHING").bind(REALM).bind(USER).execute(&f.admin).await.unwrap();
}
async fn mfa_peer(f: &Fixture, email: &str) -> String {
    let id: String = sqlx::query_scalar("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES(gen_random_uuid(),$1::text::uuid,$2,clock_timestamp(),clock_timestamp()) RETURNING id::text")
        .bind(REALM).bind(email).fetch_one(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_credential(realm_id,user_id,password_hash,credential_version,password_changed_at) SELECT realm_id,$1::text::uuid,password_hash,1,clock_timestamp() FROM bloc.realm_user_credential WHERE realm_id=$2::text::uuid AND user_id=$3::text::uuid")
        .bind(&id).bind(REALM).bind(USER).execute(&f.admin).await.unwrap();
    id
}

async fn rotation_enroll(f: &Fixture, b: &mut Browser, email: &str, key: &str) -> (String, String) {
    let base = format!("/realms/{REALM}");
    let (status, html, headers) = contract_login(b, REALM, email, CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("{base}/mfa"));
    let csrf = b.token(&format!("{base}/mfa")).await;
    let setup = format!("{base}/account/security/totp");
    let (status, html, _) = b
        .request("POST", &format!("{setup}/start"), &[("csrf", &csrf)])
        .await;
    assert_eq!(status, 303, "{html}");
    let (factor, pending_key): (String, String) = sqlx::query_as(
        "SELECT id::text,encryption_key_id::text FROM bloc.mfa_encrypted_payload WHERE purpose=2",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(pending_key, key);
    let (status, html, _) = b.request("GET", &format!("{setup}/setup"), &[]).await;
    assert_eq!(status, 200);
    let secret = totp_manual_key(&html).to_owned();
    let csrf = b.token(&format!("{setup}/setup")).await;
    let code = totp_code_for_secret(f, &secret, false).await;
    let (status, html, headers) = b
        .request(
            "POST",
            &format!("{setup}/confirm"),
            &[("csrf", &csrf), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    let handoff = format!("{base}/account/security/recovery-codes");
    assert_eq!(headers["location"], handoff);
    let active_key: String = sqlx::query_scalar("SELECT encryption_key_id::text FROM bloc.mfa_encrypted_payload WHERE id=$1::text::uuid AND purpose=1")
        .bind(&factor).fetch_one(&f.admin).await.unwrap();
    assert_eq!(active_key, key);
    let handoff_key: String = sqlx::query_scalar(
        "SELECT encryption_key_id::text FROM bloc.mfa_encrypted_payload WHERE purpose=3",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(handoff_key, key);
    let csrf = b.token(&handoff).await;
    let (status, html, _) = b
        .request(
            "POST",
            &format!("{handoff}/acknowledge"),
            &[("csrf", &csrf), ("saved", "true")],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    (factor, secret)
}

async fn rotation_verify(f: &Fixture, b: &mut Browser, email: &str, factor: &str, secret: &str) {
    b.cookies.clear();
    let base = format!("/realms/{REALM}");
    let (status, html, headers) = contract_login(b, REALM, email, CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("{base}/mfa"));
    let cookie = format!("__Host-bloc-realm-{REALM}");
    assert!(!b.cookies.contains_key(&cookie));
    let csrf = b.token(&format!("{base}/mfa")).await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(35);
    let step = loop {
        let (now, floor): (i64, i64) = sqlx::query_as("SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint,last_accepted_step FROM bloc.realm_totp_factor WHERE factor_id=$1::text::uuid")
            .bind(factor).fetch_one(&f.admin).await.unwrap();
        if floor < now + 1 {
            break now.max(floor + 1);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no new valid TOTP step"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    let code = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(secret).unwrap())
        .build()
        .unwrap()
        .generate((step * 30) as u64)
        .to_string();
    let (status, html, headers) = b
        .request(
            "POST",
            &format!("{base}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("{base}/account"));
    assert_eq!(
        b.request("GET", &format!("{base}/account/profile"), &[])
            .await
            .0,
        200
    );
    let evidence: (String, String) = sqlx::query_as("SELECT mfa_method,mfa_factor_id::text FROM bloc.realm_user_session WHERE session_digest=$1 AND revoked_at IS NULL")
        .bind(sec::digest(&b.cookies[&cookie]).as_slice()).fetch_one(&f.admin).await.unwrap();
    assert_eq!(evidence, ("totp".into(), factor.into()));
}

#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c61() {
    let (f, _admin, mut old, op) = mfa_configured("mfac61").await;
    contract_seed(&f).await;
    mfa_peer(&f, "Bob@example.test").await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='required'")
        .execute(&f.admin)
        .await
        .unwrap();

    op.success(&f, &["stage", "--key-id", MFA_KEY_B]);
    let (old_factor, old_secret) =
        rotation_enroll(&f, &mut old, "Alice@example.test", MFA_KEY_A).await;
    op.success(
        &f,
        &[
            "activate",
            "--key-id",
            MFA_KEY_B,
            "--expected-generation",
            "1",
            "--confirm-replicas-restarted",
        ],
    );
    let mut new = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    let (new_factor, new_secret) =
        rotation_enroll(&f, &mut new, "Bob@example.test", MFA_KEY_B).await;

    rotation_verify(&f, &mut old, "Alice@example.test", &old_factor, &old_secret).await;
    rotation_verify(&f, &mut new, "Bob@example.test", &new_factor, &new_secret).await;
    let rows = || {
        sqlx::query_as::<_, (String, String, i64, i64, Vec<u8>)>("SELECT p.id::text,p.encryption_key_id::text,t.last_accepted_step,s.factor_epoch,p.encrypted_payload FROM bloc.mfa_encrypted_payload p JOIN bloc.realm_totp_factor t ON t.factor_id=p.id JOIN bloc.realm_user_mfa_state s ON s.realm_id=p.realm_id AND s.user_id=p.user_id WHERE p.id IN($1::text::uuid,$2::text::uuid) ORDER BY p.id")
        .bind(&old_factor).bind(&new_factor).fetch_all(&f.admin)
    };
    let before = rows().await.unwrap();
    assert_eq!(before.len(), 2);
    assert_eq!(
        before.iter().find(|row| row.0 == old_factor).unwrap().1,
        MFA_KEY_A
    );
    assert_eq!(
        before.iter().find(|row| row.0 == new_factor).unwrap().1,
        MFA_KEY_B
    );

    assert!(
        op.success(&f, &["reencrypt", "--from", MFA_KEY_A, "--batch-size", "1"])
            .contains("converted=1")
    );
    assert!(
        op.success(&f, &["reencrypt", "--from", MFA_KEY_A])
            .contains("converted=0")
    );
    let after = rows().await.unwrap();
    assert_eq!(after.len(), 2);
    for (previous, current) in before.iter().zip(&after) {
        assert_eq!(
            (&current.0, current.2, current.3),
            (&previous.0, previous.2, previous.3)
        );
        assert_eq!(current.1, MFA_KEY_B);
        if current.0 == new_factor {
            assert_eq!(current.4, previous.4);
        } else {
            let installation: String =
                sqlx::query_scalar("SELECT security_id::text FROM bloc.installation")
                    .fetch_one(&f.admin)
                    .await
                    .unwrap();
            let expected = totp_rs::Secret::try_from_base32(&old_secret).unwrap();
            assert_eq!(
                mfa_fixture_decrypt(&installation, &old_factor, &current.4, [8; 32]),
                expected.as_bytes()
            );
        }
    }
    rotation_verify(&f, &mut old, "Alice@example.test", &old_factor, &old_secret).await;
    rotation_verify(&f, &mut new, "Bob@example.test", &new_factor, &new_secret).await;
    op.success(
        &f,
        &[
            "retire",
            "--key-id",
            MFA_KEY_A,
            "--expected-generation",
            "2",
            "--confirm-backup-escrow",
        ],
    );
}

#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_c62(){
 let(f,mut b)=signed("mfac62").await;create_realm(&mut b,REALM,"Acme").await;contract_seed(&f).await;
 let op=MfaOperator::new(&f);op.success(&f,&["initialize","--key-id",MFA_KEY_A]);mfa_secret_fixture(&f).await;
 op.success(&f,&["stage","--key-id",MFA_KEY_B]);op.success(&f,&["activate","--key-id",MFA_KEY_B,"--expected-generation","1","--confirm-replicas-restarted"]);
 assert_eq!(op.run(&f,&["retire","--key-id",MFA_KEY_A,"--expected-generation","2","--confirm-backup-escrow"]).status.code(),Some(3));
 sqlx::query("UPDATE bloc.realm_user_factor SET revoked_at=clock_timestamp() WHERE id=$1::text::uuid").bind(MFA_FACTOR).execute(&f.admin).await.unwrap();
 assert_eq!(op.run(&f,&["retire","--key-id",MFA_KEY_A,"--expected-generation","2","--confirm-backup-escrow"]).status.code(),Some(3));
 let count:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.mfa_encrypted_payload").fetch_one(&f.admin).await.unwrap();assert_eq!(count,1);
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c64() {
    let (f, mut session, op, secret) = account_protected("mfac64").await;
    let base = format!("/realms/{REALM}");
    let profile = format!("{base}/account/profile");
    let verify = format!("{base}/mfa/verify");
    let confirm = format!("{base}/recover-mfa/confirm");
    assert_eq!(session.request("GET", &profile, &[]).await.0, 200);
    let epoch: i64 = sqlx::query_scalar("SELECT factor_epoch FROM bloc.realm_user_mfa_state")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    let mut flow = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    let (status, html, h) =
        contract_login(&mut flow, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(h["location"], format!("{base}/mfa"));
    let csrf = flow.token(&format!("{base}/mfa")).await;
    let mut assisted = policy_flow_replica(&f, &op, BTreeMap::new()).await;
    let code = recovery_issue(&f, &mut assisted).await;
    let assisted_csrf = recovery_exchange(&f, &mut assisted, &code).await;
    let active: (i64, i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL),(SELECT count(*) FROM bloc.realm_mfa_flow WHERE consumed_at IS NULL),(SELECT count(*) FROM bloc.realm_mfa_recovery_form),(SELECT count(*) FROM bloc.realm_mfa_recovery_link WHERE consumed_at IS NULL)").fetch_one(&f.admin).await.unwrap();
    assert_eq!(active, (1, 1, 1, 1));

    f.operator.invalidate_access().await.unwrap();
    let after: (bool, i64, bool, i64, i64, i64, i64) = sqlx::query_as("SELECT i.recovery_required,s.factor_epoch,g.invalidated_at IS NOT NULL,(SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL),(SELECT count(*) FROM bloc.realm_mfa_flow),(SELECT count(*) FROM bloc.realm_mfa_recovery_form),(SELECT count(*) FROM bloc.realm_mfa_recovery_link) FROM bloc.installation i CROSS JOIN bloc.realm_user_mfa_state s CROSS JOIN bloc.realm_mfa_recovery_generation g").fetch_one(&f.admin).await.unwrap();
    assert_eq!(after, (true, epoch + 1, true, 0, 0, 0, 0));
    let code = totp_code_for_secret(&f, &secret, true).await;
    assert_eq!(session.request("GET", &profile, &[]).await.0, 503);
    let factor_proof = [
        ("csrf", csrf.as_str()),
        ("method", "totp"),
        ("code", code.as_str()),
    ];
    let assisted_proof = [
        ("csrf", assisted_csrf.as_str()),
        ("current_password", CONTRACT_PASSWORD),
    ];
    assert_eq!(flow.request("POST", &verify, &factor_proof).await.0, 503);
    assert_eq!(
        assisted.request("POST", &confirm, &assisted_proof).await.0,
        503
    );

    let recovery = sec::encode(&[53; 32]);
    f.operator
        .issue_recovery_code(&sec::digest(&recovery))
        .await
        .unwrap();
    let credential = f.runtime.owner().await.unwrap().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let before = loop {
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&f.admin)
                .await
                .unwrap();
        if now % 30 < 22 {
            break now / 30;
        }
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    assert!(
        f.runtime
            .replace_password(
                &sec::digest(&recovery),
                credential.version,
                common::HASH,
                true
            )
            .await
            .unwrap()
    );
    let (floor, completion): (i64, i64) = sqlx::query_as("SELECT last_accepted_step,floor(extract(epoch FROM clock_timestamp())/30)::bigint FROM bloc.realm_totp_factor").fetch_one(&f.admin).await.unwrap();
    assert_eq!(
        completion, before,
        "operator completion must stay within the measured DB step"
    );
    assert!(floor > completion);

    let (status, _, h) = session.request("GET", &profile, &[]).await;
    assert_eq!(status, 303);
    assert!(
        h["location"]
            .to_str()
            .unwrap()
            .starts_with(&format!("{base}/login"))
    );
    let (status, _, h) = flow.request("POST", &verify, &factor_proof).await;
    assert_eq!(status, 303);
    assert_eq!(h["location"], format!("{base}/login?expired=mfa"));
    assert_eq!(
        assisted.request("POST", &confirm, &assisted_proof).await.0,
        409
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
#[ignore="TLS fixture"]
async fn realm_mfa_c59(){
 let(f,mut b)=signed("mfac59").await;create_realm(&mut b,REALM,"Acme").await;contract_seed(&f).await;
 let(mode,methods,epoch):(String,Vec<String>,i64)=sqlx::query_as("SELECT p.mfa_mode,p.mfa_allowed_methods,s.factor_epoch FROM bloc.realm_authentication_settings p JOIN bloc.realm_user_mfa_state s USING(realm_id)").fetch_one(&f.admin).await.unwrap();
 assert_eq!(mode,"optional");assert_eq!(methods,vec!["totp","webauthn"]);assert_eq!(epoch,1);
 let mut public=Browser::new(&f).await;let(status,html,headers)=contract_login(&mut public,REALM,"Alice@example.test",CONTRACT_PASSWORD).await;assert_eq!(status,303,"{html}");assert_eq!(headers["location"],format!("/realms/{REALM}/account"));
 let(password,mfa):(bool,bool)=sqlx::query_as("SELECT password_verified_at IS NOT NULL,mfa_method IS NULL AND mfa_factor_id IS NULL AND mfa_verified_at IS NULL FROM bloc.realm_user_session").fetch_one(&f.admin).await.unwrap();assert!(password&&mfa);
 let op=MfaOperator::new(&f);mfa_upgrade_preserves(&f,&op).await;
}
#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_c60(){
 let(f,mut b)=signed("mfac60").await;let op=MfaOperator::new(&f);
 mfa_startup_diagnostics(&f,&op);
 assert_eq!(b.request("GET","/readyz",&[]).await.0,503);
 let config=Config::new("https://bloc.example.test","127.0.0.1/32",[7;32]).unwrap().with_mfa_keyring(&op.dir.join("keys")).unwrap();
 let mut mounted=Browser{app:router(Application::new(bloc::storage::Storage::connect(&f.url("runtime_user"),&f.ca).await.unwrap(),config).await.unwrap()),cookies:BTreeMap::new()};
 assert_eq!(mounted.request("GET","/readyz",&[]).await.0,503);
 op.success(&f,&["initialize","--key-id",MFA_KEY_A]);assert_eq!(mounted.request("GET","/readyz",&[]).await.0,200);
 op.success(&f,&["stage","--key-id",MFA_KEY_B]);
 let mut incomplete:serde_json::Value=serde_json::from_slice(&std::fs::read(op.dir.join("keys")).unwrap()).unwrap();incomplete["keys"].as_array_mut().unwrap().truncate(1);std::fs::write(op.dir.join("incomplete"),serde_json::to_vec(&incomplete).unwrap()).unwrap();
 let config=Config::new("https://bloc.example.test","127.0.0.1/32",[7;32]).unwrap().with_mfa_keyring(&op.dir.join("incomplete")).unwrap();
 let mut missing=Browser{app:router(Application::new(bloc::storage::Storage::connect(&f.url("runtime_user"),&f.ca).await.unwrap(),config).await.unwrap()),cookies:BTreeMap::new()};assert_eq!(missing.request("GET","/readyz",&[]).await.0,503);
 std::fs::write(op.dir.join("keys"),"{}").unwrap();
 assert!(Config::new("https://bloc.example.test","127.0.0.1/32",[7;32]).unwrap().with_mfa_keyring(&op.dir.join("keys")).is_err());
 assert_eq!(mounted.request("GET","/readyz",&[]).await.0,200);
 std::fs::remove_file(op.dir.join("keys")).unwrap();assert!(Config::new("https://bloc.example.test","127.0.0.1/32",[7;32]).unwrap().with_mfa_keyring(&op.dir.join("keys")).is_err());
}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c66() {
    let (f, mut browser, op, csrf, code) = mfa_challenge("mfac66").await;
    sqlx::query("INSERT INTO bloc.realm_mfa_flow(realm_id,user_id,bearer_digest,browser_digest,purpose,credential_version,factor_epoch,policy_version,user_version,password_verified_at,csrf_token,created_at,expires_at) SELECT realm_id,user_id,decode(repeat('22',32),'hex'),browser_digest,purpose,credential_version,factor_epoch,policy_version,user_version,password_verified_at,csrf_token,clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute' FROM bloc.realm_mfa_flow").execute(&f.admin).await.unwrap();
    let ids = || {
        sqlx::query_scalar::<_, String>("SELECT id::text FROM bloc.realm_mfa_flow ORDER BY id")
            .fetch_all(&f.admin)
    };
    let before = ids().await.unwrap();
    assert_eq!(before.len(), 2);
    sqlx::raw_sql("CREATE FUNCTION bloc.mfa_test_fail_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic maintenance failure'; END $$;CREATE TRIGGER mfa_test_fail BEFORE DELETE ON bloc.realm_mfa_flow FOR EACH ROW EXECUTE FUNCTION bloc.mfa_test_fail_delete();").execute(&f.admin).await.unwrap();
    let url = op.dir.join("maintenance-url");
    std::fs::write(&url, f.url("maintenance_user")).unwrap();
    let maintain = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_bloc"))
            .args(["database", "maintain"])
            .env("BLOC_DATABASE_URL_FILE", &url)
            .env("BLOC_DATABASE_CA_FILE", &f.ca)
            .output()
            .unwrap()
    };
    let failed = maintain();
    assert_eq!(failed.status.code(), Some(1));
    assert!(failed.stdout.is_empty());
    assert_eq!(
        failed.stderr,
        b"bloc: database operation unavailable
"
    );
    assert_eq!(ids().await.unwrap(), before);
    policy_flow_no_success(&f).await;
    sqlx::query("DROP TRIGGER mfa_test_fail ON bloc.realm_mfa_flow")
        .execute(&f.admin)
        .await
        .unwrap();
    let succeeded = maintain();
    assert_eq!(succeeded.status.code(), Some(0));
    let (count, live): (i64, bool) = sqlx::query_as(
        "SELECT count(*),bool_and(expires_at>clock_timestamp()) FROM bloc.realm_mfa_flow",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!((count, live), (1, true));
    let (status, html, headers) = browser
        .request(
            "POST",
            &format!("/realms/{REALM}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/account"));
}

#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_privilege_audit_contract(){
 mfa_recovery_audit_assertions().await;
 mfa_denial_dimension_contract().await;
 let(f,mut b)=signed("mfaaudit").await;create_realm(&mut b,REALM,"Acme").await;contract_seed(&f).await;
 let op=MfaOperator::new(&f);op.success(&f,&["initialize","--key-id",MFA_KEY_A]);mfa_secret_fixture(&f).await;
 op.success(&f,&["stage","--key-id",MFA_KEY_B]);op.success(&f,&["activate","--key-id",MFA_KEY_B,"--expected-generation","1","--confirm-replicas-restarted"]);
 sqlx::raw_sql("CREATE FUNCTION bloc.mfa_test_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='mfa_key_reencrypt' THEN RAISE EXCEPTION 'synthetic audit failure';END IF; RETURN NEW; END $$;CREATE TRIGGER mfa_test_fail_audit BEFORE INSERT ON bloc.security_audit_event FOR EACH ROW EXECUTE FUNCTION bloc.mfa_test_fail_audit();").execute(&f.admin).await.unwrap();
 assert_eq!(op.run(&f,&["reencrypt","--from",MFA_KEY_A]).status.code(),Some(1));
 let key:String=sqlx::query_scalar("SELECT encryption_key_id::text FROM bloc.mfa_encrypted_payload").fetch_one(&f.admin).await.unwrap();assert_eq!(key,MFA_KEY_A);
 sqlx::query("DROP TRIGGER mfa_test_fail_audit ON bloc.security_audit_event").execute(&f.admin).await.unwrap();
 op.success(&f,&["reencrypt","--from",MFA_KEY_A]);
 for role in ["runtime_user","operator_user","maintenance_user"]{
  let pool=f.pool(role).await;
  for table in ["mfa_encrypted_payload","mfa_encryption_key_registry","realm_totp_factor","realm_user_factor","realm_mfa_flow"]{
   assert!(sqlx::query(sqlx::AssertSqlSafe(format!("SELECT * FROM bloc.{table}"))).fetch_all(&pool).await.is_err());
   assert!(sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM bloc.{table}"))).execute(&pool).await.is_err());
  }
 }
 let unsafe_functions:i64=sqlx::query_scalar("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='bloc' AND p.proname LIKE 'mfa_%' AND p.prosecdef AND NOT coalesce(p.proconfig @> ARRAY['search_path=pg_catalog, bloc, pg_temp'],false)").fetch_one(&f.admin).await.unwrap();assert_eq!(unsafe_functions,0);
}
fn mfa_binary_readiness(f:&Fixture,op:&MfaOperator,binary:&std::path::Path,url:&str)->u16{
 use std::io::{Read,Write};
 let address=std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
 std::fs::write(op.dir.join("serve-url"),url).unwrap();std::fs::write(op.dir.join("abuse"),[7;32]).unwrap();
 let child=std::process::Command::new(binary).env("BLOC_DATABASE_URL_FILE",op.dir.join("serve-url")).env("BLOC_DATABASE_CA_FILE",&f.ca).env("BLOC_MFA_KEYRING_FILE",op.dir.join("keys")).env("BLOC_ABUSE_KEY_FILE",op.dir.join("abuse")).env("BLOC_BIND_ADDR",address.to_string()).env("BLOC_CANONICAL_ORIGIN","https://bloc.example.test").env("BLOC_TRUSTED_PROXY_CIDRS","127.0.0.1/32").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
 struct Running(std::process::Child);impl Drop for Running{fn drop(&mut self){let _=self.0.kill();let _=self.0.wait();}}
 let mut child=Running(child);
 for _ in 0..150{
  if let Ok(mut stream)=std::net::TcpStream::connect(address){stream.set_read_timeout(Some(std::time::Duration::from_secs(8))).unwrap();stream.write_all(b"GET /readyz HTTP/1.1\r\nHost: bloc.example.test\r\nConnection: close\r\n\r\n").unwrap();let mut text=String::new();stream.read_to_string(&mut text).unwrap();return text.split_whitespace().nth(1).unwrap().parse().unwrap();}
  assert!(child.0.try_wait().unwrap().is_none(),"binary exited before readiness");std::thread::sleep(std::time::Duration::from_millis(100));
 }
 panic!("binary did not start")
}
#[tokio::test]
#[ignore="TLS fixture and retained pre-MFA binary"]
async fn realm_mfa_c65(){
 let old=std::path::PathBuf::from(std::env::var_os("BLOC_MFA_LEGACY_BINARY").expect("retained base executable required"));
 let f=Fixture::new("mfac65").await;let op=MfaOperator::new(&f);
 assert_eq!(mfa_binary_readiness(&f,&op,&old,&f.url("runtime_user")),503);
 let root=sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(Fixture::options("probe","probe")).await.unwrap();
 let database=format!("mfa_old_{}",std::process::id());sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database} OWNER migrator_user"))).execute(&root).await.unwrap();
 let url=f.url("migrator_user").replace(&f.database,&database);std::fs::write(op.dir.join("legacy-url"),&url).unwrap();
 let output=std::process::Command::new(&old).args(["database","migrate"]).env("BLOC_DATABASE_URL_FILE",op.dir.join("legacy-url")).env("BLOC_DATABASE_CA_FILE",&f.ca).output().unwrap();assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
 let runtime=f.url("runtime_user").replace(&f.database,&database);
 assert_eq!(mfa_binary_readiness(&f,&op,std::path::Path::new(env!("CARGO_BIN_EXE_bloc")),&runtime),503);
 assert_eq!(mfa_binary_readiness(&f,&op,&old,&runtime),200);
}
#[tokio::test]
#[ignore="documentation contract proof"]
async fn realm_mfa_c67(){
 let text=include_str!("../../docs/realm-mfa-operations.md");
 for statement in ["Database-only compromise lacks key material", "Runtime compromise can", "compromised origin can steal proofs", "no production acceptance"]{assert!(text.contains(statement),"missing trust boundary: {statement}");}
}
async fn mfa_upgrade_preserves(f: &Fixture, op: &MfaOperator) {
    let old = std::path::PathBuf::from(
        std::env::var_os("BLOC_MFA_LEGACY_BINARY")
            .expect("retained base executable required for backfill proof"),
    );
    let database = format!("mfa_upgrade_{}", f.database);
    let root = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(Fixture::options("probe", "probe"))
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE {database} OWNER migrator_user"
    )))
    .execute(&root)
    .await
    .unwrap();
    let url = f.url("migrator_user").replace(&f.database, &database);
    std::fs::write(op.dir.join("upgrade-url"), &url).unwrap();
    let output = std::process::Command::new(old)
        .args(["database", "migrate"])
        .env("BLOC_DATABASE_URL_FILE", op.dir.join("upgrade-url"))
        .env("BLOC_DATABASE_CA_FILE", &f.ca)
        .output()
        .unwrap();
    assert!(output.status.success());
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(Fixture::options(&database, "probe"))
        .await
        .unwrap();
    sqlx::raw_sql("INSERT INTO bloc.realm(id,name,created_at,updated_at) VALUES('11111111-1111-4111-8111-111111111111','Acme',clock_timestamp(),clock_timestamp());INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111','Alice@example.test',clock_timestamp(),clock_timestamp());INSERT INTO bloc.realm_user_session(realm_id,user_id,session_digest,credential_version,created_at,last_activity_at,expires_at,revoked_at,device_label) VALUES('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',decode(repeat('11',32),'hex'),1,clock_timestamp()-interval '1 hour',clock_timestamp()-interval '1 hour',clock_timestamp()-interval '30 minutes',clock_timestamp()-interval '45 minutes','Synthetic')").execute(&admin).await.unwrap();
    let existing_hash: String = sqlx::query_scalar("SELECT password_hash FROM bloc.realm_user_credential WHERE realm_id=$1::text::uuid AND user_id=$2::text::uuid")
        .bind(REALM).bind(USER).fetch_one(&f.admin).await.unwrap();
    sqlx::query("INSERT INTO bloc.realm_user_credential(realm_id,user_id,password_hash,credential_version,password_changed_at) VALUES($1::text::uuid,$2::text::uuid,$3,1,clock_timestamp()-interval '1 hour')")
        .bind(REALM).bind(USER).bind(&existing_hash).execute(&admin).await.unwrap();
    let before: (String, String) =
        sqlx::query_as("SELECT expires_at::text,revoked_at::text FROM bloc.realm_user_session")
            .fetch_one(&admin)
            .await
            .unwrap();
    let migrator = bloc::storage::Storage::connect(&url, &f.ca).await.unwrap();
    migrator.migrate().await.unwrap();
    let after: (String, String, bool, i64) = sqlx::query_as("SELECT expires_at::text,revoked_at::text,password_verified_at=created_at,factor_epoch FROM bloc.realm_user_session")
        .fetch_one(&admin).await.unwrap();
    assert_eq!((&after.0, &after.1), (&before.0, &before.1));
    assert!(after.2);
    assert_eq!(after.3, 1);
    let policy: (String, Vec<String>, i64, i64) = sqlx::query_as("SELECT mfa_mode,mfa_allowed_methods,(SELECT count(*) FROM bloc.realm_user_factor),(SELECT factor_epoch FROM bloc.realm_user_mfa_state) FROM bloc.realm_authentication_settings")
        .fetch_one(&admin).await.unwrap();
    assert_eq!(
        policy,
        (
            "optional".into(),
            vec!["totp".into(), "webauthn".into()],
            0,
            1
        )
    );

    let operator_url = op.dir.join("upgrade-operator-url");
    std::fs::write(
        &operator_url,
        f.url("operator_user").replace(&f.database, &database),
    )
    .unwrap();
    let initialized = std::process::Command::new(env!("CARGO_BIN_EXE_bloc"))
        .args(["mfa", "keys", "initialize", "--key-id", MFA_KEY_A])
        .env("BLOC_DATABASE_URL_FILE", &operator_url)
        .env("BLOC_DATABASE_CA_FILE", &f.ca)
        .env("BLOC_MFA_KEYRING_FILE", op.dir.join("keys"))
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let config = Config::new("https://bloc.example.test", "127.0.0.1/32", [7; 32])
        .unwrap()
        .with_mfa_keyring(&op.dir.join("keys"))
        .unwrap();
    let runtime = f.url("runtime_user").replace(&f.database, &database);
    let mut public = Browser {
        app: router(
            Application::new(
                bloc::storage::Storage::connect(&runtime, &f.ca)
                    .await
                    .unwrap(),
                config,
            )
            .await
            .unwrap(),
        ),
        cookies: BTreeMap::new(),
    };
    assert_eq!(public.request("GET", "/readyz", &[]).await.0, 200);
    let (status, html, headers) =
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(headers["location"], format!("/realms/{REALM}/account"));
    assert!(
        !public
            .cookies
            .contains_key(&format!("__Host-bloc-realm-mfa-{REALM}"))
    );
    assert_eq!(
        public
            .request("GET", &format!("/realms/{REALM}/account/profile"), &[])
            .await
            .0,
        200
    );
    let bearer = &public.cookies[&format!("__Host-bloc-realm-{REALM}")];
    let session: (String, i64, bool, bool) = sqlx::query_as("SELECT user_id::text,factor_epoch,password_verified_at IS NOT NULL,mfa_method IS NULL AND mfa_factor_id IS NULL AND mfa_verified_at IS NULL FROM bloc.realm_user_session WHERE session_digest=$1 AND revoked_at IS NULL")
        .bind(sec::digest(bearer).as_slice()).fetch_one(&admin).await.unwrap();
    assert_eq!(session, (USER.into(), 1, true, true));
    let flows: i64 = sqlx::query_scalar("SELECT count(*) FROM bloc.realm_mfa_flow")
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(flows, 0);
}
fn mfa_fixture_decrypt(installation:&str,record:&str,envelope:&[u8],key:[u8;32])->Vec<u8>{
 use chacha20poly1305::{XChaCha20Poly1305,XNonce,aead::{Aead,KeyInit,Payload}};
 let mut aad=envelope[..46].to_vec();for id in [installation,REALM,USER]{aad.extend_from_slice(uuid::Uuid::parse_str(id).unwrap().as_bytes());}aad.push(1);aad.extend_from_slice(uuid::Uuid::parse_str(record).unwrap().as_bytes());aad.extend_from_slice(&1u16.to_be_bytes());
 XChaCha20Poly1305::new_from_slice(&key).unwrap().decrypt(&XNonce::try_from(&envelope[22..46]).unwrap(),Payload{msg:&envelope[46..],aad:&aad}).unwrap()
}
#[tokio::test]
#[ignore="TLS fixture and two operator processes"]
async fn realm_mfa_rotation_races(){
 let(f,mut b)=signed("mfaraces").await;create_realm(&mut b,REALM,"Acme").await;contract_seed(&f).await;
 let op=MfaOperator::new(&f);op.success(&f,&["initialize","--key-id",MFA_KEY_A]);mfa_secret_fixture(&f).await;
 op.success(&f,&["stage","--key-id",MFA_KEY_B]);op.success(&f,&["activate","--key-id",MFA_KEY_B,"--expected-generation","1","--confirm-replicas-restarted"]);
 let outcomes=std::thread::scope(|scope|{let a=scope.spawn(||op.run(&f,&["reencrypt","--from",MFA_KEY_A]));let b=scope.spawn(||op.run(&f,&["reencrypt","--from",MFA_KEY_A]));[a.join().unwrap(),b.join().unwrap()]});
 let converted=outcomes.iter().filter(|o|String::from_utf8_lossy(&o.stdout).contains("converted=1")).count();assert_eq!(converted,1);
 for outcome in outcomes{assert!(matches!(outcome.status.code(),Some(0|1)));}
 let count:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.security_audit_event WHERE action='mfa_key_reencrypt'").fetch_one(&f.admin).await.unwrap();assert_eq!(count,1);
 let operator=f.pool("operator_user").await;
 let outcome:String=sqlx::query_scalar("SELECT bloc.mfa_reencrypt_commit(ARRAY[$1::text::uuid],ARRAY[1::bigint],ARRAY[decode(repeat('11',82),'hex')],1,$2::text::uuid)").bind(MFA_FACTOR).bind(MFA_KEY_B).fetch_one(&operator).await.unwrap();assert_eq!(outcome,"conflict");
}
async fn mfa_configured(name:&str)->(Fixture,Browser,Browser,MfaOperator){
 let(f,mut admin,mut public)=contract_start(name,true).await;let op=MfaOperator::new(&f);op.success(&f,&["initialize","--key-id",MFA_KEY_A]);
 for browser in [&mut admin,&mut public]{let config=Config::new("https://bloc.example.test","127.0.0.1/32",[7;32]).unwrap().with_mfa_keyring(&op.dir.join("keys")).unwrap();browser.app=router(Application::new(bloc::storage::Storage::connect(&f.url("runtime_user"),&f.ca).await.unwrap(),config).await.unwrap());}
 (f,admin,public,op)
}
async fn mfa_policy_post(admin:&mut Browser,mode:&str,methods:&[&str],confirmed:bool,password:&str)->(StatusCode,String,axum::http::HeaderMap){
 let path=format!("/admin/realms/{REALM}/authentication");let csrf=admin.token(&path).await;
 let mut fields=contract_settings(&csrf,"1");fields.extend([("mfa_mode",mode),("mfa_recovery_codes_enabled","true"),("mfa_admin_recovery_enabled","true"),("mfa_flow_ttl_seconds","300"),("mfa_admin_recovery_ttl_seconds","1800")]);
 for method in methods{fields.push((if *method=="totp"{"mfa_totp_allowed"}else{"mfa_webauthn_allowed"},"true"));}
 if confirmed{fields.extend([("confirmed","true"),("administrator_password",password)]);}
 admin.request("POST",&path,&fields).await
}
#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_c08(){let(f,mut admin,_,_op)=mfa_configured("mfac08").await;let(status,html,_)=mfa_policy_post(&mut admin,"optional",&[],false,"").await;assert_eq!(status,422,"{html}");let version:i64=sqlx::query_scalar("SELECT version FROM bloc.realm_authentication_settings").fetch_one(&f.admin).await.unwrap();assert_eq!(version,1);}
#[tokio::test]
#[ignore = "TLS fixture"]
async fn realm_mfa_c07() {
    let (f, mut admin, mut public, _op) = mfa_configured("mfac07").await;
    contract_seed(&f).await;
    mfa_peer(&f, "Bob@example.test").await;
    mfa_secret_fixture(&f).await;
    let base = format!("/realms/{REALM}");
    let (status, html, h) =
        contract_login(&mut public, REALM, "Alice@example.test", CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(h["location"], format!("{base}/mfa"));
    let csrf = public.token(&format!("{base}/mfa")).await;
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
    let (status, html, h) = public
        .request(
            "POST",
            &format!("{base}/mfa/verify"),
            &[("csrf", &csrf), ("method", "totp"), ("code", &code)],
        )
        .await;
    assert_eq!(status, 303, "{html}");
    assert_eq!(h["location"], format!("{base}/account"));
    let cookie = format!("__Host-bloc-realm-{REALM}");
    let bearer = public.cookies[&cookie].clone();
    let session = || {
        sqlx::query_as::<_, (String, String, String)>("SELECT id::text,mfa_method,mfa_factor_id::text FROM bloc.realm_user_session WHERE session_digest=$1 AND revoked_at IS NULL")
        .bind(sec::digest(&bearer).to_vec()).fetch_one(&f.admin)
    };
    let evidence = session().await.unwrap();
    assert_eq!((&*evidence.1, &*evidence.2), ("totp", MFA_FACTOR));

    let (status, html, _) = mfa_policy_post(&mut admin, "required", &["totp"], false, "").await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("<dt>Accounts requiring enrollment</dt><dd>1</dd>"));
    assert!(html.contains("<dt>Accounts with no allowed factor</dt><dd>0</dd>"));
    assert!(html.contains("Administrator password"));
    assert!(html.contains(r#"name="version" value="1""#));
    let (status, _, _) = mfa_policy_post(&mut admin, "required", &["totp"], true, "wrong").await;
    assert_eq!(status, 422);
    let (status, html, _) =
        mfa_policy_post(&mut admin, "required", &["totp"], true, CONTRACT_PASSWORD).await;
    assert_eq!(status, 303, "{html}");
    let (mode, version): (String, i64) =
        sqlx::query_as("SELECT mfa_mode,version FROM bloc.realm_authentication_settings")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!((mode.as_str(), version), ("required", 2));
    assert_eq!(
        public
            .request("GET", &format!("{base}/account/profile"), &[])
            .await
            .0,
        200
    );
    assert_eq!(public.cookies[&cookie], bearer);
    assert_eq!(session().await.unwrap(), evidence);
}
#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_c12(){
 let(f,_admin,mut public,_op)=mfa_configured("mfac12").await;contract_seed(&f).await;sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='required'").execute(&f.admin).await.unwrap();
 let(status,html,headers)=contract_login(&mut public,REALM,"Alice@example.test",CONTRACT_PASSWORD).await;assert_eq!(status,303,"{html}");assert_eq!(headers["location"],format!("/realms/{REALM}/mfa"));assert!(!public.cookies.contains_key(&format!("__Host-bloc-realm-{REALM}")));assert!(public.cookies.contains_key(&format!("__Host-bloc-realm-mfa-{REALM}")));
 let count:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.realm_user_session").fetch_one(&f.admin).await.unwrap();assert_eq!(count,0);
 let(status,html,_)=public.request("GET",&format!("/realms/{REALM}/mfa"),&[]).await;assert_eq!(status,200,"{html}");assert!(html.contains("Set up two-factor authentication"));
 let count:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.security_audit_event WHERE action IN('realm_sign_in','realm_mfa_sign_in')").fetch_one(&f.admin).await.unwrap();assert_eq!(count,0);
}
async fn mfa_challenge(name:&str)->(Fixture,Browser,MfaOperator,String,String){
 let(f,_admin,mut public,op)=mfa_configured(name).await;contract_seed(&f).await;mfa_secret_fixture(&f).await;
 let(status,html,headers)=contract_login(&mut public,REALM,"Alice@example.test",CONTRACT_PASSWORD).await;assert_eq!(status,303,"{html}");assert_eq!(headers["location"],format!("/realms/{REALM}/mfa"));
 let csrf=public.token(&format!("/realms/{REALM}/mfa")).await;
 let now:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(&f.admin).await.unwrap();let code=totp_rs::Builder::new().with_secret([9u8;20]).build().unwrap().generate(now as u64).to_string();(f,public,op,csrf,code)
}
#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_c04(){
 let(f,mut public,_op,csrf,code)=mfa_challenge("mfac04").await;
 assert!(!public.cookies.contains_key(&format!("__Host-bloc-realm-{REALM}")));
 let(status,html,headers)=public.request("POST",&format!("/realms/{REALM}/mfa/verify"),&[("csrf",&csrf),("method","totp"),("code",&code)]).await;assert_eq!(status,303,"{html}");assert_eq!(headers["location"],format!("/realms/{REALM}/account"));
 let evidence:(String,String,bool)=sqlx::query_as("SELECT mfa_method,mfa_factor_id::text,mfa_verified_at IS NOT NULL FROM bloc.realm_user_session").fetch_one(&f.admin).await.unwrap();assert_eq!(evidence,("totp".into(),MFA_FACTOR.into(),true));
}
#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_c17(){
 let(f,mut public,_op,csrf,_code)=mfa_challenge("mfac17").await;
 for attempt in 1..=5{let(status,html,headers)=public.request("POST",&format!("/realms/{REALM}/mfa/verify"),&[("csrf",&csrf),("method","totp"),("code","!!!!!!")]).await;assert_eq!(status,if attempt==5{429}else{422},"{html}");if attempt==5{assert!(headers.contains_key("retry-after"));}}
 let(failed,consumed):(i16,bool)=sqlx::query_as("SELECT failed_attempts,consumed_at IS NOT NULL FROM bloc.realm_mfa_flow").fetch_one(&f.admin).await.unwrap();assert_eq!(failed,5);assert!(consumed);
 let count:i64=sqlx::query_scalar("SELECT count(*) FROM bloc.realm_user_session").fetch_one(&f.admin).await.unwrap();assert_eq!(count,0);
}
#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_c63(){
 let (trace, sink) = mfa_capture_diagnostics();
 let _guard = tracing::subscriber::set_default(trace);
 mfa_http_foreign_owner_cipher().await;
 let(f,mut public,_op,csrf,code)=mfa_challenge("mfac63").await;
 sqlx::query("UPDATE bloc.mfa_encrypted_payload SET encrypted_payload=set_byte(encrypted_payload,octet_length(encrypted_payload)-1,get_byte(encrypted_payload,octet_length(encrypted_payload)-1)#1)").execute(&f.admin).await.unwrap();
 let(status,html,_)=public.request("POST",&format!("/realms/{REALM}/mfa/verify"),&[("csrf",&csrf),("method","totp"),("code",&code)]).await;assert_eq!(status,503,"{html}");assert!(!html.contains(&code));assert!(!html.contains("tag"));
 let(count,audits):(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM bloc.realm_user_session),(SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in')").fetch_one(&f.admin).await.unwrap();assert_eq!((count,audits),(0,0));
 let diagnostic=String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
 assert_eq!(diagnostic.lines().filter(|line| *line == "realm authority transition aborted").count(),2);
 assert!(!diagnostic.contains(&code));assert!(!diagnostic.contains(&csrf));assert!(!diagnostic.contains("BMFA"));
}
#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_c21(){
 let(f,_admin,mut public,_op)=mfa_configured("mfac21").await;contract_seed(&f).await;sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='required'").execute(&f.admin).await.unwrap();
 assert_eq!(contract_login(&mut public,REALM,"Alice@example.test",CONTRACT_PASSWORD).await.0,303);
 let csrf=public.token(&format!("/realms/{REALM}/mfa")).await;
 let(status,html,headers)=public.request("POST",&format!("/realms/{REALM}/account/security/totp/start"),&[("csrf",&csrf)]).await;assert_eq!(status,303,"{html}");assert_eq!(headers["location"],format!("/realms/{REALM}/account/security/totp/setup"));
 let(status,html,_)=public.request("GET",&format!("/realms/{REALM}/account/security/totp/setup"),&[]).await;assert_eq!(status,200,"{html}");assert!(html.contains("Setup key"));assert!(html.contains("ui-setup-secret"));assert!(html.contains("/totp/qr"));
 let key=html.split("id=\"setup-key\"").nth(1).unwrap().split('>').nth(1).unwrap().split('<').next().unwrap();assert_eq!(key.len(),32);
 let(pending,active):(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM bloc.mfa_encrypted_payload WHERE purpose=2),(SELECT count(*) FROM bloc.realm_user_factor)").fetch_one(&f.admin).await.unwrap();assert_eq!((pending,active),(1,0));
 let bytes:Vec<u8>=sqlx::query_scalar("SELECT encrypted_payload FROM bloc.mfa_encrypted_payload").fetch_one(&f.admin).await.unwrap();assert!(!bytes.windows(key.len()).any(|part|part==key.as_bytes()));
 let mut request=Request::builder().uri(format!("/realms/{REALM}/account/security/totp/qr")).header("host","bloc.example.test").header("x-forwarded-proto","https").header("x-forwarded-for","192.0.2.4").header("cookie",public.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ")).body(Body::empty()).unwrap();request.extensions_mut().insert(ConnectInfo("127.0.0.1:54321".parse::<std::net::SocketAddr>().unwrap()));
 let response=public.app.clone().oneshot(request).await.unwrap();assert_eq!(response.status(),200);assert_eq!(response.headers()["content-type"],"image/png");let bytes=to_bytes(response.into_body(),1048576).await.unwrap();assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
 let mut other = Browser { app: public.app.clone(), cookies: BTreeMap::new() };
 assert_eq!(other.request("GET", &format!("/realms/{REALM}/login"), &[]).await.0, 200);
 for borrowed in [false, true] {
     if borrowed {
         let flow = format!("__Host-bloc-realm-mfa-{REALM}");
         other.cookies.insert(flow.clone(), public.cookies[&flow].clone());
         let anonymous = format!("__Host-bloc-realm-{REALM}-anonymous");
         assert_ne!(other.cookies[&anonymous], public.cookies[&anonymous]);
     }
     for route in ["setup", "qr"] {
         let (status, html, headers) = other.request("GET", &format!("/realms/{REALM}/account/security/totp/{route}"), &[]).await;
         assert_eq!(status, 403, "{html}");
         assert_ne!(headers["content-type"], "image/png");
         assert!(!html.contains(key));
         assert!(!html.contains("id=\"setup-key\""));
     }
 }
 assert_eq!(contract_count(&f, "SELECT count(*) FROM bloc.mfa_encrypted_payload WHERE purpose=2").await, 1);
}
async fn mfa_pending_setup(name:&str)->(Fixture,Browser,MfaOperator,String,String){
 let(f,_admin,mut public,op)=mfa_configured(name).await;contract_seed(&f).await;sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='required'").execute(&f.admin).await.unwrap();assert_eq!(contract_login(&mut public,REALM,"Alice@example.test",CONTRACT_PASSWORD).await.0,303);
 let csrf=public.token(&format!("/realms/{REALM}/mfa")).await;assert_eq!(public.request("POST",&format!("/realms/{REALM}/account/security/totp/start"),&[("csrf",&csrf)]).await.0,303);
 let(_,html,_)=public.request("GET",&format!("/realms/{REALM}/account/security/totp/setup"),&[]).await;
 let key=html.split("id=\"setup-key\"").nth(1).unwrap().split('>').nth(1).unwrap().split('<').next().unwrap();let secret=totp_rs::Secret::try_from_base32(key).unwrap();let now:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(&f.admin).await.unwrap();let code=totp_rs::Builder::new().with_secret(secret).build().unwrap().generate(now as u64).to_string();
 let csrf=html.split("name=\"csrf\" value=\"").nth(1).unwrap().split('"').next().unwrap().to_owned();(f,public,op,csrf,code)
}
#[tokio::test]
#[ignore="TLS fixture"]
async fn realm_mfa_c23(){
 let(f,mut public,_op,csrf,code)=mfa_pending_setup("mfac23").await;
 let(status,html,headers)=public.request("POST",&format!("/realms/{REALM}/account/security/totp/confirm"),&[("csrf",&csrf),("code",&code)]).await;assert_eq!(status,303,"{html}");assert_eq!(headers["location"],format!("/realms/{REALM}/account/security/recovery-codes"));
 let(active,purpose,sessions):(i64,i16,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL),(SELECT purpose FROM bloc.mfa_encrypted_payload WHERE id IN(SELECT factor_id FROM bloc.realm_totp_factor)),(SELECT count(*) FROM bloc.realm_user_session)").fetch_one(&f.admin).await.unwrap();assert_eq!((active,purpose,sessions),(1,1,0));
 let csrf=public.token(&format!("/realms/{REALM}/account/security/recovery-codes")).await;
 let(status,_,_)=public.request("POST",&format!("/realms/{REALM}/account/security/recovery-codes/acknowledge"),&[("csrf",&csrf)]).await;assert_eq!(status,422);
 let(status,html,_)=public.request("POST",&format!("/realms/{REALM}/account/security/recovery-codes/acknowledge"),&[("csrf",&csrf),("saved","true")]).await;assert_eq!(status,303,"{html}");
 let evidence:(bool,bool)=sqlx::query_as("SELECT mfa_method='totp',mfa_verified_at IS NOT NULL FROM bloc.realm_user_session").fetch_one(&f.admin).await.unwrap();assert_eq!(evidence,(true,true));
}
