mod common;

use bloc::storage::{Claim, Error, Storage};
use common::{EMAIL, Fixture, HASH};
use sqlx::Row;

#[tokio::test]
#[ignore = "requires disposable TLS PostgreSQL; run tests/run_storage.py"]
async fn migration_contract() {
    let f = Fixture::new("migration").await;
    f.migrator.migrate().await.unwrap();
    assert_eq!(f.count("installation").await, 1);
    f.runtime.compatible().await.unwrap();
    assert!(
        sqlx::query("INSERT INTO bloc.installation (id) VALUES (2)")
            .execute(&f.admin)
            .await
            .is_err()
    );
    sqlx::query("UPDATE public._sqlx_migrations SET checksum = decode('00', 'hex')")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(f.runtime.compatible().await, Err(Error::Incompatible));
    assert_eq!(f.migrator.migrate().await, Err(Error::Unavailable));
    sqlx::query("DELETE FROM public._sqlx_migrations")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(f.runtime.compatible().await, Err(Error::Incompatible));
    sqlx::query("INSERT INTO public._sqlx_migrations (version, description, success, checksum, execution_time) VALUES (2, 'ahead', true, decode('00', 'hex'), 0)").execute(&f.admin).await.unwrap();
    assert_eq!(f.runtime.compatible().await, Err(Error::Incompatible));
}

#[tokio::test]
#[ignore = "requires disposable TLS PostgreSQL; run tests/run_storage.py"]
async fn capability_roles() {
    let f = Fixture::new("roles").await;
    assert_eq!(
        f.runtime.issue_setup_code(&[1; 32]).await,
        Err(Error::Unavailable)
    );
    assert_eq!(
        f.operator.claim_owner(&[1; 32], EMAIL, HASH).await,
        Err(Error::Unavailable)
    );
    for user in [
        "runtime_user",
        "operator_user",
        "maintenance_user",
        "public_user",
    ] {
        let pool = f.pool(user).await;
        for sql in [
            "INSERT INTO bloc.operator_code (installation_id,purpose,code_digest,issued_at,expires_at) VALUES (1,'setup',decode(repeat('01',32),'hex'),now(),now()+interval '15 minutes')",
            "UPDATE bloc.installation_administrator SET password_hash = 'attacker'",
            "CREATE TABLE bloc.unauthorized (id int)",
            "DELETE FROM bloc.security_audit_event",
        ] {
            let err = sqlx::query(sql).execute(&pool).await.unwrap_err();
            assert_eq!(
                err.as_database_error().unwrap().code().as_deref(),
                Some("42501"),
                "{user}: {sql}"
            );
        }
        if matches!(user, "maintenance_user" | "public_user") {
            for sql in [
                "SELECT bloc.issue_setup_code(decode(repeat('01',32),'hex'))",
                "SELECT bloc.claim_owner(decode(repeat('01',32),'hex'), 'x@example.test', 'hash')",
            ] {
                let err = sqlx::query(sql).execute(&pool).await.unwrap_err();
                assert_eq!(
                    err.as_database_error().unwrap().code().as_deref(),
                    Some("42501")
                );
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable TLS PostgreSQL; run tests/run_storage.py"]
async fn issue_and_replace() {
    let f = Fixture::new("replace").await;
    let expiry = f
        .operator
        .issue_setup_code(&[1; 32])
        .await
        .unwrap()
        .unwrap();
    assert!(expiry.ends_with('Z'));
    let row = sqlx::query("SELECT code_digest, expires_at = issued_at + interval '15 minutes' AS lifetime FROM bloc.operator_code").fetch_one(&f.admin).await.unwrap();
    assert_eq!(row.get::<Vec<u8>, _>("code_digest"), vec![1; 32]);
    assert!(row.get::<bool, _>("lifetime"));
    f.operator
        .issue_setup_code(&[2; 32])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        f.runtime.claim_owner(&[1; 32], EMAIL, HASH).await.unwrap(),
        Claim::Unusable
    );
    assert_eq!(
        f.runtime.claim_owner(&[2; 32], EMAIL, HASH).await.unwrap(),
        Claim::Created
    );
    assert_eq!(
        f.runtime
            .claim_owner(&[2; 32], "other@example.test", HASH)
            .await
            .unwrap(),
        Claim::Closed
    );
    assert!(
        f.operator
            .issue_setup_code(&[3; 32])
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(f.count("installation_administrator").await, 1);
    let (email, hash, version): (String, String, i64) = sqlx::query_as(
        "SELECT email,password_hash,credential_version FROM bloc.installation_administrator",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(email, EMAIL);
    assert_eq!(hash, HASH);
    assert_eq!(version, 1);
    let consumed: bool = sqlx::query_scalar(
        "SELECT consumed_at IS NOT NULL FROM bloc.operator_code WHERE purpose='setup'",
    )
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert!(consumed);
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM bloc.security_audit_event ORDER BY occurred_at")
            .fetch_all(&f.admin)
            .await
            .unwrap();
    assert_eq!(actions, ["code_issue", "code_issue", "setup"]);
    let columns: Vec<String> = sqlx::query_scalar("SELECT column_name::text FROM information_schema.columns WHERE table_schema='bloc' AND table_name='security_audit_event' ORDER BY ordinal_position").fetch_all(&f.admin).await.unwrap();
    assert_eq!(
        columns,
        [
            "id",
            "occurred_at",
            "installation_id",
            "administrator_id",
            "action",
            "outcome",
            "request_id",
            "realm_id",
            "realm_user_id"
        ]
    );
}

#[tokio::test]
#[ignore = "requires disposable TLS PostgreSQL; run tests/run_storage.py"]
async fn unusable_codes() {
    let f = Fixture::new("unusable").await;
    f.operator.issue_setup_code(&[1; 32]).await.unwrap();
    assert_eq!(
        f.runtime.claim_owner(&[9; 32], EMAIL, HASH).await.unwrap(),
        Claim::Unusable
    );
    // Same statement timestamp for both fields preserves the fixed lifetime constraint.
    sqlx::query("UPDATE bloc.operator_code SET issued_at=statement_timestamp()-interval '15 minutes', expires_at=statement_timestamp()").execute(&f.admin).await.unwrap();
    assert_eq!(
        f.runtime.claim_owner(&[1; 32], EMAIL, HASH).await.unwrap(),
        Claim::Unusable
    );
    f.operator.issue_setup_code(&[2; 32]).await.unwrap();
    sqlx::query("UPDATE bloc.operator_code SET consumed_at=clock_timestamp()")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        f.runtime.claim_owner(&[2; 32], EMAIL, HASH).await.unwrap(),
        Claim::Unusable
    );
    // A recovery digest cannot be matched as setup authority, even if known to the caller.
    assert_eq!(f.count("installation_administrator").await, 0);
    assert_eq!(f.count("security_audit_event").await, 2);
    f.operator.issue_setup_code(&[4; 32]).await.unwrap();
    assert_eq!(
        f.runtime.claim_owner(&[4; 32], EMAIL, HASH).await.unwrap(),
        Claim::Created
    );
    sqlx::query("INSERT INTO bloc.operator_code (installation_id,purpose,code_digest,administrator_id,credential_version,issued_at,expires_at) SELECT 1,'recovery',decode(repeat('03',32),'hex'),id,credential_version,statement_timestamp(),statement_timestamp()+interval '15 minutes' FROM bloc.installation_administrator").execute(&f.admin).await.unwrap();
    assert_eq!(
        f.runtime
            .claim_owner(&[3; 32], "Intruder@example.test", HASH)
            .await
            .unwrap(),
        Claim::Closed
    );
    assert_eq!(f.count("installation_administrator").await, 1);
    let email: String = sqlx::query_scalar("SELECT email FROM bloc.installation_administrator")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(email, EMAIL);
}

#[tokio::test]
#[ignore = "requires disposable TLS PostgreSQL; run tests/run_storage.py"]
async fn competing_claims() {
    let f = Fixture::new("race").await;
    f.operator.issue_setup_code(&[1; 32]).await.unwrap();
    let other = Storage::connect(&f.url("runtime_user"), &f.ca)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        f.runtime.claim_owner(&[1; 32], EMAIL, HASH),
        other.claim_owner(&[1; 32], "Other@example.test", HASH)
    );
    let results = [a.unwrap(), b.unwrap()];
    assert_eq!(results.iter().filter(|&&v| v == Claim::Created).count(), 1);
    assert_eq!(results.iter().filter(|&&v| v == Claim::Closed).count(), 1);
    assert_eq!(f.count("installation_administrator").await, 1);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM bloc.security_audit_event WHERE action='setup'")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(count, 1);
    assert!(sqlx::query("INSERT INTO bloc.installation_administrator (installation_id,email,password_hash,created_at,password_changed_at) VALUES (1,'third@example.test','hash',now(),now())").execute(&f.admin).await.is_err());
}

#[tokio::test]
#[ignore = "requires disposable TLS PostgreSQL; run tests/run_storage.py"]
async fn claim_and_replacement_serialize() {
    for issuance_first in [true, false] {
        let name = if issuance_first {
            "replacefirst"
        } else {
            "claimfirst"
        };
        let f = Fixture::new(name).await;
        f.operator.issue_setup_code(&[1; 32]).await.unwrap();
        let mut lock = f.admin.begin().await.unwrap();
        sqlx::query("SELECT id FROM bloc.installation WHERE id=1 FOR UPDATE")
            .execute(&mut *lock)
            .await
            .unwrap();

        async fn wait_for(f: &Fixture, user: &str) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(400);
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND wait_event_type='Lock')")
                    .bind(user).fetch_one(&f.admin).await.unwrap();
                if waiting {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "operation must queue behind installation lock"
                );
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }

        let operator = f.operator.clone();
        let runtime = f.runtime.clone();
        let issue = async move { operator.issue_setup_code(&[2; 32]).await };
        let claim = async move { runtime.claim_owner(&[1; 32], EMAIL, HASH).await };
        let (issue, claim) = if issuance_first {
            let issue = tokio::spawn(issue);
            wait_for(&f, "operator_user").await;
            let claim = tokio::spawn(claim);
            wait_for(&f, "runtime_user").await;
            (issue, claim)
        } else {
            let claim = tokio::spawn(claim);
            wait_for(&f, "runtime_user").await;
            let issue = tokio::spawn(issue);
            wait_for(&f, "operator_user").await;
            (issue, claim)
        };
        lock.commit().await.unwrap();
        let expiry = issue.await.unwrap().unwrap();
        let outcome = claim.await.unwrap().unwrap();
        if issuance_first {
            assert!(expiry.is_some());
            assert_eq!(outcome, Claim::Unusable);
            assert_eq!(f.count("installation_administrator").await, 0);
            assert_eq!(
                f.runtime.claim_owner(&[2; 32], EMAIL, HASH).await.unwrap(),
                Claim::Created
            );
            assert_eq!(f.count("security_audit_event").await, 3);
        } else {
            assert!(expiry.is_none());
            assert_eq!(outcome, Claim::Created);
            assert_eq!(f.count("security_audit_event").await, 2);
        }
        assert_eq!(f.count("installation_administrator").await, 1);
    }
}

#[tokio::test]
#[ignore = "requires disposable TLS PostgreSQL; run tests/run_storage.py"]
async fn audit_failure_rolls_back() {
    let f = Fixture::new("audit").await;
    f.operator.issue_setup_code(&[1; 32]).await.unwrap();
    f.fail_audit(true).await;
    assert_eq!(
        f.operator.issue_setup_code(&[2; 32]).await,
        Err(Error::Unavailable)
    );
    assert_eq!(
        f.runtime.claim_owner(&[1; 32], EMAIL, HASH).await,
        Err(Error::Unavailable)
    );
    assert_eq!(f.count("installation_administrator").await, 0);
    assert_eq!(f.count("security_audit_event").await, 1);
    let (digest, consumed): (Vec<u8>, bool) =
        sqlx::query_as("SELECT code_digest,consumed_at IS NOT NULL FROM bloc.operator_code")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(digest, vec![1; 32]);
    assert!(!consumed);
    f.fail_audit(false).await;
    assert_eq!(
        f.runtime.claim_owner(&[1; 32], EMAIL, HASH).await.unwrap(),
        Claim::Created
    );
}

#[tokio::test]
#[ignore = "requires disposable TLS PostgreSQL; run tests/run_storage.py"]
async fn expiry_after_lock() {
    let f = Fixture::new("lockexpiry").await;
    f.operator.issue_setup_code(&[1; 32]).await.unwrap();
    let mut lock = f.admin.begin().await.unwrap();
    sqlx::query("SELECT id FROM bloc.installation WHERE id=1 FOR UPDATE")
        .execute(&mut *lock)
        .await
        .unwrap();
    sqlx::query("UPDATE bloc.operator_code SET issued_at=statement_timestamp()-interval '15 minutes'+interval '350 milliseconds', expires_at=statement_timestamp()+interval '350 milliseconds'").execute(&mut *lock).await.unwrap();
    let runtime = f.runtime.clone();
    let claim = tokio::spawn(async move { runtime.claim_owner(&[1; 32], EMAIL, HASH).await });
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
    loop {
        let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname=current_database() AND usename='runtime_user' AND wait_event_type='Lock')")
            .fetch_one(&f.admin).await.unwrap();
        if waiting {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "claim must wait behind installation lock before code expiry"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    lock.commit().await.unwrap();
    assert_eq!(claim.await.unwrap().unwrap(), Claim::Unusable);
    assert_eq!(f.count("installation_administrator").await, 0);
}

#[tokio::test]
#[ignore = "requires disposable TLS PostgreSQL; run tests/run_storage.py"]
async fn authority_failure() {
    let f = Fixture::new("authority").await;
    #[derive(Clone)]
    struct LogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let logs = LogBuffer(Default::default());
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::info!("capture-is-active");
    assert_eq!(
        f.runtime.claim_owner(&[1; 32], EMAIL, HASH).await.unwrap(),
        Claim::Unusable
    );
    let captured = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(captured.contains("capture-is-active"));
    assert!(!captured.contains("claim_owner"));
    assert!(!captured.contains(EMAIL));
    assert!(!captured.contains(HASH));
    sqlx::query("ALTER ROLE runtime_user SET default_transaction_read_only=on")
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(matches!(
        Storage::connect(&f.url("runtime_user"), &f.ca).await,
        Err(Error::Incompatible)
    ));
    sqlx::query("ALTER ROLE runtime_user RESET default_transaction_read_only")
        .execute(&f.admin)
        .await
        .unwrap();
    let url = f.url("runtime_user").replace(
        &format!(":{}/", std::env::var("BLOC_SETUP_PORT").unwrap()),
        ":1/",
    );
    assert!(matches!(
        Storage::connect(&url, &f.ca).await,
        Err(Error::Unavailable)
    ));
    sqlx::query("DROP FUNCTION bloc.claim_owner(bytea,text,text)")
        .execute(&f.admin)
        .await
        .unwrap();
    assert_eq!(
        f.runtime.claim_owner(&[1; 32], EMAIL, HASH).await,
        Err(Error::Unavailable)
    );
    assert_eq!(f.count("installation_administrator").await, 0);
}
