mod common;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bloc::storage::Claim;
use common::{EMAIL, Fixture, HASH};
use sha2::{Digest, Sha256};
use std::{
    fs,
    process::{Command, Output},
};

fn command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bloc"));
    command
        .args(args)
        .env_remove("BLOC_DATABASE_URL_FILE")
        .env_remove("BLOC_DATABASE_CA_FILE");
    command
}

#[test]
fn usage_and_configuration() {
    for args in [
        vec!["admin", "setup-code", "secret-sentinel"],
        vec!["unknown"],
        vec!["database"],
        vec!["--help", "secret-sentinel"],
    ] {
        let output = command(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "bloc: usage error; use --help\n"
        );
    }
    for args in [["admin", "setup-code"], ["database", "migrate"]] {
        let output = command(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "bloc: invalid database configuration\n"
        );
    }
    let dir = std::env::temp_dir().join(format!("bloc-cli-invalid-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("url"), "invalid-url-secret-sentinel").unwrap();
    fs::write(dir.join("ca"), "synthetic invalid certificate").unwrap();
    for url in [
        "invalid-url-secret-sentinel",
        "postgres://localhost/bloc?host=/private/tmp/bloc-no-such-socket",
        "postgres://%2Fprivate%2Ftmp/bloc",
        "postgres://localhost/bloc?options=-c%20statement_timeout%3D0",
    ] {
        fs::write(dir.join("url"), url).unwrap();
        let output = command(&["admin", "setup-code"])
            .env("BLOC_DATABASE_URL_FILE", dir.join("url"))
            .env("BLOC_DATABASE_CA_FILE", dir.join("ca"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{url}");
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "bloc: invalid database configuration\n"
        );
    }
    fs::remove_dir_all(dir).unwrap();
    let help = command(&["--help"]).output().unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(help.stdout).unwrap(),
        "Usage: bloc [--help | database migrate | admin setup-code]\n"
    );
}

async fn invoke(f: &Fixture, user: &str, args: &[&str], suffix: &str) -> Output {
    let path = std::env::temp_dir().join(format!("bloc-cli-{}-{suffix}.txt", std::process::id()));
    fs::write(&path, f.url(user)).unwrap();
    let mut cmd = command(args);
    cmd.env("BLOC_DATABASE_URL_FILE", &path)
        .env("BLOC_DATABASE_CA_FILE", &f.ca);
    let output = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    fs::remove_file(path).unwrap();
    output
}

#[tokio::test]
#[ignore = "requires disposable TLS PostgreSQL; run tools/administrator-setup-tests.py"]
async fn durable_output_and_failures() {
    let f = Fixture::new("cli").await;
    let migration = invoke(&f, "migrator_user", &["database", "migrate"], "migration").await;
    assert_eq!(migration.status.code(), Some(0));
    assert!(migration.stdout.is_empty());
    let output = invoke(&f, "operator_user", &["admin", "setup-code"], "issue").await;
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(text.ends_with('\n'));
    let code = lines[0].strip_prefix("code=").unwrap();
    assert_eq!(code.len(), 43);
    assert_eq!(URL_SAFE_NO_PAD.decode(code).unwrap().len(), 32);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(URL_SAFE_NO_PAD.decode(code).unwrap()),
        code
    );
    let expiry = lines[1].strip_prefix("expires_at=").unwrap();
    let persisted: bool = sqlx::query_scalar("SELECT expires_at = $1::text::timestamptz AND code_digest = $2 FROM bloc.operator_code WHERE purpose='setup'")
        .bind(expiry).bind(Sha256::digest(code.as_bytes()).as_slice()).fetch_one(&f.admin).await.unwrap();
    assert!(persisted);
    assert_eq!(expiry.len(), 27);
    assert_eq!(&expiry[10..11], "T");
    assert!(expiry.ends_with('Z'));
    f.fail_audit(true).await;
    let output = invoke(&f, "operator_user", &["admin", "setup-code"], "audit").await;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "bloc: database operation unavailable\n"
    );
    f.fail_audit(false).await;
    let digest: [u8; 32] = Sha256::digest(code.as_bytes()).into();
    assert_eq!(
        f.runtime.claim_owner(&digest, EMAIL, HASH).await.unwrap(),
        Claim::Created
    );
    let output = invoke(&f, "operator_user", &["admin", "setup-code"], "closed").await;
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "bloc: setup is closed\n"
    );
    sqlx::query("DROP TABLE bloc.security_audit_event")
        .execute(&f.admin)
        .await
        .unwrap();
    // A separate fresh installation makes storage failure happen before a closed result.
    let unavailable = Fixture::new("cliunavailable").await;
    sqlx::query("DROP TABLE bloc.security_audit_event")
        .execute(&unavailable.admin)
        .await
        .unwrap();
    let output = invoke(
        &unavailable,
        "operator_user",
        &["admin", "setup-code"],
        "unavailable",
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}
