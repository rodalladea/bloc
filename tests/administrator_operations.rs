//! Real process/CLI proofs supplement the administrator authority tests.
mod common;

fn run(mode: &str, fixture: Option<&common::Fixture>) {
    let mut command = std::process::Command::new("python3");
    command.args(["tests/support/administrator_operations.py", mode]);
    command.env("BLOC_TEST_BINARY", env!("CARGO_BIN_EXE_bloc"));
    if let Some(fixture) = fixture {
        command
            .env("BLOC_TEST_DATABASE", &fixture.database)
            .env("BLOC_TEST_CA", &fixture.ca);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "operations proof {mode} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[tokio::test]
#[ignore = "disposable TLS PostgreSQL fixture and local processes"]
async fn startup_outage() {
    let fixture = common::Fixture::new("opsstartup").await;
    run("startup", Some(&fixture));
}

#[tokio::test]
#[ignore = "disposable TLS PostgreSQL fixture and local processes"]
async fn runtime_log_secrecy() {
    let fixture = common::Fixture::new("opslogs").await;
    run("logs", Some(&fixture));
}

#[tokio::test]
#[ignore = "disposable TLS PostgreSQL fixture and attached operator CLI"]
async fn restore_cli_atomicity() {
    let fixture = common::Fixture::new("opsrestore").await;
    run("restore", Some(&fixture));
}

#[tokio::test]
#[ignore = "disposable TLS PostgreSQL fixture and fenced processes"]
async fn restore_failure_fencing() {
    let fixture = common::Fixture::new("opsfencing").await;
    run("fencing", Some(&fixture));
}

#[tokio::test]
#[ignore = "disposable TLS PostgreSQL fixture and maintenance CLI"]
async fn maintenance_failure() {
    let fixture = common::Fixture::new("opsmaintenance").await;
    run("maintenance", Some(&fixture));
}

#[test]
#[ignore = "pinned Helm 4.3.1"]
fn deployment_assembly() {
    run("deployment", None);
}
