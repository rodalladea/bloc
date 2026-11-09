async fn webauthn_browser_proof(mode: &str) {
    let (f, mut admin, _public, op) = mfa_configured(&format!("webauthn{mode}")).await;
    contract_seed(&f).await;
    create_realm(&mut admin, OTHER, "Other").await;
    contract_seed_other(&f).await;
    sqlx::query("UPDATE bloc.realm_authentication_settings SET mfa_mode='required'")
        .execute(&f.admin)
        .await
        .unwrap();
    let directory = op.dir.join("services");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("runtime"), f.url("runtime_user")).unwrap();
    std::fs::write(directory.join("operator"), f.url("operator_user")).unwrap();
    std::fs::write(directory.join("abuse"), [7; 32]).unwrap();
    let mut services = Services {
        children: vec![],
        directory,
    };
    for port in [31001, 31002] {
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_bloc"))
            .env("BLOC_DATABASE_URL_FILE", services.directory.join("runtime"))
            .env("BLOC_DATABASE_CA_FILE", &f.ca)
            .env("BLOC_ABUSE_KEY_FILE", services.directory.join("abuse"))
            .env("BLOC_MFA_KEYRING_FILE", op.dir.join("keys"))
            .env("BLOC_CANONICAL_ORIGIN", "https://bloc.example.test:4443")
            .env("BLOC_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
            .env("BLOC_BIND_ADDR", format!("127.0.0.1:{port}"))
            .stdout(
                std::fs::File::create(services.directory.join(format!("service-{port}.stdout")))
                    .unwrap(),
            )
            .stderr(
                std::fs::File::create(services.directory.join(format!("service-{port}.stderr")))
                    .unwrap(),
            )
            .spawn()
            .unwrap();
        services.children.push(child);
    }
    for port in [31001, 31002] {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    let mut command = std::process::Command::new(
        std::env::var("BLOC_BROWSER_PYTHON").expect("real browser required"),
    );
    command
        .args(["tests/support/realm_mfa_webauthn_browser.py", mode])
        .env("BLOC_TEST_ORIGIN", "https://bloc.example.test:4443")
        .env(
            "BLOC_DATABASE_URL_FILE",
            services.directory.join("operator"),
        )
        .env(
            "BLOC_TEST_SPKI",
            std::env::var("BLOC_TEST_SPKI").expect("synthetic TLS pin required"),
        )
        .env("BLOC_REALM_SERVICE_LOGS", &services.directory);
    let output = tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
#[tokio::test]
#[ignore = "real TLS browser"]
async fn realm_mfa_c28() {
    webauthn_browser_proof("c28").await;
}
#[tokio::test]
#[ignore = "real TLS browser"]
async fn realm_mfa_c29() {
    webauthn_browser_proof("c29").await;
}
#[tokio::test]
#[ignore = "real TLS browser"]
async fn realm_mfa_c30() {
    webauthn_browser_proof("c30").await;
}
#[tokio::test]
#[ignore = "real TLS browser"]
async fn realm_mfa_c31() {
    webauthn_browser_proof("c31").await;
}
#[tokio::test]
#[ignore = "real TLS browser"]
async fn realm_mfa_c32() {
    webauthn_browser_proof("c32").await;
}
#[tokio::test]
#[ignore = "real TLS browser"]
async fn realm_mfa_c33() {
    webauthn_browser_proof("c33").await;
}
#[tokio::test]
#[ignore = "real TLS browser"]
async fn realm_mfa_c34() {
    webauthn_browser_proof("c34").await;
}
#[tokio::test]
#[ignore = "real TLS browser"]
async fn realm_mfa_c35() {
    webauthn_browser_proof("c35").await;
}
