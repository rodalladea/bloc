async fn screen_browser_proof(mode: &'static str, fixture_name: &str) {
    let guide = include_str!("../../docs/ui-system.md");
    let consumer = include_str!("../fixtures/ui-consumer.html");
    for component in [".ui-setup-secret", ".ui-recovery-handoff"] {
        assert!(
            guide.contains(component),
            "shared secret component must be documented"
        );
        assert!(
            consumer.contains(&format!("class=\"{}\"", &component[1..])),
            "plain HTML consumer must demonstrate shared secret component"
        );
    }
    assert!(
        !guide.contains("planned, not implemented components"),
        "component delivery status must reflect shipped presentations"
    );
    let (f, _admin, _public, op) = mfa_configured(fixture_name).await;
    contract_seed(&f).await;
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
        .args(["tests/support/realm_mfa_browser.py", mode])
        .env("BLOC_MFA_TEST_EXECUTABLE", std::env::current_exe().unwrap())
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
async fn realm_mfa_screen_contract() {
    screen_browser_proof("screen", "mfascreenbrowser").await;
}

#[tokio::test]
#[ignore = "real TLS browser"]
async fn realm_mfa_browser_contract() {
    screen_browser_proof("journey", "mfajourneybrowser").await;
}

#[test]
#[ignore = "private browser reference-code helper"]
fn realm_mfa_browser_reference_code() {
    let secret = std::env::var("BLOC_MFA_REFERENCE_SECRET").unwrap();
    let timestamp: u64 = std::env::var("BLOC_MFA_REFERENCE_TIME")
        .unwrap()
        .parse()
        .unwrap();
    let code = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(&secret).unwrap())
        .build()
        .unwrap()
        .generate(timestamp)
        .to_string();
    std::fs::write(std::env::var("BLOC_MFA_REFERENCE_OUTPUT").unwrap(), code).unwrap();
}
