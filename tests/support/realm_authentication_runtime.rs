struct Services {
    children: Vec<std::process::Child>,
    directory: std::path::PathBuf,
}
impl Drop for Services {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn spawn_service(f: &Fixture, directory: &std::path::Path, port: u16) -> std::process::Child {
    std::process::Command::new(env!("CARGO_BIN_EXE_bloc"))
        .env("BLOC_DATABASE_URL_FILE", directory.join("runtime"))
        .env("BLOC_DATABASE_CA_FILE", &f.ca)
        .env("BLOC_ABUSE_KEY_FILE", directory.join("abuse"))
        .env("BLOC_CANONICAL_ORIGIN", "https://bloc.example.test:4443")
        .env("BLOC_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
        .env("BLOC_BIND_ADDR", format!("127.0.0.1:{port}"))
        .stdout(std::fs::File::create(directory.join(format!("service-{port}.stdout"))).unwrap())
        .stderr(std::fs::File::create(directory.join(format!("service-{port}.stderr"))).unwrap())
        .spawn()
        .unwrap()
}
async fn services(f: &Fixture) -> Services {
    let directory = std::env::temp_dir().join(format!(
        "bloc-services-{}-{}",
        std::process::id(),
        f.database
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("runtime"), f.url("runtime_user")).unwrap();
    std::fs::write(directory.join("operator"), f.url("operator_user")).unwrap();
    std::fs::write(directory.join("abuse"), [7; 32]).unwrap();
    let mut children = Vec::new();
    for port in [31001, 31002] {
        let child = spawn_service(f, &directory, port);
        children.push(child);
    }
    let services = Services {
        children,
        directory,
    };
    for port in [31001, 31002] {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "service did not listen"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    services
}
async fn realm_browser(mode: &str) {
    let f = Fixture::new(&format!("realm_browser_{}", mode)).await;
    let services = services(&f).await;
    let python = std::env::var("BLOC_BROWSER_PYTHON").expect("actual Playwright browser required");
    let mut command = std::process::Command::new(python);
    command
        .args(["tests/support/realm_authentication_browser.py", mode])
        .env("BLOC_TEST_ORIGIN", "https://bloc.example.test:4443")
        .env(
            "BLOC_TEST_SPKI",
            std::env::var("BLOC_TEST_SPKI").expect("synthetic TLS SPKI required"),
        )
        .env("BLOC_TEST_BINARY", env!("CARGO_BIN_EXE_bloc"))
        .env(
            "BLOC_DATABASE_URL_FILE",
            services.directory.join("operator"),
        )
        .env("BLOC_DATABASE_CA_FILE", &f.ca)
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
async fn realm_auth_c62() {
    realm_browser("screens").await;
}
#[tokio::test]
#[ignore = "real server header bound"]
async fn realm_auth_c48() {
    prove_clean_signin_recovery().await;
    use std::io::{Read, Write};
    let f = Fixture::new("realmheaders").await;
    let _services = services(&f).await;
    let request = |size: usize| {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", 31001)).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let bytes = format!(
            "GET /healthz HTTP/1.1\r\nHost: bloc.example.test:4443\r\nConnection: close\r\nCookie: __Host-bloc-realm-33333333-3333-4333-8333-333333333333=unrelated-realm; __Host-bloc-admin=unrelated-administrator; __Host-bloc-realm-11111111-1111-4111-8111-111111111111={}\r\n\r\n",
            "x".repeat(size)
        );
        let _ = stream.write_all(bytes.as_bytes());
        let mut response = vec![];
        let _ = stream.read_to_end(&mut response);
        String::from_utf8_lossy(&response).into_owned()
    };
    let accepted = request(262144);
    assert!(accepted.starts_with("HTTP/1.1 200"));
    let rejected = request(524288);
    assert!(
        rejected.starts_with("HTTP/1.1 431"),
        "{}",
        rejected.lines().next().unwrap_or("empty")
    );
    assert!(!rejected.to_lowercase().contains("set-cookie:"));
    let (mut low, mut high) = (262144usize, 524288usize);
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        let response = request(mid);
        if response.starts_with("HTTP/1.1 200") {
            low = mid;
        } else {
            assert!(response.starts_with("HTTP/1.1 431"));
            assert!(!response.to_lowercase().contains("set-cookie:"));
            high = mid;
        }
    }
    println!(
        "real server cookie bound: accepted {low} bytes, rejected {high} with431 and zero cookie deletion"
    );
}
