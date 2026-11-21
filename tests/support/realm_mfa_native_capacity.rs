#[test]
#[ignore = "requires real source-matched native Linux service amd64 AND arm64 records"]
fn realm_mfa_native_capacity() {
    let records = std::env::var("BLOC_MFA_NATIVE_SERVICE_EVIDENCE").expect(
        "C77 unproven: run native_service_capacity.py --realm-mfa on native amd64 and arm64, then supply combined records",
    );
    let output = std::process::Command::new("python3")
        .args([
            "tests/support/native_service_evidence.py",
            &records,
            "--realm-mfa",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
