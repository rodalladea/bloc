//! Regression tests for verified PostgreSQL transport; run tests/run_storage.py.

use bloc::storage::{Error, Storage};
use sqlx::{
    Connection, PgConnection,
    postgres::{PgConnectOptions, PgSslMode},
};
use std::{env, path::Path, time::Duration};

async fn application_connection(port_variable: &str, ca_variable: &str) -> Result<Storage, Error> {
    let url = format!(
        "postgres://probe:synthetic-probe-only@127.0.0.1:{}/probe",
        env::var(port_variable).unwrap()
    );
    Storage::connect(&url, Path::new(&env::var(ca_variable).unwrap())).await
}

fn options(port_variable: &str, ca_variable: &str) -> PgConnectOptions {
    PgConnectOptions::new()
        .host("127.0.0.1")
        .port(env::var(port_variable).unwrap().parse().unwrap())
        .username("probe")
        .password("synthetic-probe-only")
        .database("probe")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(env::var(ca_variable).unwrap())
}

async fn connect(options: PgConnectOptions) -> Result<PgConnection, sqlx::Error> {
    tokio::time::timeout(Duration::from_secs(5), PgConnection::connect_with(&options))
        .await
        .expect("local fixture connection must settle within five seconds")
}

#[tokio::test]
#[ignore = "requires tests/run_storage.py disposable PostgreSQL fixtures"]
async fn verified_tls_connects_to_expected_major() {
    assert!(
        application_connection("BLOC_SETUP_PORT", "BLOC_SETUP_CA")
            .await
            .is_ok()
    );
    let mut connection = connect(options("BLOC_SETUP_PORT", "BLOC_SETUP_CA"))
        .await
        .expect("trusted matching server must connect");
    let (version, ssl): (String, bool) = sqlx::query_as(
        "SELECT current_setting('server_version_num'), ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    let expected: u32 = env::var("BLOC_SETUP_MAJOR").unwrap().parse().unwrap();
    assert_eq!(version.parse::<u32>().unwrap() / 10000, expected);
    assert!(ssl, "backend must report an encrypted connection");
    connection.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires tests/run_storage.py disposable PostgreSQL fixtures"]
async fn untrusted_ca_is_rejected() {
    assert!(matches!(
        application_connection("BLOC_SETUP_PORT", "BLOC_SETUP_OTHER_CA").await,
        Err(Error::Unavailable)
    ));
    let result = connect(options("BLOC_SETUP_PORT", "BLOC_SETUP_OTHER_CA")).await;
    let Err(sqlx::Error::Io(error)) = result else {
        panic!("untrusted CA must fail certificate verification: {result:?}");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        format!("{error:?}").contains("InvalidCertificate(UnknownIssuer)"),
        "{error:?}"
    );
}

#[tokio::test]
#[ignore = "requires tests/run_storage.py disposable PostgreSQL fixtures"]
async fn wrong_hostname_is_rejected() {
    assert!(matches!(
        application_connection("BLOC_SETUP_WRONG_NAME_PORT", "BLOC_SETUP_CA").await,
        Err(Error::Unavailable)
    ));
    let result = connect(options("BLOC_SETUP_WRONG_NAME_PORT", "BLOC_SETUP_CA")).await;
    let Err(sqlx::Error::Io(error)) = result else {
        panic!("trusted certificate for another IP must fail TLS: {result:?}");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        format!("{error:?}").contains("InvalidCertificate(NotValidForNameContext"),
        "{error:?}"
    );
}

#[tokio::test]
#[ignore = "requires tests/run_storage.py disposable PostgreSQL fixtures"]
async fn plaintext_server_is_rejected() {
    assert!(matches!(
        application_connection("BLOC_SETUP_PLAIN_PORT", "BLOC_SETUP_CA").await,
        Err(Error::Unavailable)
    ));
    let result = connect(options("BLOC_SETUP_PLAIN_PORT", "BLOC_SETUP_CA")).await;
    let Err(sqlx::Error::Tls(error)) = result else {
        panic!("VerifyFull must refuse a server without TLS");
    };
    assert!(
        error.to_string().contains("does not support TLS"),
        "{error}"
    );
}
