#![allow(dead_code)]

use bloc::storage::Storage;
use sqlx::{
    ConnectOptions, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{env, path::PathBuf};

pub const HASH: &str = "$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljZml4dHVyZQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
pub const EMAIL: &str = "Owner@example.test";

pub struct Fixture {
    pub admin: PgPool,
    pub migrator: Storage,
    pub runtime: Storage,
    pub operator: Storage,
    pub database: String,
    pub ca: PathBuf,
}

impl Fixture {
    pub fn options(database: &str, user: &str) -> PgConnectOptions {
        PgConnectOptions::new()
            .host("127.0.0.1")
            .port(env::var("BLOC_SETUP_PORT").unwrap().parse().unwrap())
            .database(database)
            .username(user)
            .password(if user == "probe" {
                "synthetic-probe-only"
            } else {
                "synthetic-setup-only"
            })
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(env::var("BLOC_SETUP_CA").unwrap())
            .disable_statement_logging()
    }

    pub fn url(&self, user: &str) -> String {
        format!(
            "postgres://{user}:synthetic-setup-only@127.0.0.1:{}/{}",
            env::var("BLOC_SETUP_PORT").unwrap(),
            self.database
        )
    }

    pub async fn pool(&self, user: &str) -> PgPool {
        PgPoolOptions::new()
            .max_connections(3)
            .connect_with(Self::options(&self.database, user))
            .await
            .unwrap()
    }

    pub async fn new(name: &str) -> Self {
        let root = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(Self::options("probe", "probe"))
            .await
            .unwrap();
        let database = format!("setup_{name}_{}", std::process::id());
        assert!(
            database
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        );
        // Names are fixed test names plus a numeric PID, never user input.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE {database} OWNER migrator_user"
        )))
        .execute(&root)
        .await
        .unwrap();
        root.close().await;
        let admin = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(Self::options(&database, "probe"))
            .await
            .unwrap();
        let ca = PathBuf::from(env::var("BLOC_SETUP_CA").unwrap());
        let url = |user| {
            format!(
                "postgres://{user}:synthetic-setup-only@127.0.0.1:{}/{database}",
                env::var("BLOC_SETUP_PORT").unwrap()
            )
        };
        let migrator = Storage::connect(&url("migrator_user"), &ca).await.unwrap();
        migrator.migrate().await.unwrap();
        let runtime = Storage::connect(&url("runtime_user"), &ca).await.unwrap();
        let operator = Storage::connect(&url("operator_user"), &ca).await.unwrap();
        Self {
            admin,
            migrator,
            runtime,
            operator,
            database,
            ca,
        }
    }

    pub async fn count(&self, table: &str) -> i64 {
        let query = match table {
            "installation" => "SELECT count(*) FROM bloc.installation",
            "installation_administrator" => "SELECT count(*) FROM bloc.installation_administrator",
            "security_audit_event" => "SELECT count(*) FROM bloc.security_audit_event",
            _ => panic!("unknown fixture table"),
        };
        sqlx::query_scalar(query)
            .fetch_one(&self.admin)
            .await
            .unwrap()
    }

    pub async fn fail_audit(&self, enabled: bool) {
        if enabled {
            sqlx::raw_sql("CREATE FUNCTION public.fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$; CREATE TRIGGER fail_audit BEFORE INSERT ON bloc.security_audit_event FOR EACH ROW EXECUTE FUNCTION public.fail_audit();").execute(&self.admin).await.unwrap();
        } else {
            sqlx::raw_sql("DROP TRIGGER fail_audit ON bloc.security_audit_event; DROP FUNCTION public.fail_audit();").execute(&self.admin).await.unwrap();
        }
    }
}
