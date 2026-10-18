//! Shared setup authority. Callers must validate credentials and hash passwords first.

use sqlx::{
    ConnectOptions, PgPool, Row,
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{path::Path, str::FromStr, time::Duration};

/// Bounded public error categories; database errors and options must never be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Unavailable,
    Incompatible,
}

/// Outcome of an atomic ownership claim, independent of HTTP presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    Created,
    Closed,
    Unusable,
}

/// Concrete shared PostgreSQL dependency; it never migrates during construction.
#[derive(Clone)]
pub struct Storage {
    pool: PgPool,
}

fn connection_options(url: &str, ca: &Path) -> Result<PgConnectOptions, Error> {
    let options = PgConnectOptions::from_str(url).map_err(|_| Error::Configuration)?;
    if options.get_host().starts_with('/')
        || options.get_socket().is_some()
        || options.get_host().is_empty()
        || options.get_options().is_some()
        || !ca.is_file()
    {
        return Err(Error::Configuration);
    }
    Ok(options
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca)
        .options([
            ("statement_timeout", "3000"),
            ("lock_timeout", "1000"),
            ("search_path", "public"),
        ])
        .disable_statement_logging())
}

fn supported_primary(version: i32, recovery: bool, read_only: bool) -> bool {
    matches!(version / 10000, 17 | 18) && !recovery && !read_only
}

impl Storage {
    /// Connect only with verified TLS to a supported writable primary.
    pub async fn connect(url: &str, ca: &Path) -> Result<Self, Error> {
        let options = connection_options(url, ca)?;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(2))
            .connect_with(options)
            .await
            .map_err(|_| Error::Unavailable)?;
        let store = Self { pool };
        store.primary().await?;
        Ok(store)
    }

    async fn primary(&self) -> Result<(), Error> {
        let (version, recovery, read_only): (i32, bool, bool) = sqlx::query_as(
            "SELECT current_setting('server_version_num')::integer, pg_is_in_recovery(), current_setting('transaction_read_only')::boolean",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| Error::Unavailable)?;
        if supported_primary(version, recovery, read_only) {
            Ok(())
        } else {
            Err(Error::Incompatible)
        }
    }

    fn migrations() -> Migrator {
        // SQLx computes and checks the canonical migration checksum for this embedded source.
        let migration = sqlx::migrate::Migration::new(
            1,
            "setup".into(),
            sqlx::migrate::MigrationType::Simple,
            sqlx::SqlStr::from_static(include_str!("../migrations/0001_setup.sql")),
            false,
        );
        Migrator {
            migrations: vec![migration].into(),
            ..Migrator::DEFAULT
        }
    }

    /// Explicit forward migrations, with SQLx's migration lock and checksum validation.
    pub async fn migrate(&self) -> Result<(), Error> {
        self.primary().await?;
        Self::migrations()
            .run(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }

    /// Check the exact binary contract without creating or changing schema.
    pub async fn compatible(&self) -> Result<(), Error> {
        self.primary().await?;
        let rows = sqlx::query(
            "SELECT version, checksum, success FROM public._sqlx_migrations ORDER BY version",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| Error::Unavailable)?;
        let expected = Self::migrations();
        if rows.len() != expected.migrations.len() {
            return Err(Error::Incompatible);
        }
        for (row, migration) in rows.iter().zip(expected.iter()) {
            if row.get::<i64, _>("version") != migration.version
                || row.get::<Vec<u8>, _>("checksum") != migration.checksum.as_ref()
                || !row.get::<bool, _>("success")
            {
                return Err(Error::Incompatible);
            }
        }
        Ok(())
    }

    /// Issue/replace setup authority and its audit atomically. None means already owned.
    pub async fn issue_setup_code(&self, digest: &[u8; 32]) -> Result<Option<String>, Error> {
        self.compatible().await?;
        sqlx::query_scalar("SELECT bloc.issue_setup_code($1)")
            .bind(digest.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }

    /// Commit only current setup authority. No plaintext passwords belong at this boundary.
    pub async fn claim_owner(
        &self,
        digest: &[u8; 32],
        validated_email: &str,
        password_hash: &str,
    ) -> Result<Claim, Error> {
        self.compatible().await?;
        let outcome: String = sqlx::query_scalar("SELECT bloc.claim_owner($1, $2, $3)")
            .bind(digest.as_slice())
            .bind(validated_email)
            .bind(password_hash)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)?;
        match outcome.as_str() {
            "created" => Ok(Claim::Created),
            "closed" => Ok(Claim::Closed),
            "unusable" => Ok(Claim::Unusable),
            _ => Err(Error::Incompatible),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_supported_writable_primaries_are_authority() {
        for version in [160000, 170000, 180000, 190000] {
            for recovery in [false, true] {
                for read_only in [false, true] {
                    assert_eq!(
                        supported_primary(version, recovery, read_only),
                        matches!(version, 170000 | 180000) && !recovery && !read_only
                    );
                }
            }
        }
    }

    #[test]
    fn options_require_ca_and_override_insecure_tls() {
        let file = std::env::temp_dir().join(format!("bloc-options-{}.crt", std::process::id()));
        std::fs::write(&file, b"synthetic CA placeholder for option parsing only").unwrap();
        let options =
            connection_options("postgres://localhost/bloc?sslmode=disable", &file).unwrap();
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
        assert_eq!(
            options.get_options().unwrap(),
            "-c statement_timeout=3000 -c lock_timeout=1000 -c search_path=public"
        );
        std::fs::remove_file(&file).unwrap();
        assert!(matches!(
            connection_options("postgres://localhost/bloc", &file),
            Err(Error::Configuration)
        ));
    }
}
