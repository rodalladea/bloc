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
    /// Configure a bounded pool without requiring the primary to be available at startup.
    pub fn lazy(url: &str, ca: &Path) -> Result<Self, Error> {
        let options = connection_options(url, ca)?;
        Ok(Self {
            pool: PgPoolOptions::new()
                .max_connections(5)
                .acquire_timeout(Duration::from_secs(2))
                .connect_lazy_with(options),
        })
    }
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
            migrations: vec![
                migration,
                sqlx::migrate::Migration::new(
                    2,
                    "access".into(),
                    sqlx::migrate::MigrationType::Simple,
                    sqlx::SqlStr::from_static(include_str!("../migrations/0002_access.sql")),
                    false,
                ),
            ]
            .into(),
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

/// Current credential snapshot; final transitions always recheck its version.
#[derive(Clone)]
pub struct Credentials {
    pub email: String,
    pub phc: String,
    pub version: i64,
    pub recovery_required: bool,
}
impl Storage {
    pub async fn owner(&self) -> Result<Option<Credentials>, Error> {
        self.compatible().await?;
        let row = sqlx::query("SELECT * FROM bloc.owner_credentials()")
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(row.map(|r| Credentials {
            email: r.get("email"),
            phc: r.get("phc"),
            version: r.get("version"),
            recovery_required: r.get("recovery_required"),
        }))
    }
    pub async fn code_usable(&self, purpose: &str, digest: &[u8; 32]) -> Result<bool, Error> {
        self.compatible().await?;
        sqlx::query_scalar("SELECT bloc.code_usable($1,$2)")
            .bind(purpose)
            .bind(digest.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
    pub async fn issue_recovery_code(&self, digest: &[u8; 32]) -> Result<Option<String>, Error> {
        self.compatible().await?;
        sqlx::query_scalar("SELECT bloc.issue_recovery_code($1)")
            .bind(digest.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
    pub async fn authenticate(
        &self,
        digest: &[u8; 32],
        version: i64,
        browser: &[u8; 32],
        token: &[u8; 32],
        old_browser: Option<&[u8; 32]>,
    ) -> Result<bool, Error> {
        self.compatible().await?;
        sqlx::query_scalar("SELECT bloc.authenticate_session($1,$2,$3,$4,$5)")
            .bind(digest.as_slice())
            .bind(version)
            .bind(browser.as_slice())
            .bind(token.as_slice())
            .bind(old_browser.map(|v| v.as_slice()))
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
    pub async fn authorize(&self, digest: &[u8; 32]) -> Result<Option<Credentials>, Error> {
        self.compatible().await?;
        let row = sqlx::query("SELECT * FROM bloc.authorize_session($1)")
            .bind(digest.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(row.map(|r| Credentials {
            email: r.get("email"),
            phc: r.get("phc"),
            version: r.get("version"),
            recovery_required: false,
        }))
    }
    pub async fn sign_out(&self, digest: &[u8; 32]) -> Result<bool, Error> {
        self.compatible().await?;
        sqlx::query_scalar("SELECT bloc.sign_out($1)")
            .bind(digest.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
    pub async fn replace_password(
        &self,
        digest: &[u8; 32],
        version: i64,
        phc: &str,
        recovery: bool,
    ) -> Result<bool, Error> {
        self.compatible().await?;
        sqlx::query_scalar("SELECT bloc.replace_password($1,$2,$3,$4)")
            .bind(digest.as_slice())
            .bind(version)
            .bind(phc)
            .bind(recovery)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
    pub async fn invalidate_access(&self) -> Result<(), Error> {
        self.compatible().await?;
        sqlx::query("SELECT bloc.invalidate_access()")
            .execute(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }
    pub async fn maintain_access(&self) -> Result<i32, Error> {
        self.compatible().await?;
        sqlx::query_scalar("SELECT bloc.maintain_access()")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
    pub async fn reserve(&self, buckets: &[(&str, [u8; 32], i32)]) -> Result<i32, Error> {
        self.compatible().await?;
        let scopes: Vec<_> = buckets.iter().map(|b| b.0).collect();
        let keys: Vec<Vec<u8>> = buckets.iter().map(|b| b.1.to_vec()).collect();
        let units: Vec<_> = buckets.iter().map(|b| b.2).collect();
        sqlx::query_scalar("SELECT bloc.reserve_admission($1,$2,$3)")
            .bind(scopes)
            .bind(keys)
            .bind(units)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
    pub async fn form(
        &self,
        browser: &[u8; 32],
        session: Option<&[u8; 32]>,
        token: Option<&[u8; 32]>,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.compatible().await?;
        sqlx::query_scalar("SELECT bloc.form_state($1,$2,$3)")
            .bind(browser.as_slice())
            .bind(session.map(|x| x.as_slice()))
            .bind(token.map(|x| x.as_slice()))
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
    pub async fn deny(&self, action: &str, reason: &str) -> Result<(), Error> {
        self.compatible().await?;
        sqlx::query("SELECT bloc.record_denial($1,$2)")
            .bind(action)
            .bind(reason)
            .execute(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }
}
