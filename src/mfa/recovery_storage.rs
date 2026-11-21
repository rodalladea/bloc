//! Recovery adapters expose only guarded capabilities, never table access.
use crate::realm_storage::error;
use crate::{realm_storage::Error, storage::Storage};
use sqlx::Row;

pub(crate) struct AssistedForm {
    pub status: String,
    pub phc: Option<String>,
    pub credential: Option<i64>,
    pub csrf: Option<Vec<u8>>,
}
pub(crate) struct RecoveryProof<'a> {
    pub realm: &'a str,
    pub bearer: &'a [u8; 32],
    pub browser: &'a [u8; 32],
    pub csrf: &'a [u8; 32],
}
pub(crate) struct AssistedIssue<'a> {
    pub realm: &'a str,
    pub user: &'a str,
    pub session: &'a [u8; 32],
    pub browser: &'a [u8; 32],
    pub csrf: &'a [u8; 32],
    pub expected: i64,
    pub admin_version: i64,
    pub confirmed: bool,
    pub digest: &'a [u8; 32],
}
pub(crate) struct AssistedConfirmation<'a> {
    pub realm: &'a str,
    pub browser: &'a [u8; 32],
    pub token: &'a [u8; 32],
    pub expected: i64,
    pub verified: bool,
    pub bearer: &'a [u8; 32],
    pub csrf: &'a [u8; 32],
}
impl Storage {
    pub(crate) async fn mfa_code_material(
        &self,
        p: &RecoveryProof<'_>,
    ) -> Result<Option<(String, String)>, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        sqlx::query_as("SELECT * FROM bloc.mfa_code_material($1::text::uuid,$2,$3,$4)")
            .bind(p.realm)
            .bind(p.bearer.as_slice())
            .bind(p.browser.as_slice())
            .bind(p.csrf.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn mfa_code_recover(
        &self,
        p: &RecoveryProof<'_>,
        generation: Option<&str>,
        digest: Option<&[u8]>,
        bearer: &[u8; 32],
        csrf: &[u8; 32],
    ) -> Result<String, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        sqlx::query_scalar(
            "SELECT bloc.mfa_code_recover($1::text::uuid,$2,$3,$4,$5::text::uuid,$6,$7,$8)",
        )
        .bind(p.realm)
        .bind(p.bearer.as_slice())
        .bind(p.browser.as_slice())
        .bind(p.csrf.as_slice())
        .bind(generation)
        .bind(digest)
        .bind(bearer.as_slice())
        .bind(csrf.as_slice())
        .fetch_one(&self.pool)
        .await
        .map_err(error)
    }
    pub(crate) async fn mfa_assisted_issue(&self, p: AssistedIssue<'_>) -> Result<String, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        sqlx::query_scalar(
            "SELECT bloc.mfa_assisted_issue($1::text::uuid,$2::text::uuid,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(p.realm)
        .bind(p.user)
        .bind(p.session.as_slice())
        .bind(p.browser.as_slice())
        .bind(p.csrf.as_slice())
        .bind(p.expected)
        .bind(p.admin_version)
        .bind(p.confirmed)
        .bind(p.digest.as_slice())
        .fetch_one(&self.pool)
        .await
        .map_err(error)
    }
    pub(crate) async fn mfa_assisted_exchange(
        &self,
        r: &str,
        anonymous: &[u8; 32],
        token: &[u8; 32],
        digest: &[u8; 32],
        browser: &[u8; 32],
        csrf: &[u8; 32],
    ) -> Result<String, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        sqlx::query_scalar("SELECT bloc.mfa_assisted_exchange($1::text::uuid,$2,$3,$4,$5,$6)")
            .bind(r)
            .bind(anonymous.as_slice())
            .bind(token.as_slice())
            .bind(digest.as_slice())
            .bind(browser.as_slice())
            .bind(csrf.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn mfa_assisted_form(
        &self,
        r: &str,
        browser: &[u8; 32],
        token: Option<&[u8; 32]>,
    ) -> Result<AssistedForm, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        let row = sqlx::query("SELECT * FROM bloc.mfa_assisted_form($1::text::uuid,$2,$3)")
            .bind(r)
            .bind(browser.as_slice())
            .bind(token.map(|x| x.as_slice()))
            .fetch_one(&self.pool)
            .await
            .map_err(error)?;
        Ok(AssistedForm {
            status: row.get("status"),
            phc: row.get("phc"),
            credential: row.get("credential_version"),
            csrf: row.get("csrf"),
        })
    }
    pub(crate) async fn mfa_assisted_admit(
        &self,
        r: &str,
        browser: &[u8; 32],
        token: &[u8; 32],
        source: &[u8; 32],
    ) -> Result<i32, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        sqlx::query_scalar("SELECT bloc.mfa_assisted_admit($1::text::uuid,$2,$3,$4)")
            .bind(r)
            .bind(browser.as_slice())
            .bind(token.as_slice())
            .bind(source.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn mfa_assisted_confirm(
        &self,
        p: AssistedConfirmation<'_>,
    ) -> Result<String, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        sqlx::query_scalar("SELECT bloc.mfa_assisted_confirm($1::text::uuid,$2,$3,$4,$5,$6,$7)")
            .bind(p.realm)
            .bind(p.browser.as_slice())
            .bind(p.token.as_slice())
            .bind(p.expected)
            .bind(p.verified)
            .bind(p.bearer.as_slice())
            .bind(p.csrf.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
}
pub(crate) struct Choices {
    pub totp: bool,
    pub webauthn: bool,
    pub codes: bool,
    pub preferred: Option<String>,
    pub active: i64,
    pub context: String,
}
impl Storage {
    pub(crate) async fn mfa_choices(
        &self,
        r: &str,
        bearer: &[u8; 32],
        browser: &[u8; 32],
    ) -> Result<Option<Choices>, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        let row = sqlx::query("SELECT * FROM bloc.mfa_choices($1::text::uuid,$2,$3)")
            .bind(r)
            .bind(bearer.as_slice())
            .bind(browser.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(error)?;
        Ok(row.map(|row| Choices {
            totp: row.get("totp"),
            webauthn: row.get("webauthn"),
            codes: row.get("saved_codes"),
            preferred: row.get("preferred"),
            active: row.get("active_count"),
            context: row.get("context"),
        }))
    }
}
