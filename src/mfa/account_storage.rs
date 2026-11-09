//! Guarded own-account factor operations; no direct runtime table access.
use crate::realm_storage::error;
use crate::{realm_storage::Error, storage::Storage};
use sqlx::Row;

pub(crate) struct Factor {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub created: String,
    pub used: String,
    pub preferred: bool,
    pub allowed: bool,
}
pub(crate) struct Factors {
    pub factors: Vec<Factor>,
    pub epoch: i64,
    pub unused_codes: i64,
}
pub(crate) struct AccountReauth<'a> {
    pub realm: &'a str,
    pub session: &'a [u8; 32],
    pub browser: &'a [u8; 32],
    pub csrf: &'a [u8; 32],
    pub credential: i64,
    pub operation: &'a str,
    pub bearer: &'a [u8; 32],
    pub new_csrf: &'a [u8; 32],
}
pub(crate) struct AccountEdit<'a> {
    pub realm: &'a str,
    pub session: &'a [u8; 32],
    pub browser: &'a [u8; 32],
    pub csrf: &'a [u8; 32],
    pub epoch: i64,
    pub factor: Option<&'a str>,
    pub operation: &'a str,
    pub value: &'a str,
}
pub(crate) struct AccountRemove<'a> {
    pub proof: crate::realm_storage::MfaVerification<'a>,
    pub current_session: &'a [u8; 32],
    pub epoch: i64,
    pub factor: &'a str,
    pub confirmed: bool,
}
pub(crate) struct AccountCodes<'a> {
    pub realm: &'a str,
    pub bearer: &'a [u8; 32],
    pub browser: &'a [u8; 32],
    pub csrf: &'a [u8; 32],
    pub session: &'a [u8; 32],
    pub generation: &'a str,
    pub digests: Vec<Vec<u8>>,
    pub handoff: &'a str,
    pub envelope: &'a [u8],
    pub key: &'a str,
    pub key_generation: i64,
    pub new_bearer: &'a [u8; 32],
    pub new_csrf: &'a [u8; 32],
}

impl Storage {
    pub(crate) async fn mfa_account_factors(
        &self,
        r: &str,
        session: &[u8; 32],
    ) -> Result<Factors, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        let rows = sqlx::query("SELECT * FROM bloc.mfa_account_factors($1::text::uuid,$2)")
            .bind(r)
            .bind(session.as_slice())
            .fetch_all(&self.pool)
            .await
            .map_err(error)?;
        let mut result = Factors {
            factors: vec![],
            epoch: 0,
            unused_codes: 0,
        };
        for row in rows {
            result.epoch = row.get("epoch");
            result.unused_codes = row.get("unused_codes");
            if let Some(id) = row.get::<Option<String>, _>("id") {
                result.factors.push(Factor {
                    id,
                    label: row.get("label"),
                    kind: row.get("kind"),
                    created: row.get("created"),
                    used: row.get("last_used"),
                    preferred: row.get("preferred"),
                    allowed: row.get("allowed"),
                });
            }
        }
        Ok(result)
    }
    pub(crate) async fn mfa_account_reauthenticate(
        &self,
        p: AccountReauth<'_>,
    ) -> Result<String, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        sqlx::query_scalar(
            "SELECT bloc.mfa_account_reauthenticate($1::text::uuid,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(p.realm)
        .bind(p.session.as_slice())
        .bind(p.browser.as_slice())
        .bind(p.csrf.as_slice())
        .bind(p.credential)
        .bind(p.operation)
        .bind(p.bearer.as_slice())
        .bind(p.new_csrf.as_slice())
        .fetch_one(&self.pool)
        .await
        .map_err(error)
    }
    pub(crate) async fn mfa_account_continue(
        &self,
        r: &str,
        bearer: &[u8; 32],
        browser: &[u8; 32],
    ) -> Result<(String, Option<(String, i64)>), Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        let row = sqlx::query("SELECT * FROM bloc.mfa_account_continue($1::text::uuid,$2,$3)")
            .bind(r)
            .bind(bearer.as_slice())
            .bind(browser.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)?;
        let status: String = row.get("status");
        let details = if status == "ok" {
            Some((row.get("operation"), row.get("epoch")))
        } else {
            None
        };
        Ok((status, details))
    }
    pub(crate) async fn mfa_account_edit(&self, p: AccountEdit<'_>) -> Result<String, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        sqlx::query_scalar(
            "SELECT bloc.mfa_account_edit($1::text::uuid,$2,$3,$4,$5,$6::text::uuid,$7,$8)",
        )
        .bind(p.realm)
        .bind(p.session.as_slice())
        .bind(p.browser.as_slice())
        .bind(p.csrf.as_slice())
        .bind(p.epoch)
        .bind(p.factor)
        .bind(p.operation)
        .bind(p.value)
        .fetch_one(&self.pool)
        .await
        .map_err(error)
    }
    pub(crate) async fn mfa_account_remove(&self, p: AccountRemove<'_>) -> Result<String, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        let proof = p.proof;
        sqlx::query_scalar("SELECT bloc.mfa_account_remove($1::text::uuid,$2,$3,$4,$5,$6,$7::text::uuid,$8,$9,$10,$11,$12)")
            .bind(proof.realm).bind(proof.bearer.as_slice()).bind(proof.browser.as_slice()).bind(proof.token.as_slice()).bind(p.current_session.as_slice()).bind(p.epoch).bind(p.factor).bind(p.confirmed).bind(proof.session.as_slice()).bind(proof.new_browser.as_slice()).bind(proof.new_token.as_slice()).bind(proof.device).fetch_one(&self.pool).await.map_err(error)
    }
    pub(crate) async fn mfa_account_regenerate(
        &self,
        p: AccountCodes<'_>,
    ) -> Result<String, Error> {
        self.compatible().await.map_err(|_| Error::Storage)?;
        sqlx::query_scalar("SELECT bloc.mfa_account_regenerate($1::text::uuid,$2,$3,$4,$5,$6::text::uuid,$7,$8::text::uuid,$9,$10::text::uuid,$11,$12,$13)")
            .bind(p.realm).bind(p.bearer.as_slice()).bind(p.browser.as_slice()).bind(p.csrf.as_slice()).bind(p.session.as_slice()).bind(p.generation).bind(p.digests).bind(p.handoff).bind(p.envelope).bind(p.key).bind(p.key_generation).bind(p.new_bearer.as_slice()).bind(p.new_csrf.as_slice()).fetch_one(&self.pool).await.map_err(error)
    }
}
