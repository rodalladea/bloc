//! Guarded WebAuthn authority calls; no runtime table access.
use crate::realm_storage::error;
use crate::{realm_storage::Error, storage::Storage};
use sqlx::Row;

pub(crate) struct Authority<'a> {
    pub realm: &'a str,
    pub bearer: &'a [u8; 32],
    pub browser: &'a [u8; 32],
    pub token: &'a [u8; 32],
    pub registration: bool,
}
pub(crate) struct Material {
    pub handle: [u8; 32],
    pub ids: Vec<Vec<u8>>,
    pub records: Vec<Vec<u8>>,
}
pub(crate) struct Ceremony {
    pub state: Vec<u8>,
    pub handle: [u8; 32],
    pub records: Vec<Vec<u8>>,
}
pub(crate) struct Completion<'a> {
    pub authority: Authority<'a>,
    pub ceremony: &'a str,
    pub verified: bool,
    pub credential: Vec<u8>,
    pub original: Vec<u8>,
    pub updated: Vec<u8>,
    pub transports: Vec<String>,
    pub factor: &'a str,
    pub key: &'a str,
    pub key_generation: i64,
    pub generation: &'a str,
    pub digests: Vec<Vec<u8>>,
    pub handoff: &'a str,
    pub envelope: Vec<u8>,
    pub new_bearer: &'a [u8; 32],
    pub new_csrf: &'a [u8; 32],
    pub session: &'a [u8; 32],
    pub session_browser: &'a [u8; 32],
    pub session_token: &'a [u8; 32],
    pub device: String,
}

impl Storage {
    pub(crate) async fn webauthn_reject(&self, a: &Authority<'_>) -> Result<String, Error> {
        sqlx::query_scalar("SELECT bloc.mfa_webauthn_reject($1::text::uuid,$2,$3,$4)")
            .bind(a.realm)
            .bind(a.bearer.as_slice())
            .bind(a.browser.as_slice())
            .bind(a.token.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn webauthn_material(
        &self,
        a: &Authority<'_>,
        handle: &[u8; 32],
    ) -> Result<Option<Material>, Error> {
        let row =
            sqlx::query("SELECT * FROM bloc.mfa_webauthn_material($1::text::uuid,$2,$3,$4,$5,$6)")
                .bind(a.realm)
                .bind(a.bearer.as_slice())
                .bind(a.browser.as_slice())
                .bind(a.token.as_slice())
                .bind(a.registration)
                .bind(handle.as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(error)?;
        row.map(|r| {
            Ok(Material {
                handle: r
                    .get::<Vec<u8>, _>("user_handle")
                    .try_into()
                    .map_err(|_| Error::Storage)?,
                ids: r.get("credential_ids"),
                records: r.get("public_records"),
            })
        })
        .transpose()
    }
    pub(crate) async fn webauthn_start(
        &self,
        a: &Authority<'_>,
        ceremony: &str,
        bearer: &[u8; 32],
        state: Vec<u8>,
        label: &str,
    ) -> Result<String, Error> {
        sqlx::query_scalar(
            "SELECT bloc.mfa_webauthn_start($1::text::uuid,$2,$3,$4,$5,$6::text::uuid,$7,$8,$9)",
        )
        .bind(a.realm)
        .bind(a.bearer.as_slice())
        .bind(a.browser.as_slice())
        .bind(a.token.as_slice())
        .bind(a.registration)
        .bind(ceremony)
        .bind(bearer.as_slice())
        .bind(state)
        .bind(label)
        .fetch_one(&self.pool)
        .await
        .map_err(error)
    }
    pub(crate) async fn webauthn_ceremony(
        &self,
        a: &Authority<'_>,
        ceremony: &str,
    ) -> Result<Option<Ceremony>, Error> {
        let row = sqlx::query(
            "SELECT * FROM bloc.mfa_webauthn_ceremony($1::text::uuid,$2,$3,$4,$5::text::uuid,$6)",
        )
        .bind(a.realm)
        .bind(a.bearer.as_slice())
        .bind(a.browser.as_slice())
        .bind(a.token.as_slice())
        .bind(ceremony)
        .bind(a.registration)
        .fetch_optional(&self.pool)
        .await
        .map_err(error)?;
        row.map(|r| {
            Ok(Ceremony {
                state: r.get("state"),
                handle: r
                    .get::<Vec<u8>, _>("user_handle")
                    .try_into()
                    .map_err(|_| Error::Storage)?,
                records: r.get("public_records"),
            })
        })
        .transpose()
    }
    pub(crate) async fn webauthn_finish(&self, p: Completion<'_>) -> Result<String, Error> {
        let a = p.authority;
        sqlx::query_scalar("SELECT bloc.mfa_webauthn_finish($1::text::uuid,$2,$3,$4,$5::text::uuid,$6,$7,$8,$9,$10,$11,$12::text::uuid,$13::text::uuid,$14,$15::text::uuid,$16,$17::text::uuid,$18,$19,$20,$21,$22,$23,$24)")
            .bind(a.realm).bind(a.bearer.as_slice()).bind(a.browser.as_slice()).bind(a.token.as_slice()).bind(p.ceremony).bind(a.registration).bind(p.verified).bind(p.credential).bind(p.original).bind(p.updated).bind(p.transports).bind(p.factor).bind(p.key).bind(p.key_generation).bind(p.generation).bind(p.digests).bind(p.handoff).bind(p.envelope).bind(p.new_bearer.as_slice()).bind(p.new_csrf.as_slice()).bind(p.session.as_slice()).bind(p.session_browser.as_slice()).bind(p.session_token.as_slice()).bind(p.device)
            .fetch_one(&self.pool).await.map_err(error)
    }
}
