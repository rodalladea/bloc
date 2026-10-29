//! Realm authority adapters: parameters are validated at HTTP boundaries and
//! re-authorized in each guarded database operation, never by direct table access.
use crate::storage::Storage;
use sqlx::Row;

#[derive(Debug)]
pub(crate) enum Error {
    Storage,
    Capacity,
    Authority,
}
fn error(e: sqlx::Error) -> Error {
    match e.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("54000") => Error::Capacity,
        Some("28000") => Error::Authority,
        _ => Error::Storage,
    }
}
#[derive(Clone)]
pub(crate) struct Policy {
    pub registration: bool,
    pub minimum: i16,
    pub upper: bool,
    pub lower: bool,
    pub number: bool,
    pub special: bool,
    pub activation: i32,
    pub reset: i32,
    pub idle: i32,
    pub absolute: i32,
    pub limit: i16,
    pub version: i64,
}
impl Policy {
    pub fn accepts(&self, password: &str, confirmation: &str) -> bool {
        password == confirmation
            && (self.minimum as usize..=128).contains(&password.chars().count())
            && password.len() <= 512
            && (!self.upper
                || password
                    .chars()
                    .any(|c| c.is_alphabetic() && c.is_uppercase()))
            && (!self.lower
                || password
                    .chars()
                    .any(|c| c.is_alphabetic() && c.is_lowercase()))
            && (!self.number || password.chars().any(|c| c.is_ascii_digit()))
            && (!self.special || password.chars().any(|c| c.is_ascii_punctuation()))
    }
    pub fn requirements(&self) -> String {
        let mut s = format!(
            "Use {}–128 characters (at most 512 UTF-8 bytes). Spaces and Unicode are allowed.",
            self.minimum
        );
        for (enabled, text) in [
            (self.upper, " Include an uppercase letter."),
            (self.lower, " Include a lowercase letter."),
            (self.number, " Include a number from 0–9."),
            (self.special, " Include ASCII punctuation."),
        ] {
            if enabled {
                s.push_str(text)
            }
        }
        s
    }
}
#[derive(Clone, Default)]
pub(crate) struct Account {
    pub user: String,
    pub session: String,
    pub email: String,
    pub display: String,
    pub version: i64,
    pub credential: i64,
    pub phc: String,
}
pub(crate) struct Credential {
    pub user: String,
    pub phc: String,
    pub version: i64,
    pub user_version: i64,
}
pub(crate) struct Session {
    pub id: String,
    pub device: String,
    pub created: String,
    pub active: String,
    pub current: bool,
}
pub(crate) struct Authority<'a> {
    pub realm: &'a str,
    pub purpose: &'a str,
    pub browser: &'a [u8; 32],
    pub token: Option<&'a [u8; 32]>,
    pub session: Option<&'a [u8; 32]>,
    pub link: Option<&'a [u8; 32]>,
}
pub(crate) struct Commit<'a> {
    pub operation: &'a str,
    pub authority: Authority<'a>,
    pub target: Option<&'a str>,
    pub expected: i64,
    pub policy: i64,
    pub values: Vec<String>,
    pub new_session: Option<&'a [u8; 32]>,
    pub new_browser: Option<&'a [u8; 32]>,
    pub new_token: Option<&'a [u8; 32]>,
}
impl Storage {
    async fn realm_ready(&self) -> Result<(), Error> {
        self.compatible().await.map_err(|_| Error::Storage)
    }
    pub(crate) async fn realm_policy(
        &self,
        r: &str,
        admin: Option<&[u8; 32]>,
    ) -> Result<Option<Policy>, Error> {
        self.realm_ready().await?;
        let row = sqlx::query("SELECT * FROM bloc.realm_settings($1::text::uuid,$2)")
            .bind(r)
            .bind(admin.map(|x| x.as_slice()))
            .fetch_optional(&self.pool)
            .await
            .map_err(error)?;
        Ok(row.map(|x| Policy {
            registration: x.get("registration_enabled"),
            minimum: x.get("password_min_length"),
            upper: x.get("require_uppercase"),
            lower: x.get("require_lowercase"),
            number: x.get("require_number"),
            special: x.get("require_special"),
            activation: x.get("activation_ttl_seconds"),
            reset: x.get("reset_ttl_seconds"),
            idle: x.get("session_idle_seconds"),
            absolute: x.get("session_absolute_seconds"),
            limit: x.get("session_limit"),
            version: x.get("version"),
        }))
    }
    pub(crate) async fn realm_name(&self, r: &str) -> Result<Option<String>, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.realm_public_name($1::text::uuid)")
            .bind(r)
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn realm_form(&self, a: Authority<'_>) -> Result<Option<Vec<u8>>, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.realm_form($1::text::uuid,$2,$3,$4,$5,$6)")
            .bind(a.realm)
            .bind(a.purpose)
            .bind(a.browser.as_slice())
            .bind(a.session.map(|x| x.as_slice()))
            .bind(a.link.map(|x| x.as_slice()))
            .bind(a.token.map(|x| x.as_slice()))
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn realm_form_expired(
        &self,
        r: &str,
        p: &str,
        b: &[u8; 32],
    ) -> Result<bool, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.realm_form_expired($1::text::uuid,$2,$3)")
            .bind(r)
            .bind(p)
            .bind(b.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn realm_form_link(
        &self,
        r: &str,
        p: &str,
        b: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, Error> {
        self.realm_ready().await?;
        let d: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT bloc.realm_form_link($1::text::uuid,$2,$3)")
                .bind(r)
                .bind(p)
                .bind(b.as_slice())
                .fetch_one(&self.pool)
                .await
                .map_err(error)?;
        d.map(|x| x.try_into().map_err(|_| Error::Storage))
            .transpose()
    }
    pub(crate) async fn realm_reserve(&self, b: &[(&str, [u8; 32], i32)]) -> Result<i32, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.realm_reserve($1,$2,$3)")
            .bind(b.iter().map(|x| x.0).collect::<Vec<_>>())
            .bind(b.iter().map(|x| x.1.to_vec()).collect::<Vec<_>>())
            .bind(b.iter().map(|x| x.2).collect::<Vec<_>>())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn realm_credentials(
        &self,
        r: &str,
        email: &str,
    ) -> Result<Option<Credential>, Error> {
        self.realm_ready().await?;
        let row = sqlx::query("SELECT * FROM bloc.realm_credentials($1::text::uuid,$2)")
            .bind(r)
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(error)?;
        Ok(row.map(|x| Credential {
            user: x.get("user_id"),
            phc: x.get("phc"),
            version: x.get("version"),
            user_version: x.get("user_version"),
        }))
    }
    pub(crate) async fn realm_account(
        &self,
        r: &str,
        s: &[u8; 32],
        refresh: bool,
    ) -> Result<Option<Account>, Error> {
        self.realm_ready().await?;
        let row = sqlx::query("SELECT * FROM bloc.realm_account($1::text::uuid,$2,$3)")
            .bind(r)
            .bind(s.as_slice())
            .bind(refresh)
            .fetch_optional(&self.pool)
            .await
            .map_err(error)?;
        Ok(row.map(|x| Account {
            user: x.get("user_id"),
            session: x.get("session_id"),
            email: x.get("email"),
            display: x
                .get::<Option<String>, _>("display_name")
                .unwrap_or_default(),
            version: x.get("version"),
            credential: x.get("credential_version"),
            phc: x.get("phc"),
        }))
    }
    pub(crate) async fn realm_sessions(
        &self,
        r: &str,
        s: &[u8; 32],
    ) -> Result<Vec<Session>, Error> {
        self.realm_ready().await?;
        Ok(
            sqlx::query("SELECT * FROM bloc.realm_sessions($1::text::uuid,$2)")
                .bind(r)
                .bind(s.as_slice())
                .fetch_all(&self.pool)
                .await
                .map_err(error)?
                .into_iter()
                .map(|x| Session {
                    id: x.get("id"),
                    device: x.get("device_label"),
                    created: x.get("created"),
                    active: x.get("last_active"),
                    current: x.get("current"),
                })
                .collect(),
        )
    }
    pub(crate) async fn realm_commit(&self, c: Commit<'_>) -> Result<String, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.realm_commit($1::text::uuid,$2,$3,$4,$5,$6,$7::text::uuid,$8,$9,$10,$11,$12,$13)").bind(c.authority.realm).bind(c.operation).bind(c.authority.session.map(|x|x.as_slice())).bind(c.authority.browser.as_slice()).bind(c.authority.token.map(|x|x.as_slice())).bind(c.authority.link.map(|x|x.as_slice())).bind(c.target).bind(c.expected).bind(c.policy).bind(c.values).bind(c.new_session.map(|x|x.as_slice())).bind(c.new_browser.map(|x|x.as_slice())).bind(c.new_token.map(|x|x.as_slice())).fetch_one(&self.pool).await.map_err(error)
    }
    pub(crate) async fn realm_exchange(
        &self,
        a: Authority<'_>,
        new_browser: &[u8; 32],
        new_token: &[u8; 32],
    ) -> Result<String, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.realm_exchange($1::text::uuid,$2,$3,$4,$5,$6,$7)")
            .bind(a.realm)
            .bind(a.purpose)
            .bind(a.browser.as_slice())
            .bind(a.token.map(|x| x.as_slice()))
            .bind(a.link.map(|x| x.as_slice()))
            .bind(new_browser.as_slice())
            .bind(new_token.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn realm_save_settings(
        &self,
        a: Authority<'_>,
        version: i64,
        values: &[String],
        confirmed: bool,
    ) -> Result<String, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.realm_save_settings($1::text::uuid,$2,$3,$4,$5,$6,$7)")
            .bind(a.realm)
            .bind(a.session.map(|x| x.as_slice()))
            .bind(a.browser.as_slice())
            .bind(a.token.map(|x| x.as_slice()))
            .bind(version)
            .bind(values)
            .bind(confirmed)
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn realm_issue_link(
        &self,
        a: Authority<'_>,
        user: &str,
        version: i64,
        confirmed: bool,
    ) -> Result<String, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar(
            "SELECT bloc.realm_issue_link($1::text::uuid,$2::text::uuid,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(a.realm)
        .bind(user)
        .bind(a.purpose)
        .bind(a.session.map(|x| x.as_slice()))
        .bind(a.browser.as_slice())
        .bind(a.token.map(|x| x.as_slice()))
        .bind(version)
        .bind(confirmed)
        .bind(a.link.map(|x| x.as_slice()))
        .fetch_one(&self.pool)
        .await
        .map_err(error)
    }
    pub(crate) async fn realm_has_credential(
        &self,
        r: &str,
        u: &str,
        s: &[u8; 32],
    ) -> Result<bool, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.realm_has_credential($1::text::uuid,$2::text::uuid,$3)")
            .bind(r)
            .bind(u)
            .bind(s.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn realm_deny(&self, a: &str, r: &str) -> Result<(), Error> {
        self.realm_ready().await?;
        sqlx::query("SELECT bloc.realm_denial($1,$2)")
            .bind(a)
            .bind(r)
            .execute(&self.pool)
            .await
            .map_err(error)?;
        Ok(())
    }
}
