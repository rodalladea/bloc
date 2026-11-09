//! Realm authority adapters: parameters are validated at HTTP boundaries and
//! re-authorized in each guarded database operation, never by direct table access.
use crate::storage::Storage;
use sqlx::Row;

#[derive(Debug)]
pub(crate) enum Error {
    Storage,
    Aborted,
    BeforeCommit,
    Capacity,
    Authority,
}
pub(crate) fn error(e: sqlx::Error) -> Error {
    match e.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("54000") => Error::Capacity,
        Some("28000") => Error::Authority,
        _ if e.as_database_error().is_some() => Error::Aborted,
        _ => Error::Storage,
    }
}
#[derive(Clone)]
pub(crate) struct Policy {
    pub registration: bool,
    pub mfa: crate::mfa::policy::Policy,
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
            mfa: crate::mfa::policy::Policy {
                mode: match x.get::<&str, _>("mfa_mode") {
                    "disabled" => crate::mfa::policy::Mode::Disabled,
                    "required" => crate::mfa::policy::Mode::Required,
                    _ => crate::mfa::policy::Mode::Optional,
                },
                methods: x.get("mfa_allowed_methods"),
                preferred: x.get("mfa_preferred_method"),
                codes: x.get("mfa_recovery_codes_enabled"),
                assisted: x.get("mfa_admin_recovery_enabled"),
                ttl: x.get("mfa_flow_ttl_seconds"),
                recovery_ttl: x.get("mfa_admin_recovery_ttl_seconds"),
            },
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

impl Storage {
    pub(crate) async fn realm_mfa_policy_impact(
        &self,
        r: &str,
        admin: &[u8; 32],
        mode: &str,
        methods: &str,
    ) -> Result<(i64, i64), Error> {
        self.realm_ready().await?;
        sqlx::query_as("SELECT * FROM bloc.realm_mfa_policy_impact($1::text::uuid,$2,$3,string_to_array($4,','))").bind(r).bind(admin.as_slice()).bind(mode).bind(methods).fetch_one(&self.pool).await.map_err(error)
    }
    pub(crate) async fn realm_mfa_noncompliant(
        &self,
        r: &str,
        s: &[u8; 32],
    ) -> Result<bool, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.realm_mfa_noncompliant($1::text::uuid,$2)")
            .bind(r)
            .bind(s.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
}
pub(crate) struct MfaFlow {
    pub user: String,
    pub purpose: String,
    pub csrf: Vec<u8>,
    pub installation: String,
}
impl Storage {
    pub(crate) async fn realm_mfa_flow(
        &self,
        r: &str,
        bearer: &[u8; 32],
        browser: &[u8; 32],
        token: Option<&[u8; 32]>,
    ) -> Result<(String, Option<MfaFlow>), Error> {
        self.realm_ready().await?;
        let row=sqlx::query("SELECT status,(authority).id::text AS id,(authority).user_id::text AS user_id,(authority).purpose,(authority).csrf_token,(authority).factor_epoch,now_seconds,installation_id FROM bloc.mfa_flow_snapshot($1::text::uuid,$2,$3,$4)").bind(r).bind(bearer.as_slice()).bind(browser.as_slice()).bind(token.map(|v|v.as_slice())).fetch_one(&self.pool).await.map_err(error)?;
        let status: String = row.get("status");
        let flow = if status == "ok" {
            Some(MfaFlow {
                user: row.get("user_id"),
                purpose: row.get("purpose"),
                csrf: row.get("csrf_token"),
                installation: row.get("installation_id"),
            })
        } else {
            None
        };
        Ok((status, flow))
    }
    pub(crate) async fn realm_mfa_cancel(
        &self,
        r: &str,
        bearer: &[u8; 32],
        browser: &[u8; 32],
        token: &[u8; 32],
    ) -> Result<String, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.mfa_flow_cancel($1::text::uuid,$2,$3,$4)")
            .bind(r)
            .bind(bearer.as_slice())
            .bind(browser.as_slice())
            .bind(token.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
}
pub(crate) struct MfaTotpMaterial {
    pub factor: String,
    pub user: String,
    pub envelope: Vec<u8>,
    pub floor: i64,
    pub now: i64,
    pub installation: String,
}
impl Storage {
    pub(crate) async fn realm_mfa_admit(
        &self,
        r: &str,
        bearer: &[u8; 32],
        browser: &[u8; 32],
        token: &[u8; 32],
        source: &[u8; 32],
    ) -> Result<i32, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.mfa_admit($1::text::uuid,$2,$3,$4,$5)")
            .bind(r)
            .bind(bearer.as_slice())
            .bind(browser.as_slice())
            .bind(token.as_slice())
            .bind(source.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
    pub(crate) async fn realm_mfa_totp(
        &self,
        r: &str,
        bearer: &[u8; 32],
        browser: &[u8; 32],
        token: &[u8; 32],
    ) -> Result<Option<MfaTotpMaterial>, Error> {
        self.realm_ready().await?;
        let row = sqlx::query("SELECT * FROM bloc.mfa_totp_material($1::text::uuid,$2,$3,$4)")
            .bind(r)
            .bind(bearer.as_slice())
            .bind(browser.as_slice())
            .bind(token.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(error)?;
        Ok(row.map(|row| MfaTotpMaterial {
            factor: row.get("factor_id"),
            user: row.get("user_id"),
            envelope: row.get("envelope"),
            floor: row.get("replay_floor"),
            now: row.get("now_seconds"),
            installation: row.get("installation_id"),
        }))
    }
}
pub(crate) struct MfaVerification<'a> {
    pub realm: &'a str,
    pub bearer: &'a [u8; 32],
    pub browser: &'a [u8; 32],
    pub token: &'a [u8; 32],
    pub factor: Option<&'a str>,
    pub step: Option<i64>,
    pub session: &'a [u8; 32],
    pub new_browser: &'a [u8; 32],
    pub new_token: &'a [u8; 32],
    pub device: String,
}
impl Storage {
    pub(crate) async fn realm_mfa_verify(&self, p: MfaVerification<'_>) -> Result<String, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.mfa_verify_commit($1::text::uuid,$2,$3,$4,$5::text::uuid,$6,$7,$8,$9,$10,$11)").bind(p.realm).bind(p.bearer.as_slice()).bind(p.browser.as_slice()).bind(p.token.as_slice()).bind(p.factor).bind(p.step).bind(p.step.is_some()).bind(p.session.as_slice()).bind(p.new_browser.as_slice()).bind(p.new_token.as_slice()).bind(p.device).fetch_one(&self.pool).await.map_err(error)
    }
}
pub(crate) struct MfaEnrollment<'a> {
    pub realm: &'a str,
    pub bearer: &'a [u8; 32],
    pub browser: &'a [u8; 32],
    pub token: &'a [u8; 32],
    pub payload: &'a str,
    pub envelope: Vec<u8>,
    pub key: &'a str,
    pub generation: i64,
    pub new_bearer: &'a [u8; 32],
    pub new_token: &'a [u8; 32],
}
impl Storage {
    pub(crate) async fn realm_mfa_totp_start(&self, p: MfaEnrollment<'_>) -> Result<String, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.mfa_totp_start($1::text::uuid,$2,$3,$4,$5::text::uuid,$6,$7::text::uuid,$8,$9,$10)").bind(p.realm).bind(p.bearer.as_slice()).bind(p.browser.as_slice()).bind(p.token.as_slice()).bind(p.payload).bind(p.envelope).bind(p.key).bind(p.generation).bind(p.new_bearer.as_slice()).bind(p.new_token.as_slice()).fetch_one(&self.pool).await.map_err(error)
    }
    pub(crate) async fn realm_mfa_pending_totp(
        &self,
        r: &str,
        bearer: &[u8; 32],
        browser: &[u8; 32],
        token: Option<&[u8; 32]>,
    ) -> Result<Option<MfaTotpMaterial>, Error> {
        self.realm_ready().await?;
        let row = sqlx::query("SELECT * FROM bloc.mfa_totp_pending($1::text::uuid,$2,$3,$4)")
            .bind(r)
            .bind(bearer.as_slice())
            .bind(browser.as_slice())
            .bind(token.map(|t| t.as_slice()))
            .fetch_optional(&self.pool)
            .await
            .map_err(error)?;
        Ok(row.map(|row| MfaTotpMaterial {
            factor: row.get("factor_id"),
            user: row.get("user_id"),
            envelope: row.get("envelope"),
            floor: row.get("replay_floor"),
            now: row.get("now_seconds"),
            installation: row.get("installation_id"),
        }))
    }
}
pub(crate) struct MfaActivation<'a> {
    pub realm: &'a str,
    pub bearer: &'a [u8; 32],
    pub browser: &'a [u8; 32],
    pub token: &'a [u8; 32],
    pub step: Option<i64>,
    pub active_envelope: Vec<u8>,
    pub key: &'a str,
    pub key_generation: i64,
    pub generation: &'a str,
    pub digests: Vec<Vec<u8>>,
    pub handoff: &'a str,
    pub handoff_envelope: Vec<u8>,
    pub new_bearer: &'a [u8; 32],
    pub new_csrf: &'a [u8; 32],
    pub session: &'a [u8; 32],
    pub session_browser: &'a [u8; 32],
    pub session_token: &'a [u8; 32],
    pub device: String,
}
pub(crate) struct HandoffMaterial {
    pub payload: String,
    pub envelope: Vec<u8>,
    pub user: String,
    pub installation: String,
}
impl Storage {
    pub(crate) async fn realm_mfa_activate_totp(
        &self,
        p: MfaActivation<'_>,
    ) -> Result<String, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.mfa_totp_confirm($1::text::uuid,$2,$3,$4,$5,$6,$7,$8::text::uuid,$9,$10::text::uuid,$11,$12::text::uuid,$13,$14,$15,$16,$17,$18,$19)").bind(p.realm).bind(p.bearer.as_slice()).bind(p.browser.as_slice()).bind(p.token.as_slice()).bind(p.step).bind(p.step.is_some()).bind(p.active_envelope).bind(p.key).bind(p.key_generation).bind(p.generation).bind(p.digests).bind(p.handoff).bind(p.handoff_envelope).bind(p.new_bearer.as_slice()).bind(p.new_csrf.as_slice()).bind(p.session.as_slice()).bind(p.session_browser.as_slice()).bind(p.session_token.as_slice()).bind(p.device).fetch_one(&self.pool).await.map_err(error)
    }
    pub(crate) async fn realm_mfa_handoff(
        &self,
        r: &str,
        bearer: &[u8; 32],
        browser: &[u8; 32],
    ) -> Result<(String, Option<HandoffMaterial>), Error> {
        self.realm_ready().await?;
        let row = sqlx::query("SELECT * FROM bloc.mfa_handoff_present($1::text::uuid,$2,$3)")
            .bind(r)
            .bind(bearer.as_slice())
            .bind(browser.as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(error)?;
        let status: String = row.get("status");
        let material = if status == "ok" {
            Some(HandoffMaterial {
                payload: row.get("payload_id"),
                envelope: row.get("envelope"),
                user: row.get("user_id"),
                installation: row.get("installation_id"),
            })
        } else {
            None
        };
        Ok((status, material))
    }
    pub(crate) async fn realm_mfa_ack(
        &self,
        p: MfaVerification<'_>,
        saved: bool,
    ) -> Result<String, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.mfa_handoff_ack($1::text::uuid,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(p.realm)
            .bind(p.bearer.as_slice())
            .bind(p.browser.as_slice())
            .bind(p.token.as_slice())
            .bind(saved)
            .bind(p.session.as_slice())
            .bind(p.new_browser.as_slice())
            .bind(p.new_token.as_slice())
            .bind(p.device)
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }
}
pub(crate) struct HandoffReplacement<'a> {
    pub realm: &'a str,
    pub bearer: &'a [u8; 32],
    pub browser: &'a [u8; 32],
    pub token: &'a [u8; 32],
    pub generation: &'a str,
    pub digests: Vec<Vec<u8>>,
    pub handoff: &'a str,
    pub envelope: Vec<u8>,
    pub key: &'a str,
    pub key_generation: i64,
    pub new_bearer: &'a [u8; 32],
    pub new_csrf: &'a [u8; 32],
    pub session: &'a [u8; 32],
    pub session_browser: &'a [u8; 32],
    pub session_token: &'a [u8; 32],
    pub device: String,
}
impl Storage {
    pub(crate) async fn realm_mfa_replace_handoff(
        &self,
        p: HandoffReplacement<'_>,
    ) -> Result<String, Error> {
        self.realm_ready().await?;
        sqlx::query_scalar("SELECT bloc.mfa_replace_handoff($1::text::uuid,$2,$3,$4,$5::text::uuid,$6,$7::text::uuid,$8,$9::text::uuid,$10,$11,$12,$13,$14,$15,$16)").bind(p.realm).bind(p.bearer.as_slice()).bind(p.browser.as_slice()).bind(p.token.as_slice()).bind(p.generation).bind(p.digests).bind(p.handoff).bind(p.envelope).bind(p.key).bind(p.key_generation).bind(p.new_bearer.as_slice()).bind(p.new_csrf.as_slice()).bind(p.session.as_slice()).bind(p.session_browser.as_slice()).bind(p.session_token.as_slice()).bind(p.device).fetch_one(&self.pool).await.map_err(error)
    }
}
