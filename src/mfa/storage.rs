use super::*;
use crate::storage::Storage;
use sqlx::Row;

pub(crate) struct KeyStatus {
    pub installation: String,
    pub id: Option<String>,
    pub state: Option<String>,
    pub generation: i64,
    pub active: Option<String>,
    pub references: i64,
}
impl Storage {
    pub(crate) async fn mfa_keys(&self) -> Result<Vec<KeyStatus>, Error> {
        self.compatible().await.map_err(|_| Error)?;
        let rows = sqlx::query("SELECT * FROM bloc.mfa_key_status()")
            .fetch_all(&self.pool)
            .await
            .map_err(|_| Error)?;
        Ok(rows
            .into_iter()
            .map(|r| KeyStatus {
                installation: r.get("installation_id"),
                id: r.get("key_id"),
                state: r.get("state"),
                generation: r.get("generation"),
                active: r.get("active_key_id"),
                references: r.get("reference_count"),
            })
            .collect())
    }
    pub(crate) async fn mfa_ready(&self, ring: Option<&Keyring>) -> Result<(), Error> {
        let ring = ring.ok_or(Error)?;
        let keys = self.mfa_keys().await?;
        if keys.is_empty() || !keys.iter().any(|k| k.state.as_deref() == Some("active")) {
            return Err(Error);
        }
        for key in keys {
            Uuid::parse_str(&key.installation).map_err(|_| Error)?;
            if key.state.as_deref() == Some("active") && key.active != key.id {
                return Err(Error);
            }
            if key.state.as_deref() != Some("retired")
                && !ring.contains(
                    Uuid::parse_str(key.id.as_deref().ok_or(Error)?)
                        .map_err(|_| Error)?
                        .as_bytes(),
                )
            {
                return Err(Error);
            }
        }
        Ok(())
    }
    pub(crate) async fn mfa_key_change(
        &self,
        operation: &str,
        id: &str,
        generation: i64,
        confirmed: bool,
    ) -> Result<String, Error> {
        self.compatible().await.map_err(|_| Error)?;
        sqlx::query_scalar("SELECT bloc.mfa_key_change($1,$2::text::uuid,$3,$4)")
            .bind(operation)
            .bind(id)
            .bind(generation)
            .bind(confirmed)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error)
    }
    pub(crate) async fn mfa_reencrypt(
        &self,
        source: &str,
        batch: i32,
        ring: &Keyring,
    ) -> Result<usize, Error> {
        self.compatible().await.map_err(|_| Error)?;
        let rows = sqlx::query("SELECT * FROM bloc.mfa_reencrypt_read($1::text::uuid,$2)")
            .bind(source)
            .bind(batch)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| Error)?;
        if rows.is_empty() {
            return Ok(0);
        }
        let mut ids = vec![];
        let mut revisions = vec![];
        let mut envelopes = vec![];
        let generation = rows[0].get::<i64, _>("generation");
        let active = rows[0].get::<String, _>("active_key_id");
        let key = *Uuid::parse_str(&active).map_err(|_| Error)?.as_bytes();
        for row in rows {
            let id = row.get::<String, _>("id");
            let binding = Binding {
                installation: parse_id(row.get("installation_id"))?,
                realm: parse_id(row.get("realm_id"))?,
                user: parse_id(row.get("user_id"))?,
                record: parse_id(&id)?,
                purpose: match row.get::<i16, _>("purpose") {
                    1 => Purpose::ActiveTotp,
                    2 => Purpose::PendingTotp,
                    3 => Purpose::RecoveryHandoff,
                    _ => return Err(Error),
                },
                payload_version: row.get::<i16, _>("payload_version") as u16,
            };
            let old = row.get::<Vec<u8>, _>("encrypted_payload");
            let plaintext = ring.decrypt(&binding, &old)?;
            envelopes.push(ring.encrypt(key, &binding, &plaintext)?);
            ids.push(id);
            revisions.push(row.get::<i64, _>("revision"));
        }
        let outcome: String = sqlx::query_scalar(
            "SELECT bloc.mfa_reencrypt_commit($1::text[]::uuid[],$2,$3,$4,$5::text::uuid)",
        )
        .bind(&ids)
        .bind(revisions)
        .bind(envelopes)
        .bind(generation)
        .bind(active)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| Error)?;
        if outcome != "ok" {
            return Err(Error);
        }
        Ok(ids.len())
    }
}
fn parse_id(value: &str) -> Result<[u8; 16], Error> {
    Ok(*Uuid::parse_str(value).map_err(|_| Error)?.as_bytes())
}
