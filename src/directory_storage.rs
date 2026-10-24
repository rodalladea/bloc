//! Guarded directory persistence. No directory table is accessible to runtime roles.
use crate::storage::{Error, Storage};
use sqlx::Row;
#[derive(Clone, Default)]
pub(crate) struct Record {
    pub id: String,
    pub name: String,
    pub email: String,
    pub display_name: String,
    pub status: String,
    pub version: i64,
    pub created: String,
    pub updated: String,
    pub cursor: i64,
}
#[derive(Debug)]
pub(crate) enum DirectoryError {
    Authority,
    Storage,
}
fn error(e: sqlx::Error) -> DirectoryError {
    if e.as_database_error().and_then(|e| e.code()).as_deref() == Some("28000") {
        DirectoryError::Authority
    } else {
        DirectoryError::Storage
    }
}
impl From<Error> for DirectoryError {
    fn from(_: Error) -> Self {
        Self::Storage
    }
}
pub(crate) struct Mutation<'a> {
    pub operation: &'a str,
    pub realm: &'a str,
    pub user: Option<&'a str>,
    pub version: i64,
    pub profile: &'a str,
    pub display: Option<&'a str>,
    pub status: &'a str,
}
impl Storage {
    pub(crate) async fn directory_realms(
        &self,
        session: &[u8; 32],
        id: Option<&str>,
        cursor: Option<(i64, &str)>,
    ) -> Result<Vec<Record>, DirectoryError> {
        self.compatible().await?;
        let rows =
            sqlx::query("SELECT * FROM bloc.directory_realms($1,$2::text::uuid,$3,$4::text::uuid)")
                .bind(session.as_slice())
                .bind(id)
                .bind(cursor.map(|c| c.0))
                .bind(cursor.map(|c| c.1))
                .fetch_all(&self.pool)
                .await
                .map_err(error)?;
        Ok(rows
            .into_iter()
            .map(|r| Record {
                id: r.get("id"),
                name: r.get("name"),
                status: r.get("status"),
                version: r.get("version"),
                created: r.get("created"),
                updated: r.get("updated"),
                cursor: r.get("cursor_value"),
                ..Record::default()
            })
            .collect())
    }
    pub(crate) async fn directory_users(
        &self,
        session: &[u8; 32],
        realm: &str,
        id: Option<&str>,
        cursor: Option<(i64, &str)>,
    ) -> Result<Vec<Record>, DirectoryError> {
        self.compatible().await?;
        let rows=sqlx::query("SELECT * FROM bloc.directory_users($1,$2::text::uuid,$3::text::uuid,$4,$5::text::uuid)").bind(session.as_slice()).bind(realm).bind(id).bind(cursor.map(|c|c.0)).bind(cursor.map(|c|c.1)).fetch_all(&self.pool).await.map_err(error)?;
        Ok(rows
            .into_iter()
            .map(|r| Record {
                id: r.get("id"),
                email: r.get("email"),
                display_name: r
                    .get::<Option<String>, _>("display_name")
                    .unwrap_or_default(),
                status: r.get("status"),
                version: r.get("version"),
                created: r.get("created"),
                updated: r.get("updated"),
                cursor: r.get("cursor_value"),
                ..Record::default()
            })
            .collect())
    }
    pub(crate) async fn directory_mutate(
        &self,
        session: &[u8; 32],
        m: Mutation<'_>,
    ) -> Result<String, DirectoryError> {
        self.compatible().await?;
        sqlx::query_scalar(
            "SELECT bloc.directory_mutate($1,$2,$3::text::uuid,$4::text::uuid,$5,$6,$7,$8)",
        )
        .bind(session.as_slice())
        .bind(m.operation)
        .bind(m.realm)
        .bind(m.user)
        .bind(m.version)
        .bind(m.profile)
        .bind(m.display)
        .bind(m.status)
        .fetch_one(&self.pool)
        .await
        .map_err(error)
    }
}
