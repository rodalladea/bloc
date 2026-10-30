//! Administrator navigation context; a remembered realm never grants authority.
use crate::{
    directory,
    directory_storage::{DirectoryError, Record},
    storage::Storage,
};
use axum::http::HeaderMap;

pub(crate) const COOKIE: &str = "__Host-bloc-workspace";

#[derive(Default)]
pub(crate) struct Workspace {
    pub current: Record,
    pub realms: Vec<Record>,
    pub more: bool,
}
impl Workspace {
    pub async fn load(
        storage: &Storage,
        session: &[u8; 32],
        current: Record,
    ) -> Result<Self, DirectoryError> {
        let mut realms = storage.directory_realms(session, None, None).await?;
        let more = realms.len() > 50;
        realms.truncate(50);
        Ok(Self {
            current,
            realms,
            more,
        })
    }

    pub async fn entry(
        &self,
        storage: &Storage,
        session: &[u8; 32],
        headers: &HeaderMap,
    ) -> Result<String, DirectoryError> {
        if let Some(id) = preference(headers) {
            let existing = storage.directory_realms(session, Some(id), None).await?;
            if let Some(realm) = existing.first() {
                return Ok(format!("/admin/realms/{}/users", realm.id));
            }
        }
        if self.realms.len() == 1 && !self.more {
            Ok(format!("/admin/realms/{}/users", self.realms[0].id))
        } else {
            Ok("/admin/realms".into())
        }
    }
}

fn preference(headers: &HeaderMap) -> Option<&str> {
    let mut found = None;
    for header in headers.get_all("cookie") {
        for part in header.to_str().ok()?.split(';') {
            let (key, value) = part.trim().split_once('=')?;
            if key == COOKIE {
                if found.is_some() || !directory::uuid(value) {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn preference_accepts_only_one_realm_id() {
        let id = "11111111-1111-4111-8111-111111111111";
        let mut headers = HeaderMap::new();
        assert_eq!(preference(&headers), None);
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("{COOKIE}={id}")).unwrap(),
        );
        assert_eq!(preference(&headers), Some(id));
        headers.append(
            "cookie",
            HeaderValue::from_str(&format!("{COOKIE}={id}")).unwrap(),
        );
        assert_eq!(preference(&headers), None);
        for value in ["https://example.test", "../../login", "", "not-a-realm"] {
            headers.insert(
                "cookie",
                HeaderValue::from_str(&format!("{COOKIE}={value}")).unwrap(),
            );
            assert_eq!(preference(&headers), None);
        }
    }
}
