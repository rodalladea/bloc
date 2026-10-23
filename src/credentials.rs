//! Credential validation and bounded CPU work; secrets are never diagnostic values.
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Capacity,
    Unavailable,
}

pub fn normalize_email(input: &str) -> Result<String, Error> {
    let email = input.trim();
    if !email.is_ascii() || email.len() > 254 {
        return Err(Error::Invalid);
    }
    let (local, domain) = email.split_once('@').ok_or(Error::Invalid)?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&c))
    {
        return Err(Error::Invalid);
    }
    if domain.is_empty()
        || domain.len() > 253
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(Error::Invalid);
    }
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}
pub fn validate_password(password: &str, confirmation: &str) -> Result<(), Error> {
    if !(15..=128).contains(&password.chars().count())
        || password.len() > 512
        || password != confirmation
    {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
fn algorithm() -> Result<Argon2<'static>, Error> {
    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 1, Some(32)).map_err(|_| Error::Unavailable)?,
    ))
}
#[derive(Clone)]
pub struct PasswordWorker {
    slot: Arc<Semaphore>,
    #[cfg(test)]
    work: Arc<[std::sync::atomic::AtomicUsize; 4]>,
}
impl Default for PasswordWorker {
    fn default() -> Self {
        Self::new()
    }
}
impl PasswordWorker {
    pub fn new() -> Self {
        Self {
            slot: Arc::new(Semaphore::new(1)),
            #[cfg(test)]
            work: Arc::new(std::array::from_fn(|_| {
                std::sync::atomic::AtomicUsize::new(0)
            })),
        }
    }
    #[cfg(test)]
    pub(crate) fn observed_work(&self) -> [usize; 4] {
        std::array::from_fn(|i| self.work[i].load(std::sync::atomic::Ordering::SeqCst))
    }
    #[cfg(test)]
    pub(crate) fn occupy(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.slot.clone().try_acquire_owned().unwrap()
    }
    pub async fn hash(&self, password: String) -> Result<String, Error> {
        let permit = self
            .slot
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Capacity)?;
        #[cfg(test)]
        let work = self.work.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut salt = [0u8; 16];
            getrandom::fill(&mut salt).map_err(|_| Error::Unavailable)?;
            #[cfg(test)]
            work[0].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let result = algorithm()?
                .hash_password_with_salt(password.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|_| Error::Unavailable);
            #[cfg(test)]
            work[1].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            result
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
    pub async fn verify(&self, password: String, phc: String) -> Result<bool, Error> {
        let permit = self
            .slot
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Capacity)?;
        #[cfg(test)]
        let work = self.work.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let hash = PasswordHash::new(&phc).map_err(|_| Error::Unavailable)?;
            #[cfg(test)]
            work[2].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let result = Ok(algorithm()?
                .verify_password(password.as_bytes(), &hash)
                .is_ok());
            #[cfg(test)]
            work[3].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            result
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
}
