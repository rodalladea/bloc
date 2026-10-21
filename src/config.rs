//! Validated ingress and secret-file configuration.
use crate::storage::{Error, Storage};
use ipnet::IpNet;
use std::{env, fs, io::Read, net::IpAddr, path::PathBuf};

#[derive(Clone)]
pub struct Config {
    pub origin: String,
    pub host: String,
    pub proxies: Vec<IpNet>,
    pub abuse_key: [u8; 32],
}
fn file(name: &str, limit: usize) -> Result<Vec<u8>, Error> {
    let path = env::var_os(name).ok_or(Error::Configuration)?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| Error::Configuration)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Configuration)?;
    if bytes.len() > limit {
        return Err(Error::Configuration);
    }
    Ok(bytes)
}
impl Config {
    pub fn new(origin: &str, proxies: &str, abuse_key: [u8; 32]) -> Result<Self, Error> {
        let parsed =
            crate::request_security::authority_url(origin, false).ok_or(Error::Configuration)?;
        let canonical = parsed.origin().ascii_serialization();
        let host = canonical
            .strip_prefix("https://")
            .ok_or(Error::Configuration)?
            .to_owned();
        let proxies: Vec<IpNet> = proxies
            .split(',')
            .map(|s| s.trim().parse().map_err(|_| Error::Configuration))
            .collect::<Result<_, _>>()?;
        if proxies.is_empty() {
            return Err(Error::Configuration);
        }
        Ok(Self {
            origin: canonical,
            host,
            proxies,
            abuse_key,
        })
    }
    pub fn environment() -> Result<(Self, Storage), Error> {
        let origin = env::var("BLOC_CANONICAL_ORIGIN").map_err(|_| Error::Configuration)?;
        let proxies = env::var("BLOC_TRUSTED_PROXY_CIDRS").map_err(|_| Error::Configuration)?;
        let abuse_key: [u8; 32] = file("BLOC_ABUSE_KEY_FILE", 32)?
            .try_into()
            .map_err(|_| Error::Configuration)?;
        let url = String::from_utf8(file("BLOC_DATABASE_URL_FILE", 16384)?)
            .map_err(|_| Error::Configuration)?;
        let ca = PathBuf::from(env::var_os("BLOC_DATABASE_CA_FILE").ok_or(Error::Configuration)?);
        Ok((
            Self::new(&origin, &proxies, abuse_key)?,
            Storage::lazy(url.trim(), &ca)?,
        ))
    }
    pub fn trusts(&self, peer: IpAddr) -> bool {
        self.proxies.iter().any(|range| range.contains(&peer))
    }
}
