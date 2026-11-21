//! Operator-mounted keys and owner-bound MFA secret envelopes.
pub(crate) mod account_storage;
pub(crate) mod operator;
pub(crate) mod policy;
pub(crate) mod recovery;
pub(crate) mod recovery_storage;
mod storage;
pub(crate) mod totp;
pub(crate) mod webauthn;
pub(crate) mod webauthn_storage;
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::Deserialize;
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug)]
pub(crate) struct Error;
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Purpose {
    ActiveTotp = 1,
    PendingTotp = 2,
    RecoveryHandoff = 3,
}
pub(crate) struct Binding {
    pub installation: [u8; 16],
    pub realm: [u8; 16],
    pub user: [u8; 16],
    pub record: [u8; 16],
    pub purpose: Purpose,
    pub payload_version: u16,
}
#[derive(Clone)]
pub(crate) struct Keyring {
    keys: BTreeMap<[u8; 16], Zeroizing<Vec<u8>>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format_version: u16,
    keys: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: Uuid,
    key: String,
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
impl Keyring {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new(Vec::new());
        File::open(path)
            .map_err(|_| Error)?
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| Error)?;
        Self::parse(&bytes)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 16384 {
            return Err(Error);
        }
        let mut document: Document = serde_json::from_slice(bytes).map_err(|_| Error)?;
        if document.format_version != 1 || !(1..=16).contains(&document.keys.len()) {
            return Err(Error);
        }
        let mut keys = BTreeMap::new();
        for entry in &mut document.keys {
            let encoded = Zeroizing::new(std::mem::take(&mut entry.key));
            let key = Zeroizing::new(STANDARD.decode(encoded.as_bytes()).map_err(|_| Error)?);
            if key.len() != 32
                || *Zeroizing::new(STANDARD.encode(&*key)) != *encoded
                || keys.values().any(|k: &Zeroizing<Vec<u8>>| **k == *key)
                || keys.insert(*entry.id.as_bytes(), key).is_some()
            {
                return Err(Error);
            }
        }
        Ok(Self { keys })
    }
    #[cfg(test)]
    pub fn ids(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.keys.keys()
    }
    pub fn contains(&self, id: &[u8; 16]) -> bool {
        self.keys.contains_key(id)
    }
    pub fn encrypt(
        &self,
        id: [u8; 16],
        binding: &Binding,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        validate(binding, plaintext)?;
        let key = self.keys.get(&id).ok_or(Error)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error)?;
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error)?;
        let mut output = Vec::with_capacity(46 + plaintext.len() + 16);
        output.extend_from_slice(b"BMFA\x01\x01");
        output.extend_from_slice(&id);
        output.extend_from_slice(&nonce);
        let aad = binding.aad(&output);
        let encrypted = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error)?;
        output.extend_from_slice(&encrypted);
        if output.len() > 4096 {
            return Err(Error);
        }
        Ok(output)
    }
    pub fn decrypt(&self, binding: &Binding, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !(62..=4096).contains(&envelope.len()) || &envelope[..6] != b"BMFA\x01\x01" {
            return Err(Error);
        }
        let id: [u8; 16] = envelope[6..22].try_into().map_err(|_| Error)?;
        let key = self.keys.get(&id).ok_or(Error)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error)?;
        let aad = binding.aad(&envelope[..46]);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::try_from(&envelope[22..46]).map_err(|_| Error)?,
                    Payload {
                        msg: &envelope[46..],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error)?,
        );
        validate(binding, &plaintext)?;
        Ok(plaintext)
    }
}
impl Binding {
    fn aad(&self, header: &[u8]) -> Vec<u8> {
        let mut aad = header.to_vec();
        for id in [&self.installation, &self.realm, &self.user] {
            aad.extend_from_slice(id);
        }
        aad.push(self.purpose as u8);
        aad.extend_from_slice(&self.record);
        aad.extend_from_slice(&self.payload_version.to_be_bytes());
        aad
    }
}
fn validate(binding: &Binding, value: &[u8]) -> Result<(), Error> {
    if binding.payload_version != 1 {
        return Err(Error);
    }
    match binding.purpose {
        Purpose::ActiveTotp | Purpose::PendingTotp if value.len() == 20 => Ok(()),
        Purpose::RecoveryHandoff => decode_handoff(value).map(|_| ()),
        _ => Err(Error),
    }
}
pub(crate) fn encode_handoff(codes: &[String]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if codes.len() != 10 {
        return Err(Error);
    }
    let mut out = Zeroizing::new(vec![0, 10]);
    for code in codes {
        if !canonical_code(code.as_bytes()) {
            return Err(Error);
        }
        out.extend_from_slice(&26u16.to_be_bytes());
        out.extend_from_slice(code.as_bytes());
    }
    Ok(out)
}
fn canonical_code(code: &[u8]) -> bool {
    code.len() == 26
        && code
            .iter()
            .all(|c| c.is_ascii_uppercase() || matches!(c, b'2'..=b'7'))
        && matches!(
            code[25],
            b'A' | b'E' | b'I' | b'M' | b'Q' | b'U' | b'Y' | b'4'
        )
}
pub(crate) fn decode_handoff(value: &[u8]) -> Result<Zeroizing<Vec<String>>, Error> {
    if value.len() != 282 || value[..2] != [0, 10] {
        return Err(Error);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(10));
    for row in value[2..].as_chunks::<28>().0 {
        if row[..2] != [0, 26] || !canonical_code(&row[2..]) {
            return Err(Error);
        }
        out.push(String::from_utf8(row[2..].to_vec()).map_err(|_| Error)?);
    }
    Ok(out)
}
#[cfg(test)]
#[path = "mfa/tests.rs"]
mod tests;
