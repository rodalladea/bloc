use super::Error;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) struct CodeSet {
    pub digests: Vec<Vec<u8>>,
    pub payload: Zeroizing<Vec<u8>>,
}
pub(crate) fn code_digest(
    realm: &str,
    user: &str,
    generation: &str,
    code: &str,
) -> Result<Vec<u8>, Error> {
    let mut digest = Sha256::new();
    digest.update(b"bloc:mfa:recovery-code:v1");
    for id in [realm, user, generation] {
        digest.update(Uuid::parse_str(id).map_err(|_| Error)?.as_bytes());
    }
    digest.update(code.as_bytes());
    Ok(digest.finalize().to_vec())
}
pub(crate) fn generate(realm: &str, user: &str, generation: &str) -> Result<CodeSet, Error> {
    let mut codes = Zeroizing::new(Vec::with_capacity(10));
    let mut digests = Vec::with_capacity(10);
    for _ in 0..10 {
        let mut bytes = Zeroizing::new(vec![0; 16]);
        getrandom::fill(&mut bytes).map_err(|_| Error)?;
        let code = totp_rs::Secret::new(bytes.to_vec().into_boxed_slice()).to_base32();
        digests.push(code_digest(realm, user, generation, &code)?);
        codes.push(code);
    }
    let payload = super::encode_handoff(&codes)?;
    Ok(CodeSet { digests, payload })
}
pub(crate) fn normalize(value: &str) -> Option<Zeroizing<String>> {
    let mut normalized = Zeroizing::new(String::with_capacity(26));
    for byte in value.bytes() {
        match byte {
            b' ' | b'-' => {}
            b'A'..=b'Z' | b'a'..=b'z' | b'2'..=b'7' => {
                normalized.push(byte.to_ascii_uppercase() as char)
            }
            _ => return None,
        }
    }
    if normalized.len() != 26
        || !matches!(
            normalized.as_bytes()[25],
            b'A' | b'E' | b'I' | b'M' | b'Q' | b'U' | b'Y' | b'4'
        )
    {
        return None;
    }
    Some(normalized)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mfa_recovery_code_normalization() {
        let code = "A".repeat(26);
        assert_eq!(
            normalize(&format!("{}-{} ", "a".repeat(13), "a".repeat(13)))
                .as_deref()
                .map(|c| c.as_str()),
            Some(code.as_str())
        );
        for invalid in [
            format!("{code}\t"),
            format!("{code}é"),
            "A".repeat(25),
            format!("{}B", "A".repeat(25)),
        ] {
            assert!(normalize(&invalid).is_none());
        }
    }
}
