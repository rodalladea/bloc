use super::Error;
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, Builder, Totp};

pub(crate) fn verifier(secret: &[u8]) -> Result<Totp, Error> {
    if secret.len() != 20 {
        return Err(Error);
    }
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .build()
        .map_err(|_| Error)
}
pub(crate) fn accepted_step(
    secret: &[u8],
    code: &str,
    now: i64,
    floor: i64,
) -> Result<Option<i64>, Error> {
    if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return Ok(None);
    }
    let totp = verifier(secret)?;
    let center = now / 30;
    let mut found = None;
    for step in [center - 1, center, center + 1] {
        if step < 0 {
            continue;
        }
        let generated = totp.generate((step as u64) * 30).to_string();
        if bool::from(generated.as_bytes().ct_eq(code.as_bytes())) && step > floor {
            found = Some(step);
        }
    }
    Ok(found)
}
pub(crate) fn presentation(
    secret: &[u8],
    realm: &str,
    id: &str,
) -> Result<(String, Vec<u8>), Error> {
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some(format!("bloc {id}")))
        .with_account_name(realm.replace(':', " — "))
        .build()
        .map_err(|_| Error)?;
    Ok((
        totp.secret().to_base32(),
        totp.to_qr_png().map_err(|_| Error)?,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mfa_totp_fixed_profile() {
        let secret = b"12345678901234567890";
        assert_eq!(verifier(secret).unwrap().generate(59).to_string(), "287082");
        assert_eq!(accepted_step(secret, "287082", 59, -1).unwrap(), Some(1));
        assert_eq!(accepted_step(secret, "287082", 59, 1).unwrap(), None);
        assert_eq!(accepted_step(secret, "287082", 120, -1).unwrap(), None);
        assert_eq!(accepted_step(secret, "+87082", 59, -1).unwrap(), None);
        assert_eq!(accepted_step(secret, "２87082", 59, -1).unwrap(), None);
    }
}
