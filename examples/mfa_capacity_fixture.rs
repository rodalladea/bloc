//! Private pipe-only synthetic native-capacity fixture; never a production command.
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(transparent)]
struct OwnedSecret(String);
impl Drop for OwnedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl From<String> for OwnedSecret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Input {
    Seed {
        installation: Uuid,
        realm: Uuid,
        key_id: Uuid,
        key: OwnedSecret,
        indices: Vec<u16>,
    },
    Otp {
        secret: OwnedSecret,
        now: u64,
    },
}
#[derive(Serialize)]
struct Actor {
    index: u16,
    secret: String,
}
impl Drop for Actor {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
#[derive(Serialize)]
struct Code<'a> {
    code: &'a str,
}
#[derive(Serialize)]
struct Seed {
    sql: String,
    actors: Vec<Actor>,
}
fn random<const N: usize>() -> Result<[u8; N], ()> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}
fn factor_id() -> Result<Uuid, ()> {
    Ok(uuid::Builder::from_random_bytes(random()?).into_uuid())
}
fn user_id(index: u16) -> Uuid {
    Uuid::parse_str(&format!("22222222-2222-4222-8222-{index:012}"))
        .expect("bounded synthetic UUID")
}
fn envelope(
    key: &[u8],
    key_id: Uuid,
    installation: Uuid,
    realm: Uuid,
    user: Uuid,
    factor: Uuid,
    secret: &[u8],
) -> Result<Vec<u8>, ()> {
    if key.len() != 32 || secret.len() != 20 {
        return Err(());
    }
    let nonce: [u8; 24] = random()?;
    let mut output = b"BMFA\x01\x01".to_vec();
    output.extend_from_slice(key_id.as_bytes());
    output.extend_from_slice(&nonce);
    let mut aad = output.clone();
    aad.extend_from_slice(installation.as_bytes());
    aad.extend_from_slice(realm.as_bytes());
    aad.extend_from_slice(user.as_bytes());
    aad.push(1);
    aad.extend_from_slice(factor.as_bytes());
    aad.extend_from_slice(&1u16.to_be_bytes());
    let encrypted = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| ())?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: secret,
                aad: &aad,
            },
        )
        .map_err(|_| ())?;
    output.extend_from_slice(&encrypted);
    Ok(output)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn otp(secret: &[u8], now: u64) -> Result<String, ()> {
    if secret.len() != 20 {
        return Err(());
    }
    Ok(totp_rs::Builder::new()
        .with_secret(secret)
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .build()
        .map_err(|_| ())?
        .generate(now)
        .to_string())
}
fn respond(input: Input) -> Result<Zeroizing<Vec<u8>>, ()> {
    let output = match input {
        Input::Otp { secret, now } => {
            let bytes = Zeroizing::new(STANDARD.decode(secret.0.as_bytes()).map_err(|_| ())?);

            let code = Zeroizing::new(otp(&bytes, now)?);
            serde_json::to_vec(&Code {
                code: code.as_str(),
            })
            .map_err(|_| ())?
        }
        Input::Seed {
            installation,
            realm,
            key_id,
            key,
            indices,
        } => {
            let bytes = Zeroizing::new(STANDARD.decode(key.0.as_bytes()).map_err(|_| ())?);
            if bytes.len() != 32
                || indices.is_empty()
                || indices.len() > 420
                || indices.iter().any(|i| !(1..=420).contains(i))
                || indices.iter().collect::<BTreeSet<_>>().len() != indices.len()
            {
                return Err(());
            }
            let mut sql = format!(
                "BEGIN; INSERT INTO bloc.realm(id,name,created_at,updated_at) VALUES('{realm}','Capacity realm',clock_timestamp(),clock_timestamp()); UPDATE bloc.realm_authentication_settings SET mfa_mode='required',mfa_allowed_methods=ARRAY['totp'],mfa_preferred_method='totp',mfa_recovery_codes_enabled=false WHERE realm_id='{realm}';\n"
            );
            let mut actors = vec![];
            for index in indices {
                let user = user_id(index);
                let factor = factor_id()?;
                let secret = Zeroizing::new(random::<20>()?);
                let encrypted = envelope(
                    &bytes,
                    key_id,
                    installation,
                    realm,
                    user,
                    factor,
                    secret.as_slice(),
                )?;
                sql.push_str(&format!("INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES('{user}','{realm}','Capacity{index}@example.test',clock_timestamp(),clock_timestamp()); INSERT INTO bloc.realm_user_credential(realm_id,user_id,password_hash,credential_version,password_changed_at) SELECT '{realm}','{user}',password_hash,1,clock_timestamp() FROM bloc.installation_administrator; INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label) VALUES('{factor}','{realm}','{user}','totp','Capacity authenticator'); INSERT INTO bloc.mfa_encrypted_payload(id,realm_id,user_id,purpose,encryption_key_id,encrypted_payload) VALUES('{factor}','{realm}','{user}',1,'{key_id}',decode('{}','hex')); INSERT INTO bloc.realm_totp_factor(factor_id,realm_id,user_id,last_accepted_step) VALUES('{factor}','{realm}','{user}',-1);\n",hex(&encrypted)));
                actors.push(Actor {
                    index,
                    secret: STANDARD.encode(secret.as_slice()),
                });
            }
            sql.push_str("COMMIT;\n");
            serde_json::to_vec(&Seed { sql, actors }).map_err(|_| ())?
        }
    };
    Ok(Zeroizing::new(output))
}
fn parse_input(bytes: &[u8]) -> Result<Input, ()> {
    if bytes.len() > 1_048_576 {
        return Err(());
    }
    serde_json::from_slice(bytes).map_err(|_| ())
}
fn run() -> Result<(), ()> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    let input = parse_input(&bytes)?;
    let output = respond(input)?;
    if output.len() > 1_048_576 {
        return Err(());
    }
    std::io::stdout().write_all(&output).map_err(|_| ())?;
    Ok(())
}
fn main() {
    if std::env::args_os().len() != 1 || run().is_err() {
        eprintln!("synthetic MFA fixture request refused");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc_6238_maintained_generator() {
        assert_eq!(otp(b"12345678901234567890", 59).unwrap(), "287082");
        assert!(otp(b"short", 59).is_err());
    }
    #[test]
    fn owner_bound_random_nonce() {
        let ids = [
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            Uuid::from_bytes([3; 16]),
            Uuid::from_bytes([4; 16]),
            Uuid::from_bytes([5; 16]),
        ];
        let a = envelope(&[7; 32], ids[0], ids[1], ids[2], ids[3], ids[4], &[9; 20]).unwrap();
        let b = envelope(&[7; 32], ids[0], ids[1], ids[2], ids[3], ids[4], &[9; 20]).unwrap();
        assert_ne!(a, b);
        assert_eq!(&a[..6], b"BMFA\x01\x01");
        assert_eq!(a.len(), 82);
        let mut aad = a[..46].to_vec();
        for id in &ids[1..4] {
            aad.extend_from_slice(id.as_bytes());
        }
        aad.push(1);
        aad.extend_from_slice(ids[4].as_bytes());
        aad.extend_from_slice(&1u16.to_be_bytes());
        let cipher = XChaCha20Poly1305::new_from_slice(&[7; 32]).unwrap();
        assert_eq!(
            cipher
                .decrypt(
                    &XNonce::try_from(&a[22..46]).unwrap(),
                    Payload {
                        msg: &a[46..],
                        aad: &aad
                    }
                )
                .unwrap(),
            vec![9; 20]
        );
        aad[46] ^= 1;
        assert!(
            cipher
                .decrypt(
                    &XNonce::try_from(&a[22..46]).unwrap(),
                    Payload {
                        msg: &a[46..],
                        aad: &aad
                    }
                )
                .is_err()
        );
    }
    #[test]
    fn complete_420_actor_seed_is_bounded_and_unique() {
        let output = respond(Input::Seed {
            installation: Uuid::nil(),
            realm: Uuid::nil(),
            key_id: Uuid::nil(),
            key: STANDARD.encode([7; 32]).into(),
            indices: (1..=420).collect(),
        })
        .unwrap();
        assert!(output.len() < 1_048_576);
        let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let actors = parsed["actors"].as_array().unwrap();
        assert_eq!(actors.len(), 420);
        let secrets: BTreeSet<_> = actors
            .iter()
            .map(|a| a["secret"].as_str().unwrap())
            .collect();
        assert_eq!(secrets.len(), 420);
        assert!(actors.iter().all(|a| {
            STANDARD
                .decode(a["secret"].as_str().unwrap())
                .unwrap()
                .len()
                == 20
        }));
        assert_eq!(
            parsed["sql"]
                .as_str()
                .unwrap()
                .matches("INSERT INTO bloc.realm_totp_factor")
                .count(),
            420
        );
        assert!(parse_input(&vec![b' '; 1_048_577]).is_err());
    }
    #[test]
    fn strict_seed_bounds() {
        for indices in [vec![], vec![1, 1], vec![421], (1..=421).collect()] {
            assert!(
                respond(Input::Seed {
                    installation: Uuid::nil(),
                    realm: Uuid::nil(),
                    key_id: Uuid::nil(),
                    key: STANDARD.encode([7; 32]).into(),
                    indices
                })
                .is_err()
            );
        }
        assert!(
            serde_json::from_str::<Input>(
                r#"{"operation":"otp","secret":"x","now":59,"unexpected":true}"#
            )
            .is_err()
        );
    }
}
