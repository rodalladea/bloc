//! Exact-version WebAuthn adapter. Flow ownership, admission and consumption stay in storage.
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use webauthn_rs::prelude::*;

const STATE_LIMIT: usize = 32768;
const RECORD_LIMIT: usize = 16384;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Stored,
    Proof,
    Stale,
}
pub(crate) struct CeremonyStart {
    pub options: Value,
    pub state: Vec<u8>,
}
pub(crate) struct Registered {
    pub credential_id: Vec<u8>,
    pub public_record: Vec<u8>,
    pub transports: Vec<String>,
}
pub(crate) struct Authenticated {
    pub credential_id: Vec<u8>,
    pub original_record: Vec<u8>,
    pub updated_record: Vec<u8>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    format_version: u8,
    library: String,
    library_version: String,
    kind: String,
    payload: T,
}
fn pack<T: Serialize>(kind: &str, payload: T, limit: usize) -> Result<Vec<u8>, Failure> {
    let bytes = serde_json::to_vec(&Record {
        format_version: 1,
        library: "webauthn-rs".into(),
        library_version: "0.6.2".into(),
        kind: kind.into(),
        payload,
    })
    .map_err(|_| Failure::Stored)?;
    if bytes.len() > limit {
        return Err(Failure::Stored);
    }
    Ok(bytes)
}
fn unpack<T: DeserializeOwned>(kind: &str, bytes: &[u8], limit: usize) -> Result<T, Failure> {
    if bytes.len() > limit {
        return Err(Failure::Stored);
    }
    let record: Record<T> = serde_json::from_slice(bytes).map_err(|_| Failure::Stored)?;
    if record.format_version != 1
        || record.library != "webauthn-rs"
        || record.library_version != "0.6.2"
        || record.kind != kind
    {
        return Err(Failure::Stored);
    }
    Ok(record.payload)
}
pub(crate) fn origin_supported(origin: &str) -> bool {
    verifier(origin).is_ok()
}

fn verifier(origin: &str) -> Result<Webauthn, Failure> {
    let url = Url::parse(origin).map_err(|_| Failure::Stored)?;
    if url.scheme() != "https" || url.origin().ascii_serialization() != origin {
        return Err(Failure::Stored);
    }
    let host = url.host_str().ok_or(Failure::Stored)?;
    WebauthnBuilder::new(host, &url)
        .map_err(|_| Failure::Stored)?
        .rp_name("bloc")
        .allow_subdomains(false)
        .allow_any_port(false)
        .build()
        .map_err(|_| Failure::Stored)
}
fn valid_ids(ids: &[Vec<u8>]) -> bool {
    ids.len() <= 10 && ids.iter().all(|id| (1..=1024).contains(&id.len()))
}
fn response<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Failure> {
    if bytes.len() > 65536 {
        return Err(Failure::Proof);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Failure::Proof)?;
    fn bounded(value: &Value, depth: usize) -> bool {
        match value {
            Value::Array(values) => depth < 16 && values.iter().all(|v| bounded(v, depth + 1)),
            Value::Object(values) => depth < 16 && values.values().all(|v| bounded(v, depth + 1)),
            _ => true,
        }
    }
    if !bounded(&value, 0) {
        return Err(Failure::Proof);
    }
    serde_json::from_value(value).map_err(|_| Failure::Proof)
}
fn keys(records: &[Vec<u8>]) -> Result<Vec<Passkey>, Failure> {
    if records.is_empty() || records.len() > 10 {
        return Err(Failure::Stored);
    }
    let keys: Vec<Passkey> = records
        .iter()
        .map(|record| unpack("credential", record, RECORD_LIMIT))
        .collect::<Result<_, _>>()?;
    for (i, key) in keys.iter().enumerate() {
        if !(1..=1024).contains(&key.cred_id().len())
            || keys[..i]
                .iter()
                .any(|other| other.cred_id() == key.cred_id())
        {
            return Err(Failure::Stored);
        }
    }
    Ok(keys)
}
fn owner_handle(provided: Option<&[u8]>, expected: &[u8; 32]) -> Result<(), Failure> {
    if provided.is_some_and(|handle| handle != expected) {
        return Err(Failure::Proof);
    }
    Ok(())
}
pub(crate) fn register_start(
    origin: &str,
    handle: &[u8; 32],
    exclude_ids: &[Vec<u8>],
) -> Result<CeremonyStart, Failure> {
    if !valid_ids(exclude_ids) {
        return Err(Failure::Stored);
    }
    let id = Uuid::from_slice(&handle[..16]).map_err(|_| Failure::Stored)?;
    let (mut options, state) = verifier(origin)?
        .start_passkey_registration(
            id,
            "bloc account",
            "bloc account",
            Some(exclude_ids.to_vec()),
        )
        .map_err(|_| Failure::Stored)?;
    // 0.6.2 persists no user handle in RegistrationState; bind the full opaque handle in options.
    options.public_key.user.id = handle.to_vec();
    Ok(CeremonyStart {
        options: serde_json::to_value(options).map_err(|_| Failure::Stored)?,
        state: pack("registration", state, STATE_LIMIT)?,
    })
}
pub(crate) fn register_finish(
    origin: &str,
    state: &[u8],
    bytes: &[u8],
) -> Result<Registered, Failure> {
    let state: PasskeyRegistration = unpack("registration", state, STATE_LIMIT)?;
    let proof: RegisterPublicKeyCredential = response(bytes)?;
    if proof.type_ != "public-key" || !(1..=1024).contains(&proof.raw_id.len()) {
        return Err(Failure::Proof);
    }
    let key = verifier(origin)?
        .finish_passkey_registration(&proof, &state)
        .map_err(|_| Failure::Proof)?;
    let credential_id = key.cred_id().to_vec();
    if !(1..=1024).contains(&credential_id.len()) || credential_id != proof.raw_id {
        return Err(Failure::Proof);
    }
    let transports = proof
        .response
        .transports
        .unwrap_or_default()
        .into_iter()
        .filter_map(|t| serde_json::to_value(t).ok()?.as_str().map(str::to_owned))
        .filter(|s| s != "unknown")
        .collect();
    Ok(Registered {
        credential_id,
        public_record: pack("credential", key, RECORD_LIMIT)?,
        transports,
    })
}
pub(crate) fn authentication_start(
    origin: &str,
    records: &[Vec<u8>],
) -> Result<CeremonyStart, Failure> {
    let keys = keys(records)?;
    let (options, state) = verifier(origin)?
        .start_passkey_authentication(&keys)
        .map_err(|_| Failure::Stored)?;
    Ok(CeremonyStart {
        options: serde_json::to_value(options).map_err(|_| Failure::Stored)?,
        state: pack("authentication", state, STATE_LIMIT)?,
    })
}
pub(crate) fn authentication_finish(
    origin: &str,
    state: &[u8],
    bytes: &[u8],
    expected_handle: &[u8; 32],
    records: &[Vec<u8>],
) -> Result<Authenticated, Failure> {
    let state: PasskeyAuthentication = unpack("authentication", state, STATE_LIMIT)?;
    let proof: PublicKeyCredential = response(bytes)?;
    if proof.type_ != "public-key" || !(1..=1024).contains(&proof.raw_id.len()) {
        return Err(Failure::Proof);
    }
    owner_handle(proof.get_user_unique_id(), expected_handle)?;
    let keys = keys(records)?;
    let index = keys
        .iter()
        .position(|key| key.cred_id() == proof.get_credential_id())
        .ok_or(Failure::Proof)?;
    let mut key = keys[index].clone();
    let state_value = serde_json::to_value(&state).map_err(|_| Failure::Stored)?;
    let key_value = serde_json::to_value(&key).map_err(|_| Failure::Stored)?;
    if !state_value["ast"]["credentials"]
        .as_array()
        .ok_or(Failure::Stored)?
        .iter()
        .any(|credential| credential == &key_value["cred"])
    {
        return Err(Failure::Stale);
    }
    let result = verifier(origin)?
        .finish_passkey_authentication(&proof, &state)
        .map_err(|_| Failure::Proof)?;
    if !result.user_verified() || key.update_credential(&result).is_none() {
        return Err(Failure::Proof);
    }
    Ok(Authenticated {
        credential_id: result.cred_id().to_vec(),
        original_record: records[index].clone(),
        updated_record: pack("credential", key, RECORD_LIMIT)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passkey_origin_requires_a_domain() {
        assert!(origin_supported("https://bloc.example.test:4443"));
        assert!(!origin_supported("https://203.0.113.10"));
        assert!(!origin_supported("https://[2001:db8::1]"));
    }
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};

    fn synthetic_record(id: u8, counter: u32) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "format_version":1,"library":"webauthn-rs","library_version":"0.6.2","kind":"credential",
            "payload":{"cred":{
                "cred_id":URL_SAFE_NO_PAD.encode([id;32]),
                "cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":vec![1;32],"y":vec![2;32]}}},
                "counter":counter,"transports":["internal"],"user_verified":true,
                "backup_eligible":true,"backup_state":true,"registration_policy":"required",
                "extensions":{},"attestation":{"data":"None","metadata":"None"},"attestation_format":"none"
            }}
        })).unwrap()
    }

    #[test]
    fn webauthn_full_owner_handle_contract() {
        assert_eq!(owner_handle(None, &[1; 32]), Ok(()));
        assert_eq!(owner_handle(Some(&[1; 32]), &[1; 32]), Ok(()));
        assert_eq!(owner_handle(Some(&[1; 16]), &[1; 32]), Err(Failure::Proof));
        let mut other = [1; 32];
        other[31] = 2;
        assert_eq!(owner_handle(Some(&other), &[1; 32]), Err(Failure::Proof));
    }

    #[test]
    fn webauthn_authentication_snapshot_contract() {
        let origin = "https://bloc.example.test:4443";
        let records: Vec<Vec<u8>> = (1..=10).map(|id| synthetic_record(id, 0)).collect();
        let start = authentication_start(origin, &records).unwrap();
        assert_eq!(start.options["publicKey"]["rpId"], "bloc.example.test");
        assert_eq!(start.options["publicKey"]["userVerification"], "required");
        assert_eq!(
            start.options["publicKey"]["allowCredentials"]
                .as_array()
                .unwrap()
                .len(),
            10
        );
        let stored: Value = serde_json::from_slice(&start.state).unwrap();
        assert_eq!(stored["kind"], "authentication");
        assert_eq!(stored["payload"]["ast"]["policy"], "required");
        assert_eq!(
            stored["payload"]["ast"]["credentials"]
                .as_array()
                .unwrap()
                .len(),
            10
        );
        assert!(authentication_start(origin, &vec![records[0].clone(); 2]).is_err());
        assert!(authentication_start(origin, &vec![records[0].clone(); 11]).is_err());
        assert!(authentication_start(origin, &[vec![b' '; 16385]]).is_err());
        let proof = serde_json::to_vec(&json!({
            "id":URL_SAFE_NO_PAD.encode([1;32]),"rawId":URL_SAFE_NO_PAD.encode([1;32]),"type":"public-key",
            "response":{"authenticatorData":"AQ","clientDataJSON":"AQ","signature":"AQ","userHandle":URL_SAFE_NO_PAD.encode([1;32])}
        })).unwrap();
        assert!(matches!(
            authentication_finish(
                origin,
                &start.state,
                &proof,
                &[1; 32],
                &[synthetic_record(1, 1)]
            ),
            Err(Failure::Stale)
        ));
        assert!(matches!(
            authentication_finish(
                origin,
                &start.state,
                &proof,
                &[1; 32],
                &[synthetic_record(2, 0)]
            ),
            Err(Failure::Proof)
        ));
        assert!(matches!(
            authentication_finish(origin, &start.state, &proof, &[2; 32], &records),
            Err(Failure::Proof)
        ));
        assert!(matches!(
            authentication_finish(origin, &start.state, &proof, &[1; 32], &records),
            Err(Failure::Proof)
        ));
    }

    #[test]
    fn webauthn_registration_options_contract() {
        let handle = [37; 32];
        let start =
            register_start("https://bloc.example.test:4443", &handle, &[vec![4; 32]]).unwrap();
        assert_eq!(start.options["publicKey"]["rp"]["id"], "bloc.example.test");
        assert_eq!(
            start.options["publicKey"]["user"]["id"],
            URL_SAFE_NO_PAD.encode(handle)
        );
        assert_eq!(
            start.options["publicKey"]["authenticatorSelection"]["userVerification"],
            "required"
        );
        assert_eq!(start.options["publicKey"]["attestation"], "none");
        assert_eq!(
            start.options["publicKey"]["excludeCredentials"][0]["id"],
            URL_SAFE_NO_PAD.encode([4; 32])
        );
        let stored: Value = serde_json::from_slice(&start.state).unwrap();
        assert_eq!(stored["format_version"], 1);
        assert_eq!(stored["library"], "webauthn-rs");
        assert_eq!(stored["library_version"], "0.6.2");
        assert_eq!(stored["kind"], "registration");
        assert_eq!(stored["payload"]["rs"]["policy"], "required");
        assert!(start.options.get("payload").is_none());
        let next = register_start("https://bloc.example.test:4443", &handle, &[]).unwrap();
        assert_ne!(
            start.options["publicKey"]["challenge"],
            next.options["publicKey"]["challenge"]
        );
    }

    #[test]
    fn webauthn_origin_and_collection_contract() {
        for origin in [
            "http://bloc.example.test",
            "https://bloc.example.test/path",
            "https://user@bloc.example.test",
            "https://bloc.example.test?x=1",
            "https://bloc.example.test#x",
        ] {
            assert!(register_start(origin, &[1; 32], &[]).is_err(), "{origin}");
        }
        assert!(register_start("https://bloc.example.test", &[1; 32], &[vec![1; 1025]]).is_err());
        assert!(
            register_start(
                "https://bloc.example.test",
                &[1; 32],
                &vec![vec![1; 32]; 11]
            )
            .is_err()
        );
        assert!(authentication_start("https://bloc.example.test", &[]).is_err());
    }

    #[test]
    fn webauthn_persisted_format_contract() {
        let start = register_start("https://bloc.example.test", &[1; 32], &[]).unwrap();
        let value: Value = serde_json::from_slice(&start.state).unwrap();
        for (key, wrong) in [
            ("format_version", json!(2)),
            ("library", json!("other")),
            ("library_version", json!("0.6.1")),
            ("kind", json!("authentication")),
            ("unknown", json!(true)),
        ] {
            let mut invalid = value.clone();
            invalid[key] = wrong;
            assert!(matches!(
                register_finish(
                    "https://bloc.example.test",
                    &serde_json::to_vec(&invalid).unwrap(),
                    b"{}"
                ),
                Err(Failure::Stored)
            ));
        }
        assert!(matches!(
            register_finish("https://bloc.example.test", &vec![b' '; 32769], b"{}"),
            Err(Failure::Stored)
        ));
        assert!(matches!(
            register_finish("https://bloc.example.test", &start.state, b"{}"),
            Err(Failure::Proof)
        ));
        assert!(matches!(
            register_finish(
                "https://bloc.example.test",
                &start.state,
                &vec![b' '; 65537]
            ),
            Err(Failure::Proof)
        ));
    }

    #[test]
    fn webauthn_browser_json_depth_contract() {
        let start = register_start("https://bloc.example.test", &[1; 32], &[]).unwrap();
        let mut response = json!({"id":"AQ", "rawId":"AQ", "type":"public-key", "response":{"attestationObject":"AQ", "clientDataJSON":"AQ"}});
        let mut nested = json!(0);
        for _ in 0..17 {
            nested = json!([nested]);
        }
        response["extra"] = nested;
        assert!(matches!(
            register_finish(
                "https://bloc.example.test",
                &start.state,
                &serde_json::to_vec(&response).unwrap()
            ),
            Err(Failure::Proof)
        ));
    }
}
