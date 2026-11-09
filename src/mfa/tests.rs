use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

fn ring() -> Keyring {
    Keyring::parse(format!(r#"{{"format_version":1,"keys":[{{"id":"00000000-0000-4000-8000-000000000001","key":"{}"}}]}}"#, STANDARD.encode([7;32])).as_bytes()).unwrap()
}
fn owner() -> Binding {
    Binding {
        installation: [1; 16],
        realm: [2; 16],
        user: [3; 16],
        record: [4; 16],
        purpose: Purpose::ActiveTotp,
        payload_version: 1,
    }
}
#[test]
fn mfa_keyring_contract() {
    let r = ring();
    assert_eq!(r.ids().count(), 1);
    let valid = format!(
        r#"{{"format_version":1,"keys":[{{"id":"00000000-0000-4000-8000-000000000001","key":"{}"}}]}}"#,
        STANDARD.encode([7; 32])
    );
    for invalid in [
        "{}".to_owned(),
        valid.replace("version\":1", "version\":2"),
        valid.replace("\"keys\"", "\"extra\":1,\"keys\""),
        valid.replace(&STANDARD.encode([7; 32]), "AAAA"),
        valid.replace(
            &STANDARD.encode([7; 32]),
            STANDARD.encode([7; 32]).trim_end_matches('='),
        ),
        " ".repeat(16385),
    ] {
        assert!(Keyring::parse(invalid.as_bytes()).is_err());
    }
    assert!(Keyring::parse(br#"{"format_version":1,"keys":[]}"#).is_err());
    let mut invalid_utf8 = valid.as_bytes().to_vec();
    let key_offset = valid.find(&STANDARD.encode([7; 32])).unwrap();
    invalid_utf8[key_offset] = 0xff;
    assert!(Keyring::parse(&invalid_utf8).is_err());
    assert!(
        Keyring::parse(
            valid
                .replace("00000000-0000-4000-8000-000000000001", "invalid")
                .as_bytes()
        )
        .is_err()
    );
    assert!(Keyring::parse(valid.replace("\"key\"", "\"extra\":1,\"key\"").as_bytes()).is_err());
    let entry = |n| {
        format!(
            r#"{{"id":"00000000-0000-4000-8000-{n:012}","key":"{}"}}"#,
            STANDARD.encode([n as u8; 32])
        )
    };
    let sixteen = format!(
        r#"{{"format_version":1,"keys":[{}]}}"#,
        (1..=16).map(entry).collect::<Vec<_>>().join(",")
    );
    assert_eq!(
        Keyring::parse(sixteen.as_bytes()).unwrap().ids().count(),
        16
    );
    let seventeen = format!(
        r#"{{"format_version":1,"keys":[{}]}}"#,
        (1..=17).map(entry).collect::<Vec<_>>().join(",")
    );
    assert!(Keyring::parse(seventeen.as_bytes()).is_err());
    let same_id = format!(
        r#"{{"format_version":1,"keys":[{},{}]}}"#,
        entry(1),
        entry(2).replace("000000000002", "000000000001")
    );
    assert!(Keyring::parse(same_id.as_bytes()).is_err());
    let duplicate = format!(
        r#"{{"format_version":1,"keys":[{{"id":"00000000-0000-4000-8000-000000000001","key":"{0}"}},{{"id":"00000000-0000-4000-8000-000000000002","key":"{0}"}}]}}"#,
        STANDARD.encode([7; 32])
    );
    assert!(Keyring::parse(duplicate.as_bytes()).is_err());
}
#[test]
fn mfa_envelope_contract() {
    let r = ring();
    let id = *r.ids().next().unwrap();
    let b = owner();
    let value = r.encrypt(id, &b, &[9; 20]).unwrap();
    assert_eq!(&value[..6], b"BMFA\x01\x01");
    assert_eq!(value.len(), 82);
    assert_eq!(&*r.decrypt(&b, &value).unwrap(), &[9; 20]);
    assert_ne!(value, r.encrypt(id, &b, &[9; 20]).unwrap());
    for offset in 0..value.len() {
        let mut bad = value.clone();
        bad[offset] ^= 1;
        assert!(r.decrypt(&b, &bad).is_err(), "offset {offset}");
    }
    for field in 0..6 {
        let mut bad = owner();
        match field {
            0 => bad.installation[0] ^= 1,
            1 => bad.realm[0] ^= 1,
            2 => bad.user[0] ^= 1,
            3 => bad.record[0] ^= 1,
            4 => bad.purpose = Purpose::PendingTotp,
            _ => bad.payload_version = 2,
        };
        assert!(r.decrypt(&bad, &value).is_err());
    }
    assert!(r.decrypt(&b, &vec![0; 4097]).is_err());
    assert!(r.encrypt(id, &b, &[0; 19]).is_err());
    let mut handoff = owner();
    handoff.purpose = Purpose::RecoveryHandoff;
    let codes = vec!["AAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(); 10];
    let payload = encode_handoff(&codes).unwrap();
    assert_eq!(&*decode_handoff(&payload).unwrap(), &codes);
    assert!(encode_handoff(&codes[..9]).is_err());
    assert!(r.encrypt(id, &handoff, &payload).is_ok());
}
