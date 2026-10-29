//! Ingress authority and strict, bounded form decoding.
use crate::config::Config;
use axum::http::{HeaderMap, StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};
pub fn one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(first)
    }
}
pub fn source(
    config: &Config,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> Result<IpAddr, StatusCode> {
    if !config.trusts(peer.ip()) {
        return Err(StatusCode::FORBIDDEN);
    }
    if !one(headers, "host").is_some_and(|host| {
        !host.contains(['/', '?', '#', '@', '%'])
            && authority_url(&format!("https://{host}"), false)
                .is_some_and(|url| url.origin().ascii_serialization() == config.origin)
    }) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if one(headers, "x-forwarded-proto") != Some("https") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let source = one(headers, "x-forwarded-for").ok_or(StatusCode::BAD_REQUEST)?;
    if source.trim() != source {
        return Err(StatusCode::BAD_REQUEST);
    }
    source.parse().map_err(|_| StatusCode::BAD_REQUEST)
}
/// Reject lossy URL preprocessing before comparing the parsed HTTPS authority.
pub(crate) fn authority_url(value: &str, referer: bool) -> Option<url::Url> {
    if value
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        return None;
    }
    let (_, rest) = value.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if (!referer && !matches!(&rest[authority.len()..], "" | "/"))
        || authority.is_empty()
        || authority.contains(['@', '%'])
        || authority.ends_with(':')
    {
        return None;
    }
    let parsed = url::Url::parse(value).ok()?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || (!referer && (parsed.path() != "/" || parsed.query().is_some()))
    {
        return None;
    }
    Some(parsed)
}
pub fn origin(config: &Config, headers: &HeaderMap) -> bool {
    let (name, referer) = if headers.contains_key("origin") {
        ("origin", false)
    } else {
        ("referer", true)
    };
    one(headers, name)
        .and_then(|value| authority_url(value, referer))
        .is_some_and(|url| url.origin().ascii_serialization() == config.origin)
}
pub(crate) fn native_origin(headers: &HeaderMap) -> bool {
    // no-referrer serializes native form Origin as null. Fetch Metadata is
    // browser-controlled; canonical HTTPS ingress and CSRF remain mandatory.
    one(headers, "origin") == Some("null")
        && one(headers, "sec-fetch-site") == Some("same-origin")
        && one(headers, "sec-fetch-mode") == Some("navigate")
        && one(headers, "sec-fetch-dest") == Some("document")
}
pub fn random() -> Result<[u8; 32], StatusCode> {
    let mut value = [0u8; 32];
    getrandom::fill(&mut value).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(value)
}
pub fn encode(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}
pub fn decode(value: &str) -> Option<[u8; 32]> {
    if value.len() != 43 {
        return None;
    }
    let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()?;
    if encode(&bytes) != value {
        return None;
    }
    Some(bytes)
}
pub fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
pub fn keyed(config: &Config, purpose: &str, value: &str) -> Result<[u8; 32], StatusCode> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&config.abuse_key)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    mac.update(purpose.as_bytes());
    mac.update(&[0]);
    mac.update(value.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    for header in headers.get_all("cookie") {
        for part in header.to_str().ok()?.split(';') {
            let (key, value) = part.trim().split_once('=')?;
            if key == name {
                if found.is_some() || decode(value).is_none() {
                    return None;
                }
                found = Some(value.to_owned())
            }
        }
    }
    found
}
pub fn form(bytes: &[u8]) -> Result<BTreeMap<String, String>, StatusCode> {
    let fields = form_fields(bytes)?;
    if fields.keys().any(|key| {
        !matches!(
            key.as_str(),
            "csrf" | "email" | "code" | "password" | "password_confirmation" | "current_password"
        )
    }) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(fields)
}
/// Decode a bounded form, rejecting malformed encoding and duplicate fields.
/// Each caller must apply its own declared field allowlist after request protection.
pub(crate) fn form_fields(bytes: &[u8]) -> Result<BTreeMap<String, String>, StatusCode> {
    if bytes.len() > 16384 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(StatusCode::BAD_REQUEST);
            }
            i += 2;
        }
        i += 1;
    }
    let text = std::str::from_utf8(bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut result = BTreeMap::new();
    for pair in text.split('&') {
        let (key, value) = pair.split_once('=').ok_or(StatusCode::BAD_REQUEST)?;
        let decode_part = |s: &str| -> Result<String, StatusCode> {
            let mut out = Vec::new();
            let s = s.as_bytes();
            let mut i = 0;
            while i < s.len() {
                match s[i] {
                    b'+' => out.push(b' '),
                    b'%' => {
                        let h = std::str::from_utf8(&s[i + 1..i + 3])
                            .map_err(|_| StatusCode::BAD_REQUEST)?;
                        out.push(u8::from_str_radix(h, 16).map_err(|_| StatusCode::BAD_REQUEST)?);
                        i += 2
                    }
                    c => out.push(c),
                }
                i += 1;
            }
            String::from_utf8(out).map_err(|_| StatusCode::BAD_REQUEST)
        };
        let key = decode_part(key)?;
        let value = decode_part(value)?;
        if result.insert(key, value).is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    Ok(result)
}
