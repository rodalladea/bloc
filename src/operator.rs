//! Attached operator commands. Secret output is emitted only after database commit.

use crate::storage::{Error, Storage};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, Read, Write},
    path::PathBuf,
};

const HELP: &str = "Usage: bloc [--help | database migrate | admin setup-code | admin recovery-code | admin invalidate-access | database maintain]\n";

fn configuration() -> Result<(String, PathBuf), Error> {
    let url_file = env::var_os("BLOC_DATABASE_URL_FILE").ok_or(Error::Configuration)?;
    let ca = PathBuf::from(env::var_os("BLOC_DATABASE_CA_FILE").ok_or(Error::Configuration)?);
    let mut bytes = Vec::new();
    fs::File::open(url_file)
        .map_err(|_| Error::Configuration)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Configuration)?;
    if bytes.len() > 16 * 1024 {
        return Err(Error::Configuration);
    }
    let url = String::from_utf8(bytes).map_err(|_| Error::Configuration)?;
    Ok((url.trim().to_owned(), ca))
}

/// None selects the existing scaffold. Commands return stable, redacted exit codes.
pub async fn dispatch(args: Vec<String>) -> Option<i32> {
    if args.is_empty() {
        return None;
    }
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    if words == ["--help"] || words == ["-h"] {
        return Some(if io::stdout().write_all(HELP.as_bytes()).is_ok() {
            0
        } else {
            1
        });
    }
    let operation = match words.as_slice() {
        ["database", "migrate"] => "migrate",
        ["database", "maintain"] => "maintain",
        ["admin", "setup-code"] => "setup",
        ["admin", "recovery-code"] => "recovery",
        ["admin", "invalidate-access"] => "invalidate",
        _ => {
            eprintln!("bloc: usage error; use --help");
            return Some(2);
        }
    };
    let result = run(operation).await;
    Some(match result {
        Ok(code) => code,
        Err(Error::Configuration) => {
            eprintln!("bloc: invalid database configuration");
            2
        }
        Err(_) => {
            eprintln!("bloc: database operation unavailable");
            1
        }
    })
}

async fn run(operation: &str) -> Result<i32, Error> {
    let (url, ca) = configuration()?;
    let storage = Storage::connect(&url, &ca).await?;
    if operation == "migrate" {
        storage.migrate().await?;
        return Ok(0);
    }
    if operation == "maintain" {
        storage.maintain_access().await?;
        return Ok(0);
    }
    if operation == "invalidate" {
        storage.invalidate_access().await?;
        return Ok(0);
    }
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
    let code = URL_SAFE_NO_PAD.encode(bytes);
    let digest: [u8; 32] = Sha256::digest(code.as_bytes()).into();
    let expiry = if operation == "recovery" {
        storage.issue_recovery_code(&digest).await?
    } else {
        storage.issue_setup_code(&digest).await?
    };
    let Some(expiry) = expiry else {
        eprintln!(
            "bloc: {}",
            if operation == "setup" {
                "setup is closed"
            } else {
                "recovery requires an administrator"
            }
        );
        return Ok(3);
    };
    let output = format!("code={code}\nexpires_at={expiry}\n");
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(output.as_bytes())
        .map_err(|_| Error::Unavailable)?;
    stdout.flush().map_err(|_| Error::Unavailable)?;
    Ok(0)
}
