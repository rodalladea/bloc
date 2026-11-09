use super::*;
use std::{
    env,
    io::{self, Write},
    path::PathBuf,
};

pub(crate) async fn dispatch(words: &[&str]) -> i32 {
    match run(words).await {
        Ok(code) => code,
        Err(code) => {
            eprintln!("bloc: MFA key operation unavailable or invalid");
            code
        }
    }
}
async fn run(words: &[&str]) -> Result<i32, i32> {
    if words.len() < 3 || words[0..2] != ["mfa", "keys"] {
        return Err(2);
    }
    let op = words[2];
    if !matches!(
        op,
        "initialize" | "status" | "stage" | "activate" | "reencrypt" | "retire"
    ) {
        return Err(2);
    }
    let mut options = BTreeMap::new();
    let mut index = 3;
    while index < words.len() {
        let name = words[index];
        let flag = matches!(
            name,
            "--confirm-replicas-restarted" | "--confirm-backup-escrow"
        );
        if !name.starts_with("--") || options.contains_key(name) {
            return Err(2);
        }
        let value = if flag {
            "true"
        } else {
            index += 1;
            words.get(index).copied().ok_or(2)?
        };
        options.insert(name, value);
        index += 1;
    }
    let allowed: &[&str] = match op {
        "status" => &[],
        "initialize" | "stage" => &["--key-id"],
        "activate" => &[
            "--key-id",
            "--expected-generation",
            "--confirm-replicas-restarted",
        ],
        "retire" => &[
            "--key-id",
            "--expected-generation",
            "--confirm-backup-escrow",
        ],
        _ => &["--from", "--batch-size"],
    };
    if options.keys().any(|k| !allowed.contains(k)) {
        return Err(2);
    }
    let id = if op == "status" {
        None
    } else {
        Some(
            *options
                .get(if op == "reencrypt" {
                    "--from"
                } else {
                    "--key-id"
                })
                .ok_or(2)?,
        )
    };
    if let Some(id) = id {
        Uuid::parse_str(id).map_err(|_| 2)?;
    }
    let generation = if matches!(op, "activate" | "retire") {
        let n = options
            .get("--expected-generation")
            .ok_or(2)?
            .parse::<i64>()
            .map_err(|_| 2)?;
        if n < 1 {
            return Err(2);
        }
        n
    } else {
        0
    };
    let confirmed = match op {
        "activate" => options.contains_key("--confirm-replicas-restarted"),
        "retire" => options.contains_key("--confirm-backup-escrow"),
        _ => true,
    };
    if !confirmed {
        return Err(2);
    }
    let batch = options
        .get("--batch-size")
        .map(|v| v.parse::<i32>())
        .transpose()
        .map_err(|_| 2)?
        .unwrap_or(100);
    if !(1..=100).contains(&batch) {
        return Err(2);
    }
    let (url, ca) = crate::operator::configuration().map_err(|_| 2)?;
    let storage = crate::storage::Storage::connect(&url, &ca)
        .await
        .map_err(|_| 1)?;
    let ring = if op == "status" {
        None
    } else {
        Some(
            Keyring::load(&PathBuf::from(
                env::var_os("BLOC_MFA_KEYRING_FILE").ok_or(2)?,
            ))
            .map_err(|_| 2)?,
        )
    };
    let mut output = String::new();
    if op == "status" {
        for row in storage.mfa_keys().await.map_err(|_| 1)? {
            output.push_str(&format!(
                "generation={} key_id={} state={} references={}\n",
                row.generation,
                row.id.as_deref().unwrap_or("none"),
                row.state.as_deref().unwrap_or("none"),
                row.references
            ));
        }
    } else {
        let ring = ring.as_ref().ok_or(2)?;
        let id = id.ok_or(2)?;
        if !ring.contains(Uuid::parse_str(id).map_err(|_| 2)?.as_bytes()) {
            return Err(2);
        }
        if op == "reencrypt" {
            let count = storage
                .mfa_reencrypt(id, batch, ring)
                .await
                .map_err(|_| 1)?;
            let remaining = storage
                .mfa_keys()
                .await
                .map_err(|_| 1)?
                .iter()
                .find(|r| r.id.as_deref() == Some(id))
                .map(|r| r.references)
                .unwrap_or(0);
            output = format!("converted={count}\nremaining={remaining}\n");
        } else {
            let result = storage
                .mfa_key_change(op, id, generation, confirmed)
                .await
                .map_err(|_| 1)?;
            if result != "ok" {
                return Ok(if result == "invalid" { 2 } else { 3 });
            }
        }
    }
    io::stdout().write_all(output.as_bytes()).map_err(|_| 1)?;
    Ok(0)
}
