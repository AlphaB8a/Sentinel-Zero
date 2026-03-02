use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
};

use crate::receipt::sha256_hex;
use crate::verify::VerifyOutcome;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditPayload {
    ts: String,
    status: String,
    plan_id: String,
    resolved_sha256: String,
    preflight_sha256: String,
    key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditEntry {
    seq: u64,
    prev_hash: String,
    entry_hash: String,
    payload: AuditPayload,
}

pub fn append_success_event(path: &Path, outcome: &VerifyOutcome) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create audit dir {}", parent.display()))?;
    }
    verify_chain(path)?;

    let (seq, prev_hash) = read_tail(path)?;
    let payload = AuditPayload {
        ts: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        status: "ok".to_string(),
        plan_id: outcome.plan_id.clone(),
        resolved_sha256: outcome.resolved_sha256.clone(),
        preflight_sha256: outcome.preflight_sha256.clone(),
        key_id: outcome.key_id.clone(),
    };
    let entry_hash = hash_entry(seq + 1, &prev_hash, &payload)?;
    let entry = AuditEntry {
        seq: seq + 1,
        prev_hash,
        entry_hash,
        payload,
    };

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open audit chain {}", path.display()))?;
    writeln!(f, "{}", serde_json::to_string(&entry)?)
        .with_context(|| format!("append audit chain {}", path.display()))?;
    Ok(())
}

pub fn verify_chain(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let f = fs::File::open(path).with_context(|| format!("open audit chain {}", path.display()))?;
    let reader = BufReader::new(f);
    let mut prev = genesis_hash();
    let mut expected_seq = 1u64;
    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read audit chain line {}", idx + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .with_context(|| format!("parse audit chain line {}", idx + 1))?;
        if entry.seq != expected_seq {
            bail!(
                "audit chain sequence mismatch at line {}: expected {}, got {}",
                idx + 1,
                expected_seq,
                entry.seq
            );
        }
        if entry.prev_hash != prev {
            bail!(
                "audit chain prev_hash mismatch at line {}: expected {}, got {}",
                idx + 1,
                prev,
                entry.prev_hash
            );
        }
        let computed = hash_entry(entry.seq, &entry.prev_hash, &entry.payload)?;
        if entry.entry_hash != computed {
            bail!("audit chain hash mismatch at line {}", idx + 1);
        }
        prev = entry.entry_hash;
        expected_seq += 1;
    }
    Ok(())
}

fn read_tail(path: &Path) -> Result<(u64, String)> {
    if !path.exists() {
        return Ok((0, genesis_hash()));
    }
    let f = fs::File::open(path).with_context(|| format!("open audit chain {}", path.display()))?;
    let reader = BufReader::new(f);
    let mut last: Option<AuditEntry> = None;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        last = Some(serde_json::from_str::<AuditEntry>(&line)?);
    }
    if let Some(last) = last {
        Ok((last.seq, last.entry_hash))
    } else {
        Ok((0, genesis_hash()))
    }
}

fn hash_entry(seq: u64, prev_hash: &str, payload: &AuditPayload) -> Result<String> {
    let canonical = serde_json::to_vec(&(seq, prev_hash, payload))?;
    Ok(sha256_hex(&canonical))
}

fn genesis_hash() -> String {
    "0".repeat(64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn audit_chain_detects_tampering() {
        let tmp = tempdir().expect("tempdir");
        let p = tmp.path().join("audit.ndjson");
        let out = VerifyOutcome {
            plan_id: "plan1".to_string(),
            resolved_sha256: "a".repeat(64),
            preflight_sha256: "b".repeat(64),
            key_id: "k1".to_string(),
            receipt_path: tmp.path().join("r.json"),
            trust_root_path: tmp.path().join("t.json"),
            audit_path: p.clone(),
        };
        append_success_event(&p, &out).expect("append");
        append_success_event(&p, &out).expect("append2");
        let content = fs::read_to_string(&p).expect("read chain");
        let tampered = content.replacen("\"status\":\"ok\"", "\"status\":\"tampered\"", 1);
        fs::write(&p, tampered).expect("write tampered");
        let err = verify_chain(&p).expect_err("must detect tamper");
        assert!(err.to_string().contains("hash mismatch"));
    }
}
