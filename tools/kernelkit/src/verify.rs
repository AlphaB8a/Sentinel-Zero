use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::audit;
use crate::plan::{Plan as KKPlan, PromotionReceipt, TrustRoot};
use crate::receipt::{read_json_file, sha256_hex, verify_receipt_signature, SENTINEL_ONLY_SCOPE};

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub receipt_path: Option<PathBuf>,
    pub trust_root_path: Option<PathBuf>,
    pub audit_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub plan_id: String,
    pub resolved_sha256: String,
    pub preflight_sha256: String,
    pub key_id: String,
    pub receipt_path: PathBuf,
    pub trust_root_path: PathBuf,
    pub audit_path: PathBuf,
}

pub fn verify_apply_dir(apply_dir: &Path, options: &VerifyOptions) -> Result<VerifyOutcome> {
    if !apply_dir.exists() {
        bail!("verify: apply_dir does not exist: {}", apply_dir.display());
    }
    if !apply_dir.is_dir() {
        bail!(
            "verify: apply_dir must be a directory: {}",
            apply_dir.display()
        );
    }

    let preflight_path = apply_dir.join("preflight.json");
    let preflight_bytes = fs::read(&preflight_path)
        .with_context(|| format!("verify: missing preflight.json in {}", apply_dir.display()))?;
    let preflight_sha256 = sha256_hex(&preflight_bytes);

    let resolved_yaml_path = apply_dir.join("plan.resolved.yaml");
    let resolved_yaml = fs::read(&resolved_yaml_path).with_context(|| {
        format!(
            "verify: missing plan.resolved.yaml in {}",
            apply_dir.display()
        )
    })?;
    let resolved_sha256 = sha256_hex(&resolved_yaml);
    let recorded_sha = fs::read_to_string(apply_dir.join("resolved.sha256"))
        .with_context(|| format!("verify: missing resolved.sha256 in {}", apply_dir.display()))?;
    if recorded_sha.trim() != resolved_sha256 {
        bail!(
            "verify: resolved.sha256 mismatch: expected {}, got {}",
            resolved_sha256,
            recorded_sha.trim()
        );
    }

    let plan: KKPlan = serde_yaml::from_slice(&resolved_yaml)
        .context("verify: parse plan.resolved.yaml for plan_id")?;

    let receipt_path = options
        .receipt_path
        .clone()
        .unwrap_or_else(|| apply_dir.join("promotion.receipt.json"));
    let receipt: PromotionReceipt = read_json_file(&receipt_path, "promotion receipt")
        .with_context(|| {
            format!(
                "verify: expected signed receipt at {}",
                receipt_path.display()
            )
        })?;

    let trust_root_path = resolve_trust_root_path(apply_dir, options.trust_root_path.clone())?;
    let trust_root: TrustRoot =
        read_json_file(&trust_root_path, "trust root").with_context(|| {
            format!(
                "verify: expected trust root at {}",
                trust_root_path.display()
            )
        })?;

    verify_receipt_signature(&receipt, &trust_root)?;

    if receipt.scope != SENTINEL_ONLY_SCOPE {
        bail!(
            "verify: receipt scope must be {}, got {}",
            SENTINEL_ONLY_SCOPE,
            receipt.scope
        );
    }
    if receipt.payload.plan_id != plan.plan_id {
        bail!(
            "verify: receipt plan_id mismatch: expected {}, got {}",
            plan.plan_id,
            receipt.payload.plan_id
        );
    }
    if receipt.payload.resolved_sha256 != resolved_sha256 {
        bail!(
            "verify: receipt resolved_sha256 mismatch: expected {}, got {}",
            resolved_sha256,
            receipt.payload.resolved_sha256
        );
    }
    if receipt.payload.preflight_sha256 != preflight_sha256 {
        bail!(
            "verify: receipt preflight_sha256 mismatch: expected {}, got {}",
            preflight_sha256,
            receipt.payload.preflight_sha256
        );
    }

    let outcome = VerifyOutcome {
        plan_id: plan.plan_id,
        resolved_sha256,
        preflight_sha256,
        key_id: receipt.signature.key_id,
        receipt_path,
        trust_root_path,
        audit_path: resolve_audit_path(apply_dir, options.audit_path.clone())?,
    };

    write_verify_report(apply_dir, &outcome)?;
    audit::append_success_event(&outcome.audit_path, &outcome)?;
    Ok(outcome)
}

fn resolve_trust_root_path(apply_dir: &Path, override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path);
    }
    if let Ok(path) = std::env::var("SENTINEL_TRUST_ROOT_FILE") {
        return Ok(PathBuf::from(path));
    }
    let fallback = apply_dir.join("trust-root.json");
    if fallback.exists() {
        return Ok(fallback);
    }
    Err(anyhow!(
        "verify: missing trust-root.json and SENTINEL_TRUST_ROOT_FILE is not set"
    ))
}

fn resolve_audit_path(apply_dir: &Path, override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path);
    }
    if let Ok(path) = std::env::var("SENTINEL_AUDIT_CHAIN_FILE") {
        return Ok(PathBuf::from(path));
    }
    Ok(apply_dir.join("after/promotion_audit_chain.ndjson"))
}

fn write_verify_report(apply_dir: &Path, outcome: &VerifyOutcome) -> Result<()> {
    let after_dir = apply_dir.join("after");
    fs::create_dir_all(&after_dir)
        .with_context(|| format!("verify: create after dir {}", after_dir.display()))?;
    let report = json!({
        "status": "ok",
        "scope": SENTINEL_ONLY_SCOPE,
        "plan_id": outcome.plan_id,
        "resolved_sha256": outcome.resolved_sha256,
        "preflight_sha256": outcome.preflight_sha256,
        "key_id": outcome.key_id,
        "receipt_path": outcome.receipt_path,
        "trust_root_path": outcome.trust_root_path,
        "audit_path": outcome.audit_path,
    });
    fs::write(
        after_dir.join("verify.json"),
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("verify: write {}", after_dir.join("verify.json").display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use tempfile::tempdir;

    fn fixture_resolved_yaml(plan_id: &str) -> String {
        format!(
            "api_version: kernelkit.alpha.v0.1\nplan_id: {}\nprofile: immutable_operator\ncreated_ts: 1700000000\nauthor: test\ndescription: fixture\ntargets:\n  os_family: ubuntu\n  kernel_series: null\n  hardware_tags: []\npolicy:\n  apply_mode: propose_only\n  risk_level: low\n  require_tty_confirm: false\n  forbid_remote_apply: true\n  allowlist_only: true\nchanges:\n  kernel_cmdline:\n    enabled: false\n    fragment_path: /etc/kernel/cmdline.d/99-kernelkit.conf\n    require_reboot: false\n    params:\n      add: []\n      remove: []\n  sysctl:\n    enabled: false\n    file_path: /etc/sysctl.d/99-kernelkit.conf\n    set: {{}}\n  systemd:\n    enabled: false\n    dropins: []\n  udev:\n    enabled: false\n    rules_path: /etc/udev/rules.d/99-kernelkit.rules\n    rules: []\n  zram:\n    enabled: false\n    mode: systemd_zram_generator\n    config_path: /etc/systemd/zram-generator.conf\n    settings: {{}}\n  nvidia:\n    enabled: false\n    settings:\n      persistence_mode: null\n      power_limit_watts: null\n      compute_mode: null\nverification:\n  preflight_checks: []\n  postflight_checks: []\n  sentinel_emit: true\nrollback:\n  strategy: restore_previous\n  snapshot_paths: []\n",
            plan_id
        )
    }

    fn write_fixture_set(dir: &Path, plan_id: &str, tamper_receipt: bool) -> Result<()> {
        let resolved = fixture_resolved_yaml(plan_id);
        fs::write(dir.join("plan.resolved.yaml"), &resolved)?;
        fs::write(
            dir.join("resolved.sha256"),
            format!("{}\n", sha256_hex(resolved.as_bytes())),
        )?;

        let preflight = b"{\"fixture\":true}\n";
        fs::write(dir.join("preflight.json"), preflight)?;
        let preflight_hash = sha256_hex(preflight);
        let resolved_hash = sha256_hex(resolved.as_bytes());

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key_b64 = STANDARD.encode(signing_key.verifying_key().to_bytes());
        let mut payload = crate::plan::PromotionReceiptPayload {
            plan_id: plan_id.to_string(),
            resolved_sha256: resolved_hash.clone(),
            preflight_sha256: preflight_hash.clone(),
            issued_at: "2026-03-02T00:00:00Z".to_string(),
        };
        let msg = crate::receipt::canonical_payload_bytes(&payload)?;
        let sig = signing_key.sign(&msg);
        if tamper_receipt {
            payload.plan_id = "tampered".to_string();
        }
        let receipt = crate::plan::PromotionReceipt {
            version: crate::receipt::RECEIPT_VERSION.to_string(),
            scope: crate::receipt::SENTINEL_ONLY_SCOPE.to_string(),
            payload,
            signature: crate::plan::PromotionSignature {
                algorithm: crate::receipt::SIGNATURE_ALGORITHM.to_string(),
                key_id: "root-pass-fixture".to_string(),
                signature_b64: STANDARD.encode(sig.to_bytes()),
            },
        };
        fs::write(
            dir.join("promotion.receipt.json"),
            format!("{}\n", serde_json::to_string_pretty(&receipt)?),
        )?;

        let trust_root = crate::plan::TrustRoot {
            version: crate::receipt::TRUST_ROOT_VERSION.to_string(),
            scope: crate::receipt::SENTINEL_ONLY_SCOPE.to_string(),
            algorithm: crate::receipt::SIGNATURE_ALGORITHM.to_string(),
            keys: vec![crate::plan::TrustRootKey {
                key_id: "root-pass-fixture".to_string(),
                public_key_b64: verifying_key_b64,
                source: crate::plan::KeySource::Kms,
                rotation_epoch: 1,
                not_before: Some("2026-01-01T00:00:00Z".to_string()),
                not_after: Some("2027-01-01T00:00:00Z".to_string()),
                status: crate::plan::TrustRootKeyStatus::Active,
            }],
        };
        fs::write(
            dir.join("trust-root.json"),
            format!("{}\n", serde_json::to_string_pretty(&trust_root)?),
        )?;
        Ok(())
    }

    #[test]
    fn verify_apply_dir_pass_fixture() {
        let tmp = tempdir().expect("tempdir");
        write_fixture_set(tmp.path(), "pass-plan", false).expect("fixture write");
        let out = verify_apply_dir(
            tmp.path(),
            &VerifyOptions {
                receipt_path: None,
                trust_root_path: None,
                audit_path: None,
            },
        )
        .expect("verify pass");
        assert_eq!(out.plan_id, "pass-plan");
        assert!(tmp.path().join("after/verify.json").exists());
        assert!(tmp
            .path()
            .join("after/promotion_audit_chain.ndjson")
            .exists());
    }

    #[test]
    fn verify_apply_dir_fail_fixture() {
        let tmp = tempdir().expect("tempdir");
        write_fixture_set(tmp.path(), "fail-plan", true).expect("fixture write");
        let err = verify_apply_dir(
            tmp.path(),
            &VerifyOptions {
                receipt_path: None,
                trust_root_path: None,
                audit_path: None,
            },
        )
        .expect_err("verify should fail");
        assert!(err.to_string().contains("verification failed"));
    }
}
