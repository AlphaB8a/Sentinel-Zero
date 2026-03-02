use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, convert::TryInto, fs, path::Path};

use crate::plan::{
    KeySource, PromotionReceipt, PromotionReceiptPayload, PromotionSignature, TrustRoot,
    TrustRootKey, TrustRootKeyStatus,
};

pub const RECEIPT_VERSION: &str = "sentinel.promotion-receipt.v1";
pub const TRUST_ROOT_VERSION: &str = "sentinel.trust-root.v1";
pub const SENTINEL_ONLY_SCOPE: &str = "sentinel-only-promotion";
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

pub fn canonical_payload_bytes(payload: &PromotionReceiptPayload) -> Result<Vec<u8>> {
    serde_json::to_vec(payload).context("encode canonical receipt payload")
}

pub fn read_json_file<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}: {}", label, path.display()))?;
    serde_json::from_slice::<T>(&bytes)
        .with_context(|| format!("parse {} JSON: {}", label, path.display()))
}

pub fn write_receipt_template(path: &Path, payload: &PromotionReceiptPayload) -> Result<()> {
    let template = json!({
        "version": RECEIPT_VERSION,
        "scope": SENTINEL_ONLY_SCOPE,
        "payload": payload,
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": "REPLACE_WITH_TRUST_ROOT_KEY_ID",
            "signature_b64": "REPLACE_WITH_BASE64_ED25519_SIGNATURE",
        }
    });
    let out = serde_json::to_string_pretty(&template)?;
    fs::write(path, format!("{out}\n"))
        .with_context(|| format!("write receipt template {}", path.display()))
}

pub fn write_trust_root_template(path: &Path) -> Result<()> {
    let template = json!({
        "version": TRUST_ROOT_VERSION,
        "scope": SENTINEL_ONLY_SCOPE,
        "algorithm": SIGNATURE_ALGORITHM,
        "keys": [
            {
                "key_id": "REPLACE_WITH_TRUST_ROOT_KEY_ID",
                "public_key_b64": "REPLACE_WITH_BASE64_ED25519_PUBLIC_KEY",
                "source": "kms",
                "rotation_epoch": 1,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "status": "active"
            }
        ]
    });
    let out = serde_json::to_string_pretty(&template)?;
    fs::write(path, format!("{out}\n"))
        .with_context(|| format!("write trust-root template {}", path.display()))
}

pub fn validate_trust_root_contract(trust_root: &TrustRoot) -> Result<()> {
    if trust_root.version != TRUST_ROOT_VERSION {
        bail!(
            "unsupported trust root version: expected {}, got {}",
            TRUST_ROOT_VERSION,
            trust_root.version
        );
    }
    if trust_root.scope != SENTINEL_ONLY_SCOPE {
        bail!(
            "unsupported trust root scope: expected {}, got {}",
            SENTINEL_ONLY_SCOPE,
            trust_root.scope
        );
    }
    if trust_root.algorithm != SIGNATURE_ALGORITHM {
        bail!(
            "unsupported trust root algorithm: expected {}, got {}",
            SIGNATURE_ALGORITHM,
            trust_root.algorithm
        );
    }
    if trust_root.keys.is_empty() {
        bail!("trust root must contain at least one key");
    }
    let mut seen = HashSet::new();
    let mut active = 0usize;
    for key in &trust_root.keys {
        if key.key_id.trim().is_empty() {
            bail!("trust root key has empty key_id");
        }
        if !seen.insert(key.key_id.clone()) {
            bail!("duplicate trust root key_id: {}", key.key_id);
        }
        decode_base64_fixed(
            &format!("trust root key {} public_key_b64", key.key_id),
            &key.public_key_b64,
            32,
        )?;
        if key.status == TrustRootKeyStatus::Active {
            active += 1;
        }
        validate_key_time_window(key)?;
    }
    if active == 0 {
        bail!("trust root must contain at least one active key");
    }
    Ok(())
}

pub fn validate_receipt_contract(receipt: &PromotionReceipt) -> Result<()> {
    if receipt.version != RECEIPT_VERSION {
        bail!(
            "unsupported receipt version: expected {}, got {}",
            RECEIPT_VERSION,
            receipt.version
        );
    }
    if receipt.scope != SENTINEL_ONLY_SCOPE {
        bail!(
            "unsupported receipt scope: expected {}, got {}",
            SENTINEL_ONLY_SCOPE,
            receipt.scope
        );
    }
    if receipt.signature.algorithm != SIGNATURE_ALGORITHM {
        bail!(
            "unsupported signature algorithm: expected {}, got {}",
            SIGNATURE_ALGORITHM,
            receipt.signature.algorithm
        );
    }
    if receipt.signature.key_id.trim().is_empty() {
        bail!("receipt signature key_id must not be empty");
    }
    if receipt.payload.plan_id.trim().is_empty() {
        bail!("receipt payload plan_id must not be empty");
    }
    if !is_hex_sha256(&receipt.payload.resolved_sha256) {
        bail!("receipt payload resolved_sha256 must be lowercase 64-char hex");
    }
    if !is_hex_sha256(&receipt.payload.preflight_sha256) {
        bail!("receipt payload preflight_sha256 must be lowercase 64-char hex");
    }
    parse_rfc3339("receipt payload issued_at", &receipt.payload.issued_at)?;
    decode_base64_fixed(
        "receipt signature_b64",
        &receipt.signature.signature_b64,
        64,
    )?;
    Ok(())
}

pub fn build_signed_receipt(
    payload: PromotionReceiptPayload,
    key_id: String,
    signing_key_b64: &str,
) -> Result<PromotionReceipt> {
    let secret_bytes = decode_base64_fixed("signing key", signing_key_b64, 32)?;
    let secret: [u8; 32] = secret_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid signing key length"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    let msg = canonical_payload_bytes(&payload)?;
    let signature = signing_key.sign(&msg);
    Ok(PromotionReceipt {
        version: RECEIPT_VERSION.to_string(),
        scope: SENTINEL_ONLY_SCOPE.to_string(),
        payload,
        signature: PromotionSignature {
            algorithm: SIGNATURE_ALGORITHM.to_string(),
            key_id,
            signature_b64: STANDARD.encode(signature.to_bytes()),
        },
    })
}

pub fn sign_payload_b64(signing_key_b64: &str, payload: &[u8]) -> Result<String> {
    let secret_bytes = decode_base64_fixed("signing key", signing_key_b64, 32)?;
    let secret: [u8; 32] = secret_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid signing key length"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    let sig = signing_key.sign(payload);
    Ok(STANDARD.encode(sig.to_bytes()))
}

pub fn public_key_b64_from_signing_key(signing_key_b64: &str) -> Result<String> {
    let secret_bytes = decode_base64_fixed("signing key", signing_key_b64, 32)?;
    let secret: [u8; 32] = secret_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid signing key length"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    Ok(STANDARD.encode(signing_key.verifying_key().to_bytes()))
}

pub fn verify_payload_signature_b64(
    public_key_b64: &str,
    payload: &[u8],
    signature_b64: &str,
) -> Result<()> {
    let pub_bytes = decode_base64_fixed("public key", public_key_b64, 32)?;
    let pub_arr: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("public key length mismatch"))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_arr).context("invalid ed25519 public key")?;
    let sig_bytes = decode_base64_fixed("signature", signature_b64, 64)?;
    let sig = Signature::from_slice(&sig_bytes).context("invalid ed25519 signature bytes")?;
    verifying_key
        .verify(payload, &sig)
        .context("payload signature verification failed")
}

pub fn build_receipt_from_signature(
    payload: PromotionReceiptPayload,
    key_id: String,
    signature_b64: String,
) -> Result<PromotionReceipt> {
    decode_base64_fixed("receipt signature_b64", &signature_b64, 64)?;
    let receipt = PromotionReceipt {
        version: RECEIPT_VERSION.to_string(),
        scope: SENTINEL_ONLY_SCOPE.to_string(),
        payload,
        signature: PromotionSignature {
            algorithm: SIGNATURE_ALGORITHM.to_string(),
            key_id,
            signature_b64,
        },
    };
    validate_receipt_contract(&receipt)?;
    Ok(receipt)
}

pub fn build_trust_root_from_signing_key(
    signing_key_b64: &str,
    key_id: String,
) -> Result<TrustRoot> {
    let secret_bytes = decode_base64_fixed("signing key", signing_key_b64, 32)?;
    let secret: [u8; 32] = secret_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid signing key length"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    build_trust_root_from_public_key(
        key_id,
        STANDARD.encode(signing_key.verifying_key().to_bytes()),
        KeySource::Local,
        1,
        None,
        None,
    )
}

pub fn build_trust_root_from_public_key(
    key_id: String,
    public_key_b64: String,
    source: KeySource,
    rotation_epoch: u32,
    not_before: Option<String>,
    not_after: Option<String>,
) -> Result<TrustRoot> {
    let trust_root = TrustRoot {
        version: TRUST_ROOT_VERSION.to_string(),
        scope: SENTINEL_ONLY_SCOPE.to_string(),
        algorithm: SIGNATURE_ALGORITHM.to_string(),
        keys: vec![TrustRootKey {
            key_id,
            public_key_b64,
            source,
            rotation_epoch,
            not_before,
            not_after,
            status: TrustRootKeyStatus::Active,
        }],
    };
    validate_trust_root_contract(&trust_root)?;
    Ok(trust_root)
}

pub fn verify_receipt_signature(receipt: &PromotionReceipt, trust_root: &TrustRoot) -> Result<()> {
    validate_receipt_contract(receipt)?;
    validate_trust_root_contract(trust_root)?;

    let key = trust_root
        .keys
        .iter()
        .find(|key| key.key_id == receipt.signature.key_id)
        .ok_or_else(|| {
            anyhow!(
                "receipt key_id '{}' not found in trust root",
                receipt.signature.key_id
            )
        })?;

    if key.status != TrustRootKeyStatus::Active {
        bail!(
            "trust root key '{}' is not active (status={:?})",
            key.key_id,
            key.status
        );
    }
    let issued_at = parse_rfc3339("receipt payload issued_at", &receipt.payload.issued_at)?;
    ensure_issued_at_in_window(key, issued_at)?;

    let pub_bytes = decode_base64_fixed("trust root public key", &key.public_key_b64, 32)?;
    let pub_arr: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("public key length mismatch"))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_arr).context("invalid ed25519 public key")?;

    let sig_bytes = decode_base64_fixed("receipt signature", &receipt.signature.signature_b64, 64)?;
    let sig = Signature::from_slice(&sig_bytes).context("invalid ed25519 signature bytes")?;

    let msg = canonical_payload_bytes(&receipt.payload)?;
    verifying_key
        .verify(&msg, &sig)
        .context("receipt signature verification failed")?;
    Ok(())
}

fn decode_base64_fixed(label: &str, value: &str, len: usize) -> Result<Vec<u8>> {
    let out = STANDARD
        .decode(value)
        .with_context(|| format!("decode {} base64", label))?;
    if out.len() != len {
        bail!("{} length must be {} bytes, got {}", label, len, out.len());
    }
    Ok(out)
}

fn parse_rfc3339(label: &str, value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{} must be RFC3339: {}", label, value))
        .map(|v| v.with_timezone(&Utc))
}

fn validate_key_time_window(key: &TrustRootKey) -> Result<()> {
    match (&key.not_before, &key.not_after) {
        (Some(nb), Some(na)) => {
            let nb = parse_rfc3339("trust root key not_before", nb)?;
            let na = parse_rfc3339("trust root key not_after", na)?;
            if nb >= na {
                bail!(
                    "trust root key '{}' has invalid window: not_before >= not_after",
                    key.key_id
                );
            }
        }
        (Some(nb), None) => {
            parse_rfc3339("trust root key not_before", nb)?;
        }
        (None, Some(na)) => {
            parse_rfc3339("trust root key not_after", na)?;
        }
        (None, None) => {}
    }
    Ok(())
}

fn ensure_issued_at_in_window(key: &TrustRootKey, issued_at: DateTime<Utc>) -> Result<()> {
    if let Some(nb) = &key.not_before {
        let nb = parse_rfc3339("trust root key not_before", nb)?;
        if issued_at < nb {
            bail!(
                "receipt issued_at {} is before trust root key '{}' not_before {}",
                issued_at,
                key.key_id,
                nb
            );
        }
    }
    if let Some(na) = &key.not_after {
        let na = parse_rfc3339("trust root key not_after", na)?;
        if issued_at > na {
            bail!(
                "receipt issued_at {} is after trust root key '{}' not_after {}",
                issued_at,
                key.key_id,
                na
            );
        }
    }
    Ok(())
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{KeySource, TrustRoot, TrustRootKey, TrustRootKeyStatus};
    use proptest::prelude::*;

    fn fixture_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn fixture_payload() -> PromotionReceiptPayload {
        PromotionReceiptPayload {
            plan_id: "kk-plan-001".to_string(),
            resolved_sha256: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            preflight_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            issued_at: "2026-03-02T00:00:00Z".to_string(),
        }
    }

    fn fixture_trust_root(signing_key: &SigningKey) -> TrustRoot {
        TrustRoot {
            version: TRUST_ROOT_VERSION.to_string(),
            scope: SENTINEL_ONLY_SCOPE.to_string(),
            algorithm: SIGNATURE_ALGORITHM.to_string(),
            keys: vec![TrustRootKey {
                key_id: "root-2026-03".to_string(),
                public_key_b64: STANDARD.encode(signing_key.verifying_key().to_bytes()),
                source: KeySource::Kms,
                rotation_epoch: 1,
                not_before: Some("2026-01-01T00:00:00Z".to_string()),
                not_after: Some("2027-01-01T00:00:00Z".to_string()),
                status: TrustRootKeyStatus::Active,
            }],
        }
    }

    #[test]
    fn receipt_verification_pass_fixture() {
        let signing_key = fixture_signing_key();
        let payload = fixture_payload();
        let trust_root = fixture_trust_root(&signing_key);
        let msg = canonical_payload_bytes(&payload).expect("payload bytes");
        let sig = signing_key.sign(&msg);
        let receipt = PromotionReceipt {
            version: RECEIPT_VERSION.to_string(),
            scope: SENTINEL_ONLY_SCOPE.to_string(),
            payload,
            signature: PromotionSignature {
                algorithm: SIGNATURE_ALGORITHM.to_string(),
                key_id: "root-2026-03".to_string(),
                signature_b64: STANDARD.encode(sig.to_bytes()),
            },
        };
        verify_receipt_signature(&receipt, &trust_root).expect("should verify");
    }

    #[test]
    fn receipt_verification_fail_signature_fixture() {
        let signing_key = fixture_signing_key();
        let mut payload = fixture_payload();
        let trust_root = fixture_trust_root(&signing_key);
        let msg = canonical_payload_bytes(&payload).expect("payload bytes");
        let sig = signing_key.sign(&msg);
        payload.plan_id = "kk-plan-tampered".to_string();
        let receipt = PromotionReceipt {
            version: RECEIPT_VERSION.to_string(),
            scope: SENTINEL_ONLY_SCOPE.to_string(),
            payload,
            signature: PromotionSignature {
                algorithm: SIGNATURE_ALGORITHM.to_string(),
                key_id: "root-2026-03".to_string(),
                signature_b64: STANDARD.encode(sig.to_bytes()),
            },
        };
        let err = verify_receipt_signature(&receipt, &trust_root).expect_err("must fail");
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn receipt_verification_fail_non_active_key_fixture() {
        let signing_key = fixture_signing_key();
        let payload = fixture_payload();
        let mut trust_root = fixture_trust_root(&signing_key);
        trust_root.keys[0].status = TrustRootKeyStatus::Revoked;
        trust_root.keys.push(TrustRootKey {
            key_id: "root-2026-04".to_string(),
            public_key_b64: trust_root.keys[0].public_key_b64.clone(),
            source: KeySource::Kms,
            rotation_epoch: 2,
            not_before: None,
            not_after: None,
            status: TrustRootKeyStatus::Active,
        });

        let msg = canonical_payload_bytes(&payload).expect("payload bytes");
        let sig = signing_key.sign(&msg);
        let receipt = PromotionReceipt {
            version: RECEIPT_VERSION.to_string(),
            scope: SENTINEL_ONLY_SCOPE.to_string(),
            payload,
            signature: PromotionSignature {
                algorithm: SIGNATURE_ALGORITHM.to_string(),
                key_id: "root-2026-03".to_string(),
                signature_b64: STANDARD.encode(sig.to_bytes()),
            },
        };
        let err = verify_receipt_signature(&receipt, &trust_root).expect_err("must fail");
        assert!(err.to_string().contains("not active"));
    }

    proptest! {
        #[test]
        fn reject_non_sha256_receipt_hashes(non_hex in "[^a-f0-9]{1,64}") {
            let mut payload = fixture_payload();
            payload.resolved_sha256 = non_hex;
            let receipt = PromotionReceipt {
                version: RECEIPT_VERSION.to_string(),
                scope: SENTINEL_ONLY_SCOPE.to_string(),
                payload,
                signature: PromotionSignature {
                    algorithm: SIGNATURE_ALGORITHM.to_string(),
                    key_id: "root-2026-03".to_string(),
                    signature_b64: STANDARD.encode([0u8;64]),
                },
            };
            prop_assert!(validate_receipt_contract(&receipt).is_err());
        }
    }
}
