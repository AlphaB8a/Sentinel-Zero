use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{convert::TryInto, fs, path::Path};

use crate::plan::{
    PromotionReceipt, PromotionReceiptPayload, PromotionSignature, TrustRoot, TrustRootKey,
    TrustRootKeyStatus,
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
    for key in &trust_root.keys {
        if key.key_id.trim().is_empty() {
            bail!("trust root key has empty key_id");
        }
        decode_base64_fixed(
            &format!("trust root key {} public_key_b64", key.key_id),
            &key.public_key_b64,
            32,
        )?;
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
    Ok(TrustRoot {
        version: TRUST_ROOT_VERSION.to_string(),
        scope: SENTINEL_ONLY_SCOPE.to_string(),
        algorithm: SIGNATURE_ALGORITHM.to_string(),
        keys: vec![TrustRootKey {
            key_id,
            public_key_b64: STANDARD.encode(signing_key.verifying_key().to_bytes()),
            status: TrustRootKeyStatus::Active,
        }],
    })
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

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{TrustRoot, TrustRootKey, TrustRootKeyStatus};

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
}
