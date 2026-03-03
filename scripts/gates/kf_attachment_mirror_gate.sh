#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLAN="${ROOT}/docs/kernelkit/examples/nomad.v0.1.yaml"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

echo "[gate] kf attachment mirror gate start"

cargo run -q -p kernelkit -- --out-dir "${TMP_ROOT}" profile apply "${PLAN}" --propose-only >/tmp/kernelkit_kf_apply.out
APPLY_DIR="$(find "${TMP_ROOT}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [[ -z "${APPLY_DIR}" ]]; then
  echo "[gate][FAIL] no apply dir generated"
  exit 1
fi

KEY_B64="$(python3 - <<'PY'
import base64
print(base64.b64encode(bytes([41])*32).decode())
PY
)"

cargo run -q -p kernelkit -- profile sign-receipt "${APPLY_DIR}" --signing-key-b64 "${KEY_B64}" --key-id root-kf-mirror-gate >/tmp/kernelkit_kf_sign.out
cargo run -q -p kernelkit -- profile verify "${APPLY_DIR}" >/tmp/kernelkit_kf_verify.out

MIRROR_ROOT="${TMP_ROOT}/kf-mirror-out"
./scripts/integration/kf_mirror_export.sh \
  --apply-dir "${APPLY_DIR}" \
  --out-dir "${MIRROR_ROOT}" \
  --mirror-id "gate-test" >/tmp/kernelkit_kf_mirror.out

MANIFEST="${MIRROR_ROOT}/gate-test/mirror_manifest.json"
if [[ ! -f "${MANIFEST}" ]]; then
  echo "[gate][FAIL] missing mirror manifest: ${MANIFEST}"
  exit 1
fi

python3 - <<'PY' "${MANIFEST}" "${MIRROR_ROOT}/gate-test"
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
bundle_dir = pathlib.Path(sys.argv[2])
doc = json.loads(manifest_path.read_text(encoding="utf-8"))

required = {
    "plan.resolved.yaml",
    "resolved.sha256",
    "preflight.json",
    "apply.sh",
    "rollback.sh",
    "promotion.receipt.json",
    "trust-root.json",
    "after/verify.json",
    "after/promotion_audit_chain.ndjson",
}

if doc.get("attachment_mode") != "standalone_mirror_v1":
    raise SystemExit("[gate][FAIL] unexpected attachment_mode")
if doc.get("target_host") != "KF":
    raise SystemExit("[gate][FAIL] unexpected target_host")

listed = {item["path"] for item in doc.get("files", [])}
missing = sorted(required - listed)
if missing:
    raise SystemExit(f"[gate][FAIL] manifest missing required paths: {missing}")

for item in doc.get("files", []):
    rel = item["path"]
    sha = item["sha256"]
    path = bundle_dir / rel
    if not path.is_file():
        raise SystemExit(f"[gate][FAIL] missing mirrored file: {path}")
    import hashlib
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != sha:
        raise SystemExit(f"[gate][FAIL] checksum mismatch for {rel}")
PY

echo "[gate] kf attachment mirror gate PASS"
