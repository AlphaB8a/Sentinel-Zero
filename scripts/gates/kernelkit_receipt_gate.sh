#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLAN="${ROOT}/docs/kernelkit/examples/nomad.v0.1.yaml"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

echo "[gate] kernelkit receipt gate start"

cargo run -q -p kernelkit -- --out-dir "${TMP_ROOT}" profile apply "${PLAN}" --propose-only >/tmp/kernelkit_apply.out
APPLY_DIR="$(find "${TMP_ROOT}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [[ -z "${APPLY_DIR}" ]]; then
  echo "[gate][FAIL] no apply dir generated"
  exit 1
fi
echo "[gate] apply dir: ${APPLY_DIR}"

set +e
cargo run -q -p kernelkit -- profile verify "${APPLY_DIR}" >/tmp/kernelkit_verify_fail.out 2>&1
VERIFY_FAIL_CODE=$?
set -e
if [[ "${VERIFY_FAIL_CODE}" -eq 0 ]]; then
  echo "[gate][FAIL] verify unexpectedly passed without signed receipt"
  cat /tmp/kernelkit_verify_fail.out
  exit 1
fi
echo "[gate] verify fail-closed without signed receipt: OK"

KEY_B64="$(python3 - <<'PY'
import base64
print(base64.b64encode(bytes([11])*32).decode())
PY
)"
cargo run -q -p kernelkit -- profile sign-receipt "${APPLY_DIR}" --signing-key-b64 "${KEY_B64}" --key-id root-ci-gate >/tmp/kernelkit_sign.out
cargo run -q -p kernelkit -- profile verify "${APPLY_DIR}" >/tmp/kernelkit_verify_pass.out

if [[ ! -f "${APPLY_DIR}/after/verify.json" ]]; then
  echo "[gate][FAIL] missing verify report"
  exit 1
fi

grep -q '"status": "ok"' "${APPLY_DIR}/after/verify.json"
grep -q '"scope": "sentinel-only-promotion"' "${APPLY_DIR}/after/verify.json"
grep -q '"key_id": "root-ci-gate"' "${APPLY_DIR}/after/verify.json"

echo "[gate] kernelkit receipt gate PASS"
