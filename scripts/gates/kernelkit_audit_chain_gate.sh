#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLAN="${ROOT}/docs/kernelkit/examples/nomad.v0.1.yaml"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

echo "[gate] kernelkit audit chain gate start"

cargo run -q -p kernelkit -- --out-dir "${TMP_ROOT}" profile apply "${PLAN}" --propose-only >/tmp/kernelkit_apply_audit.out
APPLY_DIR="$(find "${TMP_ROOT}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
KEY_B64="$(python3 - <<'PY'
import base64
print(base64.b64encode(bytes([17])*32).decode())
PY
)"

cargo run -q -p kernelkit -- profile sign-receipt "${APPLY_DIR}" --signing-key-b64 "${KEY_B64}" --key-id root-audit-gate >/tmp/kernelkit_sign_audit.out
cargo run -q -p kernelkit -- profile verify "${APPLY_DIR}" >/tmp/kernelkit_verify_audit_1.out
cargo run -q -p kernelkit -- profile verify "${APPLY_DIR}" >/tmp/kernelkit_verify_audit_2.out

AUDIT_FILE="${APPLY_DIR}/after/promotion_audit_chain.ndjson"
if [[ ! -f "${AUDIT_FILE}" ]]; then
  echo "[gate][FAIL] missing audit chain file"
  exit 1
fi

cargo run -q -p kernelkit -- profile audit-verify "${AUDIT_FILE}" >/tmp/kernelkit_audit_verify_ok.out

python3 - "$AUDIT_FILE" <<'PY'
import pathlib,sys
p = pathlib.Path(sys.argv[1])
txt = p.read_text()
p.write_text(txt.replace('"status":"ok"','"status":"tampered"',1))
PY

set +e
cargo run -q -p kernelkit -- profile audit-verify "${AUDIT_FILE}" >/tmp/kernelkit_audit_verify_fail.out 2>&1
RC=$?
set -e
if [[ "${RC}" -eq 0 ]]; then
  echo "[gate][FAIL] audit verification unexpectedly passed after tamper"
  cat /tmp/kernelkit_audit_verify_fail.out
  exit 1
fi

echo "[gate] kernelkit audit chain tamper detection PASS"
