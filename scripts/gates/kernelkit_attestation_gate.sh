#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

echo "[gate] kernelkit attestation gate start"

KEY_B64="$(python3 - <<'PY'
import base64
print(base64.b64encode(bytes([23])*32).decode())
PY
)"

cargo run -q -p kernelkit -- profile attest-build \
  --workspace "${ROOT}" \
  --out-dir "${TMP_ROOT}" \
  --signing-key-b64 "${KEY_B64}" \
  --key-id root-attest-gate \
  --key-source local >/tmp/kernelkit_attest.out

ATTEST_FILE="${TMP_ROOT}/build.attestation.slsa.json"
SBOM_FILE="${TMP_ROOT}/sbom.cargo-metadata.json"

[[ -f "${ATTEST_FILE}" ]] || { echo "[gate][FAIL] missing attestation"; exit 1; }
[[ -f "${SBOM_FILE}" ]] || { echo "[gate][FAIL] missing sbom"; exit 1; }

cargo run -q -p kernelkit -- profile verify-attestation "${ATTEST_FILE}" >/tmp/kernelkit_attest_verify_ok.out

python3 - "${ATTEST_FILE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
obj = json.loads(p.read_text())
obj["payload"]["scope"] = "tampered-scope"
p.write_text(json.dumps(obj, separators=(",", ":")))
PY

set +e
cargo run -q -p kernelkit -- profile verify-attestation "${ATTEST_FILE}" >/tmp/kernelkit_attest_verify_fail.out 2>&1
RC=$?
set -e
if [[ "${RC}" -eq 0 ]]; then
  echo "[gate][FAIL] verify-attestation unexpectedly passed after tamper"
  cat /tmp/kernelkit_attest_verify_fail.out
  exit 1
fi

echo "[gate] kernelkit attestation signature/scope checks PASS"
