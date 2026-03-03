#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

echo "[gate] zero-residue negative gate start"

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

fixture="${TMP_ROOT}/nftables.conf"
receipt="${TMP_ROOT}/zero_residue_negative_receipt.json"
run_log="${TMP_ROOT}/assert_zero_residue_negative.log"

cat >"${fixture}" <<'EOF'
# fixture for fail-closed validation
table inet filter {
  chain input {
    type filter hook input priority 0;
    # SZ_CANARY marker must trigger persistence_residue_detected
    tcp dport 17778 counter drop
  }
}
EOF

set +e
./scripts/security/assert_zero_residue.sh \
  --ports "17777,17778" \
  --marker "SZ_CANARY" \
  --receipt-path "${receipt}" \
  --persistence-files "${fixture}" >"${run_log}" 2>&1
assert_rc=$?
set -e

if [[ "${assert_rc}" -eq 0 ]]; then
  echo "[gate][FAIL] assert_zero_residue unexpectedly passed for a residue fixture"
  cat "${run_log}"
  exit 1
fi

if [[ ! -f "${receipt}" ]]; then
  echo "[gate][FAIL] missing negative receipt: ${receipt}"
  exit 1
fi

python3 - <<'PY' "${receipt}"
import json
import pathlib
import sys

receipt_path = pathlib.Path(sys.argv[1])
doc = json.loads(receipt_path.read_text(encoding="utf-8"))

if doc.get("receipt_type") != "sentinel_zero.zero_residue.v1":
    raise SystemExit("[gate][FAIL] unexpected receipt_type")
if doc.get("overall_pass") is not False:
    raise SystemExit("[gate][FAIL] expected overall_pass=false")
if "persistence_residue_detected" not in doc.get("errors", []):
    raise SystemExit("[gate][FAIL] persistence_residue_detected missing from errors")
PY

echo "[gate] zero-residue negative gate PASS"
