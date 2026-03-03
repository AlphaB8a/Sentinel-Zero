#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

echo "[gate] state intake negative gate start"

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

BASE_CONTRACT="${ROOT}/DOCS/CONTRACTS/STATE_INTAKE_CURRENT_v1.json"
SCHEMA_PATH="${ROOT}/CONTRACTS/schemas/state_intake_contract_v1.schema.json"

if [[ ! -f "${BASE_CONTRACT}" ]]; then
  echo "[gate][FAIL] missing baseline contract: ${BASE_CONTRACT}"
  exit 1
fi

MISSING_POLICY="${TMP_ROOT}/missing_evidence_policy.json"
MISSING_REF="${TMP_ROOT}/missing_reference.json"

python3 - <<'PY' "${BASE_CONTRACT}" "${MISSING_POLICY}" "${MISSING_REF}"
import json
import pathlib
import sys

base = pathlib.Path(sys.argv[1])
out_missing_policy = pathlib.Path(sys.argv[2])
out_missing_ref = pathlib.Path(sys.argv[3])

doc = json.loads(base.read_text(encoding="utf-8"))

missing_policy = json.loads(json.dumps(doc))
missing_policy.pop("evidence_policy", None)
out_missing_policy.write_text(json.dumps(missing_policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")

missing_ref = json.loads(json.dumps(doc))
missing_ref["inputs"]["workorders"]["paths"] = ["DOES_NOT_EXIST/WORKORDER.yaml"]
out_missing_ref.write_text(json.dumps(missing_ref, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

set +e
out_policy="$(python3 ./scripts/security/check_state_intake_contract.py --repo-root "${ROOT}" --contract "${MISSING_POLICY}" --schema "${SCHEMA_PATH}" 2>&1)"
rc_policy=$?
set -e

if [[ "${rc_policy}" -eq 0 ]]; then
  echo "[gate][FAIL] expected failure for missing evidence_policy"
  exit 1
fi
if [[ "${out_policy}" != *"STATE_INTAKE_EVIDENCE_POLICY_MISSING"* ]]; then
  echo "[gate][FAIL] expected STATE_INTAKE_EVIDENCE_POLICY_MISSING"
  printf '%s\n' "${out_policy}"
  exit 1
fi

set +e
out_ref="$(python3 ./scripts/security/check_state_intake_contract.py --repo-root "${ROOT}" --contract "${MISSING_REF}" --schema "${SCHEMA_PATH}" 2>&1)"
rc_ref=$?
set -e

if [[ "${rc_ref}" -eq 0 ]]; then
  echo "[gate][FAIL] expected failure for missing referenced file"
  exit 1
fi
if [[ "${out_ref}" != *"STATE_INTAKE_REFERENCED_FILE_MISSING"* ]]; then
  echo "[gate][FAIL] expected STATE_INTAKE_REFERENCED_FILE_MISSING"
  printf '%s\n' "${out_ref}"
  exit 1
fi

echo "[gate] state intake negative gate PASS"
