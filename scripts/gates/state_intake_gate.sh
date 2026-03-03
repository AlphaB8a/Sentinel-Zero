#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

CONTRACT_PATH="${STATE_INTAKE_CONTRACT_PATH:-${ROOT}/DOCS/CONTRACTS/STATE_INTAKE_CURRENT_v1.json}"
SCHEMA_PATH="${STATE_INTAKE_SCHEMA_PATH:-${ROOT}/CONTRACTS/schemas/state_intake_contract_v1.schema.json}"

echo "[gate] state intake gate start"
out="$(python3 ./scripts/security/check_state_intake_contract.py --repo-root "${ROOT}" --contract "${CONTRACT_PATH}" --schema "${SCHEMA_PATH}")"

if [[ -z "${out}" ]]; then
  echo "[gate][FAIL] state intake checker produced no output"
  exit 1
fi

contract_sha="$(printf '%s\n' "${out}" | sed -n 's/.*contract_sha256=\([0-9a-f]\{64\}\).*/\1/p' | head -n 1)"
if [[ -z "${contract_sha}" ]]; then
  echo "[gate][FAIL] state intake checker output missing contract hash"
  printf '%s\n' "${out}"
  exit 1
fi

printf '%s\n' "${out}"
echo "[gate] STATE_INTAKE_OK contract_sha256=${contract_sha}"
echo "[gate] state intake gate PASS"
