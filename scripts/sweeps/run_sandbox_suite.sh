#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

export CARGO_HOME="${TMP_ROOT}/cargo-home"
export CARGO_TARGET_DIR="${TMP_ROOT}/target"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
mkdir -p "${CARGO_HOME}" "${CARGO_TARGET_DIR}"

echo "[sweep] isolated sandbox"
echo "[sweep] CARGO_HOME=${CARGO_HOME}"
echo "[sweep] CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"

cargo fetch --locked
./scripts/gates/state_intake_gate.sh
./scripts/gates/state_intake_negative_gate.sh
cargo test --workspace --locked
cargo clippy --workspace -- -D warnings
./scripts/gates/ipc_abuse_gate.sh
./scripts/gates/zero_residue_negative_gate.sh
./scripts/gates/kf_attachment_mirror_gate.sh
./scripts/gates/secrets_pattern_gate.sh
./scripts/gates/cargo_audit_gate.sh
./scripts/gates/kernelkit_receipt_gate.sh
./scripts/gates/kernelkit_audit_chain_gate.sh
./scripts/gates/kernelkit_attestation_gate.sh
./scripts/gates/kernelkit_verify_perf_gate.sh
ZERO_RESIDUE_RECEIPT="/tmp/sz_zero_residue_receipt.sandbox.json"
./scripts/security/assert_zero_residue.sh "17777,17778" "SZ_CANARY" "${ZERO_RESIDUE_RECEIPT}" >/dev/null
python3 - <<'PY' "${ZERO_RESIDUE_RECEIPT}"
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text(encoding="utf-8"))
if doc.get("receipt_type") != "sentinel_zero.zero_residue.v1":
    raise SystemExit("invalid receipt_type")
if doc.get("overall_pass") is not True:
    raise SystemExit("zero residue receipt did not pass")
PY
echo "[sweep] ZERO_RESIDUE_OK receipt=${ZERO_RESIDUE_RECEIPT}"

echo "[sweep] SANDBOX_SUITE_OK"
