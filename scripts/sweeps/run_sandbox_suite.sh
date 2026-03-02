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
cargo test --workspace --locked
cargo clippy --workspace -- -D warnings
./scripts/gates/ipc_abuse_gate.sh
./scripts/gates/secrets_pattern_gate.sh
./scripts/gates/cargo_audit_gate.sh
./scripts/gates/kernelkit_receipt_gate.sh
./scripts/gates/kernelkit_audit_chain_gate.sh
./scripts/gates/kernelkit_attestation_gate.sh
./scripts/gates/kernelkit_verify_perf_gate.sh

echo "[sweep] SANDBOX_SUITE_OK"
