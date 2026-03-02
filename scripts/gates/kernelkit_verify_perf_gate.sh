#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLAN="${ROOT}/docs/kernelkit/examples/nomad.v0.1.yaml"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

ITERATIONS="${KERNELKIT_VERIFY_PERF_ITERS:-20}"
MAX_TOTAL_MS="${KERNELKIT_VERIFY_PERF_MAX_TOTAL_MS:-10000}"

echo "[gate] kernelkit verify perf gate start (iters=${ITERATIONS}, max_total_ms=${MAX_TOTAL_MS})"

cargo run -q -p kernelkit -- --out-dir "${TMP_ROOT}" profile apply "${PLAN}" --propose-only >/tmp/kernelkit_perf_apply.out
APPLY_DIR="$(find "${TMP_ROOT}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
KEY_B64="$(python3 - <<'PY'
import base64
print(base64.b64encode(bytes([29])*32).decode())
PY
)"
cargo run -q -p kernelkit -- profile sign-receipt "${APPLY_DIR}" --signing-key-b64 "${KEY_B64}" --key-id root-perf-gate >/tmp/kernelkit_perf_sign.out

START_NS="$(date +%s%N)"
for _ in $(seq 1 "${ITERATIONS}"); do
  cargo run -q -p kernelkit -- profile verify "${APPLY_DIR}" >/tmp/kernelkit_perf_verify.out
done
END_NS="$(date +%s%N)"
TOTAL_MS="$(( (END_NS - START_NS) / 1000000 ))"

if [[ "${TOTAL_MS}" -gt "${MAX_TOTAL_MS}" ]]; then
  echo "[gate][FAIL] verify perf budget exceeded: total_ms=${TOTAL_MS} max_total_ms=${MAX_TOTAL_MS}"
  exit 1
fi

echo "[gate] kernelkit verify perf PASS total_ms=${TOTAL_MS}"
