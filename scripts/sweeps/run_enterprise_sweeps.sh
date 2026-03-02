#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

N="${1:-25}"
if ! [[ "${N}" =~ ^[0-9]+$ ]]; then
  echo "[enterprise-sweep][FAIL] N must be an integer (15..30)"
  exit 1
fi
if (( N < 15 || N > 30 )); then
  echo "[enterprise-sweep][FAIL] N must be in [15, 30]"
  exit 1
fi

LOG_DIR="${ROOT}/docs/sweeps"
mkdir -p "${LOG_DIR}"

success_count=0
streak_100=0
best_streak_100=0

run_cached_sweep() {
  cargo test --workspace --locked
  cargo clippy --workspace -- -D warnings
  ./scripts/gates/ipc_abuse_gate.sh
  ./scripts/gates/secrets_pattern_gate.sh
  ./scripts/gates/cargo_audit_gate.sh
  ./scripts/gates/kernelkit_receipt_gate.sh
  ./scripts/gates/kernelkit_audit_chain_gate.sh
  ./scripts/gates/kernelkit_attestation_gate.sh
  ./scripts/gates/kernelkit_verify_perf_gate.sh
}

echo "[enterprise-sweep] prefetching locked dependencies"
cargo fetch --locked >/dev/null

for i in $(seq 1 "${N}"); do
  sweep_id="$(printf "%02d" "${i}")"
  log_path="${LOG_DIR}/Opt.Sweep_${sweep_id}"
  tmp_out="$(mktemp)"
  started_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  set +e
  run_cached_sweep >"${tmp_out}" 2>&1
  sweep_rc=$?
  set -e

  ended_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  perf_total_ms="$(grep -Eo 'total_ms=[0-9]+' "${tmp_out}" | tail -n 1 | cut -d= -f2 || true)"
  if [[ -z "${perf_total_ms}" ]]; then
    perf_total_ms="UNKNOWN"
  fi
  gate_summary="$(grep -E '^\[gate\]|^\[sweep\]' "${tmp_out}" || true)"

  if [[ "${sweep_rc}" -eq 0 ]]; then
    success_count=$((success_count + 1))
    streak_100=$((streak_100 + 1))
    if (( streak_100 > best_streak_100 )); then
      best_streak_100="${streak_100}"
    fi
    sweep_status="PASS"
    tests_line="sandbox suite PASS (tests/clippy/gates)"
    vuln_line="No known vulnerabilities reported by cargo-audit gate"
    perf_line="KernelKit verify perf gate total_ms=${perf_total_ms}"
    remaining="No new runtime regressions observed in this sweep"
  else
    streak_100=0
    sweep_status="FAIL"
    tests_line="sandbox suite FAIL (see command summary below)"
    vuln_line="UNKNOWN (sweep failed before complete evidence)"
    perf_line="UNKNOWN (sweep failed before perf evidence)"
    remaining="Investigate failing gate/test before next sweep"
  fi

  lock_diff="$(git diff --name-only -- Cargo.lock Cargo.toml || true)"
  api_diff="$(git diff --name-only -- crates/sentinel_protocol crates/sentinel_core/src/ipc docs/protocol/IPC_NDJSON_V1.md || true)"
  schema_diff="$(git diff --name-only -- docs/kernelkit/examples tools/kernelkit/src/plan.rs || true)"

  {
    echo "Sweep #: ${i}"
    echo "Changes shipped: Verification-only sweep; no additional code edits in this iteration."
    echo "Bugs fixed: None in this iteration."
    echo "Vulns (severity) + fix: ${vuln_line}"
    echo "Perf/latency work + measured delta: ${perf_line}"
    echo "WOW upgrade (shipped/spec): Shipped - one-command continuous enterprise sweep runner with strict per-sweep logs."
    echo "Tests added + results: ${tests_line}"
    echo "Remaining risks/TODO: ${remaining}"
    echo "Major-change confidence:"
    echo "    • Shipped major change: NO"
    echo "    • Evidence bundle (if YES): N/A"
    echo "    • If deferred: no major-change scope in this iteration"
    echo "Assumption Ledger:"
    echo "    OBSERVED:"
    echo "      - sweep_status=${sweep_status}"
    echo "      - started_utc=${started_utc}"
    echo "      - ended_utc=${ended_utc}"
    echo "      - success_count=${success_count}"
    echo "      - current_100_streak=${streak_100}"
    echo "      - best_100_streak=${best_streak_100}"
    echo "    ASSUMED:"
    echo "      - Full enterprise hardening posture depends on periodic human threat-model review."
    echo "    UNKNOWN:"
    echo "      - Live production behavior under real external traffic (LOCAL-only validation)."
    echo "Drift checks:"
    echo "    - dependency locks diff: ${lock_diff:-NONE}"
    echo "    - API surface diff (protocol/ipc docs): ${api_diff:-NONE}"
    echo "    - config/schema diff: ${schema_diff:-NONE}"
    echo "    - determinism re-verify: cached locked sweep ${sweep_status}"
    echo "Command summary:"
    if [[ -n "${gate_summary}" ]]; then
      echo "${gate_summary}"
    else
      echo "(no gate summary captured)"
    fi
  } >"${log_path}"

  echo "[enterprise-sweep] ${i}/${N} ${sweep_status} -> ${log_path}"

  rm -f "${tmp_out}"
done

pass_rate_pct=$(( (success_count * 100) / N ))
echo "[enterprise-sweep] completed N=${N} success=${success_count} pass_rate=${pass_rate_pct}% best_100_streak=${best_streak_100}"

if (( best_streak_100 < 5 )); then
  echo "[enterprise-sweep][WARN] 100%-pass streak below 5 (best=${best_streak_100})"
fi
