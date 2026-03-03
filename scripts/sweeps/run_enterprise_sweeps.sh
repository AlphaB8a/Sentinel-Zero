#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

N="${1:-25}"
if ! [[ "${N}" =~ ^[0-9]+$ ]]; then
  echo "[enterprise-sweep][FAIL] N must be an integer (15..50)"
  exit 1
fi
if (( N < 15 || N > 50 )); then
  echo "[enterprise-sweep][FAIL] N must be in [15, 50]"
  exit 1
fi

LOG_DIR="${ROOT}/docs/sweeps"
mkdir -p "${LOG_DIR}"

success_count=0
streak_100=0
best_streak_100=0
prev_perf_total_ms=""
prev_thermal_max_c=""
perf_values_tmp="$(mktemp)"
thermal_values_tmp="$(mktemp)"
trap 'rm -f "${perf_values_tmp}" "${thermal_values_tmp}"' EXIT

capture_thermal_max_c() {
  local max_temp=""
  local source="none"
  local sensor_values=""
  local sys_values=""

  if command -v sensors >/dev/null 2>&1; then
    sensor_values="$(sensors 2>/dev/null | grep -Eo '\+[0-9]+(\.[0-9]+)?°C' | tr -d '+°C' || true)"
    if [[ -n "${sensor_values}" ]]; then
      max_temp="$(printf "%s\n" "${sensor_values}" | awk '$1>=0 && $1<=150 { if(!seen || $1>max){max=$1; seen=1} } END{if(seen) printf "%.1f", max}')"
      if [[ -n "${max_temp}" ]]; then
        source="lm-sensors"
      fi
    fi
  fi

  if [[ -z "${max_temp}" ]] && compgen -G "/sys/class/thermal/thermal_zone*/temp" >/dev/null; then
    sys_values="$(cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null || true)"
    if [[ -n "${sys_values}" ]]; then
      max_temp="$(printf "%s\n" "${sys_values}" | awk '
        function to_celsius(raw) {
          if (raw > 1000000) return raw / 1000000;
          if (raw > 1000) return raw / 1000;
          return raw;
        }
        {
          c = to_celsius($1);
          if (c >= 0 && c <= 150) {
            if (!seen || c > max) {
              max = c;
              seen = 1;
            }
          }
        }
        END { if (seen) printf "%.1f", max }')"
      if [[ -n "${max_temp}" ]]; then
        source="sysfs"
      fi
    fi
  fi

  if [[ -z "${max_temp}" ]]; then
    echo "UNKNOWN|${source}"
  else
    echo "${max_temp}|${source}"
  fi
}

run_cached_sweep() {
  local zero_residue_receipt="$1"
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
  echo "[gate] zero residue guard start"
  ./scripts/security/assert_zero_residue.sh "17777,17778" "SZ_CANARY" "${zero_residue_receipt}" >/dev/null
  python3 - <<'PY' "${zero_residue_receipt}"
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
  echo "[gate] ZERO_RESIDUE_OK receipt=${zero_residue_receipt}"
  echo "[gate] zero residue guard PASS"
}

echo "[enterprise-sweep] prefetching locked dependencies"
cargo fetch --locked >/dev/null

for i in $(seq 1 "${N}"); do
  sweep_id="$(printf "%02d" "${i}")"
  log_path="${LOG_DIR}/Opt.Sweep_${sweep_id}"
  log_file_name="$(basename "${log_path}")"
  tmp_out="$(mktemp)"
  zero_residue_receipt="/tmp/sz_zero_residue_receipt.sweep_${sweep_id}.json"
  started_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  set +e
  run_cached_sweep "${zero_residue_receipt}" >"${tmp_out}" 2>&1
  sweep_rc=$?
  set -e

  ended_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  perf_total_ms="$(grep -Eo 'total_ms=[0-9]+' "${tmp_out}" | tail -n 1 | cut -d= -f2 || true)"
  if [[ -z "${perf_total_ms}" ]]; then
    perf_total_ms="UNKNOWN"
  fi
  thermal_capture="$(capture_thermal_max_c)"
  thermal_max_c="${thermal_capture%%|*}"
  thermal_source="${thermal_capture##*|}"
  perf_delta_vs_prev="UNKNOWN"
  if [[ "${perf_total_ms}" =~ ^[0-9]+$ ]] && [[ "${prev_perf_total_ms}" =~ ^[0-9]+$ ]]; then
    delta=$((perf_total_ms - prev_perf_total_ms))
    if (( delta > 0 )); then
      perf_delta_vs_prev="+${delta}ms"
    elif (( delta < 0 )); then
      perf_delta_vs_prev="${delta}ms"
    else
      perf_delta_vs_prev="0ms"
    fi
  fi
  if [[ "${perf_total_ms}" =~ ^[0-9]+$ ]]; then
    prev_perf_total_ms="${perf_total_ms}"
    echo "${perf_total_ms}" >>"${perf_values_tmp}"
  fi
  thermal_delta_vs_prev="UNKNOWN"
  if [[ "${thermal_max_c}" =~ ^[0-9]+(\.[0-9]+)?$ ]] && [[ "${prev_thermal_max_c}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    thermal_delta_vs_prev="$(awk -v cur="${thermal_max_c}" -v prev="${prev_thermal_max_c}" 'BEGIN { d=cur-prev; if (d>0) printf "+%.1fC", d; else if (d<0) printf "%.1fC", d; else printf "0.0C" }')"
  fi
  if [[ "${thermal_max_c}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    prev_thermal_max_c="${thermal_max_c}"
    echo "${thermal_max_c}" >>"${thermal_values_tmp}"
  fi
  gate_summary="$(grep -E '^\[gate\]|^\[sweep\]' "${tmp_out}" || true)"
  intake_contract_sha="$(grep -Eo 'STATE_INTAKE_OK contract_sha256=[0-9a-f]+' "${tmp_out}" | tail -n 1 | awk -F= '{print $2}' || true)"
  if [[ -z "${intake_contract_sha}" ]]; then
    intake_contract_sha="UNKNOWN"
  fi

  if [[ "${sweep_rc}" -eq 0 ]]; then
    success_count=$((success_count + 1))
    streak_100=$((streak_100 + 1))
    if (( streak_100 > best_streak_100 )); then
      best_streak_100="${streak_100}"
    fi
    sweep_status="PASS"
    tests_line="sandbox suite PASS (tests/clippy/gates)"
    vuln_line="No known vulnerabilities reported by cargo-audit gate"
    perf_line="KernelKit verify perf gate total_ms=${perf_total_ms} (delta_vs_prev=${perf_delta_vs_prev})"
    thermo_line="Thermal proxy max_c=${thermal_max_c} source=${thermal_source} (delta_vs_prev=${thermal_delta_vs_prev})"
    remaining="No new runtime regressions observed in this sweep"
    annotation_line="FAIL=NO; BUGS=NONE_FOUND_THIS_SWEEP; ADD_ONS=KF_MIRROR_GATE+ZERO_RESIDUE_GUARD; UPGRADE=PERF_AND_THERMAL_TRACKING"
  else
    streak_100=0
    sweep_status="FAIL"
    tests_line="sandbox suite FAIL (see command summary below)"
    vuln_line="UNKNOWN (sweep failed before complete evidence)"
    perf_line="UNKNOWN (sweep failed before perf evidence)"
    thermo_line="UNKNOWN (sweep failed before complete thermal evidence)"
    remaining="Investigate failing gate/test before next sweep"
    annotation_line="FAIL=YES; BUGS=INVESTIGATE_GATE_OR_TEST_FAILURE; ADD_ONS=NONE; UPGRADE=NONE"
  fi

  lock_diff="$(git diff --name-only -- Cargo.lock Cargo.toml || true)"
  api_diff="$(git diff --name-only -- crates/sentinel_protocol crates/sentinel_core/src/ipc docs/protocol/IPC_NDJSON_V1.md || true)"
  schema_diff="$(git diff --name-only -- docs/kernelkit/examples tools/kernelkit/src/plan.rs || true)"
  contract_interfaces="IPC NDJSON v1 + sentinel_protocol::IpcMessage/Ack; kernelkit profile apply/verify/sign-receipt/attest/verify-attestation"
  contract_invariants="fail-closed receipt verify; signed trust-root scope=sentinel-only-promotion; bounded IPC lines/timeouts/message caps/connections"
  contract_versions="docs/protocol/IPC_NDJSON_V1.md; tools/kernelkit plan schema kernelkit.alpha.v0.1; docs/canary/ZERO_RESIDUE_POLICY_CONTRACT_v1.md; Cargo.lock pinned"
  contract_repro="cargo test --workspace --locked && cargo clippy --workspace -- -D warnings && scripts/gates/*.sh && scripts/security/assert_zero_residue.sh \"17777,17778\" \"SZ_CANARY\" \"/tmp/sz_zero_residue_receipt.sweep.json\""

  risk_item_1="R1|Medium|Medium|Open|Local-only validation cannot prove internet-scale behavior"
  risk_item_2="R2|Low|Low|Open|Perf gate is single-host synthetic and may not map to all hardware"
  risk_item_3="R3|Low|Low|Mitigated|IPC abuse paths now covered by targeted regression tests and gate"

  radar_1="Continuous diagnostics dashboard|5|5|5|4|19"
  radar_2="Connection-flood soak test harness|4|5|4|4|17"
  radar_3="Policy-pack templates for deployment profiles|4|4|5|4|17"
  radar_4="Structured runbook generator from sweep logs|3|4|5|5|17"

  {
    echo "Sweep #: ${i}"
    echo "Changes shipped: Verification-only sweep; no additional code edits in this iteration."
    echo "Bugs fixed: None in this iteration."
    echo "Vulns (severity) + fix: ${vuln_line}"
    echo "Perf/latency work + measured delta: ${perf_line}"
    echo "Thermo output proxy + measured delta: ${thermo_line}"
    echo "Annotation (fail/bugs/add-ons/upgrades): ${annotation_line}"
    echo "WOW upgrade (shipped/spec): Shipped - one-command continuous enterprise sweep runner with strict per-sweep logs."
    echo "Tests added + results: ${tests_line}"
    echo "Remaining risks/TODO: ${remaining}"
    echo "Major-change confidence:"
    echo "    • Shipped major change: NO"
    echo "    • Evidence bundle (if YES): N/A"
    echo "    • If deferred: no major-change scope in this iteration"
    echo "Pinned System Contract:"
    echo "    - supported interfaces + behavior invariants: ${contract_interfaces}; ${contract_invariants}"
    echo "    - versioned configs/schemas: ${contract_versions}"
    echo "    - reproducible build/test commands: ${contract_repro}"
    echo "Findings log:"
    echo "    - F0: intake_contract_sha256=${intake_contract_sha}"
    echo "    - F1: sweep_status=${sweep_status}; deterministic gate bundle executed"
    echo "    - F2: perf_total_ms=${perf_total_ms}; perf_delta_vs_prev=${perf_delta_vs_prev}"
    echo "    - F3: drift(lock/api/schema)=(${lock_diff:-NONE})|(${api_diff:-NONE})|(${schema_diff:-NONE})"
    echo "Risk register (severity|likelihood|status):"
    echo "    - ${risk_item_1}"
    echo "    - ${risk_item_2}"
    echo "    - ${risk_item_3}"
    echo "Upgrade Radar backlog (WOW|Enterprise|Maintainability|EffortInv|Total):"
    echo "    - ${radar_1}"
    echo "    - ${radar_2}"
    echo "    - ${radar_3}"
    echo "    - ${radar_4}"
    echo "Top 3 next-sweep priorities:"
    echo "    - P1: Extend IPC abuse suite with multi-connection saturation integration test (PROPOSED until implemented)."
    echo "    - P2: Add sweep artifact trend index (perf + gate durations) for ops visibility (PROPOSED until implemented)."
    echo "    - P3: Add license/abandonware explicit gate output parsing in logs (PROPOSED until implemented)."
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
    echo "Log file: ${log_file_name}"
  } >"${log_path}"

  echo "[enterprise-sweep] ${i}/${N} ${sweep_status} -> ${log_path}"

  rm -f "${tmp_out}"
done

pass_rate_pct=$(( (success_count * 100) / N ))
echo "[enterprise-sweep] completed N=${N} success=${success_count} pass_rate=${pass_rate_pct}% best_100_streak=${best_streak_100}"

if [[ -s "${perf_values_tmp}" ]]; then
  perf_count="$(awk 'END{print NR}' "${perf_values_tmp}")"
  perf_min="$(awk 'NR==1{min=$1} $1<min{min=$1} END{print min}' "${perf_values_tmp}")"
  perf_avg="$(awk '{sum+=$1} END{if(NR>0) printf "%.2f", sum/NR}' "${perf_values_tmp}")"
  perf_max="$(awk 'NR==1{max=$1} $1>max{max=$1} END{print max}' "${perf_values_tmp}")"
  echo "[enterprise-sweep] perf_total_ms_stats count=${perf_count} min=${perf_min} avg=${perf_avg} max=${perf_max}"
fi

if [[ -s "${thermal_values_tmp}" ]]; then
  therm_count="$(awk 'END{print NR}' "${thermal_values_tmp}")"
  therm_min="$(awk 'NR==1{min=$1} $1<min{min=$1} END{printf "%.1f", min}' "${thermal_values_tmp}")"
  therm_avg="$(awk '{sum+=$1} END{if(NR>0) printf "%.1f", sum/NR}' "${thermal_values_tmp}")"
  therm_max="$(awk 'NR==1{max=$1} $1>max{max=$1} END{printf "%.1f", max}' "${thermal_values_tmp}")"
  echo "[enterprise-sweep] thermal_max_c_stats count=${therm_count} min=${therm_min} avg=${therm_avg} max=${therm_max}"
else
  echo "[enterprise-sweep][WARN] thermal_max_c_stats unavailable (no lm-sensors/sysfs data)"
fi

if (( best_streak_100 < 5 )); then
  echo "[enterprise-sweep][WARN] 100%-pass streak below 5 (best=${best_streak_100})"
fi
