#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

PORTS_CSV="${PORTS_CSV:-17777,17778}"
MARKER="${MARKER:-SZ_CANARY}"
FAIL_ON_UNKNOWN="${FAIL_ON_UNKNOWN:-0}"
RECEIPT_PATH="${RECEIPT_PATH:-${ROOT}/docs/canary/zero_residue_receipt.json}"

usage() {
  cat <<'EOF'
Usage: scripts/security/assert_zero_residue.sh [options]
       scripts/security/assert_zero_residue.sh [ports_csv] [marker] [receipt_path]

Options:
  --ports <csv>           Ports to check (default: 17777,17778).
  --marker <name>         Firewall marker/chain token (default: SZ_CANARY).
  --receipt-path <path>   Write JSON receipt to this path.
  --fail-on-unknown       Exit non-zero when UNKNOWN checks are present.
  -h, --help              Show this help.
EOF
}

# Positional form support:
#   ./scripts/security/assert_zero_residue.sh "17777,17778" "SZ_CANARY" "docs/canary/zero_residue_receipt.json"
if (($# > 0)) && [[ "$1" != -* ]]; then
  PORTS_CSV="$1"
  shift
fi
if (($# > 0)) && [[ "$1" != -* ]]; then
  MARKER="$1"
  shift
fi
if (($# > 0)) && [[ "$1" != -* ]]; then
  RECEIPT_PATH="$1"
  shift
fi

while (($# > 0)); do
  case "$1" in
    --ports)
      shift
      if (($# == 0)); then
        echo "[zero-residue][FAIL] --ports requires a value"
        exit 2
      fi
      PORTS_CSV="$1"
      ;;
    --marker)
      shift
      if (($# == 0)); then
        echo "[zero-residue][FAIL] --marker requires a value"
        exit 2
      fi
      MARKER="$1"
      ;;
    --receipt-path)
      shift
      if (($# == 0)); then
        echo "[zero-residue][FAIL] --receipt-path requires a value"
        exit 2
      fi
      RECEIPT_PATH="$1"
      ;;
    --fail-on-unknown)
      FAIL_ON_UNKNOWN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[zero-residue][FAIL] unknown arg: $1"
      usage
      exit 2
      ;;
  esac
  shift
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

CHECKS_FILE="${TMP_DIR}/checks.ndjson"
touch "${CHECKS_FILE}"

IFS=',' read -r -a PORTS <<< "${PORTS_CSV}"
if [[ "${#PORTS[@]}" -eq 0 ]]; then
  echo "[zero-residue][FAIL] no ports provided"
  exit 2
fi
for p in "${PORTS[@]}"; do
  p="${p// /}"
  if ! [[ "${p}" =~ ^[0-9]+$ ]]; then
    echo "[zero-residue][FAIL] invalid port: ${p}"
    exit 2
  fi
done

listeners_found=()
errors=()
unknown_checks=()
is_root="false"
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  is_root="true"
fi

run_cmd_capture() {
  local name="$1"
  shift
  local out="${TMP_DIR}/${name}.out"
  local err="${TMP_DIR}/${name}.err"
  set +e
  "$@" >"${out}" 2>"${err}"
  local rc=$?
  set -e
  echo "${rc}"
}

append_check() {
  printf '%s\n' "$1" >>"${CHECKS_FILE}"
}

for p in "${PORTS[@]}"; do
  p="${p// /}"
  ss_rc="$(run_cmd_capture "ss_${p}" ss -lntp)"
  ss_hit="false"
  if [[ "${ss_rc}" -eq 0 ]] && rg -q ":${p}\\b" "${TMP_DIR}/ss_${p}.out"; then
    ss_hit="true"
  fi
  lsof_ran="false"
  lsof_rc=127
  lsof_hit="false"
  if command -v lsof >/dev/null 2>&1; then
    lsof_ran="true"
    lsof_rc="$(run_cmd_capture "lsof_${p}" lsof -iTCP -sTCP:LISTEN -P -n)"
    if [[ "${lsof_rc}" -eq 0 ]] && rg -q "\\b${p}\\b" "${TMP_DIR}/lsof_${p}.out"; then
      lsof_hit="true"
    fi
  else
    unknown_checks+=("lsof_unavailable")
  fi
  if [[ "${ss_hit}" == "true" || "${lsof_hit}" == "true" ]]; then
    listeners_found+=("${p}")
  fi
  check_json="$(python3 - <<'PY' "${p}" "${ss_rc}" "${ss_hit}" "${lsof_ran}" "${lsof_rc}" "${lsof_hit}"
import json
import sys
port, ss_rc, ss_hit, lsof_ran, lsof_rc, lsof_hit = sys.argv[1:]
print(json.dumps({
    "name": "listener_check",
    "port": int(port),
    "ss": {"ran": True, "rc": int(ss_rc), "hit": ss_hit == "true"},
    "lsof": {"ran": lsof_ran == "true", "rc": int(lsof_rc), "hit": lsof_hit == "true"},
}))
PY
)"
  append_check "${check_json}"
done

if [[ "${#listeners_found[@]}" -gt 0 ]]; then
  errors+=("listeners_present")
fi

# Fail-closed for persistence markers in /etc/nftables.conf when present.
nft_conf_present="false"
nft_conf_marker_hit="false"
nft_conf_ports_hit="false"
if [[ -f "/etc/nftables.conf" ]]; then
  nft_conf_present="true"
  if rg -q --fixed-strings "${MARKER}" /etc/nftables.conf; then
    nft_conf_marker_hit="true"
  fi
  for p in "${PORTS[@]}"; do
    p="${p// /}"
    if rg -q "\\b${p}\\b" /etc/nftables.conf; then
      nft_conf_ports_hit="true"
      break
    fi
  done
fi
check_json="$(python3 - <<'PY' "${nft_conf_present}" "${MARKER}" "${nft_conf_marker_hit}" "${nft_conf_ports_hit}"
import json
import sys
present, marker, marker_hit, ports_hit = sys.argv[1:]
print(json.dumps({
    "name": "nftables_conf_persistence_check",
    "path": "/etc/nftables.conf",
    "present": present == "true",
    "marker": {"value": marker, "hit": marker_hit == "true"},
    "ports_hit": ports_hit == "true",
}))
PY
)"
append_check "${check_json}"
if [[ "${nft_conf_present}" == "true" ]] && \
   [[ "${nft_conf_marker_hit}" == "true" || "${nft_conf_ports_hit}" == "true" ]]; then
  errors+=("nftables_conf_persistence_detected")
fi

# Root-only live ruleset checks.
if [[ "${is_root}" == "true" ]]; then
  live_hit="false"
  iptables_state="OK"
  nft_state="OK"

  if command -v iptables >/dev/null 2>&1; then
    ipt_rc="$(run_cmd_capture "iptables_input" iptables -S INPUT)"
    if [[ "${ipt_rc}" -ne 0 ]]; then
      iptables_state="ERROR_RC_${ipt_rc}"
      unknown_checks+=("iptables_input_unavailable")
    else
      if rg -q --fixed-strings "${MARKER}" "${TMP_DIR}/iptables_input.out"; then
        live_hit="true"
      fi
      for p in "${PORTS[@]}"; do
        p="${p// /}"
        if rg -q "\\b${p}\\b" "${TMP_DIR}/iptables_input.out"; then
          live_hit="true"
        fi
      done
    fi
  else
    iptables_state="UNAVAILABLE"
    unknown_checks+=("iptables_binary_unavailable")
  fi

  if command -v nft >/dev/null 2>&1; then
    nft_rc="$(run_cmd_capture "nft_ruleset" nft list ruleset)"
    if [[ "${nft_rc}" -ne 0 ]]; then
      nft_state="ERROR_RC_${nft_rc}"
      unknown_checks+=("nft_ruleset_unavailable")
    else
      if rg -q --fixed-strings "${MARKER}" "${TMP_DIR}/nft_ruleset.out"; then
        live_hit="true"
      fi
      for p in "${PORTS[@]}"; do
        p="${p// /}"
        if rg -q "\\b${p}\\b" "${TMP_DIR}/nft_ruleset.out"; then
          live_hit="true"
        fi
      done
    fi
  else
    nft_state="UNAVAILABLE"
    unknown_checks+=("nft_binary_unavailable")
  fi

  check_json="$(python3 - <<'PY' "${iptables_state}" "${nft_state}" "${live_hit}"
import json
import sys
iptables_state, nft_state, live_hit = sys.argv[1:]
print(json.dumps({
    "name": "live_firewall_check",
    "is_root": True,
    "iptables": {"state": iptables_state},
    "nft": {"state": nft_state},
    "hit": live_hit == "true",
}))
PY
)"
  append_check "${check_json}"
  if [[ "${live_hit}" == "true" ]]; then
    errors+=("live_firewall_residue_detected")
  fi
else
  check_json="$(python3 - <<'PY'
import json
print(json.dumps({
    "name": "live_firewall_check",
    "is_root": False,
    "iptables": {"state": "UNKNOWN"},
    "nft": {"state": "UNKNOWN"},
    "hit": False,
    "note": "non-root run: live firewall state intentionally not asserted",
}))
PY
)"
  append_check "${check_json}"
  unknown_checks+=("live_firewall_non_root")
fi

if [[ "${FAIL_ON_UNKNOWN}" -eq 1 && "${#unknown_checks[@]}" -gt 0 ]]; then
  errors+=("unknown_checks_present")
fi

overall_pass="true"
if [[ "${#errors[@]}" -gt 0 ]]; then
  overall_pass="false"
fi

printf '%s\n' "${listeners_found[@]}" >"${TMP_DIR}/listeners.txt"
printf '%s\n' "${errors[@]}" >"${TMP_DIR}/errors.txt"
printf '%s\n' "${unknown_checks[@]}" >"${TMP_DIR}/unknown.txt"

python3 - <<'PY' "${RECEIPT_PATH}" "${PORTS_CSV}" "${MARKER}" "${is_root}" "${overall_pass}" "${CHECKS_FILE}" "${TMP_DIR}/listeners.txt" "${TMP_DIR}/errors.txt" "${TMP_DIR}/unknown.txt"
import json
import pathlib
import sys

(
    receipt_path,
    ports_csv,
    marker,
    is_root,
    overall_pass,
    checks_file,
    listeners_file,
    errors_file,
    unknown_file,
) = sys.argv[1:]


def read_lines(path: str):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


ports = [int(p.strip()) for p in ports_csv.split(",") if p.strip()]
listeners_found = read_lines(listeners_file)
errors = read_lines(errors_file)
unknown = read_lines(unknown_file)
checks = [json.loads(line) for line in read_lines(checks_file)]

doc = {
    "receipt_type": "sentinel_zero.zero_residue.v1",
    "ports": ports,
    "marker": marker,
    "is_root": is_root == "true",
    "listeners_found": [int(p) for p in listeners_found],
    "errors": errors,
    "checks": checks,
    "overall_pass": overall_pass == "true",
    "unknown_checks": unknown,
}

p = pathlib.Path(receipt_path)
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(doc, indent=2, sort_keys=True))
PY

echo "zero_residue_receipt_written=${RECEIPT_PATH}"
if [[ "${overall_pass}" != "true" ]]; then
  echo "ZERO_RESIDUE_ASSERTION_FAILED" >&2
  exit 1
fi
echo "ZERO_RESIDUE_OK"
