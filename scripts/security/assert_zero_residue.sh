#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

PORTS_CSV="${PORTS_CSV:-17777,17778}"
MARKER="${MARKER:-SZ_CANARY}"
FAIL_ON_UNKNOWN="${FAIL_ON_UNKNOWN:-0}"
RECEIPT_PATH="${RECEIPT_PATH:-${ROOT}/docs/canary/zero_residue_receipt.json}"
PERSISTENCE_FILES_SPEC="${ZERO_RESIDUE_PERSISTENCE_FILES:-}"

DEFAULT_PERSISTENCE_FILES=(
  "/etc/iptables/rules.v4"
  "/etc/iptables/rules.v6"
  "/etc/sysconfig/iptables"
  "/etc/nftables.conf"
)
PERSISTENCE_FILES=("${DEFAULT_PERSISTENCE_FILES[@]}")

usage() {
  cat <<'EOF'
Usage: scripts/security/assert_zero_residue.sh [options]
       scripts/security/assert_zero_residue.sh [ports_csv] [marker] [receipt_path]

Options:
  --ports <csv>           Ports to check (default: 17777,17778).
  --marker <name>         Firewall marker/chain token (default: SZ_CANARY).
  --receipt-path <path>   Write JSON receipt to this path.
  --persistence-files <paths>
                          Colon-separated list of persistence files to inspect.
  --fail-on-unknown       Exit non-zero when UNKNOWN checks are present.
  -h, --help              Show this help.
EOF
}

# Positional form:
# ./scripts/security/assert_zero_residue.sh "17777,17778" "SZ_CANARY" "docs/canary/zero_residue_receipt.json"
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
    --persistence-files)
      shift
      if (($# == 0)); then
        echo "[zero-residue][FAIL] --persistence-files requires a value"
        exit 2
      fi
      PERSISTENCE_FILES_SPEC="$1"
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

USE_RG=0
if command -v rg >/dev/null 2>&1; then
  USE_RG=1
fi

IFS=',' read -r -a PORTS <<< "${PORTS_CSV}"
if [[ "${#PORTS[@]}" -eq 0 ]]; then
  echo "[zero-residue][FAIL] no ports provided"
  exit 2
fi
for i in "${!PORTS[@]}"; do
  p="${PORTS[$i]// /}"
  if ! [[ "${p}" =~ ^[0-9]+$ ]]; then
    echo "[zero-residue][FAIL] invalid port: ${p}"
    exit 2
  fi
  PORTS[$i]="${p}"
done

if [[ -n "${PERSISTENCE_FILES_SPEC}" ]]; then
  IFS=':' read -r -a raw_paths <<< "${PERSISTENCE_FILES_SPEC}"
  PERSISTENCE_FILES=()
  for path in "${raw_paths[@]}"; do
    if [[ -n "${path}" ]]; then
      PERSISTENCE_FILES+=("${path}")
    fi
  done
fi
if [[ "${#PERSISTENCE_FILES[@]}" -eq 0 ]]; then
  echo "[zero-residue][FAIL] no persistence files configured"
  exit 2
fi

listeners_found=()
errors=()
unknown_checks=()
is_root="false"
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  is_root="true"
fi

append_check() {
  printf '%s\n' "$1" >>"${CHECKS_FILE}"
}

add_unknown() {
  local item="$1"
  for cur in "${unknown_checks[@]}"; do
    if [[ "${cur}" == "${item}" ]]; then
      return
    fi
  done
  unknown_checks+=("${item}")
}

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

run_probe_capture() {
  local name="$1"
  shift
  local mode="$1"
  shift
  local out="${TMP_DIR}/${name}.out"
  local err="${TMP_DIR}/${name}.err"
  set +e
  if [[ "${mode}" == "root" || "${mode}" == "sudo" ]]; then
    sudo "$@" >"${out}" 2>"${err}"
  else
    "$@" >"${out}" 2>"${err}"
  fi
  local rc=$?
  set -e
  echo "${rc}"
}

match_fixed() {
  local pattern="$1"
  local file="$2"
  if ((USE_RG)); then
    rg -q --fixed-strings -- "${pattern}" "${file}"
  else
    grep -Fq -- "${pattern}" "${file}"
  fi
}

match_regex() {
  local pattern="$1"
  local file="$2"
  if ((USE_RG)); then
    rg -q -- "${pattern}" "${file}"
  else
    grep -Eq -- "${pattern}" "${file}"
  fi
}

for p in "${PORTS[@]}"; do
  ss_rc="$(run_cmd_capture "ss_${p}" ss -lntp)"
  ss_hit="false"
  if [[ "${ss_rc}" -eq 0 ]] && match_regex ":${p}([^0-9]|$)" "${TMP_DIR}/ss_${p}.out"; then
    ss_hit="true"
  fi

  lsof_ran="false"
  lsof_rc=127
  lsof_hit="false"
  if command -v lsof >/dev/null 2>&1; then
    lsof_ran="true"
    lsof_rc="$(run_cmd_capture "lsof_${p}" lsof -iTCP -sTCP:LISTEN -P -n)"
    if [[ "${lsof_rc}" -eq 0 ]] && match_regex "(^|[^0-9])${p}([^0-9]|$)" "${TMP_DIR}/lsof_${p}.out"; then
      lsof_hit="true"
    fi
  else
    add_unknown "lsof_unavailable"
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

persistence_hits=()
files_checked=()
for path in "${PERSISTENCE_FILES[@]}"; do
  if [[ -f "${path}" ]]; then
    files_checked+=("${path}")
    if match_fixed "${MARKER}" "${path}"; then
      persistence_hits+=("${path}:marker")
    fi
    for p in "${PORTS[@]}"; do
      if match_regex "(^|[^0-9])${p}([^0-9]|$)" "${path}"; then
        persistence_hits+=("${path}:port:${p}")
        break
      fi
    done
  fi
done

printf '%s\n' "${files_checked[@]}" >"${TMP_DIR}/files_checked.txt"
printf '%s\n' "${persistence_hits[@]}" >"${TMP_DIR}/persistence_hits.txt"
check_json="$(python3 - <<'PY' "${MARKER}" "${TMP_DIR}/files_checked.txt" "${TMP_DIR}/persistence_hits.txt"
import json
import pathlib
import sys
marker, files_path, hits_path = sys.argv[1:]

def lines(path):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]

print(json.dumps({
    "name": "persistence_config_check",
    "marker": marker,
    "files_checked": lines(files_path),
    "hits": lines(hits_path),
}))
PY
)"
append_check "${check_json}"

if [[ "${#persistence_hits[@]}" -gt 0 ]]; then
  errors+=("persistence_residue_detected")
fi

probe_mode="non_root_unknown"
if [[ "${is_root}" == "true" ]]; then
  probe_mode="root"
elif sudo -n true >/dev/null 2>&1; then
  probe_mode="sudo"
fi

live_hit="false"
iptables_state="UNKNOWN"
nft_state="UNKNOWN"
if [[ "${probe_mode}" == "root" || "${probe_mode}" == "sudo" ]]; then
  if command -v iptables >/dev/null 2>&1; then
    ipt_rc="$(run_probe_capture "iptables_input" "${probe_mode}" iptables -S INPUT)"
    if [[ "${ipt_rc}" -eq 0 ]]; then
      iptables_state="OK"
      if match_fixed "${MARKER}" "${TMP_DIR}/iptables_input.out"; then
        live_hit="true"
      fi
      for p in "${PORTS[@]}"; do
        if match_regex "(^|[^0-9])${p}([^0-9]|$)" "${TMP_DIR}/iptables_input.out"; then
          live_hit="true"
        fi
      done
    else
      iptables_state="ERROR_RC_${ipt_rc}"
      add_unknown "iptables_input_unavailable"
    fi
  else
    iptables_state="UNAVAILABLE"
    add_unknown "iptables_binary_unavailable"
  fi

  if command -v nft >/dev/null 2>&1; then
    nft_rc="$(run_probe_capture "nft_ruleset" "${probe_mode}" nft list ruleset)"
    if [[ "${nft_rc}" -eq 0 ]]; then
      nft_state="OK"
      if match_fixed "${MARKER}" "${TMP_DIR}/nft_ruleset.out"; then
        live_hit="true"
      fi
      for p in "${PORTS[@]}"; do
        if match_regex "(^|[^0-9])${p}([^0-9]|$)" "${TMP_DIR}/nft_ruleset.out"; then
          live_hit="true"
        fi
      done
    else
      nft_state="ERROR_RC_${nft_rc}"
      add_unknown "nft_ruleset_unavailable"
    fi
  else
    nft_state="UNAVAILABLE"
    add_unknown "nft_binary_unavailable"
  fi
else
  add_unknown "live_firewall_non_root"
fi

check_json="$(python3 - <<'PY' "${probe_mode}" "${iptables_state}" "${nft_state}" "${live_hit}"
import json
import sys
probe_mode, iptables_state, nft_state, live_hit = sys.argv[1:]
is_root = probe_mode == "root"
note = ""
if probe_mode == "sudo":
    note = "non-root run using sudo -n for read-only firewall inspection"
elif probe_mode == "non_root_unknown":
    note = "non-root run without sudo -n; live firewall state intentionally UNKNOWN"
print(json.dumps({
    "name": "live_firewall_check",
    "probe_mode": probe_mode,
    "is_root": is_root,
    "iptables": {"state": iptables_state},
    "nft": {"state": nft_state},
    "hit": live_hit == "true",
    "note": note,
}))
PY
)"
append_check "${check_json}"

if [[ "${live_hit}" == "true" ]]; then
  errors+=("live_firewall_residue_detected")
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
