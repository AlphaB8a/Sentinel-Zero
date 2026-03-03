#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

PORT_1="${PORT_1:-17777}"
PORT_2="${PORT_2:-17778}"
CANARY_CHAIN="${CANARY_CHAIN:-SZ_CANARY}"
FAIL_ON_UNKNOWN=0
RECEIPT_PATH="${RECEIPT_PATH:-${ROOT}/docs/canary/zero_residue_receipt.json}"

usage() {
  cat <<'EOF'
Usage: scripts/security/assert_zero_residue.sh [options]

Options:
  --receipt-path <path>   Write JSON receipt to this path.
  --fail-on-unknown       Exit non-zero if privileged checks are UNKNOWN.
  -h, --help              Show this help.
EOF
}

while (($# > 0)); do
  case "$1" in
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

SS_MATCHES_FILE="${TMP_DIR}/ss_matches.txt"
LSOF_MATCHES_FILE="${TMP_DIR}/lsof_matches.txt"
IPT_MATCHES_FILE="${TMP_DIR}/iptables_matches.txt"
IPT_ERROR_FILE="${TMP_DIR}/iptables_error.txt"
NFT_MATCHES_FILE="${TMP_DIR}/nft_matches.txt"
NFT_ERROR_FILE="${TMP_DIR}/nft_error.txt"
PERSIST_MATCHES_FILE="${TMP_DIR}/persistence_matches.txt"

touch "${SS_MATCHES_FILE}" "${LSOF_MATCHES_FILE}" "${IPT_MATCHES_FILE}" "${IPT_ERROR_FILE}" \
  "${NFT_MATCHES_FILE}" "${NFT_ERROR_FILE}" "${PERSIST_MATCHES_FILE}"

status_ss="PASS"
status_lsof="PASS"
status_iptables="PASS"
status_nft="PASS"
status_persistence="PASS"

if ss -lntp | egrep ":${PORT_1}|:${PORT_2}" >"${SS_MATCHES_FILE}" 2>/dev/null; then
  if [[ -s "${SS_MATCHES_FILE}" ]]; then
    status_ss="FAIL"
  fi
fi

if command -v lsof >/dev/null 2>&1; then
  if lsof -iTCP -sTCP:LISTEN -P | egrep "${PORT_1}|${PORT_2}" >"${LSOF_MATCHES_FILE}" 2>/dev/null; then
    if [[ -s "${LSOF_MATCHES_FILE}" ]]; then
      status_lsof="FAIL"
    fi
  fi
else
  status_lsof="UNKNOWN"
  echo "lsof unavailable" >"${LSOF_MATCHES_FILE}"
fi

run_privileged_or_plain() {
  if sudo -n true >/dev/null 2>&1; then
    sudo "$@"
  else
    "$@"
  fi
}

if command -v iptables >/dev/null 2>&1; then
  if run_privileged_or_plain iptables -S INPUT >"${TMP_DIR}/iptables_input.txt" 2>"${IPT_ERROR_FILE}"; then
    rg -n "${PORT_1}|${PORT_2}|${CANARY_CHAIN}" "${TMP_DIR}/iptables_input.txt" >"${IPT_MATCHES_FILE}" || true
    if [[ -s "${IPT_MATCHES_FILE}" ]]; then
      status_iptables="FAIL"
    fi
  else
    status_iptables="UNKNOWN"
  fi
else
  status_iptables="UNKNOWN"
  echo "iptables unavailable" >"${IPT_ERROR_FILE}"
fi

if command -v nft >/dev/null 2>&1; then
  if run_privileged_or_plain nft list ruleset >"${TMP_DIR}/nft_ruleset.txt" 2>"${NFT_ERROR_FILE}"; then
    rg -n "${PORT_1}|${PORT_2}|${CANARY_CHAIN}" "${TMP_DIR}/nft_ruleset.txt" >"${NFT_MATCHES_FILE}" || true
    if [[ -s "${NFT_MATCHES_FILE}" ]]; then
      status_nft="FAIL"
    fi
  else
    status_nft="UNKNOWN"
  fi
else
  status_nft="UNKNOWN"
  echo "nft unavailable" >"${NFT_ERROR_FILE}"
fi

for f in /etc/iptables/rules.v4 /etc/iptables/rules.v6 /etc/sysconfig/iptables /etc/nftables.conf; do
  if [[ -f "${f}" ]]; then
    if rg -n "${PORT_1}|${PORT_2}|${CANARY_CHAIN}" "${f}" >>"${PERSIST_MATCHES_FILE}"; then
      :
    fi
  fi
done
if [[ -s "${PERSIST_MATCHES_FILE}" ]]; then
  status_persistence="FAIL"
fi

overall="PASS"
if [[ "${status_ss}" == "FAIL" || "${status_lsof}" == "FAIL" || "${status_iptables}" == "FAIL" || \
      "${status_nft}" == "FAIL" || "${status_persistence}" == "FAIL" ]]; then
  overall="FAIL"
fi
if [[ "${overall}" == "PASS" && "${FAIL_ON_UNKNOWN}" -eq 1 ]] && \
   [[ "${status_lsof}" == "UNKNOWN" || "${status_iptables}" == "UNKNOWN" || "${status_nft}" == "UNKNOWN" ]]; then
  overall="FAIL"
fi

mkdir -p "$(dirname "${RECEIPT_PATH}")"

python3 - <<'PY' "${RECEIPT_PATH}" "${overall}" "${FAIL_ON_UNKNOWN}" "${PORT_1}" "${PORT_2}" "${CANARY_CHAIN}" \
  "${status_ss}" "${status_lsof}" "${status_iptables}" "${status_nft}" "${status_persistence}" \
  "${SS_MATCHES_FILE}" "${LSOF_MATCHES_FILE}" "${IPT_MATCHES_FILE}" "${IPT_ERROR_FILE}" \
  "${NFT_MATCHES_FILE}" "${NFT_ERROR_FILE}" "${PERSIST_MATCHES_FILE}"
import datetime as dt
import json
import pathlib
import socket
import sys

(
    receipt_path,
    overall,
    fail_on_unknown,
    port_1,
    port_2,
    chain,
    status_ss,
    status_lsof,
    status_iptables,
    status_nft,
    status_persistence,
    ss_file,
    lsof_file,
    ipt_file,
    ipt_err_file,
    nft_file,
    nft_err_file,
    persistence_file,
) = sys.argv[1:]


def read_lines(path: str):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    return [line.rstrip("\n") for line in p.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


checks = {
    "listeners_ss": {"status": status_ss, "matches": read_lines(ss_file)},
    "listeners_lsof": {"status": status_lsof, "matches": read_lines(lsof_file)},
    "iptables_input": {
        "status": status_iptables,
        "matches": read_lines(ipt_file),
        "error": read_lines(ipt_err_file),
    },
    "nft_ruleset": {
        "status": status_nft,
        "matches": read_lines(nft_file),
        "error": read_lines(nft_err_file),
    },
    "persistence_files": {"status": status_persistence, "matches": read_lines(persistence_file)},
}

unknown = [name for name, result in checks.items() if result["status"] == "UNKNOWN"]
failed = [name for name, result in checks.items() if result["status"] == "FAIL"]

observed = []
if checks["listeners_ss"]["status"] == "PASS":
    observed.append(f"no listeners found on {port_1}/{port_2} via ss")
if checks["listeners_lsof"]["status"] == "PASS":
    observed.append(f"no listeners found on {port_1}/{port_2} via lsof")
if checks["persistence_files"]["status"] == "PASS":
    observed.append("no residue in common persistence files")

assumed = []
if checks["listeners_lsof"]["status"] == "UNKNOWN":
    assumed.append("lsof inspection unavailable; relying on ss signal")

unknown_notes = []
for name in unknown:
    errors = checks[name].get("error") or checks[name].get("matches") or []
    if errors:
        unknown_notes.append(f"{name}: {' | '.join(errors)}")
    else:
        unknown_notes.append(f"{name}: unavailable")

receipt = {
    "kind": "sentinel_zero.zero_residue_receipt.v1",
    "timestamp_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "host": socket.gethostname(),
    "context": {
        "ports_checked": [int(port_1), int(port_2)],
        "canary_chain": chain,
        "fail_on_unknown": fail_on_unknown == "1",
    },
    "checks": checks,
    "summary": {
        "status": overall,
        "failed_checks": failed,
        "unknown_checks": unknown,
    },
    "assumption_ledger": {
        "OBSERVED": observed,
        "ASSUMED": assumed,
        "UNKNOWN": unknown_notes,
    },
}

path = pathlib.Path(receipt_path)
path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(receipt, indent=2, sort_keys=True))
PY

echo "[zero-residue] receipt: ${RECEIPT_PATH}"
if [[ "${overall}" == "PASS" ]]; then
  echo "[zero-residue] PASS"
  exit 0
fi
echo "[zero-residue][FAIL] detected residue or unknown checks under strict mode"
exit 1
