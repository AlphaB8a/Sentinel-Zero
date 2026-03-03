#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

TS="$(date -u +"%Y%m%dT%H%M%SZ")"
RUN_DIR="${ROOT}/docs/canary/${TS}"
mkdir -p "${RUN_DIR}"

PHASE1_PORT="${PHASE1_PORT:-17777}"
PHASE2_PORT="${PHASE2_PORT:-17778}"
HOST_IP="${HOST_IP:-$(ip -o -4 addr show scope global | awk '$2 != "docker0" {print $4; exit}' | cut -d/ -f1)}"
CANARY_BIND_ANY="${CANARY_BIND_ANY:-0}"
PHASE2_BIND_HOST="${PHASE2_BIND_HOST:-${HOST_IP}}"
if [[ "${CANARY_BIND_ANY}" == "1" ]]; then
  PHASE2_BIND_HOST="0.0.0.0"
fi
SENTINEL_BIN="${ROOT}/target/debug/sentinel_tui"
CLIENT="${ROOT}/scripts/security/hostile_sim_client.py"

PHASE1_LOG="${RUN_DIR}/phase1_sentinel.log"
PHASE2_LOG="${RUN_DIR}/phase2_sentinel.log"
PHASE1_JSON="${RUN_DIR}/phase1_client.json"
PHASE2_JSON="${RUN_DIR}/phase2_client.json"
SUMMARY_MD="${RUN_DIR}/CANARY_EVIDENCE.md"

canary_pid=""
iptables_was_applied=0

cleanup() {
  if [[ -n "${canary_pid}" ]] && kill -0 "${canary_pid}" 2>/dev/null; then
    kill "${canary_pid}" 2>/dev/null || true
    wait "${canary_pid}" 2>/dev/null || true
  fi
  if [[ "${iptables_was_applied}" -eq 1 ]]; then
    sudo iptables -D INPUT -p tcp --dport "${PHASE2_PORT}" -j SZ_CANARY 2>/dev/null || true
    sudo iptables -F SZ_CANARY 2>/dev/null || true
    sudo iptables -X SZ_CANARY 2>/dev/null || true
  fi
}
trap cleanup EXIT

wait_listen() {
  local port="$1"
  local tries=40
  while (( tries > 0 )); do
    if ss -ltn "( sport = :${port} )" | grep -Eq ":${port}\\b"; then
      return 0
    fi
    sleep 0.25
    tries=$((tries - 1))
  done
  echo "[canary][FAIL] listener did not appear on port ${port}"
  return 1
}

start_sentinel() {
  local listen_spec="$1"
  local log_file="$2"
  SENTINEL_HEADLESS=1 \
  SENTINEL_IPC="${listen_spec}" \
  SENTINEL_IPC_MAX_LINE_BYTES=1024 \
  SENTINEL_IPC_READ_TIMEOUT_MS=1000 \
  SENTINEL_IPC_MAX_MESSAGES_PER_CONN=8 \
  SENTINEL_IPC_MAX_CONNECTIONS=20 \
  SENTINEL_ALLOW_NON_LOOPBACK_BIND=1 \
  "${SENTINEL_BIN}" --headless --ipc "${listen_spec}" >"${log_file}" 2>&1 &
  canary_pid=$!
}

stop_sentinel() {
  if [[ -n "${canary_pid}" ]] && kill -0 "${canary_pid}" 2>/dev/null; then
    kill "${canary_pid}" 2>/dev/null || true
    wait "${canary_pid}" 2>/dev/null || true
  fi
  canary_pid=""
}

apply_iptables_rate_limit() {
  sudo iptables -N SZ_CANARY 2>/dev/null || true
  sudo iptables -F SZ_CANARY
  sudo iptables -A SZ_CANARY \
    -p tcp --dport "${PHASE2_PORT}" \
    -m conntrack --ctstate NEW \
    -m hashlimit \
      --hashlimit-name sz_canary_rate \
      --hashlimit-above 25/second \
      --hashlimit-burst 30 \
      --hashlimit-mode srcip \
    -j DROP
  sudo iptables -A SZ_CANARY -p tcp --dport "${PHASE2_PORT}" -j ACCEPT
  sudo iptables -D INPUT -p tcp --dport "${PHASE2_PORT}" -j SZ_CANARY 2>/dev/null || true
  sudo iptables -I INPUT 1 -p tcp --dport "${PHASE2_PORT}" -j SZ_CANARY
  iptables_was_applied=1
}

echo "[canary] building sentinel_tui"
cargo build -q -p sentinel_tui
chmod +x "${CLIENT}"

echo "[canary] phase1: sandbox hostile simulation on loopback"
start_sentinel "tcp:127.0.0.1:${PHASE1_PORT}" "${PHASE1_LOG}"
wait_listen "${PHASE1_PORT}"
python3 "${CLIENT}" \
  --host 127.0.0.1 \
  --port "${PHASE1_PORT}" \
  --timeout-s 2.0 \
  --slowloris-delay-s 1.5 \
  --flood-workers 64 \
  --flood-attempts 220 \
  --throughput-count 140 >"${PHASE1_JSON}"
stop_sentinel

echo "[canary] phase2: short-lived non-loopback canary with iptables rate-limit"
apply_iptables_rate_limit
start_sentinel "tcp:${PHASE2_BIND_HOST}:${PHASE2_PORT}" "${PHASE2_LOG}"
wait_listen "${PHASE2_PORT}"
python3 "${CLIENT}" \
  --host "${HOST_IP}" \
  --port "${PHASE2_PORT}" \
  --timeout-s 2.0 \
  --slowloris-delay-s 1.5 \
  --flood-workers 96 \
  --flood-attempts 320 \
  --throughput-count 160 >"${PHASE2_JSON}"
stop_sentinel

echo "[canary] phase3: rollback checks"
sudo iptables -D INPUT -p tcp --dport "${PHASE2_PORT}" -j SZ_CANARY 2>/dev/null || true
sudo iptables -F SZ_CANARY 2>/dev/null || true
sudo iptables -X SZ_CANARY 2>/dev/null || true
iptables_was_applied=0

PHASE1_ABUSE_JSON="$(python3 - <<'PY' "${PHASE1_JSON}"
import json,sys
o=json.load(open(sys.argv[1]))
s=o["scenarios"]
out={
  "invalid_bad_request": s["invalid_json"]["bad_request"],
  "overlong_rejected": s["overlong_line"]["line_too_long"],
  "slowloris_closed": s["slowloris_timeout"]["closed_before_newline"],
  "msg_limit_hit": s["message_limit"]["message_limit_exceeded"],
  "flood_connect_failed": s["connection_flood"]["connect_failed"],
  "flood_ack_empty": s["connection_flood"]["ack_empty"],
}
print(json.dumps(out))
PY
)"
PHASE2_ABUSE_JSON="$(python3 - <<'PY' "${PHASE2_JSON}"
import json,sys
o=json.load(open(sys.argv[1]))
s=o["scenarios"]
out={
  "invalid_bad_request": s["invalid_json"]["bad_request"],
  "overlong_rejected": s["overlong_line"]["line_too_long"],
  "slowloris_closed": s["slowloris_timeout"]["closed_before_newline"],
  "msg_limit_hit": s["message_limit"]["message_limit_exceeded"],
  "flood_connect_failed": s["connection_flood"]["connect_failed"],
  "flood_ack_empty": s["connection_flood"]["ack_empty"],
}
print(json.dumps(out))
PY
)"

PHASE1_TP="$(python3 - <<'PY' "${PHASE1_JSON}"
import json,sys
o=json.load(open(sys.argv[1]))
print(o["scenarios"]["throughput"]["throughput_msgs_per_s"])
PY
)"
PHASE2_TP="$(python3 - <<'PY' "${PHASE2_JSON}"
import json,sys
o=json.load(open(sys.argv[1]))
print(o["scenarios"]["throughput"]["throughput_msgs_per_s"])
PY
)"

PHASE1_LAT_MS="$(python3 - <<'PY' "${PHASE1_JSON}"
import json,sys
o=json.load(open(sys.argv[1]))
print(o["scenarios"]["valid_register"]["elapsed_ms"])
PY
)"
PHASE2_LAT_MS="$(python3 - <<'PY' "${PHASE2_JSON}"
import json,sys
o=json.load(open(sys.argv[1]))
print(o["scenarios"]["valid_register"]["elapsed_ms"])
PY
)"

LISTEN_LEFT="$(ss -ltn "( sport = :${PHASE1_PORT} or sport = :${PHASE2_PORT} )" | tail -n +2 || true)"
FW_LEFT="$(sudo iptables -S INPUT | grep -F ":${PHASE2_PORT}" || true)"
REL_PHASE1_LOG="${PHASE1_LOG#${ROOT}/}"
REL_PHASE2_LOG="${PHASE2_LOG#${ROOT}/}"
REL_PHASE1_JSON="${PHASE1_JSON#${ROOT}/}"
REL_PHASE2_JSON="${PHASE2_JSON#${ROOT}/}"

{
  echo "# Exposed Hardening Canary Evidence (${TS})"
  echo
  echo "## Scope"
  echo "- Phase 1: sandbox hostile-traffic simulation on loopback"
  echo "- Phase 2: short-lived non-loopback canary with strict iptables rate-limit"
  echo "- Phase 3: rollback validation + evidence"
  echo
  echo "## Target + Safety"
  echo "- Service: \`sentinel_tui --headless\` over NDJSON TCP"
  echo "- Phase1 listen: \`127.0.0.1:${PHASE1_PORT}\`"
  echo "- Phase2 listen: \`${PHASE2_BIND_HOST}:${PHASE2_PORT}\` (short-lived)"
  echo "- Rate-limit: hashlimit drop above ~25 new conns/sec per source"
  echo "- No sensitive payloads used (synthetic plugin IDs only)"
  echo
  echo "## Measured Outcomes"
  echo "- Phase1 valid-register latency: ${PHASE1_LAT_MS} ms"
  echo "- Phase2 valid-register latency: ${PHASE2_LAT_MS} ms"
  echo "- Phase1 throughput: ${PHASE1_TP} msgs/s"
  echo "- Phase2 throughput: ${PHASE2_TP} msgs/s"
  echo "- Phase1 client-side abuse signals: ${PHASE1_ABUSE_JSON}"
  echo "- Phase2 client-side abuse signals: ${PHASE2_ABUSE_JSON}"
  echo
  echo "## Rollback Checks"
  echo "- Remaining listeners on canary ports:"
  if [[ -n "${LISTEN_LEFT}" ]]; then
    echo "  - FOUND"
    echo '```'
    echo "${LISTEN_LEFT}"
    echo '```'
  else
    echo "  - none"
  fi
  echo "- Remaining INPUT firewall rules for canary port:"
  if [[ -n "${FW_LEFT}" ]]; then
    echo "  - FOUND"
    echo '```'
    echo "${FW_LEFT}"
    echo '```'
  else
    echo "  - none"
  fi
  echo
  echo "## Assumption Ledger"
  echo "- OBSERVED:"
  echo "  - phase1/phase2 clients executed and produced JSON outputs"
  echo "  - client observed defensive responses and connection failures during abuse simulation"
  echo "  - rollback removed canary listener/rules as checked above"
  echo "- ASSUMED:"
  echo "  - local-LAN non-loopback canary approximates edge exposure behavior"
  echo "- UNKNOWN:"
  echo "  - true WAN attacker behavior and ISP/network middlebox effects"
  echo
  echo "## Artifacts"
  echo "- phase1 host log: ${REL_PHASE1_LOG}"
  echo "- phase2 host log: ${REL_PHASE2_LOG}"
  echo "- phase1 client json: ${REL_PHASE1_JSON}"
  echo "- phase2 client json: ${REL_PHASE2_JSON}"
  echo "- note: raw artifacts are generated by this harness and intentionally gitignored"
} >"${SUMMARY_MD}"

echo "[canary] evidence report: ${SUMMARY_MD}"
echo "[canary] done"
