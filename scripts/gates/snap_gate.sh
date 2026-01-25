#!/usr/bin/env bash
set -euo pipefail

SNAP="alphabeta-sentinel"
HEADLESS_APP="$SNAP.sentinel-headless"
DEMO_APP="$SNAP.demo-plugin"
LOG="/tmp/alphabeta-sentinel-headless.log"
export SENTINEL_OFFLINE_MS=3000

echo "[1] Start headless..."
: > "$LOG"
snap run "$HEADLESS_APP" >"$LOG" 2>&1 &
HPID=$!
sleep 1

echo "[2] Run demo once..."
snap run "$DEMO_APP" || true
sleep 2

echo "[3] Wait for offline set..."
sleep 5

echo "[4] Run demo again to clear..."
snap run "$DEMO_APP" || true
sleep 2

echo "[5] Check logs for SET/CLEAR..."
grep -E "ALERT_(SET|CLEAR).*collector\\.offline\\.demo\\.bridge" "$LOG" | tail -n 40 || true

echo "[6] Stop headless..."
kill "$HPID" 2>/dev/null || true

echo "DONE"
unset SENTINEL_OFFLINE_MS
