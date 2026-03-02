#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

echo "[gate] cargo audit gate start"

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "[gate] cargo-audit missing; installing"
  cargo install cargo-audit --locked
fi

cargo audit >/tmp/sentinel_cargo_audit.out

if grep -q "warning:" /tmp/sentinel_cargo_audit.out; then
  echo "[gate] cargo audit warnings detected (non-vulnerability advisories)"
fi

echo "[gate] cargo audit PASS (no known vulnerabilities)"
