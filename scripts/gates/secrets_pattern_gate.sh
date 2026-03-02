#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

echo "[gate] secrets pattern gate start"

PATTERN='(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----)'

HITS="$(rg -n --hidden -S -g '!.git/' -g '!target/' -g '!snap/' -e "${PATTERN}" . || true)"
if [[ -n "${HITS}" ]]; then
  echo "[gate][FAIL] potential secret material detected"
  echo "${HITS}"
  exit 1
fi

echo "[gate] secrets pattern gate PASS"
