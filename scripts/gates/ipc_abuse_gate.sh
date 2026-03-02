#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

echo "[gate] ipc abuse gate start"

cargo test -q -p sentinel_core engine::plugin_host::tests::handle_stream_

echo "[gate] ipc abuse gate PASS"
