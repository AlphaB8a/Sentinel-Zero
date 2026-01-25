# Sentinel Zero

Ironclad terminal system monitor with plugin sensor kits and an optional AI worker.

## Layout
- Sidebar + 70/30 main split
- Left: Dashboard (45%) / Processes (55%)
- Right: AI Console (60%) / Inspector (40%)

## Build
```bash
cargo build
cargo run -p sentinel_tui
```

## IPC
Plugins connect via newline-delimited JSON (NDJSON) over a Unix socket.
See `docs/protocol/IPC_NDJSON_V1.md`.
