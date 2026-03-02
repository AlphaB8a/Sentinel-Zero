# Session Log

Session ID: 9e38606b-e2a1-4276-b5f8-9975f24b3cf3

## Scope
- Stabilize Sentinel IPC + TUI/alerts + Bridge Mode harness.
- Add protocol v1.1 message types and ack shape.
- Add KernelKit v0.1 propose-only CLI stub with deterministic artifacts.
- Harden runtime gates (offline threshold override + alert transition logs).

## Changes (What Was Done)

### Sentinel protocol + core
- Added v1.1 protocol types and ack shape in `crates/sentinel_protocol/src/lib.rs` (Hello, Heartbeat, PushAlerts, AlertCard, Severity, Ack).
- Added new alert rules engine in `crates/sentinel_core/src/alerts/mod.rs` and exported module in `crates/sentinel_core/src/lib.rs`.
- Added disk free sampling using `sysinfo::Disks` in `crates/sentinel_core/src/engine/physics.rs` and plumbed `disk_free_pct` into `Snapshot`.
- Extended internal engine events in `crates/sentinel_core/src/engine/mod.rs` to include Hello/Heartbeat/Alerts.
- Updated IPC host to parse Hello/Heartbeat/PushAlerts and return Ack payloads with optional id echo in `crates/sentinel_core/src/engine/plugin_host.rs`.

### TUI + Bridge Mode
- Added `UiMode::Bridge` toggle with `b` keybind in `crates/sentinel_tui/src/main.rs`.
- Implemented Bridge layout with 6 panels + alerts list in `crates/sentinel_tui/src/ui/mod.rs`.
- Added canonical label constants and deterministic source priority (`host`, `demo.bridge`, `demo`) in `crates/sentinel_tui/src/ui/mod.rs`.
- Added `metrics_latest` adapter map and ingestion helpers in `crates/sentinel_tui/src/main.rs`.
- Injected host metrics (CPU load, RAM used, Disk free) into `metrics_latest` for Bridge Mode.
- Added alert diff logging via `AlertDiffTracker` from core; TUI only calls it during alert evaluation.
- Added PerfKit v0.1 proposal-only ActionCards in TUI runtime and rendered them in Bridge Mode Actions panel.
- Fixed TUI deprecation warnings: `f.area()` and `render_widget(&TextArea, ...)`.

### Demo plugins
- Rust demo plugin updated to send Hello, Register, canonical metrics, and heartbeats with ACK reads in `plugins/examples/rust_plugin_demo/src/main.rs`.
- Demo plugin identity set to `demo.bridge` for deterministic routing.
- Rust example plugin updated to honor `SENTINEL_IPC` and read ACKs; uses current-thread runtime.
- Python demo updated to honor `SENTINEL_IPC`, support unix/tcp, and read ACKs.

### IPC transport + spec
- Added listen spec parsing (`unix:` / `tcp:` / path shorthand) and transport selection in IPC host and SDK.
- Documented IPC NDJSON v1.0 in `docs/protocol/IPC_NDJSON_V1.md` (including optional id echo behavior).

### KernelKit v0.1 CLI stub (propose-only)
- Added new workspace member: `tools/kernelkit`.
- Implemented strict plan schema (deny_unknown_fields) in `tools/kernelkit/src/plan.rs`.
- Deterministic normalization in `tools/kernelkit/src/normalize.rs`.
- CLI stub in `tools/kernelkit/src/main.rs` for `profile apply` (propose-only), `verify`, `rollback`, `list`, `diff`.
- Deterministic artifact tree generation: resolved plan yaml, sha256, preflight.json, apply.sh, rollback.sh, before/after snapshots.
- Added example plan at `docs/kernelkit/examples/nomad.v0.1.yaml` for deterministic gate runs.

## Improvements
- Deterministic Bridge Mode metrics with strict label matching and explicit source priority.
- Offline threshold now configurable via `SENTINEL_OFFLINE_MS` (in core alerts).
- Alert transition logging (`ALERT_SET`/`ALERT_CLEAR`) is emitted by the core diff tracker; evaluator remains in the TUI loop.
- Headless mode now drains IPC events and runs periodic alert evaluation to emit `ALERT_SET`/`ALERT_CLEAR`.
- Ack responses now structured via `Ack` and include Hello response fields.
- PerfKit v0.1 ActionCards are proposal-only, computed in the TUI runtime, and rendered in Bridge Mode.

## Fixes
- Resolved TUI deprecation warnings (ratatui frame sizing, textarea widget rendering).
- Fixed ratatui/crossterm interop by using `ratatui::crossterm` types.
- Fixed IPC host acking to echo optional `id` field and respond consistently on parse errors.
- Resolved sysinfo disk API usage with `Disks` for 0.30.x.

## Runtime Verification (Observed)
- Headless host + demo plugin ACKs verified over unix socket; Hello ACK includes negotiated caps.
- Socket creation and IPC listen confirmed via `ss -xl`.
- Headless mode now computes alerts and should emit greppable `ALERT_SET`/`ALERT_CLEAR` transitions when conditions change; interactive Bridge Mode requires a real TTY and was not executed in this sandbox.

## Builds Executed
- `cargo build -p sentinel_tui` (required network for new tracing deps).
- `cargo build -p sentinel_plugin_sdk`.
- `cargo build -p sentinel_plugin_example_rust`.
- `cargo build -p sentinel_rust_plugin_demo`.
- `cargo build -p kernelkit` (required network for new deps).

## Network / Sandbox Notes
- Building new crates required network access for crates.io.
- Interactive TUI cannot run in this sandbox without a real TTY.
- Unix socket binds in `/tmp` require escalated permissions in this environment.

## Current Verification Gates (To Run Locally)
- `SENTINEL_OFFLINE_MS=3000` headless run + greppable `ALERT_SET/CLEAR` transitions.
- Interactive Bridge Mode (`b` toggle) with demo plugin to confirm panel values and alerts.
- Bridge Mode Actions panel: run demo plugin and confirm proposal-only ActionCards render under Alerts.
- KernelKit determinism: compare `resolved.sha256` across two propose-only runs using `docs/kernelkit/examples/nomad.v0.1.yaml`.

## End of Session Summary
- Protocol v1.1 types, core alert engine, IPC ack behavior, and Bridge Mode UI are implemented.
- Deterministic metrics adapter and canonical label routing are wired.
- KernelKit v0.1 propose-only CLI and deterministic artifact generation are in place.
- Alert diff logging now lives in core and is driven by `SENTINEL_OFFLINE_MS` for deterministic gate checks.

## 2026-03-02 Receipt Hardening Sweep
- Added strict cryptographic promotion receipt contracts and trust-root schema in `tools/kernelkit/src/plan.rs`.
- Added Ed25519 verification/signing utilities in `tools/kernelkit/src/receipt.rs`.
- Added strict fail-closed verifier path in `tools/kernelkit/src/verify.rs`:
  - `profile verify` now validates preflight/resolved hashes + signed receipt + trust-root key status.
  - Enforces scope: `sentinel-only-promotion`.
  - Emits deterministic `after/verify.json` report.
- Added `profile sign-receipt` command in `tools/kernelkit/src/main.rs` to produce:
  - `promotion.receipt.json`
  - matching `trust-root.json`
- Hardened policy enforcement in `enforce_policy`:
  - `forbid_remote_apply`
  - `require_tty_confirm`
  - `allowlist_only` path guard
- Added deterministic tie-break sorting in physics process rows (CPU desc, pid/name asc) in `crates/sentinel_core/src/engine/physics.rs`.
- Added deterministic PASS/FAIL tests for receipt verification and apply-dir verifier.
- Added enterprise CI guard: `scripts/gates/kernelkit_receipt_gate.sh` and wired into `.github/workflows/ci.yml`.

## 2026-03-02 Dependabot Remediation + Flip Checklist Hardening
- Resolved active vulnerability advisories detected by `cargo audit`:
  - `bytes` upgraded to `1.11.1` (RUSTSEC-2026-0007 remediation path).
  - `time` upgraded to `0.3.47` (RUSTSEC-2026-0009 remediation path).
- Removed `atty` usage from KernelKit and switched TTY checks to stable std API:
  - `std::io::IsTerminal` for stdin/stdout checks in `tools/kernelkit/src/main.rs`.
  - Dropped `atty` dependency from `tools/kernelkit/Cargo.toml`.
- Modernized TUI dependency chain to remove unsound `lru 0.12.x` path:
  - `ratatui` -> `0.30`
  - `crossterm` -> `0.29`
  - `tui-textarea` -> maintained `tui-textarea-2` package (`0.10.0`)
- Added dedicated security audit gate:
  - New gate script `scripts/gates/cargo_audit_gate.sh`
  - Wired into `.github/workflows/ci.yml`
- Updated release/flip checklist:
  - Added **Sentinel sink entry** checklist for `promotion_audit_chain.ndjson`.
  - Added explicit **evidence bundle pointers** (verify report, receipt, trust root, attestation, SBOM, due diligence docs).
- Integrity verification after remediation:
  - `cargo test --workspace` PASS
  - `cargo clippy --workspace -- -D warnings` PASS
  - all kernelkit gates PASS
  - `cargo audit` reports no vulnerabilities (one non-vulnerability unmaintained warning remains: `rustls-pemfile`).
- Repository audit note:
  - GitHub repo visibility confirmed as public (`AlphaB8a/Sentinel-Zero`, `isPrivate=false`).
