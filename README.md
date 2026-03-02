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

## KernelKit Promotion Receipts (Cryptographic)
Sentinel promotion verification is fail-closed by default:

```bash
# 1) Generate propose-only artifacts
cargo run -p kernelkit -- --out-dir /tmp/kk profile apply docs/kernelkit/examples/nomad.v0.1.yaml --propose-only

# 2) Sign receipt + emit matching trust-root
cargo run -p kernelkit -- profile sign-receipt /tmp/kk/<apply-id> --signing-key-b64 "<base64-32-byte-ed25519-secret>" --key-id "root-ops-01"

# 3) Verify cryptographically (fails if receipt or trust-root missing/invalid)
cargo run -p kernelkit -- profile verify /tmp/kk/<apply-id>
```

Verification enforces `scope=sentinel-only-promotion`, signed payload integrity, trust-root key status, and writes `after/verify.json`.

## Enterprise Hardening Surfaces
- mTLS plugin transport mode: `tcp+tls:<addr>` / `tcps:<addr>`
  - Requires `SENTINEL_TLS_CERT_FILE`, `SENTINEL_TLS_KEY_FILE`, `SENTINEL_TLS_CA_FILE`
  - TLS key file permissions are enforced on Unix (no group/world access, no symlinks); override only for legacy setups with `SENTINEL_TLS_ALLOW_INSECURE_KEY_PERMS=1`.
  - Non-loopback TCP bind is denied by default; opt-in only with `SENTINEL_ALLOW_NON_LOOPBACK_BIND=1`.
  - Unix socket parent directory permissions are checked (owner-only by default); override only for legacy setups with `SENTINEL_IPC_ALLOW_INSECURE_DIR_PERMS=1`.
  - Optional hard limit override: `SENTINEL_IPC_MAX_LINE_BYTES` (range: `1024..=1048576`, default `65536`)
  - Optional read timeout override: `SENTINEL_IPC_READ_TIMEOUT_MS` (range: `1000..=300000`, default `30000`)
  - Optional per-connection message cap: `SENTINEL_IPC_MAX_MESSAGES_PER_CONN` (range: `1..=1000000`, default `10000`)
  - Optional concurrent connection cap: `SENTINEL_IPC_MAX_CONNECTIONS` (range: `1..=100000`, default `256`)
- Trust-root lifecycle operations:
  - `kernelkit profile rotate-trust-root ...`
  - `kernelkit profile audit-verify <audit_chain.ndjson>`
- Signed provenance/SBOM attestation:
  - `kernelkit profile attest-build ...`
  - `kernelkit profile verify-attestation <build.attestation.slsa.json>`
  - `--kms-sign-cmd` now requires an absolute executable path (no args), non-symlink, non-group/world-writable, and must return a 64-byte Ed25519 signature in base64.
  - KMS command invocation is stdin-closed and enforces bounded payload/signature size.

## Continuous Enterprise Sweeps
One command runs repeated deterministic sweeps and writes strict logs:

```bash
# default N=25 (must be in [15, 30])
./scripts/sweeps/run_enterprise_sweeps.sh

# explicit N
./scripts/sweeps/run_enterprise_sweeps.sh 15
```

Per-sweep logs are emitted to `docs/sweeps/Opt.Sweep_XX`.

## IPC
Plugins connect via newline-delimited JSON (NDJSON) over a Unix socket.
See `docs/protocol/IPC_NDJSON_V1.md`.
