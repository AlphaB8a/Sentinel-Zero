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
- Trust-root lifecycle operations:
  - `kernelkit profile rotate-trust-root ...`
  - `kernelkit profile audit-verify <audit_chain.ndjson>`
- Signed provenance/SBOM attestation:
  - `kernelkit profile attest-build ...`
  - `kernelkit profile verify-attestation <build.attestation.slsa.json>`

## IPC
Plugins connect via newline-delimited JSON (NDJSON) over a Unix socket.
See `docs/protocol/IPC_NDJSON_V1.md`.
