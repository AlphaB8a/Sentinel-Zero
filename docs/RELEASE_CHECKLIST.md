# Release Checklist — v0.1.0

Status: in progress (manual gates pending)

## Versioning
- Tag: v0.1.0
- Commit: dd779c406cd0cfd746bc5d13b0f0a6b206e6e6d7

## Artifact Hashes
- target/release/sentinel_tui: 6357c44e8b0c6b77bcc225efe6c7d39ea9fe85901c33ff347017b80aaaaefa2d
- target/release/kernelkit: 59287b2965ce82e047dd41f71a766e08198361546241944400fcf1ddfebeb436
- alphabeta-sentinel_0.1.0_amd64.snap: 12deed294dcb48bff27f0efa4b2f7911b631250992a3552300014efc334945a4

## Gates
### Build / Lint
- [x] cargo fmt --all --check
- [x] cargo build --release
- [x] cargo test
- [x] cargo clippy --all-targets -- -D warnings
- [x] cargo audit gate (no known vulnerabilities): `./scripts/gates/cargo_audit_gate.sh`

### Sentinel Native Headless Gate
- [x] ALERT_SET collector.offline.demo.bridge @ 2026-01-25T01:30:21.713767Z
- [x] ALERT_CLEAR collector.offline.demo.bridge @ 2026-01-25T01:30:23.769029Z

### Interactive Bridge Mode (Manual)
- [ ] Press b toggles Bridge Mode reliably
- [ ] Alerts panel renders
- [ ] Actions panel renders under Alerts
- [ ] No auto-exec (proposal-only)

### KernelKit Determinism (Release Binary)
- [x] resolved.sha256 match across runs
- [x] resolved.sha256 (latest): 6206579687d08aae5a9742efffe61d078438187f5bc68922b39ee2ce92254968
- [x] signed promotion receipt gate (fail without receipt, pass with trusted signature)
- [x] trust-root enforcement (active key required, revoked key fails)

### Flip Checklist (Sentinel Sink + Evidence Bundle)
#### Sentinel Sink Entry
- [ ] Verify append in sink chain: `<apply_dir>/after/promotion_audit_chain.ndjson`
- [ ] Verify sink integrity: `cargo run -p kernelkit -- profile audit-verify <apply_dir>/after/promotion_audit_chain.ndjson`
- [ ] Record sink pointer in release notes (path + latest `seq` + `plan_id` + `key_id`)

#### Evidence Bundle Pointers
- [ ] Verify report pointer: `<apply_dir>/after/verify.json`
- [ ] Receipt pointer: `<apply_dir>/promotion.receipt.json`
- [ ] Trust root pointer: `<apply_dir>/trust-root.json`
- [ ] Build attestation pointer: `<attestation_dir>/build.attestation.slsa.json`
- [ ] SBOM pointer: `<attestation_dir>/sbom.cargo-metadata.json`
- [ ] Due diligence pointer: `docs/SENTINEL_ZERO_AUTHORITY_AND_DUE_DILIGENCE.md`
- [ ] Layman summary pointer: `docs/SENTINEL_ZERO_LAYMAN_SUMMARY.md`

### Snap Strict Confinement Gate (Manual sudo)
- [x] sudo snap install --dangerous ./alphabeta-sentinel_0.1.0_amd64.snap
- [x] ./scripts/gates/snap_gate.sh shows:
  - ALERT_SET collector.offline.demo.bridge @ 2026-01-25T03:38:17.705524Z
  - ALERT_CLEAR collector.offline.demo.bridge @ 2026-01-25T03:38:23.104185Z

## Notes
- Snap uses TCP 127.0.0.1:7777 inside strict confinement (expected).
- KernelKit remains GitHub-only (not bundled in snap).
