# Sentinel Zero: Authority Model and Due Diligence (2026-03-02)

## 1) What Sentinel Zero Is
Sentinel Zero is a governed runtime and promotion-verification authority for high-trust operational and creative pipelines.

At a system level, Sentinel Zero combines:
- Real-time runtime telemetry and plugin ingestion (`sentinel_core`, `sentinel_tui`, `sentinel_plugin_sdk`).
- Deterministic promotion verification (`kernelkit profile verify`) that is fail-closed.
- Cryptographically signed promotion receipts and trust-root validation.
- Tamper-evident audit chaining for promotion decisions.
- Signed build provenance/SBOM attestation surfaces.

Core design intent: promotion decisions are not based on claims; they are based on verifiable artifacts.

## 2) How Sentinel Zero Functions Inside KF and KA
This section describes role boundaries for integration.

### KF (Kinetic Foundry)
Within KF, Sentinel Zero acts as the policy and proof authority for promotion of governed runs.

Responsibilities in KF context:
- Verify that promotion artifacts match exact resolved plan and preflight outputs.
- Enforce `scope=sentinel-only-promotion` and active trust-root key requirements.
- Produce machine-readable verification reports (`after/verify.json`).
- Append immutable-sequence audit entries for promotion events.

Outcome: KF can use Sentinel as an objective promotion gate, not a discretionary toggle.

### KA (Kinetic Academy)
Within KA, Sentinel Zero acts as a reproducibility and assessment authority for labs/tracks.

Responsibilities in KA context:
- Verify student/operator runs against declared plan artifacts.
- Require signed receipts for "promotion-ready" status in coursework or operator certification exercises.
- Provide auditable pass/fail traces rather than subjective grading for operational correctness.

Outcome: KA can teach governance as a repeatable engineering discipline.

### KPF (Kinetic Proof Framework)
Sentinel Zero is the execution-side verifier that KPF can rely on for proof material quality.

Responsibilities in KPF context:
- Emit and verify receipt/trust-root/audit artifacts compatible with proof-first narratives.
- Support provenance/attestation packaging for downstream validation workflows.

Outcome: KPF gets cryptographically anchored, replayable evidence from Sentinel-controlled flows.

## 3) Sentinel Zero as a Standalone Authority
Sentinel Zero is designed to function independently of KF/KA branding.

As a standalone authority, it provides:
- Independent promotion verification (`kernelkit profile verify`).
- Independent receipt signing and trust-root lifecycle management.
- Independent audit-chain verification (`kernelkit profile audit-verify`).
- Independent build provenance verification (`kernelkit profile verify-attestation`).

This means third-party operators can use Sentinel Zero as a neutral control-plane verifier in non-KF environments.

## 4) Technical Functioning (Current)

### 4.1 Runtime and plugin boundary
- Transport: Unix sockets, TCP loopback, and enterprise `tcp+tls` / `tcps`.
- mTLS configuration via cert/key/CA environment variables.
- Host-side NDJSON parsing with enforced maximum line size (`SENTINEL_IPC_MAX_LINE_BYTES`), fail-fast behavior on over-limit lines.

### 4.2 Promotion verification path
`kernelkit profile verify <apply_dir>` validates:
- `plan.resolved.yaml` hash matches `resolved.sha256`.
- `preflight.json` hash integrity.
- Signed `promotion.receipt.json` integrity and scope.
- Trust-root key status and key-window validity.
- Plan ID and content hash matching between receipt and local artifacts.

Fail-closed behavior:
- Missing/invalid receipt or trust root fails verification.
- Non-active or out-of-window keys fail verification.

### 4.3 Audit chain
- Successful verify appends an NDJSON audit entry containing sequence, previous hash, and entry hash.
- Chain verification rejects tampering, sequence gaps, and hash mismatch.

### 4.4 Build provenance and attestation
- Build attestation includes signed provenance payload + SBOM output.
- Attestation verification checks scope/signature invariants for evidence integrity.

## 5) Due Diligence Evidence (Executed)

Recent hardening commits:
- `c7a81c4`: mTLS transport, audit chain, attestation, key lifecycle hardening.
- `5903904`: bounded IPC lines + strict KMS signer command contract.

Validation evidence:
- `cargo test --workspace`: PASS (repeated).
- `cargo clippy --workspace -- -D warnings`: PASS (repeated).
- Gates PASS:
  - `kernelkit_receipt_gate.sh`
  - `kernelkit_audit_chain_gate.sh`
  - `kernelkit_attestation_gate.sh`
  - `kernelkit_verify_perf_gate.sh`
- Stress reliability: 5 consecutive full sweeps passed (`FIVE_SWEEPS_OK`).

## 6) Enterprise Posture Against Approved Gap List

### Gap 1: Hardware/KMS-backed key lifecycle
Status: **Partially addressed**.
- Added source-aware key metadata, rotation epoch, validity windows.
- Added KMS command integration contract hardening.
- Remaining: direct cloud/HSM provider adapters, managed rotation orchestration.

### Gap 2: Signed provenance/SBOM/SLSA-style attestations
Status: **Substantially addressed (v1)**.
- Build attestation generation and verification paths exist.
- Remaining: formal SLSA level target definition + external verifier interoperability matrix.

### Gap 3: Authenticated + encrypted plugin transport (mTLS)
Status: **Addressed**.
- Added `tcp+tls`/`tcps` support with client cert auth on host and plugin.
- Remaining: cert issuance/rotation/revocation automation and operational runbooks.

### Gap 4: Tamper-evident audit log chain
Status: **Addressed (local chain model)**.
- Chained, hash-linked NDJSON log with verifier.
- Remaining: external immutable sink / remote witness anchoring for stronger non-repudiation.

### Gap 5: Broader testing depth and SLO gates
Status: **Improved**.
- Added new integrity gates and repeated sweep stress runs.
- Remaining: dedicated fuzz/property expansion beyond current receipt negative case, chaos/load suites with explicit SLO thresholds.

## 7) Use Cases Beyond KF/KA/KPF
Sentinel Zero can be deployed outside the AlphaBeta stack for:
- Regulated CI/CD promotion controls for infra changes.
- Media pipeline release governance where output proofs are mandatory.
- SOC/NOC operational change authority with cryptographic receipts.
- Vendor plugin ecosystems requiring mTLS and deterministic ingest controls.
- Academic or enterprise training programs requiring reproducibility-based competency gating.

## 8) Key Risks and Controls

Current risks:
- KMS integration currently command-contract based (not native provider SDK).
- Audit chain is local by default unless externally anchored.
- `cargo-audit` not installed in this environment during this pass.

Controls already in place:
- Fail-closed verification path.
- Strict signer command and signature-shape validation.
- mTLS transport support and explicit trust inputs.
- Tamper-evident audit-chain verification.
- Repeated test/clippy/gate sweeps.

## 9) Conclusion
Sentinel Zero is now a credible enterprise-oriented promotion authority core with meaningful cryptographic and transport hardening.

It is suitable today for governed internal production and controlled partner rollout.

For full enterprise maturity, next priority is operationalizing trust infrastructure (native KMS/HSM adapters, certificate lifecycle automation, and externalized immutable audit anchoring).
