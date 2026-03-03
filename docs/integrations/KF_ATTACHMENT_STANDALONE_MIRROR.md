# KF Attachment Plan (Standalone Mirror Mode)

## Goal
Attach Sentinel Zero to KF workflows without turning Sentinel into a dependent subsystem.

## Operating Principle
Sentinel remains standalone.
Attachment is one-way by mirrored evidence artifacts, not direct API coupling.

## Mirror Contract
Export command:

```bash
./scripts/integration/kf_mirror_export.sh \
  --apply-dir <kernelkit_apply_dir> \
  --out-dir docs/integrations/kf_mirror_exports
```

Exported bundle (`standalone_mirror_v1`) includes:
- `plan.resolved.yaml`
- `resolved.sha256`
- `preflight.json`
- `apply.sh`
- `rollback.sh`
- `promotion.receipt.json`
- `trust-root.json`
- `after/verify.json`
- `after/promotion_audit_chain.ndjson`
- `mirror_manifest.json` (sha256 + size for every mirrored file)

## Why Mirror Mode
- Prevents tight runtime coupling to KF internals.
- Preserves Sentinel as an independent verifier and audit authority.
- Allows deterministic replay and third-party verification from immutable artifact sets.

## Trust Boundary
- Sentinel produces and verifies artifacts locally.
- KF consumes mirrored outputs as read-only evidence.
- No Sentinel runtime control-plane calls from KF are required.

## CI/Sweep Enforcement
- `scripts/gates/kf_attachment_mirror_gate.sh` validates end-to-end mirror readiness.
- Gate is wired into CI and sweep suites alongside security and governance gates.

## Remaining Work (Roadmap)
- Mirror transport and retention policy between Sentinel and KF storage domains.
- Optional signing of `mirror_manifest.json` for cross-domain non-repudiation.
- KF-side ingestion validator (read-only) to enforce mirror schema and checksums.
