# Sweep Logs

`docs/sweeps/Opt.Sweep_XX` files are generated evidence logs from `scripts/sweeps/run_enterprise_sweeps.sh`.

## Policy Contract Link
- Zero-residue policy contract: [ZERO_RESIDUE_POLICY_CONTRACT_v1.md](../canary/ZERO_RESIDUE_POLICY_CONTRACT_v1.md)
- State intake contract: [STATE_INTAKE_CONTRACT_v1.md](../../DOCS/CONTRACTS/STATE_INTAKE_CONTRACT_v1.md)

## Notes
- Sweep logs are append-only evidence snapshots per run.
- Operational residue assertions are enforced by `scripts/security/assert_zero_residue.sh`.
- Fail-closed residue detection is continuously validated by `scripts/gates/zero_residue_negative_gate.sh`.
- Sweep execution is fail-closed on intake validity via `scripts/gates/state_intake_gate.sh`.
- Missing/incomplete intake behavior is validated by `scripts/gates/state_intake_negative_gate.sh`.
