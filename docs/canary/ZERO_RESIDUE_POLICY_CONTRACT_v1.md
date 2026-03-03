# Zero Residue Policy Contract v1

## Contract ID
- contract_id: SZ_ZERO_RESIDUE_CONTRACT_V1
- scope: canary / exposure simulations / short-lived listeners
- invariant: "Creativity can vary; validation cannot."

## Definition: Zero Residue
A canary/exposure run is "zero residue" when, after shutdown/rollback:

1. No process is listening on declared canary ports (default: `17777`/`17778`).
2. No persistence markers exist in readable firewall persistence config:
   - `/etc/nftables.conf` contains neither:
     - the marker string (`SZ_CANARY`), nor
     - the canary ports as tokens.
3. Repo hygiene:
   - evidence reports and harness tools are tracked
   - raw runtime logs and volatile phase outputs are not tracked

## Privilege Boundary Rule
If the operator is non-root, the live firewall state (`iptables`/`nft` ruleset) is:
- classified as `UNKNOWN`
- not asserted
- not grounds for failure

If the operator is root, the live firewall state must be checked and must not reference canary ports or marker.

## Required Evidence Artifact
A JSON receipt must be emitted by the checker:
- `receipt_type`: `sentinel_zero.zero_residue.v1`
- includes:
  - `ports`
  - `marker`
  - `is_root`
  - `checks[]`
  - `errors[]`
  - `overall_pass` boolean

Default tool:
- `scripts/security/assert_zero_residue.sh`

## How To Run (Local)
Non-root (acceptable; live firewall `UNKNOWN`):
- `./scripts/security/assert_zero_residue.sh "17777,17778" "SZ_CANARY" "docs/canary/zero_residue_receipt.json"`

Root (preferred for full closure):
- `sudo ./scripts/security/assert_zero_residue.sh "17777,17778" "SZ_CANARY" "docs/canary/zero_residue_receipt.root.json"`

## CI Requirement
CI must run the zero-residue assertion and publish the receipt artifact.
