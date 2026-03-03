# Sentinel Zero Residue Policy Contract (v1)

## Purpose
This contract defines the minimum post-test state after hostile simulation or short-lived exposed canary runs.

## Zero-Residue Invariants
- No listeners on canary ports `17777` and `17778` outside active canary runtime.
- No active firewall markers for canary rule chain `SZ_CANARY`.
- No persistent firewall residue in common persistence files:
  - `/etc/iptables/rules.v4`
  - `/etc/iptables/rules.v6`
  - `/etc/sysconfig/iptables`
  - `/etc/nftables.conf`
- No raw runtime canary artifacts tracked in git (`phase*_client.json`, `phase*_sentinel.log`).

## Enforcement
- Script: `scripts/security/assert_zero_residue.sh`
- Receipt: JSON (`sentinel_zero.zero_residue_receipt.v1`) with:
  - check statuses (`PASS` | `FAIL` | `UNKNOWN`)
  - failed and unknown check lists
  - assumption ledger (`OBSERVED`, `ASSUMED`, `UNKNOWN`)
- CI guard runs the script in strict mode:
  - `--fail-on-unknown` enabled
  - pipeline fails on residue detection or unknown privileged state

## Local Verification Commands
```bash
ss -lntp | egrep ':17777|:17778' || true
lsof -iTCP -sTCP:LISTEN -P | egrep '17777|17778' || true
sudo iptables -S INPUT | grep 17778 || true
sudo nft list ruleset | grep 17778 || true
```

## Rollback Requirement
If any check fails:
- remove canary listeners
- remove `SZ_CANARY` INPUT hooks and chain rules
- rerun `assert_zero_residue.sh` until receipt status is `PASS`
