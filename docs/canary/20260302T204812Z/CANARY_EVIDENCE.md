# Exposed Hardening Canary Evidence (20260302T204812Z)

## Scope
- Phase 1: sandbox hostile-traffic simulation on loopback
- Phase 2: short-lived non-loopback canary with strict iptables rate-limit
- Phase 3: rollback validation + evidence
- Zero-residue policy contract: [ZERO_RESIDUE_POLICY.md](../../security/ZERO_RESIDUE_POLICY.md)

## Target + Safety
- Service: `sentinel_tui --headless` over NDJSON TCP
- Phase1 listen: `127.0.0.1:17777`
- Phase2 listen: `0.0.0.0:17778` (short-lived)
- Rate-limit: hashlimit drop above ~25 new conns/sec per source
- No sensitive payloads used (synthetic plugin IDs only)

## Measured Outcomes
- Phase1 valid-register latency: 0.543 ms
- Phase2 valid-register latency: 0.585 ms
- Phase1 throughput: 5433.461 msgs/s
- Phase2 throughput: 25.863 msgs/s
- Phase1 client-side abuse signals: {"invalid_bad_request": true, "overlong_rejected": true, "slowloris_closed": true, "msg_limit_hit": 1, "flood_connect_failed": 1, "flood_ack_empty": 128}
- Phase2 client-side abuse signals: {"invalid_bad_request": true, "overlong_rejected": true, "slowloris_closed": true, "msg_limit_hit": 1, "flood_connect_failed": 189, "flood_ack_empty": 202}

## Rollback Checks
- Remaining listeners on canary ports:
  - none
- Remaining INPUT firewall rules for canary port:
  - none

## Assumption Ledger
- OBSERVED:
  - phase1/phase2 clients executed and produced JSON outputs
  - client observed defensive responses and connection failures during abuse simulation
  - rollback removed canary listener/rules as checked above
- ASSUMED:
  - local-LAN non-loopback canary approximates edge exposure behavior
- UNKNOWN:
  - true WAN attacker behavior and ISP/network middlebox effects

## Artifacts
- phase1 host log: /vault/STUDIO/PROJECTS/STAGING/SENTINEL_ZERO/Sentinel-Zero/docs/canary/20260302T204812Z/phase1_sentinel.log
- phase2 host log: /vault/STUDIO/PROJECTS/STAGING/SENTINEL_ZERO/Sentinel-Zero/docs/canary/20260302T204812Z/phase2_sentinel.log
- phase1 client json: /vault/STUDIO/PROJECTS/STAGING/SENTINEL_ZERO/Sentinel-Zero/docs/canary/20260302T204812Z/phase1_client.json
- phase2 client json: /vault/STUDIO/PROJECTS/STAGING/SENTINEL_ZERO/Sentinel-Zero/docs/canary/20260302T204812Z/phase2_client.json
