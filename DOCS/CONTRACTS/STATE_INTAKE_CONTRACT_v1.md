# STATE_INTAKE_CONTRACT_v1
Status: LOCKED v1
Purpose: Minimum required state for a governed autonomy sweep.
Audience: Operators, Orchestrators, Evaluators, and Gatekeepers.

## 1. Why this exists
High autonomy fails in two ways:
- Overconfidence without state (hallucinated execution).
- Paralysis from ambiguity (HALT loops).

This contract makes autonomy deterministic:
- If state is present and valid, the system proceeds.
- If state is missing or ambiguous, the system fails closed with explicit reasons.

## 2. Contract semantics
- The contract is a single JSON object conforming to the schema:
  `state.intake.contract.v1`
- Unknown fields are forbidden by default (`additionalProperties=false`).
- Missing required fields must hard fail.
- This contract is not a plan. It is the substrate for planning.

## 3. Required major sections
A) Identity & Run Context
B) Target System Snapshot (what is being worked on)
C) Authority & Execution Boundaries (what can/cannot be done)
D) Lane & Data Origin Policy (Verified Origin vs Quarantine)
E) Tooling & Runtime Inventory (local + hosted, with constraints)
F) Evidence Requirements (what must be produced to claim PASS)
G) Current State & Inputs (logs, diffs, artifacts, workorders)
H) Objectives & Acceptance Criteria (what "done" means)
I) Stop Conditions & Escalations (when to HALT or request human)
J) Optional: Research Pass Instructions (web citations mode)

## 4. Fail-closed doctrine
A sweep must not start if:
- Target is undefined
- Authority model is undefined
- Data origin policy is missing
- Evidence requirements are missing
- Execution environment is unknown
- Required inputs for the run are missing (e.g., workorders referenced but not present)

## 5. Outputs expected per sweep (minimum)
- PLAN
- OBSERVED / ASSUMED / PROPOSED separation
- EXECUTION (design-level unless logs provided)
- VALIDATION (exact commands + acceptance criteria)
- TRACEABILITY_MATRIX
- STATUS
- STATE_SAVE

## 6. Versioning
- v1 is additive-only.
- v2 may introduce optional fields but must preserve backward compatibility policies explicitly.

## 7. Operational usage
- Any sweep runner must validate this contract before running tests/gates.
- Every sweep log should capture the contract hash for traceability.
- Validation must fail closed with deterministic refusal codes.

## 8. Recommended hard-fail reasons (stable IDs)
- `STATE_INTAKE_MISSING_FIELD`
- `STATE_INTAKE_SCHEMA_INVALID`
- `STATE_INTAKE_AUTHORITY_AMBIGUOUS`
- `STATE_INTAKE_POLICY_MISSING`
- `STATE_INTAKE_EVIDENCE_POLICY_MISSING`
- `STATE_INTAKE_REFERENCED_FILE_MISSING`
- `STATE_INTAKE_QUARANTINE_EXPORT_VIOLATION`

## 9. Current implementation hooks
- Checker: `scripts/security/check_state_intake_contract.py`
- Positive gate: `scripts/gates/state_intake_gate.sh`
- Negative gate: `scripts/gates/state_intake_negative_gate.sh`
- CI integration: `.github/workflows/ci.yml` build job
- Sweep integration:
  - `scripts/sweeps/run_sandbox_suite.sh`
  - `scripts/sweeps/run_enterprise_sweeps.sh`
