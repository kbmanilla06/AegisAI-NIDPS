# Definition of Done

A task is done only when applicable items below have evidence.

## Requirement and design

- Acceptance criteria and requirement IDs are met.
- Scope/non-scope and assumptions are explicit.
- Architecture, threat model, schemas, and risk register are updated for material changes.

## Implementation quality

- Smallest coherent change; typed interfaces; no duplicate logic or unjustified architecture replacement.
- Inputs validated; errors stable/safe; logs structured and non-sensitive.
- Backward compatibility/version behavior documented.

## Verification

- Unit plus applicable negative, boundary, authorization, integration, concurrency, idempotency, migration, security, performance, and E2E tests pass.
- Formatting, lint, types, dependency/static/secret/container checks pass where configured.
- Commands and actual results are recorded; skipped checks are justified, not passed.

## Data/ML

- Provenance, licenses, manifests, leakage review, versions, metrics, card, compatibility, integrity, and rollback are complete where relevant.

## Prevention

- Simulation remains the only MVP mode.
- Allowlist, critical target, evidence, duration, expiry, rollback, audit, idempotency, and no-side-effect tests pass where relevant.

## Operations and delivery

- Migration forward/rollback and data preservation reviewed.
- Documentation/runbooks updated.
- Diff/staging reviewed; no secret, unauthorized data, large accidental artifact, or unrelated change.
- No unresolved Critical/High finding.
- Accurate Conventional Commit and rollback note proposed.

Sprint completion additionally requires every sprint acceptance criterion and an end-of-sprint report; incomplete tests/docs mean incomplete work.
