# Prevention Simulation Safety Model

## Scope

Sprints 0–9 provide Level 0 observation and Level 1 simulation only. There is no real firewall adapter, privileged container, host networking capability, or production enforcement configuration.

## Separation

1. Detection answers what may be suspicious and why.
2. Policy evaluates whether a proposed defensive action would be eligible under documented gates.
3. The simulation adapter records what would occur, verification intent, expiration, and rollback metadata.

## Mandatory gates

| Gate | MVP behavior |
|---|---|
| Environment | Must equal controlled simulation |
| Authorization | Requester needs explicit simulation permission |
| Target validity | Canonical supported target; no arbitrary command/input |
| Internal/external | Unknown fails eligibility; internal receives stricter denial/default |
| Allowlist | Match denies proposal and records reason |
| Critical asset | Critical target denies or requires future high-impact workflow |
| Evidence | Referenced, current, versioned signals required |
| Model/anomaly-only | Always insufficient |
| Intelligence freshness | Expired intelligence ignored; never sole proof |
| Duration | Positive and below policy maximum; expiration mandatory |
| Rollback | Structured rollback metadata mandatory |
| Duplicate/replay | Idempotency and unique request/execution checks |
| Rate/cooldown | Evaluated even in simulation to validate future design |

## Adapter contract

- `validate`: validate typed proposal and mode.
- `preview`: return a safe structured representation, not an executable shell string.
- `execute`: persist a `simulated` result only.
- `verify`: confirm the simulated record and confirm no real side effect path was invoked.
- `rollback`: record simulated reversal.
- `status`: return lifecycle and audit references.

## State machine

Draft → Evaluated → Rejected or Previewed → Simulated → Expired/Rolled back. Invalid or skipped transitions fail. Replays return the existing result or a conflict; they never create a second execution.

## Required invariants

Simulation is default; models cannot execute; corroboration is required by policy design; allowlists are checked; critical assets are stricter; duration/rollback/audit are mandatory; high-impact/permanent/automatic actions do not exist in MVP; every gate result and policy version is stored.

## Verification evidence for Sprint 9

- Dependency graph contains no real enforcement adapter.
- Runtime containers lack privileged/host-network/firewall capabilities.
- Before/after host firewall state is identical during the E2E simulation suite.
- Allowlist, critical-target, model-only, anomaly-only, expired-intelligence, missing-duration, missing-rollback, replay, duplicate, concurrency, and expiry tests pass.

## Later work

Approval-based lab enforcement is a separately approved Sprint 10 design. This document grants no authority to implement or test it.
