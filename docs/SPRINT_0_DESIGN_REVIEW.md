# Sprint 0 Design Review

**Date:** 2026-07-14
**Scope:** Design review, followed by separately authorized foundation work
**Decision:** APPROVED FOR THE AUTHORIZED SPRINT 0 FOUNDATION

## Findings

### High

- **DR-01 — Dataset use rights were incomplete.** Official UNSW terms permit academic research use, require citations, and require author agreement for commercial use. Corrected with an official-source review and a no-download/no-redistribution gate until repository visibility, license, and intended use are resolved.
- **DR-02 — Cookie-session design contradicted refresh-token API language.** Removed the refresh endpoint and specified opaque server-side sessions, secure cookie attributes, rotation/revocation, CSRF token, Origin validation, and exact credentialed CORS.

### Medium

- **DR-03 — Celery serialization security was unspecified.** Restricted tasks to JSON-only bounded envelopes and added threat/test requirements prohibiting pickle task serialization.
- **DR-04 — Approved choices were still labeled open.** Updated the decision register, architecture, deployment, PRD, ML plan, data flow, backlog, and planning report.
- **DR-05 — Retention was incomplete.** Flow, alert, audit, and upload periods are resolved; incident notes, reports, predictions, and exceptional holds remain open.
- **DR-06 — MVP breadth remains high for one developer.** Keep strict vertical slices and stop the public MVP at Sprint 9. External intelligence, offline PCAP depth, and advanced models should remain minimal until core deterministic workflows pass.

### Low

- **DR-07 — Model serialization remains undecided.** This does not block the initial scaffold if model loading is absent, but it blocks Sprint 5 artifact implementation.
- **DR-08 — Numeric performance and rate limits are intentionally unset.** Establish them from the declared development machine and representative measurements rather than inventing targets.

## Remaining design decision

Repository visibility, license/intended use, development-machine specification, and retention periods were resolved by the owner. Safe model serialization format remains deferred and blocks Sprint 5 model-artifact work, not Sprint 0 or Sprint 1.

## Residual risks

Dataset leakage/domain shift, false positives, unsafe parsers, RBAC/CSRF mistakes, Celery/broker exposure, artifact compromise, sensitive-data leakage, supply-chain compromise, scope pressure, and simulation capability drift. Controls are designed but unverified until implementation and tests exist.

## Approval boundary

The owner supplied all decisions needed for the foundation and separately approved its implementation. This approval does not authorize dataset acquisition, model training/loading, live capture, real prevention, Sprint 1 features, a commit, or publication.
