# Requirements Specification

**Status:** Approved baseline; implementation is sprint-gated
**ID convention:** FR functional, NFR quality, SEC security, PRIV privacy, DET detection, PREV prevention, ML machine learning.

## Functional requirements

| ID | Requirement | MVP priority |
|---|---|---|
| FR-001 | Manage users, roles, permissions, assets, and sensors | Must |
| FR-002 | Ingest normalized flows, Zeek logs, Suricata EVE JSON, and authorized offline PCAP jobs | Must |
| FR-003 | Validate, normalize, version, and deduplicate telemetry | Must |
| FR-004 | Normalize Suricata signature alerts | Must |
| FR-005 | Execute versioned behavioral rules with windows and evidence | Must |
| FR-006 | Train, register, activate, serve, and roll back supervised models under review | Must |
| FR-007 | Produce anomaly scores through a versioned detector | Must |
| FR-008 | Fuse signals into documented risk/confidence/severity outputs | Must |
| FR-009 | Store explanations, intelligence context, and MITRE mappings | Must |
| FR-010 | Manage alert status, assignment, notes, and false-positive disposition | Must |
| FR-011 | Group alerts into incidents with timelines and ownership | Must |
| FR-012 | Deliver live alert notifications over an authenticated bounded channel | Should |
| FR-013 | Preview and simulate policy-controlled prevention | Must |
| FR-014 | Record audit events for security-sensitive operations | Must |
| FR-015 | Produce controlled reports and health views | Should |

## Non-functional requirements

| ID | Requirement | Verification intent |
|---|---|---|
| NFR-001 | Reproducible local environment | Clean-machine setup test after scaffold approval |
| NFR-002 | Typed, modular interfaces | Static typing and contract review |
| NFR-003 | Safe failure and graceful degradation | Dependency/parser failure tests |
| NFR-004 | Idempotent ingestion and prevention simulation | Replay/concurrency tests |
| NFR-005 | Accessible web UI | Automated and manual accessibility checks |
| NFR-006 | Observable processing | Correlation IDs, metrics, health/readiness checks |
| NFR-007 | Bounded resource consumption | File, record, queue, time, memory, and rate limits |
| NFR-008 | Backward-compatible versioned contracts | Schema/model/rule compatibility tests |
| NFR-009 | Documented representative performance | Load profile and measured results; no invented targets |
| NFR-010 | Recoverable persistent state | Migration rollback and later backup/restore tests |

## Security requirements

| ID | Requirement |
|---|---|
| SEC-001 | Server-side RBAC enforces least privilege for every protected action. |
| SEC-002 | Passwords use a recognized adaptive hash; tokens/sessions expire and can be revoked. |
| SEC-003 | Login and sensitive endpoints have throttling and safe generic errors. |
| SEC-004 | Inputs are schema-validated; outputs are safely encoded. |
| SEC-005 | Database access is parameterized and mass assignment is prevented. |
| SEC-006 | Uploads are content/schema validated, renamed internally, isolated, and resource-limited. |
| SEC-007 | Secrets come from managed configuration and never enter source, logs, reports, or client bundles. |
| SEC-008 | CORS is allowlisted; CSRF protection is used when cookie authentication applies. |
| SEC-009 | Audit records cover identity, rules, thresholds, models, exports, alerts, incidents, and simulation. |
| SEC-010 | Dependencies, code, containers, and secrets are scanned in CI after implementation. |
| SEC-011 | Untrusted serialized model objects are never loaded without provenance/integrity and an approved safe format policy. |
| SEC-012 | Errors expose stable codes and correlation IDs, not stack traces or internal paths. |
| SEC-013 | Browser authentication uses opaque server-side sessions with secure cookie attributes, rotation, idle/absolute expiry, and revocation. |
| SEC-014 | Unsafe browser requests require a session-bound CSRF token and same-origin validation; credentialed wildcard CORS is prohibited. |
| SEC-015 | Celery uses JSON-only bounded task envelopes; pickle task serialization is prohibited. |

## Privacy requirements

| ID | Requirement |
|---|---|
| PRIV-001 | Collect network metadata rather than payloads by default. |
| PRIV-002 | Raw PCAP access is restricted and retention is configurable. |
| PRIV-003 | Sensitive addresses are masked or pseudonymized in exports/demos where practical. |
| PRIV-004 | External lookups are optional and disclose only the minimum indicator data. |
| PRIV-005 | Deletion/retention jobs preserve necessary audit integrity and legal constraints. |

## Detection requirements

| ID | Requirement |
|---|---|
| DET-001 | Every alert includes source, evidence, timestamps, category, and version references. |
| DET-002 | Initial behavioral scope covers scans, repeated failures, high connection rate, DNS volume, possible beaconing, and outbound volume. |
| DET-003 | Rules define thresholds/windows, false-positive considerations, investigation guidance, and tests. |
| DET-004 | Duplicate and alert-flood suppression are deterministic and observable. |
| DET-005 | Risk-scoring logic and contributing signals are documented and inspectable. |
| DET-006 | MITRE mappings are qualified and carry mapping provenance. |

## ML requirements

| ID | Requirement |
|---|---|
| ML-001 | Begin with Logistic Regression and Random Forest; add complexity only with measured value. |
| ML-002 | Training, validation, and untouched test data are separated without leakage. |
| ML-003 | Training and inference use the same versioned preprocessing. |
| ML-004 | Reports include per-class metrics, false positives/negatives, calibration, latency, throughput, memory, and limitations. |
| ML-005 | Model artifacts carry provenance, integrity, dataset, feature, runtime, and compatibility metadata. |
| ML-006 | Promotion and rollback require review; drift never auto-promotes. |
| ML-007 | Model confidence is evidence, never proof or prevention authorization. |

## Prevention requirements

| ID | Requirement |
|---|---|
| PREV-001 | Sprints 0–9 support simulation only and make no network changes. |
| PREV-002 | Detection, policy eligibility, and adapter execution are separate interfaces. |
| PREV-003 | Policy evaluates authorization, environment, target, allowlist, criticality, evidence, freshness, duration, rollback, duplicate, and rate constraints. |
| PREV-004 | Every request records reason, preview, gate results, policy version, expiration, and rollback metadata. |
| PREV-005 | Idempotency keys and uniqueness constraints prevent duplicate execution records. |
| PREV-006 | Anomaly-only and model-only evidence are never eligible for automatic prevention. |
| PREV-007 | Permanent actions and automatic enforcement are prohibited in the MVP. |
| PREV-008 | Simulation behavior is verified to leave operating-system firewall state unchanged. |

## Traceability and change control

Every backlog item references requirement IDs. Material requirement changes update the PRD, architecture, threat model, risk register, tests, and decision log before implementation.

## Assumptions and approvals

Confirmed scope is listed in `docs/PRD.md`. Open decisions are tracked in `docs/DECISIONS.md`; unapproved assumptions must not silently become security-sensitive behavior.
