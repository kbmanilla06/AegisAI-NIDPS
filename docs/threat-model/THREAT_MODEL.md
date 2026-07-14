# STRIDE Threat Model and Security Backlog

**Scope:** Sprints 0–9 design; simulation-only prevention
**Method:** STRIDE plus abuse-case review
**Status:** Sprint 2 review applied for the hostile upload, sensor, worker, artifact, and retention boundaries

## Assets

Credentials, permissions, sensor identity, telemetry, uploads, normalized events, alerts/evidence, incident records, rules/thresholds, datasets/features/labels, model artifacts, intelligence, prevention policies/previews, allowlists, audit records, reports, service availability, and portfolio credibility.

## Threat actors

Unauthenticated internet/local user, compromised sensor, malicious low-privilege user, malicious/compromised administrator, poisoned data/feed provider, dependency attacker, and accidental operator error.

## Severity method

Severity combines plausible impact and likelihood for the proposed local MVP. Critical/High items block implementation or release until controlled; residual severity assumes listed mitigations are implemented and verified.

## Threat register

| ID | STRIDE | Threat/path | Impact | Likelihood | Severity | Planned controls | Verification | Residual |
|---|---|---|---|---|---|---|---|---|
| TM-01 | S/T | Forged or replayed sensor events | False alerts/data pollution | High | High | Hashed rotatable sensor credential, active/source scope, canonical sensor-bound identity, unique ledger, replay idempotency | Forged/source-scope/duplicate/replay tests | Medium; no timestamp replay window yet |
| TM-02 | T/D/E | Malicious upload/parser exploit/zip bomb | Code execution or outage | High | Critical | Content+schema validation, no archive support/execution, opaque safe files, non-root/read-only worker, byte/record/flow/time/container limits | Deterministic fuzz, malformed/truncated/oversized/traversal/resource tests | Medium; native parser hardening remains |
| TM-03 | D | Telemetry/alert flood | Queue/storage/UI exhaustion | High | High | Per-identity Redis rate limit, request/record caps, deduplication, bounded queue consumers/query pages, delayed/failed metrics | Limit/rate/idempotency tests; real-stack task checks | Medium; representative load testing deferred |
| TM-04 | S/E | Credential theft or brute force | Unauthorized access | Medium | High | Adaptive hash, TLS, throttling, expiry/revocation, least privilege, audit | Auth abuse tests | Medium |
| TM-05 | E | RBAC or mass-assignment bypass | Sensitive changes | Medium | High | Central permission service, explicit fields, negative matrix tests | Per-endpoint role tests | Low |
| TM-06 | T | SQL/command/path/template injection | Data loss, code execution | Medium | Critical | Parameterization, typed schemas, no shell, internal paths, encoding | SAST and negative tests | Low |
| TM-07 | I | Stack traces/logs/reports leak secrets/data | Privacy/credential exposure | High | High | Stable errors, redaction, log schema, export RBAC | Log/error/report review | Low |
| TM-08 | T | Dataset/label poisoning | Misleading model and claims | Medium | High | Official source, checksum, manifest, access/review, quality analysis | Provenance and distribution checks | Medium |
| TM-09 | T | Train-test leakage/feature manipulation | Inflated metrics, poor detection | High | High | Source/time-aware splits, banned fields, parity/leakage tests | Split audit and feature review | Low |
| TM-10 | T/E | Artifact replacement or unsafe deserialization | Code execution/wrong model | Medium | Critical | Controlled format policy, checksum/signature, registry RBAC, compatibility checks | Corrupt/replaced artifact tests | Low |
| TM-11 | T/E | Rule/threshold/model activation tampering | Blind spots or alert flood | Medium | High | Versioning, approvals, audit, regression tests, rollback | Unauthorized/change regression tests | Low |
| TM-12 | I | External TI query leaks internal indicators | Privacy/intelligence exposure | Medium | Medium | Optional lookup, minimization, allowlisted providers, cache | Network/request review | Low |
| TM-13 | T | Stale/conflicting intelligence treated as proof | False positives/unsafe action | High | High | Expiry, confidence, provenance, conflict display, no sole authority | Expired/conflict tests | Low |
| TM-14 | R/T | Audit omission or tampering | Lost accountability | Medium | High | Append-oriented records, restricted mutation, fail-closed sensitive writes, backup | Mutation/omission and restore tests | Medium |
| TM-15 | E/T | Model directly reaches prevention | Unsafe network action | Low | Critical | Architectural separation, no adapter capability in MVP, contract tests | Dependency and OS-state review | Low |
| TM-16 | E/T | Allowlist/criticality bypass | Simulated unsafe recommendation; future outage | Medium | High | Authoritative assets, fail-closed policy, gate evidence, negative tests | Allowlist/internal/critical tests | Low |
| TM-17 | T/D | Duplicate or concurrent prevention requests | Repeated future action | Medium | High | Idempotency key, unique constraint, locking, status machine | Replay/concurrency tests | Low |
| TM-18 | T | Non-expiring/no-rollback policy | Future persistent outage | Medium | Critical | DB constraints, maximum duration, rollback metadata required, permanent action prohibited | Constraint/policy tests | Low |
| TM-19 | E | Unauthorized/self approval | Future prevention abuse | Medium | High | Explicit permissions and later separation of duties | Role/self-approval tests | Low |
| TM-20 | D/T | Dependency/queue/DB partial failure | Lost, duplicate, or inconsistent state | High | High | Atomic DB work, unique idempotency, late ack, bounded retries, dispatch failure state, engine lifecycle, degraded health | Queue failure, replay, repeated-task, cleanup and health tests | Medium; automated orphan reconciliation deferred |
| TM-21 | T/E | Compromised dependency/container/CI action | Supply-chain compromise | Medium | Critical | Pinning, lockfiles, scans, provenance, least-privilege CI, reviewed updates | SBOM/scans/workflow review | Medium |
| TM-22 | R/E | Malicious insider exports or alters sensitive data | Privacy/integrity loss | Medium | High | Least privilege, export audit/redaction, two-person review for sensitive future controls | Permission and audit review | Medium |
| TM-23 | D | Oversized model/explanation/report workload | Resource exhaustion | Medium | Medium | Size/time/memory limits, async jobs, pagination/cache | Stress/timeout tests | Low |
| TM-24 | T | Unsafe default enables enforcement | Network outage | Low in design | Critical | No real adapter/capability S0–9, simulation constant, configuration test | OS firewall diff and config tests | Low |
| TM-25 | S/T | CSRF or session fixation causes unauthorized state change | Sensitive configuration/data change | Medium | High | Secure opaque cookie, session rotation, CSRF token, Origin checks, exact CORS | CSRF, fixation, cookie, cross-origin tests | Low |
| TM-26 | T/E | Malicious Celery serialization/task envelope | Worker code execution or resource abuse | Medium | Critical | JSON-only serializer, task allowlist, bounded IDs, no pickle, broker isolation | Serializer/config and malformed-task tests | Low |

## Prioritized security backlog

1. **P0:** Enforce simulation-only architecture with no privileged/network enforcement capability.
2. **P0:** Define centralized RBAC and permission test matrix.
3. **P0:** Define safe upload/parser isolation and resource limits.
4. **P0:** Define model artifact provenance, safe-format, integrity, compatibility, and rollback policy.
5. **P0:** Add database invariants for idempotency, expiry, rollback metadata, version references, and state transitions.
6. **P1:** Add sensor authentication/replay protection and ingestion backpressure.
7. **P1:** Implement safe error/log schemas and audit fail-closed rules.
8. **P1:** Add dataset provenance, leakage review, and train/serve parity controls.
9. **P1:** Add supply-chain scanning/pinning and least-privilege CI design.
10. **P1:** Add retention/redaction and export controls.
11. **P0:** Implement cookie-session fixation/CSRF protections and an exhaustive cross-origin test matrix.
12. **P0:** Lock Celery to JSON-only messages and reject unregistered or oversized tasks.

## Security acceptance gates

- No Critical/High threat is accepted without an owner, mitigation, verification test, and explicit residual-risk decision.
- The threat model is updated before implementing a new trust boundary, input type, external integration, model format, or prevention capability.
- Sprint 9 release requires direct evidence that simulation changes no firewall/network state.
