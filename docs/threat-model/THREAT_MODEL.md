# STRIDE Threat Model and Security Backlog

**Scope:** Sprints 0–9 design; simulation-only prevention
**Method:** STRIDE plus abuse-case review
**Status:** Gate 5S-A review applied for closed synthetic generation, label separation, split/leakage evidence, claims, artifacts, worker limits, review RBAC, and retention boundaries

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
| TM-11 | T/E | Rule/threshold/model activation tampering | Blind spots or alert flood | Medium | High | Immutable complete definition hash/DB trigger, separate review/activation permission, expected-active locking, audit, regression evidence, rollback | Six-role denial, mutation, lifecycle, concurrent expectation, rollback tests | Low for deterministic rules; model path deferred |
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
| TM-27 | I/D | Sensitive or unbounded live alert notification | Endpoint leakage or client/broker exhaustion | Medium | High | Exact Origin/session/RBAC before upgrade and every 15 seconds, ID-only payload, 100-message client queue, revoked/expired/slow-client close, REST authorization/polling | WebSocket denial/revocation/contract tests and real Redis task check | Medium; representative fan-out load deferred |
| TM-28 | T/R | Duplicate, late, or reordered evidence rewrites alert history | False counts or lost provenance | High | High | Fixed UTC buckets, stable series/semantic/fingerprint hashes, DB uniqueness, append evidence, immutable snapshots | exact-rerun, out-of-order, late-evidence, cleanup tests | Low |
| TM-29 | T/R | Feature definition/order/window drift breaks reproducibility | Invalid training/inference evidence | High | High | Immutable schema/hash, closed implementation, stable tuple ordering, snapshot/vector/artifact hashes, PostgreSQL mutation trigger | Determinism, parity, mutation, schema-compatibility tests | Low for feature v1 |
| TM-30 | T/I | Labels, identities, or post-detection fields leak into model values | Inflated metrics or privacy exposure | High | High | Explicit denylist, identity used only for grouping/provenance, strict output column allowlist, no raw vector API/UI | Leakage fixtures and Parquet column inspection | Low for implemented path; split audit remains required |
| TM-31 | T/D/E | Malicious or corrupt feature artifact/path/native Parquet input | Tampering, traversal, outage, or unsafe future load | Medium | High | Opaque UUID object, controlled root, atomic mode-0600 write, non-executable Parquet, SHA-256 verify, byte/row/column/time caps, no client artifact import | traversal/hash/size tests, dependency audit, worker limits | Medium; native/container scan deferred |
| TM-32 | T/R | Unauthorized or self-review changes feature/dataset governance | Unreviewed data contract or dataset use | Medium | High | Security Administrator-only review/manage, CSRF+Origin, explicit fields, immutable definitions, complete audit | six-role denial and audit tests | Low for solo-project governance |
| TM-33 | R/T | Dataset metadata is mistaken for acquisition approval | Terms breach or unreviewed data use | Medium | High | acquisition=false, files empty, proposal API rejects files/acquisition, publisher review record, explicit raw-PCAP exclusion | API/migration/document review | Low until separate acquisition authorization |
| TM-34 | S/E/I | Malicious or redirected dataset URL reaches credentials, internal services, or unapproved hosts | SSRF, credential disclosure, data exfiltration | Medium | Critical | Query/userinfo/fragment-free HTTPS, exact server-side host allowlist, public-DNS and reported redirect-chain validation, no browser URL input, no enabled transport/task at pre-acquisition gate | URL/host/redirect/RBAC tests | Low before transport enablement; peer-IP pinning review required later |
| TM-35 | T/D | Dataset transfer exceeds approved bytes, time, disk, media, or integrity bounds | Disk/memory exhaustion or corrupted evidence | Medium | High | Exact advertised sizes, content-length/media checks, streaming caps/hash, 50 GiB reserve, deadline/retry limits, mode-0600 staging, atomic rename and failure cleanup | size/media/hash/deadline/storage tests | Low for synthetic orchestrator; real transport unimplemented |
| TM-36 | R/E | Proposal is treated as owner approval or acquisition actor accepts its own dataset | Unauthorized acquisition or governance bypass | Medium | High | Database state constrained to proposed, immutable proposal row, separate `datasets:acquire`/`datasets:accept`, no approval/transfer endpoint or Celery task, complete audit | six-role/CSRF/state/migration tests | Low at pre-acquisition gate |
| TM-37 | T/R | Synthetic label, scenario, group, or partition leaks into the model matrix | Misleading demo metrics or invalid evidence | High | High | Separate strict target sidecar; exact 39+7 selector; banned-column and perfect-separator checks; immutable hashes | contract, Parquet-column, leakage, and negative-selector tests | Low for Gate 5S-A; multivariate leakage remains later review |
| TM-38 | T/R | Related synthetic rows cross partitions or the test set is opened early | Inflated or non-reproducible demo evidence | High | High | Whole groups, non-overlapping time bands, stable identity hashes, exact/vector/group/rounded-vector checks, sealed-test flag | split ratio/support/duplicate/determinism tests | Low before model work |
| TM-39 | R/I | Synthetic evidence is presented as UNSW-NB15 or real-network performance | Portfolio credibility, governance, or terms harm | High | High | Machine-readable false flags, exact immutable limitation, no numeric performance claim, UI/report assertions, publication review | manifest/API/UI/diff tests | Low while uncommitted; owner review required |
| TM-40 | D/T/E | Synthetic generator/task/artifact path is abused for code, network, resource, or path actions | Outage, data exposure, or scope escape | Medium | Critical | Closed server catalog, fixed counts/seed, documentation addresses, no free-form/network input, UUID-only JSON task, 120/135-second limits, controlled mode-0600 root, non-root/read-only/cap-drop container | hostile contract, resource, path, Celery, Compose, and static dependency tests | Low locally; representative hard-kill/load evidence remains future hardening |

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
