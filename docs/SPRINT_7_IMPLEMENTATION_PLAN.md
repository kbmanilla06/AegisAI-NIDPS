# Sprint 7 Implementation Plan — Explainability, Threat Intelligence, and MITRE Context

**Planning date:** 2026-07-15
**Status:** Planning only; owner approval required
**Target:** Sprint 7 — offline explainability, synthetic/bundled threat-intelligence context, and MITRE ATT&CK mapping
**Release boundary:** Sprints 0–9, IDS with simulated IPS
**Planning baseline:** public `main` at `1b62b035b3be5add1d5cf515c9558555f2eb81fb` (Sprint 6 implementation `e11f10398776ea0e348e4e2e2adc07a184759be9`)
**Synthetic boundary:** Gate 5S-A/B/C and Sprint 6 Gate 6A/6B evidence only; UNSW-NB15 acquisition remains blocked; no external network access

## 1. Entry-gate evidence

The Sprint 6 publication gate is satisfied:

- Sprint 6 implementation commit `e11f10398776ea0e348e4e2e2adc07a184759be9` is published on public `main` (Gate 6A anomaly, Gate 6B transparent fusion, Gate 6C completion review).
- Publication-documentation commit `1b62b035b3be5add1d5cf515c9558555f2eb81fb` is the current `origin/main` tip and current `HEAD`.
- Hosted CI Run #13 (`29397915436`) passed for the Sprint 6 implementation commit `e11f103`.
- Hosted CI Run #14 (`29398307144`) for the documentation commit `1b62b03` failed on attempt 1 (a pre-existing, environment-dependent disk-space flake in three Sprint 5 `tests/unit/test_dataset_acquisition.py` cases that require ≥50 GiB free) and **passed on attempt 2 (rerun)** with all three jobs green. Public `main` is green.
- **Working-tree note:** the tree is **not** fully clean at planning time. It carries one uncommitted documentation edit, `docs/SPRINT_6_COMPLETION_REPORT.md` (the Run #14 triage note from the prior session), plus this new planning document. No production code, migration, or fixture is modified. Implementation must not begin until the tree state is reconciled by the owner and a clean, separately reviewed starting point is confirmed.

This document is documentation-only. It authorizes no code, migration, model activation, online inference, real-dataset use, external network access, prevention capability, commit, or publication.

## 2. Governing material reconciled

This plan is reconciled against the complete governing documents and Sprint 5–6 evidence:

- `AegisAI-NIDPS-Master-Prompt.md` (Sprint 7 = explainability and threat intelligence)
- `AegisAI-NIDPS-Implementation-Guide.md` (§6 Sprint 7 procedure and exit gate)
- `docs/PRD.md`, `docs/REQUIREMENTS.md` (FR-009, DET-005, DET-006, ML-007, PRIV-004), `docs/USE_CASES.md` (UC-08 threat intelligence, AC-10/AC-12)
- `docs/BACKLOG.md`, `docs/DECISIONS.md`, `docs/DEFINITION_OF_DONE.md`
- `docs/DATABASE.md`, `docs/SCHEMAS.md`, `docs/ML_PLAN.md`, `docs/DETECTION_ARCHITECTURE.md`
- `docs/api/API.md`, `docs/architecture/ARCHITECTURE.md`, `docs/architecture/DATA_FLOW.md`
- `docs/threat-model/THREAT_MODEL.md` (TM-12, TM-13, TM-22, TM-39)
- `docs/TEST_STRATEGY.md`, `docs/DEPLOYMENT_STRATEGY.md`, `docs/RISK_REGISTER.md`, `docs/PREVENTION_SAFETY.md`
- `docs/SPRINT_5_*` plans/reports and `docs/SPRINT_6_IMPLEMENTATION_PLAN.md` / `docs/SPRINT_6_COMPLETION_REPORT.md`

Where older API/backlog/ML text describes future model, intelligence, or workflow routes, this plan treats those routes as proposed and does not infer implementation authority. `docs/BACKLOG.md`, `docs/ML_PLAN.md`, `docs/DATABASE.md`, `docs/SCHEMAS.md`, and `docs/api/API.md` status lines lag actual Sprint 5/6 delivery and must be reconciled during implementation, not silently.

## 3. Confirmed requirements and invariants

These are not new owner decisions:

1. The first release is Sprints 0–9: IDS with simulated IPS.
2. Explanations, intelligence matches, and MITRE mappings are **evidence, never prevention authorization** (ML-007, PREV-006, AC-10). No model, anomaly score, explanation, or indicator match executes or authorizes any action.
3. Detection, assessment/fusion, prevention policy, and prevention adapters remain separate; explainability and intelligence are additional evidence producers, not enforcement paths.
4. Canonical flow v1, `flow_features/1.0.0`, the 39 ordered model features, the seven provenance columns, Gate 5S-A/B/C hashes, and Sprint 6 Gate 6A detector/threshold and Gate 6B policy hashes are immutable inputs.
5. Labels, scenario family, group, partition, endpoint identity, exact event time, and raw vectors are never surfaced through explanations, intelligence output, or MITRE evidence.
6. Explanations and intelligence matching are **offline batch only**. No API/worker startup loads or activates a model; no request-time scoring; the Sprint 6 sealed test is not reopened or retuned.
7. Every explanation-method, explanation, intelligence source, indicator, match, MITRE catalog, and mapping is versioned, hash-bound, and auditable.
8. ONNX plus canonical JSON remains the only safe model-artifact direction; no pickle/joblib/Python-object loading. Explanation attribution over a model uses the approved ONNX runtime over synthetic vectors; no unsafe deserialization is introduced.
9. PostgreSQL is authoritative. Celery messages are JSON-only and carry bounded UUIDs only. Redis is coordination, never source of truth.
10. Controlled local artifacts use opaque references, mode-0600 atomic writes, SHA-256 verification, bounded size, and retention cleanup.
11. Sprint 7 must not mutate alerts, detections, rules, incidents, prevention state, network state, or firewall state. Alert/incident projection remains Sprint 8.
12. Threat intelligence in Sprint 7 is **synthetic/bundled fixtures only, with zero external network access**. Publisher/provider contact, live feeds, and external lookups are cancelled/deferred, consistent with the standing UNSW-NB15 and no-publisher-contact decisions (C-27–C-30).
13. Stale, expired, or single-source intelligence can never become enforcement authority and is never sole proof (TM-13, PREV-006).

## 4. Sprint 7 scope

### 4.1 Included after separate implementation authorization

- A strict, versioned explanation-method contract and per-result explanation contract for the reviewed synthetic supervised candidate (Gate 5S-B/C) and the Gate 6A anomaly candidate.
- Deterministic, offline batch explanation generation over synthetic training/validation reference vectors and the previously-locked Gate 6A test-evidence run, using the cheapest faithful method per model (Section 6). No model activation, no online inference, no test-set reopening.
- Analyst-readable explanation summaries that state association, not causation, and carry the mandatory synthetic limitation and false-capability flags.
- A strict, versioned threat-intelligence source and indicator contract with normalization, provenance, confidence, first/last seen, expiry, and permitted-use.
- **Bundled/synthetic** indicator import only (controlled server-side fixtures), expiry enforcement, allowlist-conflict handling, and conflicting-source display. No external feed fetch and no network egress.
- Deterministic, offline indicator matching over synthetic flow/feature provenance producing metadata-only match records. No alert or prevention side effect.
- A bundled, versioned MITRE ATT&CK technique catalog and qualified mapping contract attaching technique ID, rationale, evidence source, mapping version/date, and confidence.
- Optional, owner-gated wiring of the Sprint 6-reserved `intelligence` fusion source into a **new reviewed** ensemble policy version, strictly offline and non-authoritative (Section 9).
- Additive reversible PostgreSQL metadata (`0010_sprint7_explainability_intelligence`) for explanation methods/results, intelligence sources/indicators/matches, MITRE catalog/mappings, and Sprint 7 permissions.
- JSON-only UUID Celery tasks with resource, timeout, idempotency, reconciliation, and cleanup controls.
- Central RBAC, CSRF/Origin enforcement, creator/reviewer separation, safe append-only audit, controlled artifacts, and retention.
- Minimal metadata/aggregate-only APIs and dashboard views for explanation, indicator, match, and MITRE review, all carrying the exact synthetic limitation.
- Synthetic/hostile fixtures created before implementation, plus unit, contract, integration, security, migration, determinism, resource, Docker, Celery, frontend, accessibility, and simulation-only tests.

### 4.2 Explicitly excluded

- Real datasets, UNSW-NB15 acquisition, the `NUSW-NB15_features.csv`/`NUSW-NB15_GT.csv` candidates, mirrors, tokenized URLs, samples, packets, PCAPs, payloads, or any network download.
- **Any external threat-intelligence feed, provider lookup, DNS/WHOIS/reputation query, or outbound request; publisher or provider contact.** External-lookup interfaces may be reserved in contract only, disabled, with no enabled transport and no Celery task.
- Online or automatic inference, API request-time scoring/explanation, model loading at API/detection startup, or model activation.
- Alert creation or mutation, detection-rule mutation, incident creation, risk updates to existing alerts, prevention recommendations, policy execution, or firewall integration.
- Incident/SOC workflows and dashboards (Sprint 8) and prevention policy/adapter work (Sprint 9+).
- Full kernel/tree SHAP requiring loading a pickled/joblib estimator, custom operators, or any Python-object artifact; auto-retraining, auto-promotion, drift changes, or test-set retuning.
- Arbitrary indicator/artifact/URL upload, browser-supplied paths/URLs/model input, privileged containers, host networking, firewall capabilities, commit, or publication.

## 5. Proposed Sprint 7 gates

Implementation should use three explicit stop gates:

### Gate 7A — Offline explainability evidence
Freeze the explanation-method contract, the per-result explanation contract, the faithful-method selection per model, and the limitation text. Generate hostile/golden fixtures first. Produce deterministic offline explanations for the reviewed supervised and anomaly candidates over synthetic reference vectors and the locked Gate 6A evidence, bind them to model-version and method-version hashes, and produce explanation artifact/report hashes. Do not activate any model or reopen the sealed test.

### Gate 7B — Offline threat-intelligence and MITRE evidence
Freeze intelligence source/indicator contracts, expiry and allowlist-conflict behavior, the bundled MITRE catalog, and the mapping contract. Import only bundled/synthetic indicator fixtures with no network. Run deterministic offline matching over synthetic provenance, produce metadata-only match and mapping evidence, and (if owner-approved) create one new reviewed ensemble policy version that consumes the offline `intelligence` source non-authoritatively. Do not write alerts, incidents, or prevention state.

### Gate 7C — Completion review
Run the complete local gates, review the diff for scope and Critical/High issues, produce `docs/SPRINT_7_COMPLETION_REPORT.md`, and stop uncommitted. Publication and any later online/alert/prevention integration require separate owner authorization.

## 6. Explainability design (planning only)

### 6.1 Method selection (cheapest faithful method)
Explanations are computed **offline** and must be faithful without unsafe deserialization:

| Candidate | Global explanation | Per-instance attribution (offline) |
|---|---|---|
| Supervised baseline (logistic-type, if that is the reviewed Gate 5S-B/C candidate) | Coefficients captured as a hash-bound explanation artifact at review time | Exact deterministic linear contribution `coef_i × standardized_value_i` |
| Supervised tree/forest candidate | Model-native impurity feature importances captured as a hash-bound artifact | Bounded deterministic permutation or occlusion attribution computed via the approved ONNX runtime over synthetic vectors |
| Anomaly Isolation Forest (Gate 6A ONNX) | Deterministic permutation importance over the synthetic normal-reference population | Bounded deterministic occlusion/permutation attribution via the Gate 6A ONNX score over synthetic vectors |

The recommended default uses only (a) importances/coefficients already derivable from the reviewed candidate and (b) permutation/occlusion attributions computed through the existing ONNX inference path over synthetic vectors. This needs no Python-object load, no online endpoint, and no new native dependency. Full SHAP (kernel/tree) is **excluded by default** because faithful SHAP requires the estimator object, which the safe-format policy forbids loading; SHAP may be reconsidered only under a separately reviewed safe-reconstruction path.

### 6.2 Explanation contract
`ExplanationV1` is strict and immutable and binds:
- explanation-method version/hash and target model version/hash (stored together);
- source example identity as restricted provenance (synthetic example ID / window), never raw endpoints, labels, or full probability arrays;
- ordered top-K contributing features (feature key from `FEATURE_DICTIONARY_V1`, raw value, transformed meaning, direction, bounded magnitude, uncertainty);
- an analyst summary constrained to association language;
- determinism seed/settings and a canonical SHA-256 over the definition;
- machine-readable false-capability flags and the exact synthetic limitation.

K is bounded (recommended top-10). Non-finite attributions, missing model versions, or method/model hash mismatch fail closed. Explanations are never presented as causation, maliciousness, probability of attack, or prevention justification.

### 6.3 Safety
Explanation code cannot import or call alert, incident, prevention, shell, socket, or firewall interfaces. It reads only reviewed artifacts by opaque reference and synthetic vectors, and writes only bounded explanation metadata.

## 7. Threat-intelligence design (planning only)

### 7.1 Source and indicator contracts
`IntelligenceSourceV1` records a bundled source name, trust level, terms reference, and enabled flag. `IndicatorV1` is strict and immutable and records:
- indicator type (`ipv4`, `ipv6`, `domain`, `url`, `sha256`) with canonical normalization;
- a **normalized value hash** for privacy-sensitive types (raw value minimized per PRIV-004; small controlled display only where the value is itself synthetic/documentation-range);
- source reference, confidence, first/last seen, and mandatory `expires_at`;
- permitted-use flags that explicitly deny enforcement authority.

### 7.2 Import — bundled/synthetic only, no network
Indicators are imported only from controlled server-side fixtures shipped in the repository under documentation/synthetic ranges. There is no external feed client, no outbound transport, and no import route that accepts a URL or file from the browser. This mirrors the Sprint 5 no-network posture and the standing no-publisher-contact decision.

### 7.3 Expiry, allowlist conflict, and matching
- Expired indicators are excluded from any authority and are clearly marked stale; they may remain visible as historical context only.
- An indicator matching an allowlisted target is flagged `ALLOWLIST_CONFLICT` and cannot become authority; all conflicting sources are displayed.
- Matching is deterministic and offline over synthetic flow/feature provenance, producing `IndicatorMatchV1` metadata records (indicator ref, matched provenance ref, matched_at, state). No alert, incident, or prevention record is created or mutated.

## 8. MITRE ATT&CK mapping design (planning only)

A bundled, versioned `MitreTechniqueCatalogV1` (technique ID, name, tactic, catalog version/date, hash) ships in the repository; no live ATT&CK fetch occurs. `MitreMappingV1` attaches a technique ID to a deterministic detection signal or synthetic evidence class with mapping rationale, evidence source, mapping version/date, and confidence. Mappings are qualified: network behavior may indicate a technique but does not prove adversary intent (DET-006). Only defensible mappings for the existing deterministic rules and synthetic evidence classes are included; speculative mappings are excluded.

## 9. Optional fusion integration (owner decision)

Sprint 6 reserved but did not implement the `intelligence` fusion source. Sprint 7 may, only if the owner approves, implement it as an **offline, non-authoritative** evidence contribution:

- A new reviewed `ensemble_policy_versions` row (additive data; no schema change) that adds an `intelligence` source with a small predeclared weight, gated by expiry, confidence, and provenance completeness.
- Invariants preserved: absent/expired/single-source intelligence never contributes as authority; `automation_eligible=false` and `prevention_mode="simulation"` remain fixed; the assessment remains an offline sidecar and never mutates alerts or prevention.
- The existing Sprint 6 policy remains valid; the new version is a separate immutable policy with its own hash and review event.

Recommended default: **include** intelligence as offline evidence via one new reviewed policy version, because Sprint 7's purpose is to make intelligence usable as transparent context. If the owner prefers minimal scope, defer fusion wiring and ship intelligence + MITRE as standalone offline evidence only.

## 10. Evidence and provenance

Each explanation, indicator, match, and mapping binds to:
- accepted Gate 5S-A dataset/feature/split hashes and Gate 5S-B/C reviewed candidate hashes;
- Gate 6A detector/threshold and Gate 6B policy hashes (for explanations and any fusion wiring);
- explanation-method, intelligence-source, indicator, MITRE-catalog, and mapping version hashes;
- source synthetic example/flow/signal identities as restricted provenance;
- code commit and dependency/runtime lock hash;
- resource and task outcome metadata.

Reports and UI are aggregate. Restricted row-level explanation/match lineage may be stored for 30 days (matching prediction/flow retention) solely for deterministic replay and later Sprint 8 projection; it contains no endpoint addresses, payloads, labels, or raw vectors.

## 11. Lifecycle

- Explanation methods: `draft → reviewed → retired`. Explanations reference exactly one reviewed method and one model version.
- Intelligence sources and indicators: `imported → reviewed_synthetic → expired | retired`. There is no `active`/online state.
- MITRE catalog/mappings: `draft → reviewed → retired`; immutable definitions; a change creates a new version and review event.
- Any ensemble policy addition uses the existing `draft → reviewed → retired` lifecycle. Review requires a Security Administrator distinct from the creating System Administrator.

## 12. PostgreSQL migration design (planning only)

Proposed additive migration: `0010_sprint7_explainability_intelligence` (follows `0009_sprint6_anomaly_ensemble`).

Tables/metadata:
1. `explanation_method_versions` — immutable method/algorithm/config/target-model-compatibility/hashes, lifecycle, creator/reviewer, limitation flags, retention.
2. `explanations` — bounded per-result explanation sidecars linked to model version and method version; top-K attributions, direction/magnitude/uncertainty, provenance ref, version hashes, limitation flags, expiry; no endpoint/label/vector/full-probability fields.
3. `intelligence_sources` — bundled source name, trust, terms, enabled flag, review state.
4. `indicators` — type, normalized value hash, source ref, confidence, first/last seen, `expires_at`, permitted-use flags; unique by type/value-hash/source; expiry index.
5. `indicator_matches` — indicator ref, matched synthetic provenance ref, matched_at, state, conflict flags; no endpoint/payload fields.
6. `mitre_technique_catalog` — bundled immutable technique catalog with version/hash.
7. `mitre_mappings` — technique ref, evidence class/signal ref, rationale, mapping version/date, confidence; immutable definition.
8. Sprint 7 permissions and role grants.

Required constraints: immutable definition fields (PostgreSQL trigger), one reviewer distinct from creator, valid state transitions, hash/size/score bounds, one idempotency key per actor and operation, foreign-key lineage, no active/online model state, expiry indexes, and retention-safe cleanup. Downgrade refuses while explanation artifacts, indicators, or matches remain inventoried; after explicit cleanup/retirement it removes only Sprint 7 objects and preserves Sprints 0–6. Migration tests cover fresh upgrade, existing-data upgrade, downgrade refusal, cleanup, downgrade, re-upgrade, immutable-field mutation, concurrent review, and audit-failure rollback.

## 13. Celery tasks and resource limits

Registered JSON-only tasks carry one UUID only:
- `explainability.generate_batch(batch_id)` — bounded offline explanation generation; idempotent single retry after reconciliation.
- `intelligence.import_fixture(job_id)` — bundled fixture import only; no network; no automatic retry.
- `intelligence.match_batch(batch_id)` — bounded offline matching; idempotent single retry.
- `sprint7.reconcile()` — recover stale persisted jobs safely.
- `sprint7.cleanup()` — expiry cleanup with audit.

Proposed ARM64 host-aware defaults (aligned with Sprint 6): worker memory 4 GiB hard, CPU 2 cores, numerical threads 1, rows per batch 10,000 max, synthetic reference rows 7,200 max, explanation/report artifact 16 MiB, bundled indicator set ≤ 5,000 entries, soft/hard task time 300/360 s for explanation generation and 120/135 s for import/matching, PIDs 128, concurrency 1. Workers use late acknowledgement, prefetch 1, **no outbound network**, read-only root, no privilege/host network/capabilities, and controlled writable volumes only. A resource breach terminates the job, deletes partial objects, records a stable code, and never emits partial evidence.

## 14. Minimal APIs and UI (design only)

Proposed metadata/aggregate-only routes under `/api/v1`:

| Method/path | Purpose | Controls |
|---|---|---|
| `GET /explanation-methods` and `/{id}` | Method metadata | `explanations:read`, no artifact path |
| `POST /explanation-methods/{id}/review` | Review/reject method | `explanations:review`, creator separation, CSRF/Origin, audit |
| `POST /explanation-batches` | Request offline explanation batch | explicit permission, CSRF/Origin, idempotency, exact accepted hashes |
| `GET /explanation-batches` and `/{id}` | Status/counts/safe errors | authorized metadata only |
| `GET /explanations/summary` | Aggregate top-feature/direction distributions | `detections:read_metrics`, bounded filters, no raw vectors |
| `GET /intelligence/sources` and `/indicators` | Redacted source/indicator metadata | `intelligence:read`, value hashes only, expiry shown |
| `POST /intelligence/imports` | Import a bundled fixture set | `intelligence:import`, fixture name only (no URL/file), CSRF/Origin, idempotency, audit |
| `POST /intelligence/indicators/{id}/review` | Review/expire indicator | `intelligence:review`, creator separation, audit |
| `POST /intelligence/match-batches` and `GET .../{id}` | Offline match request/status | explicit permission, aggregate metadata only |
| `GET /mitre/techniques` and `/mappings` | Bundled catalog and qualified mappings | `mitre:read`, provenance shown |

There is no external-lookup route, arbitrary URL/file import, online explanation/score endpoint, activation route, alert/incident mutation route, prevention route, raw vector/endpoint export, or browser-supplied task/model/path input. The dashboard adds an authenticated offline-only view showing explanation/indicator/MITRE metadata, aggregate distributions, expiry/conflict state, source provenance, and the exact synthetic limitation. Controls hide or disable when the server permission is absent; the UI is never the authorization boundary.

## 15. RBAC, CSRF, and audit

Proposed permissions:

| Permission | Role(s) |
|---|---|
| `explanations:read` | Senior Analyst, Security Administrator, System Administrator, Auditor |
| `explanations:generate` | System Administrator (and Senior/Security Administrator per owner choice) |
| `explanations:review` | Security Administrator only |
| `intelligence:read` | SOC Analyst, Senior Analyst, Security Administrator, System Administrator, Auditor |
| `intelligence:import` | Security Administrator (and System Administrator per owner choice) |
| `intelligence:review` | Security Administrator only |
| `intelligence:match` | Senior Analyst, Security Administrator, System Administrator |
| `mitre:read` | SOC Analyst, Senior Analyst, Security Administrator, System Administrator, Auditor |
| `ensemble:review` (reuse) | Security Administrator only (for optional new policy version) |

Reviewers cannot review their own method/indicator/mapping/policy. Unsafe requests require the existing opaque session, session-bound CSRF token, exact allowed Origin, rate limit, and optimistic expected-state checks. Audit covers method/source/catalog creation and review, indicator import and expiry, match and explanation batch request/start/success/failure, allowlist-conflict detection, artifact-integrity failures, cleanup, and downgrade refusal. Metadata contains hashes, counts, versions, actor IDs, reason codes, and correlation IDs only — never paths, tokens, endpoint identities, raw indicator values, raw rows, exception text, or full probability vectors. Audit persistence failure fails closed for review and batch acceptance.

## 16. Retention and privacy

- Explanation artifacts: 30 days after rejection/final decision (candidate); reviewed method artifacts 180 days or until superseded plus rollback review.
- Row-level explanation and indicator-match sidecars: 30 days, matching prediction/flow retention.
- Indicators and MITRE catalog/mappings: retained by version under audit policy; expired indicators are excluded from authority and cleaned per policy.
- Aggregate reports and manifests: retained by version.
- Temporary partial artifacts: immediate deletion with bounded cleanup within 24 hours; no exceptional investigation holds for the MVP.

Raw endpoints, labels, payloads, vectors, and probability arrays are never in ordinary reports/UI. Sensitive indicator values are minimized to normalized hashes (PRIV-004). Small groups are suppressed or aggregated. Every surface carries the exact synthetic-demo limitation and machine-readable false-capability flags.

## 17. Security, privacy, and failure controls

### Security controls
- Treat explanation artifacts, indicator fixtures, MITRE catalogs, mapping text, and analyst summaries as hostile input; validate canonical JSON and reject unknown fields, oversized files, symlinks, traversal, non-finite tensors, and incompatible hashes.
- Use opaque server-side artifact references; no user path/URL/model/indicator-file input; no outbound socket in any Sprint 7 code path.
- Keep explainability/intelligence code unable to call alert, incident, prevention, shell, socket, or firewall interfaces; verify by dependency and OS-capability review.
- Verify all lineage hashes at every transition and quarantine on mismatch.
- Run dependency, SBOM, native-runtime, secret, container, and simulation-only checks; unresolved Critical/High findings block the gate.

### Privacy and claim controls
- Synthetic labels and synthetic indicators are non-semantic software-test constructs only.
- No UNSW-NB15, real-network, real-feed, production, zero-day, causation, or prevention-suitability claim is permitted.
- Aggregate-only API/UI/report output; restricted sidecar lineage has short retention and no endpoints.

### Failure behavior

| Failure | Required response |
|---|---|
| Method/model hash mismatch | Reject explanation batch; no partial output |
| Non-finite/out-of-range attribution | Reject source/batch per contract; never clip silently |
| Missing/corrupt/oversized artifact or fixture | Quarantine; no implicit fallback |
| Expired indicator used as authority | Rejected; marked stale; audit reason |
| Allowlist conflict | Flag `ALLOWLIST_CONFLICT`; deny authority; preserve evidence |
| Invalid source/mapping/version | Reject batch; audit stable reason |
| Any outbound-network attempt in a Sprint 7 path | Fail closed; treated as a Critical defect |
| Resource/time limit | Terminate, delete partial output, preserve safe counts |
| Duplicate/replayed task | Return existing authoritative status; no duplicate rows |
| Database/audit failure | No review/acceptance/state transition; fail closed |
| Worker crash | Lease/reconcile stale job; never duplicate a successful batch |
| Cleanup failure | Keep metadata, audit overdue item, retry boundedly |

## 18. Fixture-first and test matrix

Fixtures must be small, deterministic, synthetic, and created before implementation:
1. Reference, intrusion-like, novel-but-benign, constant-feature, empty, single-row, and non-finite vectors for explanation attribution.
2. Method-determinism, top-K-boundary, direction/magnitude, and uncertainty fixtures.
3. Valid/expired/malformed/duplicated/conflicting/low-confidence indicator fixtures across all indicator types; allowlist-conflict fixtures.
4. Bundled MITRE catalog and defensible/undefensible mapping fixtures.
5. Corrupt/oversized/wrong-hash/traversal/symlink artifact fixtures; hostile summary/mapping text, endpoint-like strings, Unicode/control, and redaction fixtures.
6. Duplicate/out-of-order/replayed batches and concurrent expected-state review cases.
7. Optional fusion fixtures: intelligence-present, intelligence-absent, intelligence-expired, and single-source cases proving non-authority.

Required gates:
- schema/hash/unknown-field and version compatibility;
- deterministic repeated explanation runs and method/model parity;
- offline-only proof (no network syscall) for import/match/explanation paths;
- expiry, allowlist-conflict, conflicting-source, and no-sole-authority behavior;
- exact evidence/provenance hash binding and no endpoint/label/vector/raw-indicator leakage;
- artifact operator/shape/external-data/size/path/integrity tests;
- Celery JSON-only UUID, idempotency, leases, crash/reconcile, resource, and no-network tests;
- RBAC role-matrix negative, self-review denial, CSRF/Origin, IDOR, rate limits, and audit fail-closed tests;
- migration upgrade/downgrade/re-upgrade and immutable constraints;
- retention cleanup and rollback-predecessor protection;
- Docker health, non-root/read-only/cap-drop/no-host-network, Celery registration, and simulation-only OS-state checks;
- frontend lint/type/build/unit/accessibility and limitation/false-flag assertions;
- secret, large-file, dependency, SBOM/Trivy or documented equivalent, and native ARM64 scans;
- if fusion wiring is approved: fusion truth-table extension proving intelligence never grants authority and expired/single-source cases add only uncertainty.

## 19. Resource, performance, and reproducibility evidence

Every run records code commit, dependency lock/SBOM hash, feature/preprocessing/model/method/catalog hashes, seed, thread settings, row/indicator counts, elapsed time, peak RSS, CPU, artifact size, and safe terminal status. Synthetic observations are not capacity, detection-performance, or intelligence-accuracy claims. The completion report must include measured host results for explanation generation, import, matching, and cleanup; failing a proposed limit rejects the run or requires a measured reduction and owner approval. Limits must not be raised silently.

## 20. Dependencies, assumptions, and deferred work

### Confirmed dependencies
- Published Sprint 6 baseline and hosted CI success (Run #14 attempt 2 green): satisfied.
- Accepted Gate 5S-A/B/C and Gate 6A/6B hashes and the synthetic-only limitation: satisfied.
- Canonical flow/feature v1, deterministic rules, reviewed supervised/anomaly candidates, RBAC/audit, controlled artifacts, Celery/Redis/PostgreSQL, Docker health: existing.
- ONNX runtime already present for Gate 6A: reused for offline permutation/occlusion attribution; no new native dependency required by the default explainability method.

### Assumptions
- Reviewed synthetic supervised/anomaly candidate metadata may be referenced only by persisted offline jobs; it is not active or online.
- Synthetic indicators and the bundled MITRE catalog are software-contract constructs, not real feeds or live ATT&CK data.
- Row-level explanation/match lineage may be stored for deterministic replay for 30 days without exposing it through ordinary APIs.
- Distinct System Administrator/Security Administrator accounts are the available technical separation in this solo project.

### Deferred work
- Real dataset acquisition, all publisher/provider contact, and any external threat-intelligence feed or lookup.
- Online inference/model activation, request-time explanation, and any live telemetry integration.
- Alert/incident projection and SOC workflows (Sprint 8); prevention policy/adapter (Sprint 9+).
- Full SHAP under a separately reviewed safe-reconstruction path; second explanation methods; drift/feedback learning; automatic promotion; real enforcement.

## 21. Decisions requiring owner approval

1. Approve the three-gate Sprint 7 boundary (7A explainability, 7B intelligence/MITRE, 7C completion review).
2. Approve synthetic/bundled-only evidence as the sole Sprint 7 input; keep UNSW-NB15 acquisition blocked, publisher/provider contact cancelled, and **all external intelligence lookups deferred with no network egress**.
3. Approve the default faithful explanation methods (coefficients/native importances plus offline permutation/occlusion via ONNX) and the exclusion of estimator-loading SHAP.
4. Approve the `ExplanationV1` top-K bound, direction/magnitude/uncertainty fields, and association-only summary constraint.
5. Approve the bundled indicator import model (fixtures only, no URL/file/network) and the normalized-value-hash privacy default.
6. Approve indicator expiry, allowlist-conflict, and no-sole-authority behavior exactly as defined.
7. Approve the bundled MITRE catalog and qualified mapping contract; approve which deterministic rules/synthetic classes receive defensible mappings.
8. **Decide whether to wire the offline `intelligence` fusion source into one new reviewed ensemble policy version (recommended) or defer it.**
9. Approve the additive reversible `0010_sprint7_explainability_intelligence` migration and downgrade-inventory refusal.
10. Approve the proposed permissions, creator/reviewer separation, and offline-only APIs/UI.
11. Approve the resource/time/artifact/indicator limits and retry policy.
12. Approve the exact mandatory limitation text and false-capability flags on every surface (Section 25).
13. Confirm Sprint 7 must not create or mutate alerts, detections, incidents, rules, model active state, or prevention records, and performs no network access.

No unanswered decision is inferred as approval.

## 22. Major risks and mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Explanation implies causation or real maliciousness | High | Association-only summaries, exact limitation, UI/report language tests |
| SHAP/estimator loading reintroduces unsafe deserialization | Critical | Default to ONNX-based permutation/occlusion; exclude estimator-loading SHAP; dependency/format review |
| Explanation attribution is nondeterministic | High | Fixed seed/settings, repeated-run hash tests, method/model hash binding |
| External intelligence lookup or feed fetch leaks internal data or adds SSRF surface (TM-12) | Critical | No transport, no URL/file input, offline-only fixtures, no-network tests, OS-capability review |
| Stale/single-source intelligence treated as proof (TM-13) | High | Expiry exclusion, confidence/provenance gating, no-sole-authority tests, allowlist-conflict flag |
| Indicator or endpoint data leaks through matches/reports | High | Normalized value hashes, no endpoint fields, aggregate APIs, 30-day expiry, redaction tests |
| Intelligence silently gains enforcement authority via fusion | Critical | `automation_eligible=false` fixed, non-authoritative weight, new reviewed policy hash, fusion truth-table tests |
| MITRE mapping overstates adversary intent | Medium | Qualified mappings, provenance, defensible-only inclusion |
| Offline evidence reaches alerts or prevention | Critical | Sidecar-only contract, dependency guard, no alert/prevention imports/writes, OS-state scan |
| Artifact replacement/path traversal/resource exhaustion | High | Opaque refs, mode-0600 atomic files, size/shape/path/hash checks, bounded workers |
| Native/supply-chain dependency issue | Critical | Pinned versions, SBOM, Trivy/equivalent, pip-audit, no unresolved Critical/High findings |
| Synthetic evidence presented as real NIDPS/feed effectiveness (TM-39) | High | Machine-readable false flags, exact limitation, no numeric/effectiveness claim, publication review |
| Scope expands into Sprint 8 | High | Explicit exclusions, migration/API boundaries, diff review, completion gate |

No Critical or High residual risk may be accepted silently; the completion report must name owner, evidence, review date, and disposition.

## 23. Proposed Sprint 7 acceptance criteria

Sprint 7 is complete only if every applicable criterion passes:
1. Published Sprint 6 SHA/CI and reconciled-tree entry evidence is recorded.
2. Synthetic/bundled-only source and mandatory limitation/false flags are proven; UNSW acquisition, provider contact, and external lookups remain blocked/deferred with no network egress.
3. Fixtures exist before explainability/intelligence implementation and contain no real data/feed/model artifacts.
4. Explanation-method and explanation contracts are immutable, hash-bound, and bound to model versions; attributions are deterministic and faithful.
5. Explanations are offline-only; no model is activated or loaded online; the Sprint 6 sealed test is not reopened or retuned.
6. Explanation output states association not causation and carries the exact limitation and false flags.
7. Intelligence source/indicator contracts are strict, versioned, and expiry-bound; import is bundled/fixture-only with proven no network access.
8. Expired, allowlisted-conflicting, and single-source indicators never become authority and are covered by tests.
9. Indicator matching and MITRE mapping produce metadata-only evidence and cannot create/mutate alerts, detections, incidents, rules, prevention, or network state.
10. If approved, intelligence fusion is a new reviewed offline policy version that never grants authority; otherwise fusion is untouched.
11. PostgreSQL migration `0010` upgrades, downgrades safely after inventory, and re-upgrades without orphaning prior metadata.
12. RBAC/CSRF/Origin, creator/reviewer separation, IDOR/redaction, audit, idempotency, retention, and cleanup tests pass.
13. JSON-only UUID Celery tasks, resource/time limits, crash reconciliation, no-network behavior, Docker security, and health gates pass.
14. Frontend quality/accessibility and exact limitation/false-capability assertions pass.
15. Formatting, linting, typing, unit/contract/integration/security/dependency/secret/SBOM/container/resource checks pass, with skips recorded honestly.
16. No Critical or High issue remains; no model is active or online; no real dataset/feed, capture, prevention capability, external network access, commit, or publication is introduced.
17. `docs/SPRINT_7_COMPLETION_REPORT.md` records hashes, commands, results, limitations, failures/skips, and the final gate decision.

## 24. Implementation sequence after authorization

1. Reconfirm public baseline, hosted CI, and a clean/reconciled inherited diff; preserve history.
2. Update only the affected design/threat/risk/schema/API/test/deployment records required by the approved plan (including the lagging status lines in Section 2).
3. Create hostile/golden explainability, intelligence, and MITRE fixtures before implementation.
4. Add strict contracts, manifests, limitation flags, and permissions.
5. Add migration `0010` and controlled artifact/reconciliation interfaces.
6. Implement Gate 7A explanation methods and offline attribution over synthetic vectors; bind method/model hashes; parity/determinism checks.
7. Stop and review Gate 7A explanation hashes.
8. Implement Gate 7B intelligence contracts, bundled import, expiry/allowlist-conflict handling, offline matching, bundled MITRE catalog/mappings, optional reviewed fusion policy, APIs/UI, and tests.
9. Stop before any alert/incident projection, model activation, online inference, external lookup, real dataset/feed use, or prevention work.
10. Run completion gates, update the completion report, review the complete diff, and stop uncommitted for approval.

## 25. Planning decision

**CONDITIONALLY READY FOR OWNER REVIEW.** The proposed design follows the master prompt's Sprint 7 definition (explainability, threat intelligence, MITRE) and its separation of detection, assessment, policy, and enforcement; preserves the accepted synthetic-only, offline, no-activation, no-network boundary; keeps explanations and intelligence strictly as evidence; and adds explicit stop gates. Implementation remains blocked until the owner approves the Section 21 decisions, reconciles the working tree, and supplies the exact Sprint 7 authorization.

## 26. Exact Sprint 7 implementation authorization prompt

```text
Approve all recommended defaults in docs/SPRINT_7_IMPLEMENTATION_PLAN.md and begin AegisAI NIDPS Sprint 7 using its three-gate boundary: Gate 7A offline explainability evidence, Gate 7B offline threat-intelligence and MITRE evidence, and Gate 7C completion review.

Before proceeding:
- Confirm public main contains Sprint 6 implementation commit e11f10398776ea0e348e4e2e2adc07a184759be9 and documentation commit 1b62b035b3be5add1d5cf515c9558555f2eb81fb.
- Confirm hosted CI Run #14 attempt 2 succeeded for 1b62b035b3be5add1d5cf515c9558555f2eb81fb and that the working tree contains only separately reviewed prior changes plus this authorized Sprint 7 work; reconcile the uncommitted Sprint 6 completion-report note first.
- Read all governing documents, Sprint 5/6 plans and reports, and docs/SPRINT_7_IMPLEMENTATION_PLAN.md completely.
- Do not rewrite published history.

Use only the accepted synthetic Gate 5S-A/B/C and Sprint 6 Gate 6A/6B evidence and bundled synthetic fixtures. Keep UNSW-NB15 acquisition blocked, publisher and provider contact cancelled, and all external threat-intelligence lookups deferred with zero network egress. Do not use real or third-party datasets, feeds, mirrors, tokenized links, samples, packets, PCAPs, payloads, or network downloads.

Approve these Sprint 7 defaults:
- Gate 7A/7B/7C boundaries as defined in the plan.
- Cheapest faithful explanation methods only: model-native importances/coefficients plus deterministic offline permutation/occlusion attribution computed through the existing ONNX runtime over synthetic vectors; no estimator-loading SHAP, no online endpoint, no model activation, and no reopening or retuning of the Sprint 6 sealed test.
- ExplanationV1 with bounded top-K attributions, direction/magnitude/uncertainty, association-only analyst summaries, and method/model hash binding.
- Bundled/synthetic threat intelligence only: strict IntelligenceSourceV1/IndicatorV1 contracts, fixture-only import with no URL/file/network input, normalized-value-hash privacy default, mandatory expiry, allowlist-conflict flagging, conflicting-source display, and no-sole-authority behavior.
- Deterministic offline indicator matching producing metadata-only records, and a bundled versioned MITRE ATT&CK catalog with qualified MitreMappingV1 mappings for defensible deterministic rules and synthetic evidence classes only.
- [Choose one] Wire the offline intelligence fusion source into one new reviewed ensemble policy version that never grants authority (recommended), OR defer fusion wiring and ship intelligence and MITRE as standalone offline evidence.
- Additive reversible migration 0010_sprint7_explainability_intelligence; distinct System Administrator creator and Security Administrator reviewer; JSON-only UUID Celery tasks; resource, timeout, retention, cleanup, audit, CSRF/Origin, and RBAC controls from the plan.
- Offline batch explanation, import, and match jobs plus aggregate/metadata-only APIs and UI. No online endpoint, model activation, API/detection startup load, external lookup, alert/detection/rule/incident/prevention mutation, or network state change.

Implement only Gate 7A, Gate 7B, and their tests/documentation. Create fixtures before implementation. Bind every explanation, indicator, match, mapping, and any new policy to the accepted Gate 5S-A/B/C and Gate 6A/6B hashes and exact feature/preprocessing/runtime hashes. Preserve the mandatory limitation text exactly:

SYNTHETIC DEMO ONLY. This dataset and its labels were generated by AegisAI scenarios to test software contracts. Results do not measure UNSW-NB15 performance, real-network intrusion detection, generalization, zero-day detection, production readiness, or prevention suitability. Explanations describe association within synthetic data, not causation or real-world maliciousness. Threat-intelligence indicators and MITRE mappings are synthetic or bundled fixtures, not real feeds or live lookups. The model is offline-only and cannot create or modify alerts or prevention actions.

Every explanation, indicator, match, mapping, metric, artifact, manifest, report, API response, and UI view must carry that limitation and machine-readable false-capability flags. Never claim real, production, zero-day, real-feed, causation, or prevention effectiveness.

Do not acquire/contact/download/read any real dataset or threat-intelligence feed; perform any external lookup or outbound request; fit on or retune the sealed test; activate/load a model online; create predictions or explanations through an online endpoint; mutate alerts, detections, rules, incidents, or prevention; configure live capture; add firewall integration; use privileged containers, host networking, firewall capabilities, or enforcement dependencies; begin Sprint 8 or later; commit; or publish.

Run and record all applicable formatting, linting, typing, unit, contract, determinism, explanation-parity, offline-no-network, expiry/allowlist-conflict, leakage, artifact-integrity, migration, RBAC-negative-matrix, CSRF/Origin, audit, idempotency, resource, retention, Docker, Celery, frontend, accessibility, dependency, SBOM/Trivy or documented equivalent, secret, large-file, health, and simulation-only checks. Stop at the uncommitted Gate 7C completion gate and wait for separate owner review/publication approval.
```
