# AegisAI NIDPS Post-MVP Gate P4 Implementation Plan

**Status:** Approved implementation basis — Gate P4 implementation remains uncommitted

**Scope:** Synthetic/offline deployment reproducibility and release assurance

**Plan baseline:** `720c5e33960212c6f2130e4ac1fe9a1948b5fcb2`

**Hosted CI:** Run `29594167997` — completed successfully for the plan baseline

**Predecessor:** `docs/POST_MVP_GATE_P3_COMPLETION_REPORT.md`

## 1. Executive decision

Gate P4 should prove that the already-built synthetic/offline, simulation-only
product can be reproduced safely from a clean checkout on the supported ARM64
development machine. It is a deployment and assurance gate, not a feature
sprint. The authoritative target is local, disposable Docker Compose; no
public, production, or laboratory enforcement deployment is in scope.

P4 must preserve the accepted Gate 5S-A/B/C evidence and the P1–P3 contracts.
It may add only the metadata or documentation required to record reproducibility
evidence. It must not alter accepted synthetic hashes, fit preprocessing, train
or activate a model, enable online inference, or change detection, alert,
incident, assessment, or prevention state.

The roadmap’s P5 portfolio demonstration remains a later, separately authorized
gate. P4 may provide a technical runbook and machine-readable evidence package,
but it does not authorize public release, screenshots, recordings, tags, or
portfolio publication.

## 2. Verified starting point

| Item | Confirmed value |
| --- | --- |
| Public `main` | `720c5e33960212c6f2130e4ac1fe9a1948b5fcb2` |
| Hosted workflow | Run `29594167997`, `ci`, completed with `success` |
| Current branch | `feat/sprint-9-prevention-simulation` |
| P3 publication | Recorded in `docs/POST_MVP_GATE_P3_COMPLETION_REPORT.md` |
| P3 publication CI | Run `29593691056`, successful |
| Working tree | Contains inherited Sprint 10 planning/preflight changes; they are outside P4 and must remain untouched |

The inherited Sprint 10 files are not a P4 dependency and must not be staged,
rewritten, deleted, or included in a later P4 commit. This planning document is
the only file created by the present planning request.

## 3. Confirmed requirements

The following requirements are inherited and are not open to reinterpretation:

1. The product remains synthetic-only and offline. Real and third-party data,
   UNSW-NB15/NUSW-NB15, mirrors, samples, publisher contact, and dataset
   acquisition remain blocked.
2. Simulation is the only prevention behavior. Real, automatic, firewall,
   host-state, socket, subprocess, packet, network-namespace, or privileged
   enforcement is prohibited.
3. Online inference, model activation, automatic training/promotion/retraining,
   and model/anomaly-only prevention remain disabled.
4. No model, anomaly result, monitoring result, feedback item, report, or
   reproducibility run may mutate alerts, detections, assessments, incidents,
   or prevention state.
5. Every synthetic artifact, report, API response, and UI surface carries the
   exact inherited synthetic-demo limitation text and machine-readable
   false-capability flags. No real-world performance or prevention claim is
   permitted.
6. Accepted Gate 5S-A/B/C hashes, feature/schema contracts, manifests, and
   evidence are immutable inputs. P4 must verify them, never regenerate or
   replace them.
7. Controlled local artifacts use opaque paths, PostgreSQL references, SHA-256
   integrity, mode-700 directories, mode-600 temporary files, and approved
   retention/cleanup. Existing defaults remain: flows 30 days, alerts/audit
   180 days, and feature/model/monitoring evidence 30 days where applicable;
   exceptional holds are disabled.
8. Authentication, secure server-side cookie sessions, RBAC, CSRF plus Origin
   enforcement, IDOR protection, safe errors, and complete audit records remain
   mandatory.
9. Celery messages remain JSON-only and UUID/server-reference based. No task may
   receive a URL, arbitrary path, executable payload, credential, or model
   bytes from a browser.
10. The local deployment must be bounded, recoverable, accessible, and safe to
    fail closed. Critical or High security findings block the gate.

## 4. Assumptions

- The P3-published Compose topology, image pins, dependency constraints, and
  health/readiness contracts are the starting point; P4 does not upgrade them
  merely for convenience.
- The supported authoritative environment is the owner’s ARM64 development
  machine (Apple M2, 8 GiB RAM, macOS 26.5.2, approximately 300 GiB available
  project disk). A different host may be used for diagnosis, but it cannot
  replace ARM64 evidence without an owner decision.
- P1 and P2 metadata APIs/reports and Gate 5S-C isolated offline scoring are
  stable enough to be exercised as read-only evidence sources.
- Reproducibility comparisons exclude explicitly non-deterministic fields such
  as run timestamps and host paths; all content hashes, counts, statuses,
  policy versions, and synthetic evidence identities must match exactly.
- No new migration, API, UI, or Celery task is needed by default. If
  implementation proves one necessary, it must be additive, reversible,
  metadata-only, and separately identified in the completion report.
- Dependency and image retrieval, if unavoidable, uses only approved registries
  and package indexes without credentials or dataset URLs; the reproducibility
  run itself must be repeatable from the recorded lock/pin set.

## 5. Proposed Gate P4 scope

### 5.1 Reproducibility evidence contract

Define a versioned metadata contract, proposed as
`deployment_reproducibility/1.0.0`, containing:

- baseline commit and branch identity;
- host architecture, operating-system version, Docker/Compose versions, and
  UTC run identity;
- Compose configuration hash and image digest for API, migration, worker,
  scheduler, and dashboard;
- Python, Node, native-library, CI-action, and report-tool lock/provenance
  identities;
- SBOM hashes and vulnerability-scan status;
- environment-template hash and a boolean proving that no credential was used;
- migration head, upgrade/downgrade/re-upgrade result, readiness result, and
  bounded resource configuration;
- accepted Gate 5S-A/B/C input hashes and output report/artifact hashes;
- two-run comparison status, exact mismatch categories if any, and safe reason
  codes;
- backup/restore and retention-cleanup evidence references;
- limitation text, false-capability flags, retention class, producer, and
  reviewer state.

The contract stores metadata and aggregate evidence only. It must never contain
raw flows, endpoint addresses, payloads, credentials, cookies, query strings,
internal paths, model inputs, stack traces, or dataset bytes.

### 5.2 Clean ARM64 environment run

The implementation should exercise, in a disposable Compose project and
controlled local artifact volume:

1. clean checkout and environment-template setup with no credentials;
2. pinned image verification and reproducible build/start;
3. migration upgrade, readiness, liveness, and dashboard checks;
4. bounded existing Celery worker/scheduler startup and task inventory;
5. read-only synthetic monitoring/report/scoring evidence generation using the
   accepted server-side artifacts;
6. deterministic quality, report, and evidence-hash comparison across two
   independent clean runs;
7. disposable PostgreSQL backup/restore and controlled-volume hash/path
   revalidation;
8. retention cleanup and safe handling of expired, missing, corrupt, partial,
   over-limit, or unavailable inputs; and
9. teardown that removes disposable containers, volumes, and temporary files
   without deleting retained project evidence outside the approved policy.

No run may open the sealed model test again, fit preprocessing, create a new
model, load an active model, produce online predictions, or write alert,
detection, incident, assessment, or prevention state.

### 5.3 Runtime isolation and posture evidence

P4 should record and test that all containers use non-root users where supported,
read-only roots where supported, dropped capabilities, bounded CPU/memory/PID
resources, internal service networking, and localhost-only published ports.
It must prove `privileged=false`, no host networking, no host filesystem or
Docker socket mount, no firewall capability, no packet/interface access, no
socket or subprocess enforcement path, and no unexpected outbound dependency.

### 5.4 Documentation and runbooks

Produce implementation evidence for:

- clean-machine quick-start and exact commands;
- dependency/image/SBOM provenance and vulnerability handling;
- migration, health, Celery, backup/restore, retention, and teardown runbooks;
- deterministic synthetic evidence comparison and mismatch triage;
- disk/memory/CPU/time failure handling and fail-closed recovery;
- local-only security and privacy boundaries;
- an evidence index linking hashes without exposing sensitive content.

These are technical runbooks, not a public portfolio release. P5 owns the final
demonstration, screenshots, recordings, and publication decision.

## 6. Explicit non-goals and prohibited changes

P4 must not:

- acquire, download, inspect, parse, or emulate UNSW/NUSW or any real dataset;
- contact the publisher or use mirrors, samples, tokenized URLs, or arbitrary
  network sources;
- activate, register for online use, load at API/detection startup, or score a
  model online;
- fit preprocessing, train/tune/calibrate a model, or change accepted Gate 5S
  evidence;
- add live capture, packet handling, interface monitoring, network namespaces,
  sockets, subprocesses, host-state/firewall integration, privileged
  containers, host networking, or enforcement dependencies;
- mutate alerts, detections, incidents, assessments, prevention simulations,
  rules, or analyst ground truth;
- add a public deployment target, external telemetry backend, automatic
  promotion/retraining, or a new Sprint/Gate 10 capability;
- weaken RBAC, CSRF/Origin, audit, retention, path, artifact, or limitation
  controls; or
- commit, push, tag, release, or publish anything under this planning request.

## 7. Workstreams and required evidence

| Workstream | Required result |
| --- | --- |
| Environment manifest | Versioned digest/lock/action/native-dependency inventory with SBOM hashes and no credentials |
| Clean start | Two disposable ARM64 Compose runs, migration/readiness/liveness/dashboard pass, bounded resources |
| Synthetic determinism | Accepted input identity unchanged; output/report hashes match under the comparison policy |
| Recovery | Disposable PostgreSQL and controlled-volume restore, hash revalidation, idempotent replay, partial-restore refusal |
| Retention | Expired evidence cleanup, lease/hold refusal, audit record, and no deletion outside policy |
| Isolation | Non-root/read-only/capability/resource/no-host-network/no-enforcement evidence |
| Security QA | Dependency/license/SBOM/CVE/secret/large-file/static capability checks with no unresolved Critical/High |
| Documentation | Reproducibility, recovery, teardown, failure, evidence-index, and limitations runbooks |

## 8. APIs, UI, migrations, and Celery boundaries

- Existing metadata-only APIs may expose a reproducibility run status, evidence
  hashes, safe failure category, and retention metadata. They may not expose
  paths, credentials, raw content, model inputs, or arbitrary execution.
- Existing dashboard views may show run status and aggregate evidence, but each
  view must display the exact limitation banner and all false-capability flags.
- No new write endpoint is proposed. Any administrative finalization or cleanup
  remains RBAC-protected, CSRF/Origin-protected, reason-required, and audited.
- No migration is proposed by default. If an evidence-record table is needed,
  use one additive reversible migration with downgrade refusal while populated,
  and verify upgrade/downgrade/re-upgrade in disposable PostgreSQL.
- Existing Celery tasks remain UUID-only, JSON-only, server-resolved, bounded,
  idempotent, and audit-visible. A reproducibility task must not accept a
  browser path, URL, file, command, shell text, or artifact bytes; a local
  offline command is preferred over adding a task.

## 9. Resource, failure, and recovery policy

- Enforce measured CPU, memory, PID, disk, row, artifact-size, queue, retry,
  concurrency, and wall-clock limits already documented by Compose and the
  applicable Gate 5S/P1/P2 contracts. Do not silently raise a limit.
- Missing dependencies, insufficient disk/memory, health failure, hash mismatch,
  unsafe container posture, unsupported architecture, stale input, or incomplete
  restore yields a sanitized `not_evaluable`/`failed_closed` result and blocks
  acceptance.
- Retries are bounded and idempotent by run UUID. Partial artifacts are
  quarantined or deleted safely; no partial result is treated as evidence.
- A mismatch in accepted input hashes is a hard stop, not an opportunity to
  regenerate synthetic data. A timestamp-only difference may be recorded as
  non-authoritative metadata; content differences fail the run.
- Teardown must be safe to repeat. Recovery must revalidate PostgreSQL references,
  artifact paths, SHA-256, size, schema, retention, and limitation flags.

## 10. Security, privacy, and supply-chain controls

1. Use allowlisted environment variables and redact secrets before persistence
   or display. No cookies, tokens, credentials, signed URLs, or host paths may
   enter logs or reports.
2. Keep service ports bound to localhost and verify no public bind, host network,
   privileged mode, Docker socket, firewall capability, or host-state mutation.
3. Re-run dependency/license, native ARM64 compatibility, SBOM, Trivy (or a
   documented equivalent), secret, large-file, static capability, and safe-error
   scans. Any unresolved Critical/High issue blocks P4.
4. Pin base images by digest, application dependencies and CI actions by reviewed
   versions, and report the exact architecture. A security update that changes
   an accepted hash requires a new owner review rather than silent replacement.
5. Keep reports aggregate-only and enforce redaction of endpoint addresses,
   analyst notes, payloads, internal paths, and model inputs.
6. Audit run creation, verification, finalization, failed-closed outcomes,
   cleanup, backup/restore, integrity failures, and administrative changes with
   actor, role, reason, correlation ID, before/after hash, and safe outcome.
7. Keep the exact limitation language and false-capability flags machine-readable
   on every stored artifact, report, API response, and UI surface.

## 11. Test and verification matrix

| Area | Required evidence |
| --- | --- |
| Scope/static | Diff allowlist; searches prove no dataset, capture, enforcement, activation, or public-network capability |
| Environment | Clean checkout, env-template, digest/lock verification, ARM64 Compose build/start |
| Health | API liveness/readiness, PostgreSQL, Redis, worker/scheduler, dashboard, bounded shutdown |
| Determinism | Two clean runs; exact input/output/report hash comparison and mismatch handling |
| Synthetic invariants | Gate 5S-A/B/C hashes unchanged; limitation text and all false flags present |
| Database | Upgrade, downgrade, re-upgrade, populated-evidence downgrade refusal, backup/restore, corruption/partial recovery |
| Artifacts | Opaque path, SHA-256, size/schema/reference, mode 700/600, retention and cleanup |
| Celery | JSON/UUID inspection, allowlisted tasks, bounded retries/time/resources, idempotency/concurrency |
| Security | Auth/RBAC-negative, IDOR, CSRF/Origin, session, audit, redaction, safe errors, capability scans |
| Supply chain | Lock/dependency/license, ARM64 native compatibility, SBOM, Trivy/equivalent, secret/large-file scans |
| Containers | Non-root, read-only, dropped capabilities, no privileged/host-network/socket/host mounts, localhost-only |
| Frontend | Lint, typecheck, build, tests, accessibility, limitation/flag visibility |
| Recovery | Teardown/restart, restore/revalidation, disk/memory/health failure, no partial evidence acceptance |

## 12. Dependencies and sequencing

P4 depends on:

- the public baseline and successful hosted CI recorded above;
- the final P3 report and its no-Critical/High disposition;
- accepted Gate 5S-A/B/C evidence and stable P1/P2 metadata/report contracts;
- the existing P3-pinned ARM64 Compose images and dependency constraints;
- a disposable ARM64 host with Docker Compose, sufficient disk, memory, and
  no requirement for credentials or external services; and
- owner approval of this plan and the exact P4 implementation prompt.

P4 must complete before any P5 portfolio demonstration. It does not depend on,
and must not unblock, Gate 10B/10C, real prevention, live capture, real data,
publisher contact, online inference, or public deployment.

## 13. Major risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Host-dependent hashes or native behavior | ARM64 authority, lock/pin manifest, two independent clean runs, explicit comparison policy |
| Image/dependency drift | Digest pins, lockfiles, SBOM/CVE evidence, review on any pin change |
| Reproducibility run leaks secrets or paths | Credential-free env template, field allowlists, redaction tests, safe errors |
| Partial restore or corrupt artifact appears valid | Transactional restore, SHA-256/schema/size revalidation, quarantine and fail closed |
| Disk/memory pressure on 8 GiB host | Existing limits, preflight reserve check, bounded cleanup, no silent limit increases |
| Retention cleanup deletes evidence needed for review | Policy/lease checks, dry-run report, audit, no exceptional holds |
| P4 scope drifts toward activation or enforcement | Static/runtime capability scans, write-path deny tests, strict diff allowlist |
| Technical evidence becomes a misleading portfolio claim | Limitation text, false flags, aggregate-only reports, P5 review gate |
| Tooling unavailable (for example Trivy) | Document unavailable checks accurately; do not claim them as passed; owner decides whether to install or defer |

## 14. Decisions requiring explicit owner approval

1. Approve Gate P4 as deployment reproducibility and release assurance only,
   with P5 portfolio work remaining separate.
2. Approve ARM64 local Docker Compose as the authoritative target and localhost-
   only exposure; approve no public or production deployment target.
3. Approve exact hash comparison for content/manifest/report evidence while
   excluding timestamps and host-specific paths from the comparison.
4. Approve the proposed `deployment_reproducibility/1.0.0` evidence contract
   and no new migration/API/UI/task unless implementation proves it necessary.
5. Reaffirm current retention defaults and no exceptional holds for P4 evidence.
6. Approve use of pinned registries/package indexes only for dependency setup,
   with no credentials, dataset URLs, publisher contact, or arbitrary downloads.
7. Approve the required zero-Critical/High supply-chain gate and the documented
   treatment of unavailable scanners.
8. Approve whether a technical demo runbook may be included in P4 while all
   screenshots, recordings, tags, and public portfolio publication remain P5.
9. Confirm no P4 decision may re-enable real data, live capture, online
   inference, model activation, automatic prevention, or public-network use.

## 15. Proposed Gate P4 acceptance criteria

Gate P4 is complete only if all criteria below pass or have an explicitly
owner-accepted non-security residual recorded in the completion report:

1. A clean ARM64 checkout starts the local Compose stack with no credentials,
   no public bind, successful migrations, liveness/readiness, dashboard access,
   bounded Celery, and repeatable teardown.
2. Image digests, dependency/native versions, CI action versions, Compose hash,
   and SBOM hashes are recorded; no unresolved Critical/High finding remains.
3. Two independent clean runs produce identical accepted input identities,
   synthetic aggregate evidence, report content hashes, statuses, and policy
   versions under the approved comparison policy.
4. Accepted Gate 5S-A/B/C hashes are unchanged and all synthetic limitation text
   and false-capability flags remain present everywhere.
5. Backup/restore, migration downgrade/re-upgrade, artifact revalidation,
   retention cleanup, teardown, and partial-failure recovery are evidenced.
6. RBAC, CSRF/Origin, IDOR, session, audit, redaction, artifact path/integrity,
   resource, idempotency, and safe-failure tests pass.
7. Container inspection proves non-root/read-only/capability/resource posture,
   no privileged mode, host networking, host mounts, Docker socket, packet,
   firewall, host-state, socket, subprocess, or enforcement capability.
8. Frontend quality/accessibility, health, dependency, secret, large-file,
   static capability, and simulation-only checks pass.
9. Documentation includes exact commands, tool versions, hashes, limits,
   failures/skips, recovery/teardown, retention, assumptions, and residuals.
10. Review confirms no code path activates a model, enables online inference,
    mutates alerts/detections/incidents, acquires data, contacts the publisher,
    or performs real/automatic prevention.

## 16. Deferred work and prohibited capabilities

The following remain deferred indefinitely or to a separately authorized gate:
P5 portfolio publication; real or lab enforcement; automatic prevention; live
capture; real/third-party datasets; publisher outreach; public-network
deployment; online inference; model activation; automatic retraining or
promotion; and any Sprint 11 work dependent on those capabilities.

## 17. Exact Gate P4 implementation authorization prompt

Use this prompt only after explicit owner approval of Section 14:

> Approve and begin AegisAI NIDPS Gate P4 implementation using
> `docs/POST_MVP_GATE_P4_PLAN.md`.
>
> Before proceeding, confirm public `main` is
> `720c5e33960212c6f2130e4ac1fe9a1948b5fcb2`, hosted CI Run `29594167997`
> completed successfully, the working tree is classified without rewriting or
> deleting inherited Sprint 10 files, and the accepted Gate 5S-A/B/C evidence
> remains unchanged. Read all governing documents, the final Gate P3 completion
> report, and this plan completely.
>
> Authorize Gate P4 only: clean ARM64 local Docker Compose reproducibility,
> pinned dependency/image/action and SBOM evidence, migration/health/Celery
> verification, deterministic synthetic/offline evidence comparison,
> disposable backup/restore and retention/cleanup evidence, runtime isolation,
> bounded-resource and safe-failure checks, metadata-only reproducibility
> evidence if required, and the associated runbooks, tests, and completion
> documentation. Use only accepted synthetic/offline artifacts and the existing
> simulation-only product.
>
> Preserve all Gate 5S-A/B/C hashes, exact synthetic-demo limitation text,
> machine-readable false-capability flags, 30/180-day retention policy,
> controlled-volume/SHA-256 artifact integrity, RBAC, secure cookie sessions,
> CSRF/Origin, audit, JSON-only UUID Celery, idempotency, and simulation-only
> guarantees. Fail closed on hash mismatch, unsafe container posture, missing
> health/dependency/resource evidence, partial recovery, or any unresolved
> Critical/High finding.
>
> Do not use real or third-party datasets, UNSW-NB15/NUSW-NB15, mirrors,
> tokenized links, samples, publisher contact, live capture, public networks,
> online inference, model activation, preprocessing fitting, training, tuning,
> calibration, automatic promotion/retraining, alert/detection/incident/
> assessment/prevention mutation, firewall or host-state integration, sockets,
> subprocesses, packets, privileged containers, host networking, Docker socket
> mounts, enforcement dependencies, Gate 10B/10C, P5, or Sprint 11. Do not
> create a public deployment, tag, release, commit, or publish anything.
>
> Run and record all applicable formatting, linting, typing, unit/integration,
> determinism, migration, backup/restore, retention, artifact, RBAC/IDOR,
> CSRF/Origin, audit, resource, Celery, Docker/isolation, dependency/license,
> SBOM/Trivy-equivalent, secret, large-file, health, frontend/accessibility,
> and simulation-only checks. Every evidence artifact, report, API response,
> and UI view must retain the exact limitation text and false-capability flags.
> Stop at the uncommitted Gate P4 completion gate and report files changed,
> hashes, commands/results, failures/skips, assumptions, residual risks,
> acceptance status, and the exact separate Gate P4 publication-review prompt.

## 18. Planning status

**IMPLEMENTATION COMPLETE — UNCOMMITTED REVIEW GATE.** The authorized work
creates no production capability, does not access data, and does not authorize
publication, model activation, online inference, or prevention action.
