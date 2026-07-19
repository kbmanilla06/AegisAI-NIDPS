# AegisAI NIDPS Post-MVP Gate P5 Implementation Plan

**Status:** Planning only — owner approval required before implementation
**Baseline:** Public `main` at `2e4e3a6d9c927b731237de20847214e75f6a31e8`
**Hosted CI:** Run `29675999780` passed
**Predecessor:** `docs/POST_MVP_GATE_P4_COMPLETION_REPORT.md`
**Scope:** Portfolio documentation and a reproducible synthetic/offline demonstration

## 1. Executive decision

Gate P5 is the final portfolio-evidence gate for the AegisAI NIDPS
synthetic-only MVP. It packages the already accepted Sprints 0–9 and post-MVP
P1–P4 evidence into a clean-checkout demonstration that is understandable,
repeatable, and honest about its limits. It does not add detection, model,
monitoring, inference, or prevention capability.

The default outcome is a local, credential-free demonstration using only
project-generated synthetic artifacts and the existing simulation adapter.
Portfolio publication is a separate owner decision. No screenshot, recording,
tag, release, commit, repository upload, or public hosting is authorized by
this plan.

## 2. Verified starting point

| Item | Confirmed value |
|---|---|
| Public `main` | `2e4e3a6d9c927b731237de20847214e75f6a31e8` |
| Hosted CI | Run `29675999780` passed (`ci`) |
| Gate P4 | Published; reproducibility and release-assurance evidence complete |
| Synthetic evidence | Gate 5S-A/B/C hashes accepted and unchanged |
| Prevention | Simulation only; no real or automatic enforcement |
| Dataset status | UNSW-NB15 acquisition blocked; publisher outreach cancelled |
| Working-tree inheritance | Sprint 10 planning/preflight files remain outside P5 scope and must be preserved |

The working tree is not treated as a clean P5 implementation workspace until
the inherited Sprint 10 files are classified or isolated. They must not be
deleted, rewritten, staged, or included in a P5 change.

## 3. Confirmed requirements

The following are fixed by the master prompt, implementation guide, roadmap,
and accepted prior gates:

1. The portfolio target is an academic/portfolio synthetic simulation, not a
   production NIDPS or a claim of real-world detection performance.
2. Only project-generated synthetic canonical-flow-v1 evidence may be used in
   the demonstration. No real or third-party dataset, sample, PCAP, mirror, or
   UNSW/NUSW file may be accessed.
3. Publisher outreach remains cancelled and UNSW-NB15 acquisition remains
   blocked.
4. Live packet capture, interface monitoring, public-network deployment, and
   online inference remain absent.
5. Models and anomaly evidence remain offline/non-activating. No model may be
   loaded by API or detection startup, promoted automatically, or used to
   mutate alerts, detections, incidents, assessments, or prevention state.
6. Prevention remains simulation-only. No firewall, host-state, socket,
   subprocess, packet, network-namespace, privileged-container, or enforcement
   capability may be introduced.
7. Existing accepted Gate 5S-A/B/C hashes, feature contracts, retention rules,
   limitation text, machine-readable false-capability flags, RBAC,
   CSRF/Origin, audit, artifact-integrity, and JSON-only UUID Celery controls
   are immutable inputs.
8. Every portfolio-facing artifact and view must visibly state the exact
   synthetic-demo limitation and expose the false-capability flags.
9. Raw payloads, credentials, cookies, tokens, internal paths, signed URLs,
   unrestricted endpoint lists, and analyst-note text must not appear in
   portfolio materials.
10. Any P5 implementation must end at an uncommitted completion gate and
    require a separate review/publication approval.

## 4. Scope

### 4.1 In scope for a later implementation authorization

- A clean-checkout quick start that uses `.env.example`, local Docker Compose,
  synthetic fixtures, and no credentials or external services.
- A scripted, deterministic demonstration of ingestion/review, deterministic
  detection evidence, offline synthetic model/anomaly evidence, monitoring and
  aggregate reporting, analyst feedback metadata, and simulated prevention.
- Portfolio-safe README sections, architecture/data-flow/threat-model visuals,
  sprint/gate history, decision history, model/data/feature/monitoring cards,
  limitations, test/security/SBOM/performance/recovery summaries, and a
  troubleshooting/runbook index.
- Sanitized screenshots or a short recording captured only from the local
  synthetic demo, subject to a redaction checklist and owner approval.
- Reproducibility checks that compare accepted hashes, report identities,
  limitation flags, and expected aggregate outputs without reopening the sealed
  test or generating new model evidence.
- A portfolio review package that records evidence hashes, commands, tool
  versions, known residuals, and claim boundaries.

### 4.2 Out of scope

- Any production code change that enables a deferred capability.
- Any real or third-party data, including UNSW-NB15/NUSW-NB15.
- Publisher contact, dataset browsing, downloads, metadata probes, or transfer.
- Live capture, public-network access, online inference, model activation,
  automatic retraining/promotion, or model registry mutation.
- Real or automatic prevention, lab enforcement, firewall/host-state changes,
  sockets, subprocesses, packets, network namespaces, or privileged containers.
- Alert/detection/incident/assessment/prevention mutation caused by the demo.
- Public hosting, release tags, repository publication, social-media posting, or
  portfolio upload before a separate owner decision.

## 5. Proposed P5 work decomposition

P5 may be implemented as three explicitly bounded work packages while keeping
one final P5 review gate. Approval of a work package does not authorize the
next one unless the owner says so.

### P5-A — Evidence and documentation package

- Build an evidence index from existing published reports and hashes.
- Draft README/quick-start, architecture and data-flow diagrams, threat-model
  summary, sprint/gate history, decision register summary, and limitation page.
- Draft dataset, feature, model/anomaly, monitoring, and simulated-prevention
  cards using existing metadata only.
- Draft test/security/SBOM, performance, backup/restore, retention, and
  accessibility summaries from recorded results; never invent a result.
- Add a claims-review table mapping every portfolio claim to evidence or marking
  it prohibited/deferred.

### P5-B — Local demonstration package

- Add only non-production demo assets/scripts needed to run the existing system
  from a clean checkout.
- Use fixed synthetic inputs and server-side artifact references; no browser or
  script input may provide a path, URL, model bytes, dataset bytes, or command.
- Demonstrate the existing offline flows and simulation preview without changing
  persistent detection, alert, incident, model, or prevention state.
- Capture screenshots/recording only after the local run passes redaction,
  limitation, false-flag, and privacy checks.
- Provide a deterministic fallback text transcript if video capture is not
  permitted or reproducible on the host.

### P5-C — Final review package

- Re-run clean-checkout and synthetic-only checks.
- Verify every claim, screenshot, recording, card, and README surface against
  the evidence index.
- Verify no secrets, raw endpoint addresses, internal paths, dataset bytes,
  model inputs, or prohibited capability references escaped into materials.
- Produce a completion report and a separate owner decision on portfolio
  publication. No publication follows automatically from technical readiness.

## 6. Demonstration contract

### 6.1 Required sequence

The proposed ten-minute demonstration should be deterministic and bounded:

1. Show the project purpose, scope, and synthetic-only limitation banner.
2. Start the local Compose stack from a clean checkout using non-secret
   validation values and localhost-only ports.
3. Show health/readiness and bounded worker status without exposing secrets.
4. Replay a small project-generated synthetic telemetry fixture or reference an
   already accepted synthetic artifact; do not access a real dataset.
5. Show evidence-bearing deterministic detection and the immutable rule/source
   version references.
6. Show offline synthetic model/anomaly/monitoring metadata and aggregate
   reports, including hashes and `not_evaluable` behavior where applicable.
7. Show analyst feedback as a bounded, audited observation; explicitly state it
   is not ground truth and cannot relabel or retrain anything.
8. Show a prevention policy evaluation and simulated preview/execution/rollback
   record. Demonstrate that no operating-system or network state changes.
9. Show RBAC/audit evidence, retention metadata, and artifact-integrity status.
10. End with limitations, prohibited capabilities, residual risks, and the
    separate publication decision.

### 6.2 Demonstration invariants

- Synthetic labels retain `synthetic_benign_like` and
  `synthetic_intrusion_like`; they must not be shortened to `benign`, `attack`,
  or `intrusion`.
- No numeric performance claim is made for real traffic, UNSW-NB15, or any
  production environment.
- Every metric, chart, screenshot, recording frame, report, and UI panel has
  the exact limitation text and machine-readable false-capability flags where
  the surface supports metadata.
- The sealed test is not reopened and no new preprocessing/model artifact is
  created.
- Simulation uses the existing policy gates and writes only its existing
  simulation/audit records; it cannot invoke a command or network API.

## 7. Portfolio content specification

### 7.1 README and quick start

The README should state:

- what AegisAI is and is not;
- the IDS plus simulated-IPS boundary;
- synthetic/offline data provenance and accepted hashes;
- local prerequisites and resource expectations;
- credential-free setup using `.env.example` and localhost-only Compose;
- how to run the scripted demo and its expected safe outputs;
- quality/security/CI evidence with dates and exact run identifiers;
- retention, backup/restore, audit, and artifact-integrity controls;
- known residuals and unavailable tools;
- no real dataset, live capture, online inference, automatic prevention, or
  real-world performance claim;
- the MIT code-license boundary and prohibition on implying dataset rights.

Commands must be copied from verified runbooks, must not contain credentials,
and must not point at arbitrary URLs or external infrastructure.

### 7.2 Architecture and threat visuals

Use Mermaid or static diagrams that show:

- trust zones and data classification;
- ingestion → normalization → detection → evidence → analyst workflow;
- feature/model/anomaly evidence as offline, non-activating paths;
- monitoring/reporting as aggregate-only paths;
- prevention policy → simulation adapter with a visibly absent enforcement zone;
- RBAC, audit, retention, artifact, and recovery boundaries.

Diagram review must reject arrows implying model-to-firewall, dataset-download,
live-capture, or online-inference capability.

### 7.3 Evidence cards

Each card is short, hash-bound, and limitation-aware:

| Card | Required contents |
|---|---|
| Synthetic dataset | Generator/catalog version, seed, label semantics, row/group limits, content/split/quality/leakage hashes, no-real-data statement |
| Feature schema | Canonical flow version, 39 model + 7 provenance columns, windows, missing/unseen/range policy, schema hash |
| Supervised model | Candidate identity, ONNX/JSON safe-format policy, accepted synthetic evidence, offline-only status, no numeric real-world claim |
| Anomaly/fusion | Detector/policy versions, synthetic/offline scope, evidence boundaries, anomaly-only prohibition |
| Monitoring | Baseline/current hashes, policy version, sample sufficiency, `not_evaluable`, aggregate-only output |
| Simulated prevention | 13 gates, allowlist/critical-target/expiry/rollback/idempotency behavior, no network-state effect |
| Security/QA | CI, local scans, Docker posture, migrations, backup/restore, accessibility, known residuals |

Cards must name evidence sources and cannot introduce a stronger claim than the
source report supports.

## 8. Screenshot and recording safety procedure

This is a proposed procedure for a later authorized P5-B implementation; it is
not permission to capture media now.

1. Use a disposable local browser profile and a fresh synthetic-only database.
2. Confirm localhost-only binds, simulation mode, accepted hashes, and no
   external network dependency before capture.
3. Use a demo account with the least privilege needed for each screen. Never
   display a System Administrator credential, session cookie, CSRF token, sensor
   secret, email address, signed URL, or environment value.
4. Use only documentation-range or redacted identifiers. Mask endpoint values,
   internal IDs, paths, timestamps that could reveal local identity, and analyst
   notes unless the view is intentionally aggregate.
5. Keep the limitation banner and false-capability flags visible in every frame
   that shows a metric, model, monitoring, or prevention result.
6. Do not open browser developer tools, upload dialogs, dataset folders, raw
   artifacts, or external websites during capture.
7. After capture, hash the media, run a secret/large-file/path/endpoint scan,
   inspect every frame or transcript, and record a redaction checklist.
8. Store media outside Git during review with restrictive permissions. A later
   owner decision must name permitted destination, audience, retention, and
   whether public publication is allowed.
9. Delete rejected takes and temporary captures according to the approved
   retention procedure; record only sanitized evidence.

### Recording fallback

If recording would reveal too much local state or cannot be reproduced, use a
text transcript with static diagrams and synthetic screenshots. The transcript
must carry the same limitation text and claim review.

## 9. Reproducibility and evidence index

The P5 evidence index should be a canonical, metadata-only JSON/Markdown record
containing:

- baseline commit and hosted CI run;
- exact Gate 5S-A/B/C and P1–P4 evidence hashes;
- command/runbook identifiers and tool versions;
- demo fixture/catalog/schema identities;
- generated report and media hashes, if media is later approved;
- limitation-text version and false-capability flag set;
- retention class and expiry for each artifact;
- reviewer state and owner approval reference.

It must not contain raw rows, vectors, endpoint addresses, credentials, paths,
query strings, tokens, model inputs, or dataset bytes. Any missing, stale, or
mismatched hash makes the evidence `not_evaluable` and blocks publication.

## 10. Privacy, security, and governance controls

- Keep the existing secure cookie session, RBAC, CSRF/Origin, IDOR, audit,
  retention, and redaction behavior. Demo materials never bypass API controls.
- Treat screenshots/recordings as controlled artifacts. Restrict local access,
  hash them, set expiry, and require explicit review before sharing.
- Do not include raw telemetry, PCAP, endpoint lists, internal hostnames, model
  inputs, notes, credentials, cookies, URLs with query tokens, or exception
  traces.
- Use aggregate counts and opaque evidence IDs in portfolio reports.
- Audit demo-run creation, report generation, media review, redaction,
  finalization, export, and cleanup with actor, role, reason, correlation ID,
  before/after hash, and safe outcome.
- Keep report/media retention within owner-approved periods. Existing defaults
  are 30 days for generated reports/stored predictions and feature/model/
  monitoring evidence, 180 days for alerts/incidents/analyst notes/audit, and
  no exceptional holds.
- Portfolio publication must be opt-in, audience-specific, and reversible where
  the destination permits withdrawal.

## 11. Security and supply-chain review

The later implementation must verify, without claiming unavailable evidence:

- accepted Gate 5S-A/B/C hashes and P1–P4 hashes remain unchanged;
- no real/third-party dataset bytes, PCAP, model input, or unsafe media exists;
- Python/Node/native dependencies, Docker images, CI actions, and demo tools
  are pinned or recorded and covered by SBOM/CVE evidence;
- secret scanning, large-file scanning, path/endpoint scanning, and
  simulation-only static/runtime checks pass;
- local Docker containers remain non-root/read-only/capability-dropped where
  supported, resource bounded, localhost-only, and without host networking,
  mounts, sockets, or enforcement capabilities;
- demo scripts do not invoke shell commands from untrusted input and do not
  accept arbitrary URLs, paths, files, or model/data bytes;
- any missing scanner or unavailable environment is reported as skipped or
  `not_evaluable`, never as a pass.

## 12. Tests and acceptance matrix

### 12.1 Contract and content tests

- Required limitation text and all false flags are present in every portfolio
  artifact, report, API response, and UI view.
- Synthetic labels, accepted hashes, retention classes, and provenance match
  source manifests exactly.
- README commands, diagrams, cards, transcript, screenshots, and report links
  contain no secrets, paths, tokens, raw addresses, dataset bytes, or prohibited
  claims.
- Public-facing text never calls synthetic labels production attacks or claims
  validated prevention.

### 12.2 Reproducibility and demo tests

- Two clean local Compose runs produce matching aggregate evidence/report hashes
  under the P4 comparison policy.
- Demo replay is deterministic, bounded, idempotent, and safe to repeat.
- Missing, stale, corrupt, mismatched, or insufficient evidence produces
  `not_evaluable`/`failed_closed` and never a success claim.
- Simulation preview and rollback remain data-only; host/network state is
  unchanged before and after the demo.

### 12.3 Security and privacy tests

- Six-role RBAC negative matrix, IDOR, CSRF/Origin, session expiry/revocation,
  and audit checks remain passing for every demo route.
- Media and evidence artifacts have restrictive permissions, opaque references,
  SHA-256 hashes, expiry, and cleanup evidence.
- Secret, large-file, path, endpoint, dependency, SBOM/CVE, Docker, and
  simulation-only scans pass or are explicitly documented unavailable.
- Accessibility checks cover keyboard navigation, labels, focus, contrast,
  semantic roles, and limitation-banner visibility.

### 12.4 Documentation and claim review

- A reviewer can trace each material claim to a hash-bound report or command.
- Every known residual, failed/skipped check, and tool limitation is recorded.
- No README/card/screenshot/recording implies public-network, production,
  real-dataset, live-capture, online-inference, or real-prevention capability.

## 13. Resource, retention, and failure policy

- Use the existing ARM64 Compose resource limits; do not silently raise CPU,
  memory, PID, queue, row, artifact-size, or wall-clock limits.
- Bound demo fixture size, screenshot/recording duration, report rows, and media
  file size. Reject oversize media rather than truncating it silently.
- Keep report/media generation offline and deterministic. A failed or partial
  capture is quarantined/deleted and never presented as evidence.
- Missing dependency, unhealthy stack, insufficient disk, hash mismatch,
  unsafe container posture, or missing limitation flags returns a sanitized
  failed-closed/not-evaluable result and blocks finalization.
- Cleanup is idempotent and must not delete retained project evidence or
  inherited Sprint 10 files.

## 14. Dependencies and sequencing

P5 depends on:

- public main at the verified P4-published baseline and successful hosted CI;
- accepted Gate 5S-A/B/C evidence and stable P1–P4 reports;
- a clean ARM64 local Docker Compose run with no credentials or external
  services;
- documented tool availability for media redaction, accessibility, SBOM/CVE,
  and large-file/secret scans; and
- explicit owner approval of the P5 plan and later implementation prompt.

P5 does not depend on, and must not unblock, real data, publisher contact, live
capture, online inference, model activation, enforcement, public deployment, or
any Sprint 10/11 work.

## 15. Major risks and mitigations

| ID | Risk | Mitigation | Gate consequence |
|---|---|---|---|
| P5-R1 | Synthetic evidence is mistaken for real performance | Immutable limitation text, false flags, claim matrix, reviewer sign-off | Publication blocked |
| P5-R2 | Screenshot/recording leaks credentials or sensitive metadata | Disposable profile, least privilege, redaction scan, restrictive storage, frame review | Media rejected/deleted |
| P5-R3 | Demo script drifts or becomes nondeterministic | Fixed fixtures, accepted hashes, two clean runs, no external services | `not_evaluable` |
| P5-R4 | Portfolio material implies online/model activation or prevention | Diagram/text review and static capability scan | Publication blocked |
| P5-R5 | README commands cause unsafe external or destructive action | Local-only commands, no arbitrary inputs, copy from verified runbooks | Documentation rejected |
| P5-R6 | Public repository contains inherited/private Sprint 10 material | Diff and large-file/path review; explicit exclusions | Publication blocked until classified |
| P5-R7 | Tooling/SBOM/media/accessibility evidence is unavailable | Record exact skip and owner decision; never claim pass | Conditional or rejected |
| P5-R8 | Retention/withdrawal obligations are unclear for media | Owner approves destination, audience, retention, and deletion | No publication |
| P5-R9 | Portfolio scope expands into feature work | Strict file/scope allowlist and P5-only review | Stop and revert to plan |

## 16. Decisions requiring explicit owner approval

1. Approve Gate P5 as portfolio documentation and synthetic demonstration only.
2. Approve whether P5 should use the three proposed work packages (P5-A,
   P5-B, P5-C) or one implementation gate.
3. Approve the exact demo duration, fixture count, demo account roles, and
   localhost ports/resources.
4. Approve whether screenshots may be created, whether recordings may be
   created, and whether either may be made public.
5. Approve the permitted publication destination and audience (repository
   README/docs only, private portfolio, or another explicitly named target).
6. Approve media retention, local storage location, deletion process, and any
   withdrawal/republishing procedure. Exceptional holds remain disabled unless
   separately approved.
7. Approve whether anonymized/opaque UI identifiers may be visible or whether
   all identifiers must be redacted.
8. Approve the exact portfolio claim set and resume/case-study wording after
   evidence review; no real-world performance or prevention claim is allowed.
9. Approve treatment of unavailable scanners, recording tools, or browser
   accessibility tooling as skipped/`not_evaluable` versus a prerequisite.
10. Confirm that P5 does not authorize real datasets, publisher contact, live
    capture, online inference, model activation, public deployment, or any
    enforcement capability.

## 17. Assumptions

- The current public main and P4 report are the authoritative baseline; no
  newer separately authorized baseline is assumed.
- Existing synthetic artifacts and reports remain available through controlled
  server-side references or reproducibility evidence; no raw artifact export is
  needed for the portfolio package.
- A local browser and Docker Compose are available on the approved ARM64 host,
  but browser media capture is optional and may be replaced by a transcript.
- Portfolio reviewers need enough context to understand the safety boundaries,
  not access to raw telemetry, model inputs, or credentials.
- The repository remains public, but public repository visibility does not by
  itself authorize publishing new screenshots, recordings, releases, or claims.

## 18. Deferred work and prohibited capabilities

Deferred indefinitely or outside this plan:

- Gate 10B/10C, real/lab enforcement, automatic prevention, firewall and
  host-state adapters, sockets, subprocesses, packet handling, and privileged
  capabilities;
- live capture, public-network deployment, online inference, model activation,
  automatic training/promotion/retraining, and real datasets;
- UNSW-NB15/NUSW-NB15 access, mirrors, samples, publisher outreach, or transfer;
- mutation of alerts, detections, incidents, assessments, model registry state,
  or prevention state by demo/monitoring/reporting;
- production rollout, external monitoring backends, credentialed external
  services, and any Sprint 6–15 feature work;
- public portfolio publication until the separate owner decision is recorded.

## 19. Proposed Gate P5 acceptance criteria

Gate P5 implementation is ready for review only when all applicable criteria
pass, or a non-security residual is explicitly recorded:

1. A clean ARM64 checkout runs the documented synthetic demo with no
   credentials or external services and repeatable teardown.
2. README, quick-start, diagrams, cards, runbooks, and the evidence index are
   accurate, internally consistent, and linked to recorded hashes/results.
3. The scripted demonstration uses only project-generated synthetic artifacts,
   remains bounded/idempotent, and does not mutate alert, detection, incident,
   model, or prevention state beyond existing simulation/audit records.
4. Every portfolio surface carries the exact synthetic-demo limitation text and
   machine-readable false-capability flags where applicable.
5. Screenshots/recordings, if authorized, pass secret, endpoint, path,
   large-file, redaction, accessibility, and claim-review checks; rejected
   media is not retained.
6. Accepted Gate 5S-A/B/C and P1–P4 hashes remain unchanged; any mismatch is
   `not_evaluable` and blocks finalization.
7. Existing RBAC, CSRF/Origin, IDOR, audit, retention, artifact-integrity,
   JSON-only Celery, Docker-isolation, health, dependency/SBOM, and
   simulation-only checks remain passing or are explicitly documented.
8. No real dataset bytes, publisher interaction, live capture, online
   inference, model activation, firewall/host-state capability, socket,
   subprocess, packet, privileged container, public bind, or enforcement path
   exists in the P5 diff or demo environment.
9. The completion report records files, commands/results, hashes, claims,
   limitations, failures/skips, residual risks, and owner decisions.
10. The final package stops at an uncommitted P5 review gate. Publication is
    separately approved; no tag, release, or upload is implied.

## 20. Exact Gate P5 implementation authorization prompt

Use only after the owner reviews this plan and records every decision in
Section 16:

> Approve and begin AegisAI NIDPS Gate P5 implementation using
> `docs/POST_MVP_GATE_P5_PLAN.md`.
>
> Before proceeding, confirm public `main` is
> `2e4e3a6d9c927b731237de20847214e75f6a31e8`, hosted CI Run `29675999780`
> passed, Gate P4 publication is complete, and the accepted Gate 5S-A/B/C
> hashes remain unchanged. Read all governing documents,
> `docs/POST_MVP_SYNTHETIC_ROADMAP.md`,
> `docs/POST_MVP_GATE_P4_COMPLETION_REPORT.md`, and this plan completely.
> Preserve inherited Sprint 10 files without rewriting, deleting, staging, or
> including them in the P5 diff.
>
> Authorize only the approved P5 work packages for portfolio documentation,
> clean-checkout synthetic demonstration, evidence cards, claim review,
> aggregate-only reports, and—only if separately approved—sanitized local
> screenshots or recording. Use project-generated synthetic/offline artifacts
> and the existing simulation-only application. Keep the sealed test closed and
> do not create new preprocessing, model, anomaly, prediction, alert, or
> prevention evidence.
>
> Preserve all accepted hashes, exact synthetic-demo limitation text,
> machine-readable false-capability flags, retention, RBAC, secure cookie
> sessions, CSRF/Origin, IDOR protection, audit, JSON-only UUID Celery,
> controlled artifact paths, SHA-256 integrity, bounded resources, Docker
> isolation, health, and simulation-only guarantees. Every README/card,
> diagram, report, API/UI surface, screenshot, recording, and transcript must
> carry the applicable limitation text and must not imply real-world
> performance, live capture, online inference, model activation, or real
> prevention.
>
> Do not use real or third-party datasets, UNSW-NB15/NUSW-NB15, mirrors,
> samples, publisher contact, tokenized links, live capture, public networks,
> online inference, model activation, automatic training/promotion/retraining,
> firewall or host-state integration, sockets, subprocesses, packets, network
> namespaces, privileged containers, host networking, Docker socket mounts,
> real or automatic prevention, alert/detection/incident/assessment/model/
> prevention mutation, Gate 10B/10C, Sprint 6–15 work, or any unrelated
> refactor. Do not publish, tag, release, upload, or commit until separately
> authorized.
>
> Run and record applicable clean-checkout, synthetic-determinism,
> reproducibility, content/claim, hash, limitation/flag, RBAC/IDOR,
> CSRF/Origin, audit, retention, artifact-integrity, resource, Celery,
> Docker/isolation, health, migration, dependency/SBOM/CVE, secret,
> large-file/path/endpoint, frontend, accessibility, and simulation-only
> checks. If media is authorized, run restrictive-permission, redaction,
> frame/transcript, metadata, and deletion checks. Fail closed on hash mismatch,
> missing limitation text, unsafe posture, sensitive-data exposure, unavailable
> required evidence, or any Critical/High finding.
>
> Stop at the uncommitted Gate P5 completion gate. Report files changed,
> evidence/media hashes, commands and results, claims reviewed, failures/skips,
> assumptions, residual risks, acceptance status, and the exact separate
> publication-review prompt. Do not begin any later gate or prohibited
> capability.

## 21. Planning status

**READY FOR OWNER REVIEW.** This document creates no code, migration, task,
API, UI, media, model, dataset, enforcement capability, commit, publication,
or deployment. Gate P5 implementation remains unauthorized until the owner
approves this plan and explicitly authorizes the implementation prompt above.
