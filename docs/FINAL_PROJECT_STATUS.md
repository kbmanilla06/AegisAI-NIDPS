# AegisAI NIDPS Final Project Status

**Status:** Portfolio-ready synthetic-only milestone complete
**Date:** 2026-07-19 UTC
**Public main:** `f49252bfca237f113dc28cfbfac53d4d347e1a50`
**Hosted CI:** Run `29679178276` — passed
**Intended use:** Academic/portfolio demonstration only

## Executive summary

AegisAI NIDPS has completed the authorized IDS plus simulated-IPS product path
through Sprint 9 and the synthetic-only post-MVP gates P1–P5. The repository
contains a reproducible local ARM64 Docker Compose system, authenticated and
RBAC-protected APIs, hostile-input telemetry ingestion, deterministic
detection, synthetic feature/model evidence, aggregate monitoring and
reporting, security QA, and portfolio documentation.

The project does not claim real-world detection or prevention performance. The
UNSW-NB15 acquisition remains blocked, publisher outreach remains cancelled,
and prevention remains simulation-only.

## Completed scope

### Foundation and identity

- FastAPI API, Celery worker/scheduler, React/Vite dashboard, PostgreSQL,
  Redis, Docker Compose, environment templates, CI, health/readiness checks,
  formatting, typing, security scanning, and test harness.
- Opaque server-side cookie sessions with Secure/HttpOnly/SameSite controls,
  CSRF and Origin enforcement, session rotation/revocation/expiry, throttling,
  centralized RBAC, users, assets, sensors, hashed credentials, and audit
  foundations.

### Telemetry and deterministic detection

- Canonical flow schema v1 with strict normalized-flow, Zeek, Suricata EVE,
  and isolated offline-PCAP ingestion boundaries.
- Content/schema validation, hostile-input handling, bounded resource use,
  duplicate/idempotent replay behavior, sanitized errors, retention, and
  ingestion audit/metrics.
- Versioned deterministic rules, event-time windows, stable alert
  fingerprints, evidence provenance, deduplication/suppression, RBAC, and
  audit behavior.

### Synthetic feature and model evidence

- Versioned 39-feature plus 7-provenance-column feature contract over canonical
  flow v1, deterministic direct and 60/300-second windows, controlled Parquet,
  SHA-256 provenance, leakage/quality evidence, and group/time-aware splits.
- Synthetic Gate 5S-A generation and immutable dataset, target, feature,
  split, quality, leakage, and identity evidence.
- Gate 5S-B training-only preprocessing, bounded baseline comparison, one-time
  sealed-test opening, ONNX/canonical-JSON candidate artifacts, parity checks,
  model cards, and synthetic-demo limitations.
- Gate 5S-C reviewed synthetic registry metadata and isolated offline batch
  scoring. No model is active and no online scoring path is enabled.

### Post-MVP assurance and portfolio

- Gate P1 synthetic monitoring/drift and analyst-feedback foundations.
- Gate P2 aggregate observability, reporting, retention, and disposable
  backup/restore evidence.
- Gate P3 security hardening and full QA.
- Gate P4 clean ARM64 local Compose reproducibility and dependency/image
  evidence.
- Gate P5 portfolio README, runbook, architecture/threat summaries, sprint
  history, claims review, evidence index, cards, deterministic metadata-only
  evidence tooling, and synthetic demonstration transcript.

## Accepted synthetic evidence

The accepted Gate 5S-A/B/C evidence remains unchanged and is hash-bound in the
project records. The principal Gate 5S-A hashes are:

| Evidence | SHA-256 |
| --- | --- |
| Scenario catalog | `72ba9c2ac4a993dd7c2b1b3b3e0883a342197cc01f7271d4ef8660a5ae2f5d87` |
| Feature schema | `17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114` |
| Dataset content | `b6bf175b3db704d65efb2fd16e83cca8a6624b4fa23ef753324bceb4aeb84b9a` |
| Canonical-flow artifact | `96d1f872a389c62e0340f6f38be8158c0ae50af51a425d278bb3ad04514c95ac` |
| Target artifact | `90494acd14c28692e6cc7aafdb126a3dd1148e080e77592ddc51c4aa7ae32f70` |
| 39+7 feature artifact | `454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9` |
| Split manifest | `d85192d2f35db492b5833bab06ca36ff41ac0437faff3ba76262951cb653b895` |
| Quality report | `c9705bb627da7f69eaf4d7d0da94a83b421b3d87422d96622c25c21adb60d7f4` |
| Leakage report | `2ab7379825099cbfbda2679120aa6c789f549827cf5ee45eb7fe76f80f7ec13d` |

Gate P5 metadata evidence is deterministic:

- Stable identity SHA-256: `bac00f3d19386f85a87adb113ea336b1b8afea623fc0e74fc07153880dfa0bab`
- Canonical JSON SHA-256: `2a3fdcb53f777a7afc7f9dbeb4e35c99105ea1cc39f4f570e73f0bd94367300d`
- Temporary evidence output mode: `0600`

## Guarantees and safety boundaries

- Synthetic/offline artifacts only; no real or third-party dataset bytes are
  included.
- UNSW-NB15 and the two excluded `NUSW-...` candidates remain blocked.
- Publisher contact is cancelled.
- No live packet capture, public-network deployment, online inference, model
  activation, automatic training/promotion, or sealed-test reopening exists.
- Prevention is simulation-only and makes no firewall, socket, subprocess,
  packet, host-state, namespace, or network change.
- Models/anomaly evidence cannot directly mutate alerts, detections, incidents,
  assessments, or prevention state.
- Sensitive writes require server-side RBAC, CSRF/Origin checks, and audit
  records. Celery tasks use bounded JSON-only UUID references.
- Controlled artifacts use opaque references, SHA-256 integrity, retention and
  cleanup policies, and no credentials in code, fixtures, logs, or reports.
- Every synthetic surface carries the mandatory limitation text and
  machine-readable false-capability flags.

## Reproducibility and portfolio handoff

The supported demonstration is local and offline:

1. Start from a clean checkout on the approved ARM64 development machine.
2. Use an untracked validation-only PostgreSQL password; do not commit an
   environment file or credentials.
3. Validate Compose configuration and start the stack with `--wait`.
4. Confirm API liveness/readiness, dashboard HTTP 200, Celery ping, container
   posture, and migration upgrade/downgrade/re-upgrade.
5. Run the metadata-only P5 evidence helper twice and compare the canonical
   JSON bytes and identity hash.
6. Follow `docs/portfolio/DEMO_RUNBOOK.md` and use only the existing synthetic
   fixtures and simulation mode.
7. Tear down the disposable stack and remove its temporary volumes.

No external service, credential, dataset download, publisher link, or media
capture is required. Portfolio materials are in `docs/portfolio/`; use the
claims review and limitation cards verbatim when presenting the project.

## Quality and residual risks

The published Gate P5 review and hosted CI passed the applicable quality,
security, dependency, frontend, Docker, health, migration, Celery, retention,
artifact, reproducibility, and simulation-only checks. The following residuals
remain documented rather than hidden:

1. The full backend suite has a pre-existing timing-sensitive WebSocket
   revocation test that can fail nondeterministically; it is unrelated to P5
   files and remains a QA follow-up.
2. Trivy and Syft were unavailable in the local environment; Docker Scout was
   used as the documented equivalent and reported zero Critical/High findings
   for the reviewed application images.
3. No real dataset or real-network validation exists, so synthetic evidence
   must not be generalized to operational performance.
4. Dataset licensing/metadata resolution remains intentionally blocked; no
   acquisition decision was inferred.
5. The working tree still contains inherited, uncommitted Sprint 10 planning
   files and edits. They were preserved and excluded from the P5 commits; they
   are not an implementation baseline or authorization for Gate 10B.

## Explicitly deferred or prohibited capabilities

The following remain deferred indefinitely unless a new project charter and
separate owner authorization are provided:

- Real or automatic prevention, firewall/nftables/Suricata enforcement,
  host-state changes, sockets, subprocesses, packets, privileged containers,
  host networking, or public-network enforcement.
- Live interface capture and online inference.
- UNSW-NB15, NUSW-NB15, mirrors, samples, publisher contact, or any real or
  third-party dataset acquisition.
- Automatic model training, promotion, activation, or drift-triggered policy
  changes.
- New model/anomaly/ensemble/incident functionality beyond the accepted
  synthetic evidence.
- Gate 10B/10C, Sprint 6–15 work, release/tag/upload, and any public media
  publication without separate approval.

## Authoritative records

- [Gate P5 completion report](POST_MVP_GATE_P5_COMPLETION_REPORT.md)
- [Post-MVP synthetic roadmap](POST_MVP_SYNTHETIC_ROADMAP.md)
- [Portfolio README](portfolio/README_PORTFOLIO.md)
- [Portfolio demo runbook](portfolio/DEMO_RUNBOOK.md)
- [Decision register](DECISIONS.md)
- [Threat model](threat-model/THREAT_MODEL.md)

**Final status:** AegisAI NIDPS is complete as an academic/portfolio,
synthetic-only IDS with simulated prevention. Further capability work is not
authorized by this report.
