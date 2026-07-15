# Sprint 5 Phase 5A Pre-Acquisition Report

**Date:** 2026-07-14
**Branch:** `codex/sprint-5a-pre-acquisition`
**Baseline:** `72c97b15f9bb31ddb6810a397afc682893497bab`
**Decision:** `BLOCKED AT SOURCE-METADATA GATE`
**Repository state:** Uncommitted; no publication authorized or performed

## 1. Outcome

The Phase 5A fail-closed foundations are implemented and locally verified. No dataset file, sample, archive, or payload was downloaded or parsed. No transfer endpoint or Celery transfer task is enabled.

An exact acquisition manifest cannot yet be proposed. The separately authorized browser inspection reached the publisher's read-only SharePoint folder without opening or transferring a file. It exposed rounded sizes and CSV type indicators, but not exact byte counts, checksums, or stable query-free object URLs. More importantly, the required feature and ground-truth filenames are absent: the folder shows `NUSW-NB15_features.csv` and `NUSW-NB15_GT.csv`, while the publisher page and owner authorization name `UNSW-NB15_features.csv` and `UNSW-NB15_GT.csv`. The differently spelled objects are unapproved. Acquisition stays unauthorized.

## 2. Entry-gate evidence

- `origin/main` and the local baseline were confirmed at `72c97b15f9bb31ddb6810a397afc682893497bab`.
- GitHub Actions Run #7 (`29332025235`) was confirmed `completed/success` for that exact SHA.
- The starting worktree contained only the approved Sprint 4 publication-documentation changes and `docs/SPRINT_5_IMPLEMENTATION_PLAN.md`.
- All governing documents named by the owner and the complete Sprint 5 implementation plan were read before implementation.
- A short-lived branch, `codex/sprint-5a-pre-acquisition`, was created from the published baseline without rewriting history.

## 3. Official-source and terms findings

Official page reviewed: `https://research.unsw.edu.au/projects/unsw-nb15-dataset` (page shows “Last Updated 02 June 2021”).

Confirmed from publisher metadata:

- four principal tabular parts: `UNSW-NB15_1.csv`, `UNSW-NB15_2.csv`, `UNSW-NB15_3.csv`, and `UNSW-NB15_4.csv`, totaling 2,540,044 records;
- feature description: `UNSW-NB15_features.csv`;
- ground-truth/event documentation: `UNSW-NB15_GT.csv` and `UNSW-NB15_LIST_EVENTS.csv`;
- the approximately 100 GB raw PCAP exists and remains excluded;
- publisher-prepared train/test files exist but remain excluded from the proposed authoritative group/time-aware split;
- academic research use is stated as free; commercial use requires agreement with the authors;
- publisher-listed citations are required;
- no dataset redistribution right was identified, so dataset files remain outside Git, the MIT license, and public release artifacts.

Observed publisher-controlled browser access path:

1. `research.unsw.edu.au`
2. `unsw-my.sharepoint.com`

The shared folder was readable without sign-in. Its Download UI was enabled but was not clicked, so actual download authority was not exercised. No credential, cookie, OAuth parameter, SharePoint sharing token, account identifier, query string, or signed object URL was retained. The detailed metadata-only evidence is in `docs/data/UNSW_NB15_PREACQUISITION_REVIEW_2026-07-14.md`.

## 4. Candidate inventory — not an acquisition manifest

Because acquisition-critical fields are unavailable, this table is deliberately incomplete and must not be treated as authorization.

| Official filename | Proposed role | Advertised size | Source/redirect host | Expected media | Checksum status |
|---|---|---:|---|---|---|
| `UNSW-NB15_1.csv` | Principal tabular part 1 | 161 MB displayed; exact bytes unavailable | `unsw-my.sharepoint.com` | CSV | Not visible |
| `UNSW-NB15_2.csv` | Principal tabular part 2 | 158 MB displayed; exact bytes unavailable | `unsw-my.sharepoint.com` | CSV | Not visible |
| `UNSW-NB15_3.csv` | Principal tabular part 3 | 147 MB displayed; exact bytes unavailable | `unsw-my.sharepoint.com` | CSV | Not visible |
| `UNSW-NB15_4.csv` | Principal tabular part 4 | 93.1 MB displayed; exact bytes unavailable | `unsw-my.sharepoint.com` | CSV | Not visible |
| `UNSW-NB15_features.csv` | Official feature dictionary | Authorized name absent; unapproved `NUSW-...` object displays 3.95 KB | `unsw-my.sharepoint.com` | CSV | Not visible |
| `UNSW-NB15_GT.csv` | Conditional label provenance | Authorized name absent; unapproved `NUSW-...` object displays 82.4 MB | `unsw-my.sharepoint.com` | CSV | Not visible |
| `UNSW-NB15_LIST_EVENTS.csv` | Conditional event/group provenance | 4.53 KB displayed; exact bytes unavailable | `unsw-my.sharepoint.com` | CSV | Not visible |

`docs/data/UNSW_NB15_ACQUISITION_CANDIDATES_2026-07-14.json` records the same inventory with `acquisition_authorized=false`, rounded display sizes, and null exact byte counts. Every differently spelled or otherwise unlisted object remains excluded.

## 5. Enforced acquisition limits

| Control | Enforced maximum/default |
|---|---:|
| Combined transfer | 5 GiB |
| Per file | 2 GiB |
| File count | 10 |
| HTTPS redirects | 5 |
| Connect / idle timeout | 30 / 120 seconds |
| Per-file deadline | 30 minutes |
| Retries | 2 |
| Protected disk reserve | 50 GiB |
| Staging | Opaque UUID, mode `0600`, atomic promotion |
| Archives | Prohibited |
| Raw retention | Through review, at most 90 days without renewed approval |
| Exceptional hold | Disabled |

The client also requires an exact server-side `dataset-acquisition-manifest/v1`, an `owner_approved` state and approval reference, allowlisted public HTTPS hosts, exact advertised byte counts and media types, streaming SHA-256, redirect-chain revalidation, and protected-free-space preflight. Browser-supplied URLs, arbitrary URLs, URL credentials, query strings, fragments, private/non-global DNS resolutions, archives, excess bytes, mismatched media, incomplete transfers, and checksum mismatches fail closed. Partial and destination files are removed on failure.

The transfer client has an injected transport contract only. No concrete network transport, download API, approval transition, or Celery transfer task exists in this phase.

## 6. Files created or changed

Created:

- `services/aegis_services/datasets/__init__.py`
- `services/aegis_services/datasets/acquisition.py`
- `migrations/versions/0005_sprint5_preacquisition.py`
- `tests/fixtures/datasets/acquisition_cases.json`
- `tests/unit/test_dataset_acquisition.py`
- `tests/integration/test_dataset_acquisition_api.py`
- `docs/data/UNSW_NB15_PREACQUISITION_REVIEW_2026-07-14.md`
- `docs/data/UNSW_NB15_ACQUISITION_CANDIDATES_2026-07-14.json`
- `docs/SPRINT_5_PHASE_5A_PREACQUISITION_REPORT.md`
- `docs/SPRINT_5_IMPLEMENTATION_PLAN.md` (approved planning artifact present at entry)

Changed for Phase 5A:

- API/model/schema/permission foundations in `apps/api/aegis_api/`
- the RBAC negative matrix;
- README, backlog, decision register, database/schema/API/ML/test/deployment/risk documentation, architecture/data-flow, and threat model.

Previously approved Sprint 4 publication-record changes remain uncommitted in the same worktree and were preserved.

## 7. Migration and interfaces

Migration `0005_sprint5_preacquisition`:

- creates `dataset_acquisition_plans` for immutable `proposed` manifests only;
- adds database limits for state, total bytes, file bytes, file count, and retention;
- installs a PostgreSQL trigger rejecting proposal update/delete;
- seeds `datasets:acquire` for System Administrator and `datasets:accept` for Security Administrator;
- downgrades cleanly to `0004_sprint4_features` and re-upgrades.

API foundations:

- `GET /api/v1/dataset-acquisition-plans`: permission-controlled, sanitized metadata only;
- `POST /api/v1/dataset-acquisition-plans`: System Administrator, secure session, CSRF token and Origin enforcement, `proposed` manifests only, audited, duplicate hash rejected;
- no API returns stored source URLs or the full manifest;
- no acceptance, approval, transfer, parsing, or training endpoint exists.

The acceptance permission is reserved for a later distinct Security Administrator gate. Dataset acceptance, complete canonical-flow-v1/39-feature 60/300-second compatibility, leakage review, and group/time-aware 70/15/15 split approval remain mandatory before Phase 5B. Partial mappings, invented semantics, zero-filled missing context, and random splits remain prohibited.

## 8. Commands and check results

Representative commands actually run:

```text
git ls-remote origin refs/heads/main
GitHub API inspection for Actions Run #7
git status --short; git diff; git switch -c codex/sprint-5a-pre-acquisition
docker build ... -t aegisai-sprint5-test
ruff check .; ruff format --check .; mypy apps services
pytest tests/unit/test_dataset_acquisition.py tests/integration/test_dataset_acquisition_api.py
pytest
bandit -c pyproject.toml -r apps services
pip-audit
python scripts/check_secrets.py
python scripts/check_simulation_only.py
git diff --check
alembic upgrade head; alembic downgrade 0004_sprint4_features; alembic upgrade head
docker compose -p aegis-sprint5-preacq build/up/ps/exec
celery ... inspect ping; celery ... inspect registered
curl .../health/live; curl .../health/ready; curl dashboard
npm run lint; npm run typecheck; npm run test; npm run build
npm audit --audit-level=high
```

Results:

- Ruff lint/format: pass.
- mypy: pass across 54 source files.
- Focused acquisition/API suite: 12 passed after final fixture hygiene correction; earlier combined focused run was 24 passed.
- Full backend suite: 111 passed; 75% aggregate coverage, including existing synthetic parser, canonical mapping, feature parity/leakage, split-contract, retention, RBAC, CSRF/Origin, audit, resource, Celery-dispatch, and health coverage.
- Bandit: no issues across 7,422 lines; no High/Medium/Low findings.
- pip-audit: no known vulnerabilities; local unpublished `aegisai-nidps` package skipped as non-PyPI.
- secret scan: pass. One secret-shaped hostile URL fixture was replaced with a neutral query parameter; rejection behavior remains tested.
- simulation-only guard: pass.
- `git diff --check`: pass on host. The test image lacks Git, so the attempted in-container invocation ended with `git: not found`; this is a tooling limitation, not a repository failure.
- The host shell has no `python` executable; attempted host invocations returned `command not found`. Python checks were run successfully in the pinned test container instead.
- Migration: fresh zero-to-head pass; seeded permissions verified; direct proposal mutation rejected; downgrade to 0004 and re-upgrade pass.
- Docker Compose: PostgreSQL, Redis, API and dashboard healthy; worker and scheduler running; migration service completed.
- API liveness: `status=ok`, `prevention_mode=simulation`.
- API readiness: PostgreSQL `ok`, Redis `ok`.
- Dashboard: HTTP 200.
- Celery ping: one worker online, `pong`; registered task list contains no dataset/acquisition/transfer task.
- Celery serialization: `accept_content`, task serializer, and result serializer remain JSON-only.
- Frontend lint/typecheck/build: pass; 5 tests passed.
- npm audit: 0 vulnerabilities.
- Docker build: pass. The first build was unusually slow while retrieving the existing PyArrow dependency, but completed without changing dependencies.

Known warnings/skips:

- One upstream Starlette/httpx deprecation warning remains; it predates Phase 5A and does not affect the gate.
- Focused-test coverage warnings are expected because the focused command does not import the whole worker/application; the full suite is the coverage gate.
- No live transfer, real dataset parser/mapping test, dataset acceptance, model test, online inference test, or real prevention test was run because each is explicitly outside this authorization.
- No concrete transfer transport or Celery acquisition task was tested because neither is enabled before exact-manifest approval.

## 9. Security and scope review

No Critical or High issue was found in the implemented Phase 5A scope. Confirmed absent:

- dataset bytes, samples, extracted rows, raw PCAP, archives, or large new artifacts;
- real dataset feature materialization or partial/zero-filled mapping;
- preprocessing fitting, training, evaluation, serialization, registry, loading, activation, scoring, predictions, or alerts;
- browser-supplied/arbitrary URL transfer;
- live capture, online inference, anomaly/ensemble work, Sprint 6 work;
- real prevention, privileged containers, host networking, firewall capabilities, or enforcement dependencies;
- credentials, tokens, cookies, private paths, or authenticated source URLs in code/docs/audit output.

## 10. Assumptions and residual risks

- The publisher page statements remain authoritative, but the page’s displayed 2021 revision means terms and citations must be checked again immediately before transfer.
- SharePoint revealed two differently spelled, unapproved objects, rounded sizes only, and a tokenized sharing path. These are active blockers under the owner's rules; controls must not be weakened implicitly.
- Publisher checksums may not exist. If absent, the project can record its own streaming SHA-256 only after the owner explicitly approves that checksum status.
- The future concrete HTTP transport must bind each connection to the validated public address and revalidate every redirect to close DNS-rebinding/TOCTOU risk; the current injected interface performs no network I/O.
- Dataset redistribution remains unauthorized.
- Dataset suitability, complete canonical mapping, leakage, label quality, temporal/group split feasibility, and feature-contract parity cannot be established before controlled acquisition and remain later acceptance blockers.
- D-13 is resolved by the approved Sprint 5 defaults as ONNX model plus JSON preprocessing contract, but no model artifact work is authorized until dataset acceptance and the separate Phase 5B gate.

## 11. Gate status

| Criterion | Status |
|---|---|
| Baseline/CI/worktree verified | Pass |
| Approved defaults recorded | Pass |
| Fail-closed contracts/storage/state/RBAC/audit foundations | Pass |
| Synthetic hostile/limit/authorization tests | Pass |
| No dataset bytes transferred | Pass |
| Current terms/citations and official names revalidated | Pass |
| Folder inventory visible without opening files | Pass |
| Authorized feature/ground-truth filenames present | Blocked; differently spelled unapproved names observed |
| Exact advertised sizes | Blocked; rounded display values only |
| Media/archive status | Partial; visible objects presented as CSV, no archives observed |
| Stable publisher-controlled transfer URLs/redirect hosts | Blocked |
| Publisher checksum status | Blocked |
| Exact acquisition manifest ready for owner approval | Blocked |

**Final Phase 5A decision: BLOCKED BEFORE ACQUISITION AUTHORIZATION.** The implementation gate remains complete and fail closed. The authorized metadata inspection confirmed material filename discrepancies, rounded-only sizes, unavailable checksums, and a tokenized-only publisher sharing path.

## 12. Exact next authorization prompt

Owner decision C-29 supersedes publisher outreach. The prepared message is cancelled and must not be sent. The active fallback is `docs/SPRINT_5_NO_PUBLISHER_CONTACT_FALLBACK.md`.

The exact next owner prompt is:

```text
Cancel AegisAI NIDPS Sprint 5 publisher outreach. Do not send the prepared Gmail draft or contact the publisher through any channel.

Keep UNSW-NB15 acquisition blocked and deferred. Keep NUSW-NB15_features.csv and NUSW-NB15_GT.csv excluded. Do not use mirrors, tokenized links, HEAD/GET requests, dataset downloads, samples, or real dataset payloads.

Begin Sprint 5 synthetic-only fallback planning only using the exact scope in docs/SPRINT_5_NO_PUBLISHER_CONTACT_FALLBACK.md. Do not generate a synthetic dataset, train/load/register/activate/score a model, create migrations/APIs/UI/tasks, modify production code, commit, or publish. Stop after docs/SPRINT_5_SYNTHETIC_ONLY_PLAN.md and provide the exact synthetic-only implementation authorization prompt.
```

UNSW-NB15 acquisition is deferred. It may be reopened only through a new explicit owner authorization. Synthetic-only planning is the active proposed continuation; dataset acceptance and model implementation remain separate later gates.
