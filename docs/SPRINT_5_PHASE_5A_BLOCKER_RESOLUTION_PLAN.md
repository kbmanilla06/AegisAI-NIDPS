# Sprint 5 Phase 5A Publisher-Metadata Blocker Resolution Plan

**Date:** 2026-07-14
**Status:** Superseded by no-contact fallback C-29; acquisition remains blocked
**Branch:** `codex/sprint-5a-pre-acquisition`
**Baseline:** `72c97b15f9bb31ddb6810a397afc682893497bab`

## 1. Decision and scope

The publisher metadata inspection is formally recorded as `BLOCKED_BEFORE_ACQUISITION`. This plan compares two resolution paths without implementing either. It does not authorize a metadata request, publisher contact, token handling, acquisition manifest, transfer interface change, dataset transfer, or dataset acceptance.

No dataset file was opened, previewed, parsed, or downloaded during the inspection. Acquisition remains `false`; no transfer task or concrete transfer transport exists.

## 2. Confirmed evidence

The official publisher page names:

- `UNSW-NB15_1.csv`
- `UNSW-NB15_2.csv`
- `UNSW-NB15_3.csv`
- `UNSW-NB15_4.csv`
- `UNSW-NB15_features.csv`
- `UNSW-NB15_GT.csv`
- `UNSW-NB15_LIST_EVENTS.csv`

The publisher-controlled SharePoint folder visibly contains the four principal parts and event list under those names, but shows `NUSW-NB15_features.csv` and `NUSW-NB15_GT.csv` instead of the two authorized `UNSW-...` names.

The folder displays rounded sizes of 161 MB, 158 MB, 147 MB, 93.1 MB, 3.95 KB, 82.4 MB, and 4.53 KB. Visible objects are presented as CSV files and no archive was observed. Exact byte counts, publisher checksums, ETags/object versions, and stable query-free file URLs are unavailable. The official folder path is a tokenized SharePoint sharing URL. A Download control was visible and enabled but was not exercised.

The authoritative evidence remains:

- `docs/data/UNSW_NB15_PREACQUISITION_REVIEW_2026-07-14.md`
- `docs/data/UNSW_NB15_ACQUISITION_CANDIDATES_2026-07-14.json`

## 3. Non-negotiable invariants

Both options must preserve these controls:

1. No GET request, response body, range request, preview, sample, or dataset byte before separately authorized acquisition.
2. No arbitrary or browser-supplied URL enters an API, job, database, audit record, log, metric, fixture, report, or manifest.
3. No cookie, OAuth value, sharing token, signed query, account identifier, or complete tokenized URL is persisted or displayed.
4. Raw PCAP, publisher-prepared train/test files, mirrors, archives, and every unlisted object remain excluded.
5. The acquisition contract stays query-free and credential-free unless the owner later approves a separately threat-modeled contract change. Neither option in this plan authorizes that change.
6. System Administrator/operator and Security Administrator acceptance roles remain distinct, with the owner approving every exact candidate filename.
7. Academic/portfolio use only; repository MIT licensing does not cover dataset files; redistribution remains unauthorized.
8. Dataset acceptance, canonical-flow/39-feature compatibility, leakage, split, and Phase 5B remain later independent gates.
9. No migration, API, UI, Celery task, network client, model functionality, commit, or publication is authorized by this plan.

## 4. Option 1 — obtain publisher confirmation

### 4.1 Required publisher evidence

Request the publisher or dataset custodian to confirm, in a durable publisher-controlled response:

- whether `NUSW-NB15_features.csv` and `NUSW-NB15_GT.csv` are intentional current official names or typographical errors;
- the exact byte size of every proposed file;
- actual media type and confirmation that no file is archive-wrapped;
- SHA-256 or another publisher checksum, or an explicit statement that no checksum is published;
- a stable credential-free/query-free HTTPS object URL for each file, or confirmation that none is available;
- whether academic/portfolio download by the requesting user is permitted;
- current citation and commercial-use requirements;
- whether local integrity hashes may be retained as metadata and whether dataset bytes may be retained locally for the approved 90-day review window.

The response may be retained only if legally permissible and must exclude unnecessary personal information. Dataset terms and the response evidence receive a SHA-256 reference; secrets and message transport metadata do not enter Git.

### 4.2 Security and governance consequences

Benefits:

- strongest provenance and least ambiguity;
- preserves the current query-free acquisition contract;
- avoids processing SharePoint bearer tokens;
- can settle the spelling discrepancy, terms, download authority, checksums, and retention in one source-controlled decision;
- produces independently reviewable evidence for the Security Administrator.

Costs and risks:

- publisher response time is outside project control;
- the publisher may not respond or may not provide stable URLs/checksums;
- a response from an unverified or personal address could be spoofed or ambiguous;
- personal correspondence must be minimized and handled outside public Git;
- the response may confirm that only tokenized distribution exists, leaving acquisition blocked pending a new threat-model decision.

### 4.3 Verification rules

- Use only contact details published on the official UNSW page or a publisher-controlled domain.
- Verify sender/domain and preserve a minimal evidence hash plus sanitized summary.
- Do not treat a third-party mirror, community checksum, search result, or repository copy as publisher confirmation.
- Do not send a message until separately authorized by the owner.
- If the publisher does not resolve every required field, remain blocked.

### 4.4 Disposition

**SUPERSEDED.** Option 1 was approved for draft preparation, but owner decision C-29 now prohibits sending it. The active path is `docs/SPRINT_5_NO_PUBLISHER_CONTACT_FALLBACK.md`.

## 5. Option 2 — revised candidates plus zero-body metadata validation

### 5.1 Owner decisions required before design or execution

The owner must explicitly name and approve these differently spelled objects as revised metadata candidates:

- `NUSW-NB15_features.csv`
- `NUSW-NB15_GT.csv`

That approval would replace only the candidate spellings. It would not establish semantic correctness, dataset acceptance, acquisition authority, or permission to transfer bytes.

The owner must also explicitly authorize a metadata-only security exception allowing an ephemeral publisher sharing token to be used by a dedicated zero-body probe. This exception must not change the acquisition contract or allow tokenized URLs in a manifest.

### 5.2 Proposed zero-body gate — design only

If separately authorized, a later design would require:

- `HEAD` only; no GET fallback, range request, preview, or body reader;
- exact candidate selected server-side from an owner-approved metadata-probe manifest;
- the publisher token introduced interactively at execution time, held only in process memory, then overwritten/released;
- no token or complete URL in command arguments, environment variables, database rows, Redis/Celery messages, audit data, logs, metrics, traces, exceptions, crash reports, shell history, frontend state, clipboard history, or documentation;
- HTTPS only and a fixed allowlist of publisher-controlled hosts;
- public-DNS resolution, address binding, redirect revalidation and DNS-rebinding/TOCTOU controls on every hop;
- at most five redirects, 30-second connection timeout, 120-second response-header timeout, 30-minute absolute deadline, and no automatic retry unless separately justified;
- zero accepted response-body bytes; any body indication or received body byte is a hard failure;
- capture only sanitized hostnames, status, exact `Content-Length`, normalized `Content-Type`, safe validator/checksum header presence, and an evidence hash;
- never treat `Content-Disposition` filenames or response media declarations as trusted without matching the owner-approved candidate;
- fail if the server rejects HEAD, omits/varies `Content-Length`, uses archive media, redirects outside the allowlist, requires another credential, or exposes no stable identity;
- System Administrator execution, distinct Security Administrator review, complete safe audit, and owner approval of the resulting exact metadata.

### 5.3 Security and correctness consequences

Benefits:

- may establish exact `Content-Length`, declared `Content-Type`, and redirect hosts without intentionally transferring a response body;
- can be tightly bounded and independently audited;
- may determine whether publisher checksum headers exist.

Limitations and risks:

- a SharePoint sharing token is a bearer secret; compromise may expose the shared folder;
- tokens can leak through URL handling, proxies, TLS inspection, error telemetry, process inspection, redirects, browser history, or vendor logs even when application logging is redacted;
- HEAD may be unsupported, return different headers from GET, report the encoded representation rather than eventual stored bytes, or omit checksum information;
- `Content-Type` is declarative and not content validation;
- an enabled Download UI does not prove contractual authority or semantic correctness;
- exact Content-Length does not prove file integrity or immutability;
- owner approval of `NUSW-...` spellings does not prove those objects match the publisher-page descriptions;
- a successful probe still does not produce stable query-free acquisition URLs. Acquisition remains blocked unless the publisher supplies such URLs or the owner later authorizes a separate, fully threat-modeled acquisition-contract change;
- implementing a safe ephemeral-token path adds security-sensitive complexity for a solo academic/portfolio project.

### 5.4 Disposition

**Not recommended as the first resolution path.** It can reduce metadata uncertainty but cannot resolve the current stable query-free transfer-URL requirement and introduces bearer-token handling risk. It should be considered only after Option 1 fails and only through a separate design review and authorization.

## 6. Comparison

| Criterion | Option 1: publisher confirmation | Option 2: zero-body probe |
|---|---|---|
| Resolves filename authority | Potentially yes | Owner accepts spelling, but publisher semantics remain unconfirmed |
| Exact byte size | Publisher can state it | HEAD may report it, with representation caveats |
| Media/archive status | Publisher confirmation | Header declaration only |
| Publisher checksum | Can confirm checksum or absence | Can see only exposed headers |
| Download authority/terms | Can confirm directly | Cannot establish contractual authority |
| Stable query-free URLs | Potentially yes | No; tokenized probe does not solve this |
| Secret handling | No application token handling | High-risk ephemeral bearer token |
| Contract change | None if publisher supplies required facts | Metadata-only exception; acquisition contract unchanged |
| Engineering complexity | Low | Moderate/high security-sensitive work |
| Time predictability | External/uncertain | Technically bounded after a separate implementation gate |
| Recommended order | First | Only after Option 1 fails |

## 7. Decisions requiring owner approval

1. Option 1 is selected. Option 2 remains unapproved.
2. Decide whether `NUSW-NB15_features.csv` and `NUSW-NB15_GT.csv` may become revised candidates. Proposed default: keep excluded until publisher confirmation.
3. If Option 1 is selected, separately authorize the communication channel and message before it is sent.
4. If Option 2 is selected, explicitly authorize a metadata-only bearer-token exception and a separate implementation/security-review gate. No such exception is currently approved.
5. Decide later whether absence of publisher checksums may be accepted with locally computed streaming SHA-256 after acquisition. No decision is needed or effective before transfer authorization.
6. Decide later whether a tokenized-only acquisition path is acceptable if the publisher cannot supply stable query-free URLs. This would require a new threat model and is not covered by Option 2.

## 8. Acceptance criteria for blocker resolution

The source-metadata blocker may be cleared only when all are true:

- every candidate is explicitly named and approved by the owner;
- the spelling discrepancy is resolved with publisher evidence or an explicit owner exception that records residual semantic risk;
- exact byte size and expected media type are independently recorded for each candidate;
- archive status is false;
- checksum availability is known and its absence, if any, is explicitly accepted;
- download authority and current academic-use/citation terms are confirmed;
- a stable publisher-controlled acquisition route compatible with the approved contract exists;
- sanitized evidence and hashes are reviewed by a distinct Security Administrator;
- the exact acquisition manifest passes all existing limits and is separately approved by the owner.

If any criterion remains false or ambiguous, acquisition remains blocked.

## 9. Deferred work

- Publisher contact or metadata probe execution.
- Any change to acquisition contracts or token policy.
- Concrete HTTP transport, approval transition, transfer API, or Celery task.
- Dataset download, parsing, mapping, quality/leakage analysis, split freezing, or acceptance.
- Phase 5B preprocessing, training, evaluation, registry, scoring, or model artifacts.
- Commit or publication.

## 10. Active next prompt

Publisher contact is cancelled. The active no-email planning prompt is maintained in `docs/SPRINT_5_NO_PUBLISHER_CONTACT_FALLBACK.md`.
