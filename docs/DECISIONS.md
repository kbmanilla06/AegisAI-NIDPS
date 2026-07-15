# Decisions, Assumptions, and Approval Register

## Confirmed by project owner

| ID | Decision |
|---|---|
| C-01 | Product is AegisAI NIDPS. |
| C-02 | First release covers Sprints 0–9: IDS plus simulated IPS. |
| C-03 | Sprint 0 began as a documentation-only task; that boundary was completed before foundation work was authorized. |
| C-04 | The separately authorized foundation scope permits only the minimal scaffold, local services, security interfaces, checks, and documentation. Dataset downloads, model work, live capture, real prevention, Sprint 1 features, commits, and publication remain prohibited. |
| C-05 | Frontend is React with Vite. |
| C-06 | Background worker is Celery, using Redis as broker/short-lived coordination. |
| C-07 | Authentication uses server-side secure cookie sessions with CSRF protection; no browser JWT storage. |
| C-08 | UNSW-NB15 is the primary dataset candidate, subject to official-source/license clearance before download. |
| C-09 | Raw uploads are deleted after successful processing or within 24 hours, whichever occurs first, subject to safe failed-job handling. |
| C-10 | Flow retention is 30 days; alert and audit retention is 180 days for development. |
| C-11 | Artifacts use a controlled local volume; PostgreSQL stores references and SHA-256 hashes. |
| C-12 | Repository is public. |
| C-13 | Repository code is licensed under the MIT License. Dataset terms remain separate and no dataset is redistributed. |
| C-14 | Intended use is academic/portfolio only. |
| C-15 | Development host is an Apple M2 MacBook Air with 8 CPU cores, 8 GB RAM, macOS 26.5.2, ARM64, and approximately 300 GiB available at approval time. |
| C-16 | Incident and analyst-note retention is 180 days; generated reports and stored predictions are retained for 30 days; exceptional investigation holds are disabled for the MVP. |
| C-17 | The owner approved the recommended defaults and authorized the Sprint 0 foundation on 2026-07-14. |
| C-18 | Hosted Sprint 0 CI Run #1 passed for commit `44dbc59`; the owner authorized Sprint 1 on 2026-07-14. |
| C-19 | Sprint 1 was published as `61ef2cc9e79dbd987debc226e4349bd3cb8571a5`; hosted CI Run #2 (`29312141925`) passed before Sprint 2 began. |
| C-20 | Sprint 2 was published as `29c2891f1e6bfe6686d4ef6c2489932d2f0a2fcd`; hosted CI Run #4 passed before Sprint 3 planning. |
| C-21 | The owner approved every recommended Sprint 3 default and authorized only the exact Section 31 implementation scope on 2026-07-14. |
| C-22 | Sprint 3 was reviewed and published as `b514aa3592487a65b8de8e1cfa14f4f9b80c5976`; hosted CI Run #5 (`29325828604`) passed before Sprint 4 planning began. |
| C-23 | The owner approved all recommended Sprint 4 defaults and authorized the Section 33 implementation scope on 2026-07-14. Canonical flow v1, direct plus 60/300-second features, controlled Parquet, 30-day feature-artifact retention, and solo Security Administrator review with complete audit are fixed Sprint 4 decisions. |
| C-24 | Sprint 4 authorizes investigation of the official UNSW-NB15 source only. No dataset acquisition is authorized, and the approximately 100 GB raw PCAP is explicitly excluded. |
| C-25 | Sprint 4 was reviewed and published as `72c97b15f9bb31ddb6810a397afc682893497bab`; hosted CI Run #7 (`29332025235`) passed before Sprint 5 planning began. |
| C-26 | On 2026-07-14 the owner approved all Sprint 5 plan defaults, including separate Phase 5A/5B gates, bounded official-source acquisition controls, group/time-aware 70/15/15 split, binary supervised target, baseline sequence, and ONNX plus canonical JSON as safe-format decision D-13. This authorization permits pre-acquisition foundations and source metadata review only; no dataset transfer or model work. |
| C-27 | On 2026-07-14 the owner recorded Phase 5A publisher metadata inspection as blocked. The official folder shows unapproved `NUSW-NB15_features.csv` and `NUSW-NB15_GT.csv`, rounded sizes only, no visible publisher checksums, and no stable query-free object URLs. Acquisition remains unauthorized. Option 1 publisher confirmation is recommended; Option 2 zero-body tokenized metadata probing remains unapproved planning only. |
| C-28 | On 2026-07-14 the owner approved Option 1 as the required Phase 5A blocker-resolution path and authorized preparation of an unsent publisher clarification request only. The two `NUSW-...` objects remain excluded; publisher contact, metadata probes, acquisition, transfer, commits, and publication remain unauthorized. |
| C-29 | On 2026-07-14 the owner chose the no-publisher-contact fallback. The prepared Gmail draft is not authorized for sending. UNSW-NB15 acquisition remains blocked and deferred; only separately planned synthetic/demo work may continue, with no real-dataset performance claims. |
| C-30 | On 2026-07-14 the owner approved all recommended synthetic-only defaults and authorized Gate 5S-A only. The fixed boundary is project-generated canonical-flow-v1 data, eight closed scenario families, labels `synthetic_benign_like`/`synthetic_intrusion_like`, seed `20260714`, at most 10,000 flows/120 groups, exact 39+7 feature output with targets separate, deterministic group/time 70/15/15 split, distinct System/Security Administrator review accounts, 30-day artifacts, mandatory limitation text, no numeric performance claim, and no model work. |

## Safe working assumptions

| ID | Assumption | Consequence if wrong |
|---|---|---|
| A-01 | Local Docker Compose is preferred. | Deployment plan changes. |
| A-02 | Metadata/flows are retained; payloads are off by default. | Privacy and storage design changes. |
| A-03 | A modular monorepo suits a solo portfolio project. | Repository/service boundaries change. |
| A-04 | Synthetic/sanitized data will drive the demo. | Publication and privacy controls change. |
| A-05 | English is the initial UI/docs language. | Localization backlog changes. |

## Resolved technical decisions

| ID | Decision | Recommendation |
|---|---|---|
| D-01 | Frontend | React + Vite; authenticated SPA without SSR/SEO requirement. |
| D-02 | Worker | Celery with JSON-only task messages; no pickle task serialization. |
| D-03 | Authentication | Opaque server-side session ID in `Secure`, `HttpOnly`, `SameSite=Lax` cookie; CSRF token plus Origin checks for unsafe methods; rotate on login/privilege change. |
| D-04 | Primary dataset candidate | UNSW-NB15; official terms were reviewed, but do not download or redistribute it during Sprint 0. Reconfirm academic-use conditions and citations immediately before acquisition. |
| D-06 | Raw upload retention | Delete immediately after successful processing or by 24 hours; failed quarantined jobs remain no longer than 24 hours unless explicitly preserved for authorized analysis. |
| D-07 | Development retention | Raw uploads: delete after successful processing or within 24 hours; flows: 30 days; alerts, audit, incidents, and analyst notes: 180 days; reports and predictions: 30 days; exceptional holds disabled. |
| D-08 | File/artifact storage | Controlled local volume; DB stores opaque references, size, media type, and SHA-256. |
| D-09 | Safe model serialization | Choose after library/version threat review; prohibit arbitrary untrusted pickle. |
| D-10 | Sprint 1 password/session defaults | Argon2id (64 MiB, 3 iterations, parallelism 1); 12-character minimum; 30-minute idle and 8-hour absolute session expiry; 5 failures lock an account for 15 minutes; Redis limits an IP to 10 login attempts per 300 seconds. |
| D-11 | Built-in roles | Viewer, SOC Analyst, Senior Analyst, Security Administrator, System Administrator, and Auditor are migration-seeded; permission enforcement is server-side and centralized. |
| D-12 | Sprint 2 ingestion contract | Canonical flow schema v1; normalized JSONL first, strict Zeek connection logs, Suricata EVE flow events, and offline PCAP/PCAPNG only. No archive input and no live capture. |
| D-13 | Safe model serialization format | ONNX for the complete fitted preprocessing-plus-classifier serving artifact and canonical JSON for manifests; closed operator/opset policy, no external data/custom operators, no Python-object serving artifacts, and mandatory conversion/runtime parity. This resolves format selection only and does not authorize model work. |
| D-14 | Sprint 2 bounded defaults | 8 MiB upload, 10,000 records, 5,000 unique PCAP flows, 120-second worker soft limit, five submissions per identity per 60 seconds, 60-second delayed-job threshold. |
| D-15 | Ingestion idempotency | SHA-256 canonical event identity plus sensor scope; unique ledger/flow constraints; replay uses an actor-scoped idempotency key and reuses normalized records rather than retained raw content. |
| D-16 | Sprint 3 active rules | Activate only deterministic port-scan (20 unique ports/60 seconds), recognized Zeek connection failures (10/300 seconds), and high connection rate (100 distinct flows/60 seconds). Ambiguous DNS, beaconing, brute-force, and outbound-volume claims remain deferred. |
| D-17 | Rule lifecycle | Immutable version rows; closed evaluator registry; draft/review/activation separation; expected-active concurrency; audited deactivate/rollback; SHA-256 covers every definition field. |
| D-18 | Alert identity and evidence | `alert-fingerprint/v1`; exact reruns are no-ops, material late evidence creates a new signal in the same alert series, 100 evidence rows per alert with overflow count, evidence snapshots survive flow cleanup. |
| D-19 | Sprint 3 bounded execution | 50 active rules, 5,000 groups, 10,000 signals, 1,000 alert mutations/run, 60/75-second Celery limits, two retries, 100 queued live notifications/client. |
| D-20 | Sprint 3 semantics | No risk/confidence score, incident workflow, model/intelligence dependency, automatic disposition, or prevention action. Viewer endpoints are redacted; persisted REST state is authoritative over live notifications. |
| D-21 | Sprint 4 feature contract | Immutable `feature-schema/v1` over canonical flow v1 only; 17 direct and 11 features for each of 60/300-second inclusive event-time windows; stable `(event_time,event_key)` ordering; identities remain provenance/grouping and never vector values. |
| D-22 | Sprint 4 artifacts and governance | Zstandard-compressed Parquet on the controlled local artifact volume, SHA-256 and opaque PostgreSQL references, 30-day expiry, schema/dataset approval by Security Administrator only, and complete audit records. |
| D-23 | Sprint 4 dataset boundary | Store metadata from the official UNSW-NB15 publisher investigation only. Acquisition, download, extraction, adaptation, and redistribution remain false/empty; raw UNSW-NB15 PCAP stays excluded. |
| D-24 | Sprint 5 synthetic Gate 5S-A | Closed `synthetic-flow-scenario/v1` generator over canonical flow v1; 7,200 fixed generated rows across 120 groups and eight equal scenario families; labels live only in `synthetic-target/v1`; immutable content/split/quality/leakage hashes; sealed test partition; no external source or network request. |
| D-25 | Synthetic governance and claims | System Administrator generates and a distinct Security Administrator reviews exact hashes. Every artifact/report/UI surface carries `synthetic-demo-limitations/v1`; lifecycle has no model or active state; numeric model-performance claims are prohibited. |

The MIT License applies to repository code and documentation only; third-party datasets retain their own terms.
