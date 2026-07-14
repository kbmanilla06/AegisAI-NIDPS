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
| D-14 | Sprint 2 bounded defaults | 8 MiB upload, 10,000 records, 5,000 unique PCAP flows, 120-second worker soft limit, five submissions per identity per 60 seconds, 60-second delayed-job threshold. |
| D-15 | Ingestion idempotency | SHA-256 canonical event identity plus sensor scope; unique ledger/flow constraints; replay uses an actor-scoped idempotency key and reuses normalized records rather than retained raw content. |
## Owner decisions deferred beyond scaffolding

| ID | Decision | Why it blocks |
|---|---|---|
| D-13 | Safe model serialization format | Required before any model artifact implementation, but does not block the basic Sprint 0 scaffold if model loading is absent. |

D-13 must be answered before Sprint 5 implementation. The MIT License applies to repository code and documentation only; third-party datasets retain their own terms.
