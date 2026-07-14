# AegisAI NIDPS Product Requirements Document

**Status:** Approved baseline
**Release target:** Portfolio MVP, Sprints 0–9
**Prevention mode:** Simulation only

## Executive summary

AegisAI NIDPS is a defensive network-security platform that ingests authorized network metadata, applies signature, behavioral, supervised-ML, and anomaly detection, explains its findings, and supports SOC-style alert and incident workflows. The MVP previews and audits prevention actions but must not change firewall or network state.

## Problem

Network-security learners and small lab operators need an understandable system that correlates multiple detection methods without hiding evidence behind a model score. Existing demonstrations often focus on a single classifier, omit operational workflows, overstate dataset performance, or connect detections directly to unsafe blocking. AegisAI will demonstrate the full defensive lifecycle with traceability and safe defaults.

## Users

| Persona | Primary need |
|---|---|
| SOC Analyst | Triage, investigate, classify, and group alerts |
| Senior Analyst | Review evidence, tune thresholds, manage incidents, review prevention previews |
| Security Administrator | Manage rules, policies, allowlists, models, and integrations |
| System Administrator | Operate services, users, backups, and health controls |
| Auditor | Review append-oriented audit evidence and reports |
| Viewer/Recruiter | Safely inspect dashboards, architecture, and demonstrated results |

## Goals

1. Normalize controlled Zeek, Suricata EVE JSON, flow records, and later offline PCAP-derived telemetry.
2. Produce evidence-bearing signature and behavioral detections.
3. Compare defensible supervised baselines and add anomaly scoring.
4. Produce transparent risk, confidence, severity, and uncertainty.
5. Explain model contributions and show rule/signature evidence.
6. Support alert triage, investigation, incidents, notes, assignments, and feedback.
7. Map defensible detections to MITRE ATT&CK with mapping provenance.
8. Preview time-bounded prevention actions under a deterministic policy engine.
9. Maintain traceability across schemas, datasets, features, rules, thresholds, and models.
10. Run reproducibly in a local containerized development environment after planning approval.

## Non-goals for the MVP

- Production network deployment or enterprise-readiness claims.
- Live packet capture.
- Real firewall, nftables, iptables, cloud, endpoint, account, or VLAN changes.
- Automatic or permanent blocking.
- Offensive scanning, exploitation, credential access, malware, persistence, or evasion.
- Full packet-payload retention by default.
- A guarantee to detect all attacks or true zero-days.
- Automatic retraining or model promotion.
- Deep learning without evidence that simpler models are insufficient.

## MVP scope by sprint

| Sprint | Outcome |
|---|---|
| 0 | Approved requirements, architecture, threat model, contracts, safety plan, backlog, and minimal repository/runtime foundation |
| 1 | Identity, RBAC, assets, sensors, audit foundation |
| 2 | Safe telemetry ingestion and normalization |
| 3 | Signature normalization and behavioral detection |
| 4 | Versioned feature engineering and data pipeline |
| 5 | Reproducible supervised baselines and safe inference |
| 6 | Anomaly scoring and transparent decision fusion |
| 7 | Explainability, intelligence, and MITRE context |
| 8 | Alert, incident, and SOC dashboard workflows |
| 9 | Prevention policy and simulation adapter only |

## Primary workflows

1. Administrator registers an asset/sensor and grants least-privilege access.
2. Authorized telemetry is uploaded or replayed from controlled fixtures.
3. Ingestion validates, normalizes, versions, deduplicates, and records processing status.
4. Detection services generate evidence and candidate alerts.
5. The ensemble engine calculates documented scores without granting enforcement authority.
6. The analyst investigates evidence, records disposition, and creates an incident when warranted.
7. The system proposes a prevention preview; policy gates produce pass/fail reasons.
8. Simulation records what would happen, expiration, rollback metadata, and audit events without network changes.

## Success metrics

- 100% of alerts reference their source evidence and relevant rule/model/feature versions.
- 100% of simulated prevention requests record policy version, gate results, duration, and rollback metadata.
- 0 real network-state changes in Sprints 0–9.
- 100% of protected API operations have explicit authorization tests.
- Supported malformed telemetry fails safely without terminating the API process.
- ML reports include per-class precision/recall/F1, PR-AUC where applicable, false-positive/negative rates, calibration, latency, and limitations.
- A clean environment can reproduce the documented MVP demonstration.

## Security and privacy principles

- Authorized defensive data only; synthetic fixtures are preferred.
- Metadata-first collection and configurable retention.
- Least privilege, server-side authorization, safe errors, and non-sensitive structured logs.
- Strict upload/parser limits and isolated background processing.
- Append-oriented audit records for sensitive actions.
- No model, anomaly score, or intelligence match directly executes prevention.

## Reporting

MVP reports include alert investigation, incident, false-positive, model evaluation, simulated prevention, security health, and executive summary. Reports must enforce RBAC and exclude secrets and unnecessary raw telemetry.

## Constraints

- Portfolio project maintained initially by one developer.
- Local Docker Compose is the approved first runtime.
- Public datasets may differ from real traffic and from one another.
- External intelligence access may be unavailable or privacy-sensitive.
- Development is constrained to the approved 8 GB Apple M2 ARM64 host; later workloads require measured resource budgets.

## Dependencies

- Approved design documents and threat model.
- A legally usable primary dataset.
- Synthetic telemetry fixtures.
- PostgreSQL, Redis, background worker, API, and web UI after implementation is authorized.
- Zeek and Suricata formats; tools themselves need not run in the earliest development slice.

## Acceptance criteria for planning approval

- Requirements, schemas, components, data flows, threats, APIs, data model, ML plan, testing, deployment, risks, and backlog are mutually consistent.
- Confirmed requirements, assumptions, and approval decisions are visibly separated.
- Simulation-only prevention and no live capture are explicit.
- Open security-sensitive decisions are not silently resolved.

## Phase-two roadmap

After the Sprint 9 MVP is stable: approval-based temporary lab enforcement, limited automatic lab action, model monitoring, reporting/observability, full security hardening, and portfolio release. Each requires separate approval and evidence gates.

## Confirmed requirements

- Product name is AegisAI NIDPS.
- First release covers Sprints 0–9.
- It is an IDS with simulated IPS.
- Sprint 0 foundation implementation was separately authorized after planning approval; later sprints remain gated.

## Assumptions

- The project will be developed locally and publicly presented using sanitized data.
- The owner prefers a modular monorepo and containerized services.
- English is the initial UI and documentation language.

## Deferred decision

See `docs/DECISIONS.md`. All decisions needed for Sprint 0 and Sprint 1 are resolved. Safe model serialization remains open and must be approved before Sprint 5.
