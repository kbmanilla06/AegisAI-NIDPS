# Use Cases and Abuse Cases

## Authorized use boundary

All telemetry and testing must be synthetic, public, locally owned, or explicitly authorized. The MVP never changes network state.

## Primary use cases

### UC-01 Authenticate and access a role-appropriate workspace

- **Actor:** Any user
- **Preconditions:** Active account and valid role
- **Flow:** Authenticate; server validates credentials and throttling; an opaque server-side session is created and its ID is placed in a secure cookie; state-changing requests require CSRF and Origin validation; UI and API expose permitted actions.
- **Failure:** Generic denial, throttling/lockout as configured, auditable event without credential data.

### UC-02 Register assets and sensors

- **Actor:** Security/System Administrator
- **Flow:** Create asset and network-zone metadata; register sensor; issue/rotate protected sensor credential; audit changes.
- **Security:** Criticality and internal/external classification later constrain policy.

### UC-03 Ingest authorized telemetry

- **Actor:** Administrator or sensor
- **Flow:** Submit supported source; validate type/schema/limits; queue processing; normalize/deduplicate; expose status and metrics.
- **Failure:** Reject safely with stable error; preserve no executable or uncontrolled file path.

### UC-04 Detect and create an alert

- **Actor:** Detection services
- **Flow:** Evaluate signature/rules/models; fuse evidence; suppress duplicates; persist alert with versions; notify authorized analysts.
- **Invariant:** No detector calls a prevention adapter.

### UC-05 Investigate an alert

- **Actor:** SOC Analyst
- **Flow:** Filter/open alert; inspect evidence and explanation; change valid status; add notes; assign/disposition; audit action.

### UC-06 Manage an incident

- **Actor:** SOC/Senior Analyst
- **Flow:** Group related alerts; preserve evidence; assign owner; maintain timeline; record containment/recovery/root cause; close with justification.

### UC-07 Register and activate a model

- **Actor:** Security Administrator or approved model operator
- **Flow:** Validate provenance/integrity/compatibility/card; stage model; review evaluation; activate with audit; retain rollback target.
- **Invariant:** Activation cannot alter prevention policy.

### UC-08 Review threat intelligence

- **Actor:** Analyst/Administrator
- **Flow:** Import trusted indicator; record provenance/confidence/expiry; match; display conflicts/allowlists; expire stale values.

### UC-09 Simulate prevention

- **Actor:** Authorized analyst
- **Flow:** Request action; policy evaluates gates; preview exact effect; simulation records result, expiry, rollback metadata, and audit.
- **Invariant:** No firewall or network state changes.

### UC-10 Review audit and reports

- **Actor:** Auditor or permitted administrator
- **Flow:** Filter/export authorized data; redact sensitive fields; record export; preserve traceability.

## Abuse cases

| ID | Abuse case | Required defensive response |
|---|---|---|
| AC-01 | Upload renamed executable, malformed PCAP, archive bomb, or parser exploit | Content/schema validation, isolation, size/decompression/time/memory limits, safe worker failure |
| AC-02 | Flood ingestion or alerts to exhaust queues/storage | Authentication, quotas, rate limits, backpressure, deduplication, suppression, health alerts |
| AC-03 | Replay sensor events or prevention requests | Stable event identity, idempotency keys, uniqueness constraints, audit |
| AC-04 | Steal or brute-force credentials | Adaptive hashing, throttling, lockout, expiry/revocation, audit, secret hygiene |
| AC-05 | Use viewer/analyst role for administration | Central server-side permission checks and negative tests |
| AC-06 | Poison training data or manipulate labels/features | Dataset manifests/checksums, provenance, review, leakage/quality checks, access controls |
| AC-07 | Replace a model artifact | Integrity verification, controlled registry, immutable metadata, least privilege, rollback |
| AC-08 | Tamper with thresholds/rules to suppress or flood alerts | Versioning, authorization, change audit, review, regression suites |
| AC-09 | Bypass allowlist or mark critical asset external | Validated asset authority, policy fail-closed behavior, change audit, conflict tests |
| AC-10 | Trick model/anomaly detector into blocking | Architectural separation; model/anomaly-only evidence cannot authorize action |
| AC-11 | Alter/delete audit evidence | Append-oriented access, restricted mutation, integrity checks, backup/retention controls |
| AC-12 | Exfiltrate data through reports/logs/external lookups | RBAC, redaction, minimal external disclosure, safe structured logging, export audit |
| AC-13 | Exploit API injection, traversal, SSRF, XSS, or mass assignment | Typed schemas, parameterization, allowlists, output encoding, safe fetch policy, explicit field mapping |
| AC-14 | Supply compromised dependency/container/action | Pinning policy, provenance, scanning, least-privilege CI, reviewed updates |

## Misuse that the product must refuse

- Unauthorized capture, scanning, exploitation, or traffic generation.
- Permanent blocking or production enforcement in the MVP.
- Loading untrusted artifacts without verified provenance.
- Exporting secrets or unrestricted raw telemetry.
- Claiming an anomaly or model score proves maliciousness.
