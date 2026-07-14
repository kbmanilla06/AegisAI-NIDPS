# Detection Architecture

**Status:** Sprint 3 deterministic detection and alert generation implemented; ML, intelligence, incidents, and prevention workflows remain deferred

## Principles

Detections produce versioned evidence, not enforcement. Sprint 3 does not calculate risk or confidence and does not infer malicious intent from network behavior. Every alert is reproducible from an immutable rule definition or a strict signature event plus a versioned evidence snapshot.

## Pipeline

1. Sprint 2 canonical flows and Sprint 3 strict Suricata signature events pass schema/provenance checks.
2. Successful ingestion creates a persisted, idempotent detection run and dispatches only its UUID on the JSON-only `detection` queue.
3. Active immutable behavioral rule versions evaluate fixed UTC event-time buckets; signature events map directly to signature signals.
4. Stable semantic keys deduplicate identical signals. Material late evidence creates a new signal while preserving the alert series.
5. A versioned fingerprint creates or updates one alert per semantic series; bounded evidence snapshots remain explainable after 30-day flow cleanup.
6. PostgreSQL commits alerts before Redis publishes minimal notification IDs. REST remains authoritative and polling is the fallback. Source signatures, signals, and runs expire after 30 days; bounded evidence snapshots remain with alerts for 180 days.

Feature, ML, intelligence, ensemble, analyst disposition, and incident stages are future work and are not called by the Sprint 3 path.

## Initial rules

| Rule family | Evidence | Main false-positive considerations |
|---|---|---|
| Port scan indicator | Unique destination ports/hosts per source and window | Vulnerability scanners, admin discovery |
| Repeated failures | Failed states per source/service/window | Misconfiguration, expired credentials |
| High connection rate | Connection count/rate and burst | Proxies, monitoring, load tests |
| Suricata signature | Strict signature ID/revision/category/severity plus bounded flow tuple | Upstream signature quality and policy-only signatures |

The three behavioral rules above are the only initially active behavioral rules. DNS volume, beaconing, brute-force claims, and outbound-volume rules remain deferred until their canonical prerequisites and false-positive cases are defensible. Each rule version defines its evaluator key, validated parameters, fixed event-time window, severity, evidence contract, false-positive and investigation guidance, optional defensible MITRE mappings, and change rationale. PostgreSQL prevents mutation of definition fields after insertion.

## Alert fingerprinting

Fingerprint schema `alert-fingerprint/v1` uses the signal series key: source type, rule version or signature identity, normalized grouping, and fixed time bucket. Exact reprocessing is a no-op. Material late evidence adds a uniquely hashed signal/evidence occurrence and updates the same alert without erasing first/last seen. A maximum of 100 evidence rows is stored per alert; further occurrences increment the overflow counter. Fingerprint semantic changes require a new schema version.

## Lifecycle, authorization, and limits

Rule versions move `draft → approved → active/retired`. Creation, review, activation, deactivation, and rollback require separate centralized permissions and produce audit records; activation uses an expected-active-version check. Viewer grouping/evidence omits source and destination addresses; sensitive evidence requires `alerts:read_sensitive`.

One run evaluates at most 50 active rules, 5,000 groups, 10,000 signals, 1,000 alert mutations, and 100 evidence rows per alert. Celery uses 60-second soft and 75-second hard limits with two bounded retries. The live alert channel reauthorizes at most every 15 seconds, has an in-process queue of 100 messages per client, and closes revoked, expired, unauthorized, or slow consumers; REST polling remains available.

## Ensemble design

The exact formula is deferred until evidence distributions exist. Its contract requires normalized signature strength, behavioral strength, supervised probability, anomaly score, intelligence confidence/freshness, asset criticality, and historical context. Weights and thresholds are versioned configuration. Missing signals are explicit, not silently zeroed. Golden regression cases protect scoring changes.

## Severity and confidence

- **Risk:** estimated analyst priority, 0–100.
- **Confidence:** reliability of the assessment given evidence and model calibration.
- **Severity:** potential impact/context: informational, low, medium, high, critical.
- **Uncertainty:** missing/conflicting signals and data-quality limitations.

## MITRE mapping

Mappings attach technique ID, mapping rationale, evidence source, mapping version/date, and confidence. Network behavior may indicate a technique but does not prove adversary intent.

## Testing

Positive/negative/boundary/timezone/out-of-order/late/duplicate/replay/high-volume tests; model incompatibility/degraded tests; scoring golden cases; suppression/fingerprint regressions; false-positive fixture suite; evidence/version traceability checks.
