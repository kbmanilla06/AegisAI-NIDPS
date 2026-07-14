# Detection Architecture

## Principles

Detections produce versioned evidence, not enforcement. Deterministic methods remain available when ML or intelligence is degraded. Scores, confidence, and severity are distinct. Every alert is reproducible from stored references and configuration versions.

## Pipeline

1. Canonical telemetry passes schema and provenance checks.
2. Suricata alerts become normalized signature signals.
3. Behavioral rules evaluate event-time windows.
4. Shared feature pipeline creates versioned vectors.
5. Supervised model produces probabilities; anomaly model produces an anomaly score.
6. Fresh intelligence and asset context are joined.
7. Ensemble formula produces assessment and contributing-signal list.
8. Deduplication/suppression creates or updates an alert.
9. Analysts provide disposition used for evaluation, not immediate uncontrolled retraining.

## Initial rules

| Rule family | Evidence | Main false-positive considerations |
|---|---|---|
| Port scan indicator | Unique destination ports/hosts per source and window | Vulnerability scanners, admin discovery |
| Repeated failures | Failed states per source/service/window | Misconfiguration, expired credentials |
| High connection rate | Connection count/rate and burst | Proxies, monitoring, load tests |
| DNS volume | Query rate/unique names/failure pattern | Resolvers, updates, busy clients |
| Possible beaconing | Periodicity and repeated endpoint metadata | Health checks, telemetry agents |
| Outbound volume | Bytes/rate versus asset/time context | Backups, updates, legitimate transfers |

Each rule version defines key, description, prerequisites, event-time window, threshold, grouping, suppression, severity suggestion, MITRE mapping if defensible, evidence, investigation, tests, and change rationale.

## Alert fingerprinting

A fingerprint uses normalized rule/category, relevant endpoints or asset, bounded time bucket, and rule/assessment version. Suppression must merge evidence/counts without erasing original first/last seen. Changes to fingerprint semantics require a version.

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
