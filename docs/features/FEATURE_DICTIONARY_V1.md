# Feature Dictionary v1

Controlled Parquet artifacts store these non-model provenance columns before the 39 ordered model features: source event key, cutoff time, feature-schema hash/version, source-snapshot hash, vector hash, and bounded quality flags. They use the reserved `__aegis_` prefix. Provenance columns are never part of `ordered_values` and must be excluded by every training/inference matrix selector.

**Contract:** `feature-dictionary/v1`
**Feature schema:** `flow_features` `1.0.0`
**Input:** canonical flow schema `1` only
**Output:** 39 ordered fit-free features
**Prevention impact:** none

The authoritative machine-readable order and vocabulary are in `FEATURE_DICTIONARY_V1.json` and the immutable database feature-schema record. Raw endpoints, event/job/sensor identifiers, labels, exact timestamps, alerts, rule results, incidents, and prevention data are provenance or context only and never vector values.

## Direct features

| Feature group | Type/unit | Meaning | Missing/range policy |
|---|---|---|---|
| `duration_ms` | int64 milliseconds | Canonical duration | Required; 0–604,800,000 |
| `packet_count`, `byte_count` | int64 counts | Canonical reported totals | Required; non-negative |
| port values/presence/classes | int64/bool/category | Paired port availability and IANA numeric band | Missing ports use zero plus presence=false; no service inference |
| `protocol`, `connection_state` | category | Bounded canonical/source-aware tokens | Missing and unseen are distinct reserved tokens |
| bytes/packet and packet/byte rates | float64 | Deterministic density/rate | Zero denominator produces zero plus indicator; non-finite rejects; rate cap emits quality flag |
| zero/rate flags | bool | Quality and denominator state | Never missing |

## Window features

Both 60- and 300-second as-of windows produce flow count, unique destination-address count, unique destination-port count, packet/byte totals, recognized Zeek failure count, mean/max duration, mean bytes per flow, seconds since prior same destination/service, and a prior-service-missing indicator.

Windows are grouped by authenticated sensor scope and source address for computation. Context order is `(event_time,event_key)`. The lower time boundary and target as-of tuple are inclusive. Duplicate event keys count once; a conflicting duplicate fails. Raw grouping values are excluded from artifacts.

## Missing values and vocabularies

- Required canonical values fail validation when missing or invalid.
- `__MISSING__` differs from `__UNKNOWN__` and from numeric zero.
- Data-derived vocabularies, imputers, and statistics can only fit with an immutable training-split hash.
- Validation, test, and future inference paths can transform but cannot fit or mutate vocabularies.
- NaN and infinity are never emitted.

## Deferred features

DNS, HTTP, TLS, detailed TCP flags, packet-size samples, inter-arrival distributions, authentication outcomes, directional ratios, and beaconing statistics are excluded because canonical flow v1 does not carry defensible serving semantics for them.
