# Sprint 4 Synthetic Feature Quality Report

**Date:** 2026-07-14
**Scope:** Synthetic canonical flow v1 fixtures only
**Dataset status:** No public dataset acquired, opened, extracted, or profiled

## Purpose and limits

This report validates the implemented feature contract and pipeline mechanics; it is not evidence that UNSW-NB15 or any real traffic source is suitable for training. There are no ground-truth labels, class distributions, real capture relationships, or production representativeness claims in Sprint 4.

## Contract evidence

- Feature schema: `flow_features` `1.0.0`, input canonical flow schema `1`.
- Definition SHA-256: `17d374837008e6153c76c946ad3ac58abb5f516fb0e0e3f23305025fa8bfe114`.
- Width: 39 ordered model features: 17 direct, 11 at 60 seconds, and 11 at 300 seconds.
- Window order: `(event_time,event_key)`; lower boundary inclusive and upper boundary inclusive as-of the stable tuple.
- Group context: authenticated sensor scope plus canonical source address. Those identities are not model values.
- Missing/unseen policy: explicit presence flags, zero-denominator flags, `__MISSING__`, `__UNKNOWN__`, rejection of non-finite/invalid values, and capped rates with `rate_clipped` evidence.
- Leakage denylist includes labels, attack categories, raw endpoint identities, event/job/sensor IDs, exact event time, detection/alert/risk/incident/prevention fields, split, and source filename.

## Fixture coverage

The committed synthetic fixtures and tests cover valid, zero/missing, unseen category, Unicode/malformed scalar, duplicate, conflicting duplicate, out-of-order, exact 60/300-second boundary, sensor separation, leakage, schema mismatch, and train-only vocabulary behavior. Reference `transform_one` and optimized `transform_batch` outputs match for identical ordered context.

## Resource and integrity evidence

- The 10,000-flow ARM64/Python 3.12 performance test passed its explicit limits: under 30 seconds for transformation and under 256 MiB incremental maximum RSS. The gate records pass/fail rather than claiming an unsupported exact throughput number.
- The final isolated-stack job transformed 1 synthetic flow into 1 row in approximately 0.10 seconds of persisted job time.
- Final controlled artifact: 16,140 bytes, SHA-256 `a2f757b3b27ec5a9c3b613863270ed167d97bb11517e995d002ebafc032a3287`, 46 Parquet columns.
- The 46 columns are 7 reserved non-model provenance fields followed by the 39 ordered model features.
- Artifact inspection confirmed source-event key, cutoff, feature-schema hash/version, source-snapshot hash, vector hash, and quality flags; `src_address` and `dst_address` were absent.
- The artifact is opaque, atomic, Zstandard-compressed, controlled-volume only, and expires after 30 days.

## Deferred real-dataset quality work

Exact/near duplicates, missingness, outliers, class/label distribution, temporal/host/session relationships, dataset-native field mapping, split leakage, and benchmark coverage remain unmeasured because dataset acquisition was not authorized. They are mandatory before any training authorization.
