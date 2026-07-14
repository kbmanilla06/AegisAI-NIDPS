# UNSW-NB15 Official-Source Review

**Review date:** 2026-07-14
**Download status:** Not downloaded
**Official source:** https://research.unsw.edu.au/projects/unsw-nb15-dataset

## Officially stated characteristics

UNSW Canberra states that the dataset was created in its Cyber Range Lab using IXIA PerfectStorm to generate a mixture of modern normal activity and synthetic attack behavior. The official page describes approximately 100 GB of raw captured traffic, 2,540,044 records in four main CSV files, 49 generated features, and nine attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms.

The official page also provides prepared training and testing files with 175,341 and 82,332 records respectively. Their existence does not remove the need to audit how the split was constructed or whether host, time, flow, or generator relationships could create leakage.

## Use and citation conditions

The official page grants free use for academic research in perpetuity, requires citation of the listed dataset papers, and states that commercial use must be agreed with the authors. Therefore:

1. Repository visibility, MIT code licensing, and academic/portfolio-only intent are decided. Still require separate acquisition authorization immediately before download.
2. Do not redistribute raw files or processed extracts in Git.
3. Include required citations in dataset documentation, model cards, reports, and public claims.
4. If the portfolio or later product has commercial use, obtain author agreement first.
5. Record the exact source URL, acquisition date, filenames, sizes, and locally calculated SHA-256 values after an authorized download.

## Technical suitability

UNSW-NB15 is suitable as an initial supervised-learning benchmark because it contains normal and multiple attack categories plus published features. It is not proof of current real-world performance: traffic was generated in a specific cyber-range environment, attack behavior includes synthetic generation, and class/capture artifacts may be learnable.

## Mandatory pre-training audit

- Inspect official feature descriptions, types, units, and label fields.
- Identify row IDs, labels, ground-truth-derived, post-event, source-tool, and capture-artifact fields.
- Measure duplicates, missing/invalid values, class imbalance, and near-duplicate flows.
- Investigate the official train/test construction rather than assuming it is leakage-safe.
- Prefer a new documented source/time/host-aware split if available metadata supports it.
- Fit preprocessing on training only and retain an untouched final test set.
- Validate the selected model on a second, independently sourced dataset or controlled telemetry before making broader claims.

## Decision

**Conditionally suitable as the primary benchmark candidate.** Academic-use conditions are compatible with the approved intent, but citations, non-redistribution, acquisition provenance, and a leakage/schema audit remain mandatory. No data acquisition is authorized by this review.
