# UNSW-NB15 Official-Source Investigation

**Review date:** 2026-07-14
**Status:** Investigation complete; acquisition not authorized and not performed
**Official publisher page:** `https://research.unsw.edu.au/projects/unsw-nb15-dataset`
**Publisher:** UNSW Canberra at ADFA
**Page-reported last update:** 2021-06-02

## Confirmed official-page facts

- The page advertises PCAP, Bro/Zeek, Argus, CSV, feature-description, ground-truth, event-list, and report files through a UNSW-controlled SharePoint link.
- It describes approximately 100 GB of raw packet captures, 49 generated features, nine attack categories, and 2,540,044 records across four main CSV files.
- It lists prepared training and testing CSVs containing 175,341 and 82,332 records.
- Free use for academic research is granted in perpetuity.
- The listed works must be cited.
- Commercial use must be agreed with the authors, who assert copyright.

## Sprint 4 disposition

The official page was inspected, but its SharePoint download link was not opened. No dataset file, archive, checksum, feature-description file, or raw PCAP was requested or downloaded. The project remains academic/portfolio only. The approximately 100 GB PCAP is excluded. Prepared tabular files remain only a candidate for a separately authorized acquisition after current terms, exact filenames/sizes, storage capacity, extraction limits, and semantic mapping are approved.

The official page does not present an independent checksum in the visible source description. A future acquisition must record this absence and calculate local SHA-256 values without representing them as publisher checksums.

## Semantic and leakage blockers

UNSW-NB15's dataset-native 49-feature representation is not canonical flow v1. Every proposed input must prove compatible units, direction, timing, missingness, and serving availability. Labels, attack categories, row identifiers, capture/file identity, exact capture timing, and generator artifacts are excluded. The prepared publisher split is not accepted automatically; duplicates and host/capture/time relationships require a separate leakage review before model work.

## Required citations

The authoritative citation list remains the one on the official publisher page. At minimum it includes the 2015 UNSW-NB15 dataset paper and the publisher-listed evaluation and follow-on works. Bibliographic details must be copied from the official page at acquisition time and included in any academic output.

## Next acquisition gate

A future prompt must explicitly name the prepared files, expected total bytes, controlled storage location, current terms disposition, maximum download/extraction limits, and deletion policy. Without that approval, `acquisition_authorized` remains false and dataset metadata cannot contain file artifacts.
