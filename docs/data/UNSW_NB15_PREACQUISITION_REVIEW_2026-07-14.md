# UNSW-NB15 Pre-Acquisition Source Review — 2026-07-14

**Review times:** 2026-07-14T12:49:02Z and 2026-07-14T14:50:31Z

**Scope:** Publisher metadata and access-path review only. No dataset file, sample, archive, or payload was downloaded or parsed.

**Official page:** `https://research.unsw.edu.au/projects/unsw-nb15-dataset`

**Publisher:** UNSW Research / UNSW Canberra

**Official page revision shown:** Last Updated 02 June 2021

**Decision:** `BLOCKED_BEFORE_ACQUISITION`

## Confirmed publisher metadata

The official page currently states:

- The dataset contains approximately 100 GB of raw PCAP traffic. This remains excluded.
- The four principal tabular files are `UNSW-NB15_1.csv`, `UNSW-NB15_2.csv`, `UNSW-NB15_3.csv`, and `UNSW-NB15_4.csv`, totaling 2,540,044 records.
- The feature description is `UNSW-NB15_features.csv`.
- Ground truth is `UNSW-NB15_GT.csv`; the event listing is `UNSW-NB15_LIST_EVENTS.csv`.
- Publisher-prepared files `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` exist but remain excluded from the authoritative split proposal.
- Academic research use is granted without charge; commercial use requires agreement by the authors.
- Citation is required. The five works listed in the official dataset section must be preserved in the later dataset datasheet/model card.

The page does not grant Aegis permission to redistribute dataset files. Dataset bytes must remain outside Git and any public release artifact.

## Access-path result

The first anonymous HTTP review followed the publisher link toward Microsoft authentication and could not inspect the folder. A separately authorized browser metadata inspection on 2026-07-14 subsequently reached the read-only shared folder at `unsw-my.sharepoint.com` directly from the official publisher page without signing in. No search engine, mirror, guessed URL, or unrelated folder was used.

The folder exposed names, CSV type indicators, rounded display sizes, a read-only marker, and an enabled Download menu. The Download action was not clicked. No file was opened, previewed, parsed, or transferred. The UI did not expose exact byte counts, publisher checksums, ETags, or stable object versions. The official publisher link is a tokenized SharePoint sharing URL, so it does not satisfy the approved credential-free/query-free transfer contract.

Two material filename discrepancies were found:

- the publisher page names `UNSW-NB15_features.csv`, while the current folder visibly contains `NUSW-NB15_features.csv`;
- the publisher page names `UNSW-NB15_GT.csv`, while the current folder visibly contains `NUSW-NB15_GT.csv`.

The two observed `NUSW-...` objects were not in the owner's authorized candidate list and therefore remain excluded. Their presence cannot be treated as a typo correction without a new explicit owner decision.

No browser cookie, OAuth parameter, SharePoint sharing token, account identifier, or redirected authorization URL is recorded in this repository.

## Candidate inventory — not an acquisition manifest

| Logical file | Proposed role | Advertised size | Media type | Status |
|---|---|---:|---|---|
| `UNSW-NB15_1.csv` | Principal tabular part 1 | 161 MB displayed; exact bytes unavailable | CSV File | Present; blocked on exact bytes/URL/checksum |
| `UNSW-NB15_2.csv` | Principal tabular part 2 | 158 MB displayed; exact bytes unavailable | CSV | Present; blocked on exact bytes/URL/checksum |
| `UNSW-NB15_3.csv` | Principal tabular part 3 | 147 MB displayed; exact bytes unavailable | CSV | Present; blocked on exact bytes/URL/checksum |
| `UNSW-NB15_4.csv` | Principal tabular part 4 | 93.1 MB displayed; exact bytes unavailable | CSV | Present; blocked on exact bytes/URL/checksum |
| `UNSW-NB15_features.csv` | Official feature dictionary | Not present under authorized name | — | Blocked: folder shows unapproved `NUSW-NB15_features.csv` (3.95 KB displayed) |
| `UNSW-NB15_GT.csv` | Conditional label provenance | Not present under authorized name | — | Blocked: folder shows unapproved `NUSW-NB15_GT.csv` (82.4 MB displayed) |
| `UNSW-NB15_LIST_EVENTS.csv` | Conditional event/group provenance | 4.53 KB displayed; exact bytes unavailable | CSV | Present; blocked on exact bytes/URL/checksum |

The raw PCAP, BRO/Zeek files, Argus files, reports not explicitly named above, publisher-prepared train/test files, TON_IoT, mirrors, and all other objects are excluded.

## Terms and citation disposition

- Intended Aegis use remains academic/portfolio only.
- Repository MIT licensing does not cover dataset files.
- Commercial use is not authorized by this project decision.
- Required citations will be copied exactly from the publisher page into the accepted dataset datasheet and later model card.
- The project will not redistribute dataset bytes.
- Terms must be revalidated again immediately before any later authorized transfer.

## Acquisition blocker and resolution evidence

No acquisition authorization prompt can safely be produced. The authorized inspection established enough metadata to identify four independent blockers:

1. two required authorized names are absent and two differently spelled, unapproved names are present;
2. SharePoint reports rounded display sizes rather than exact byte counts;
3. the only publisher file path exposed by the official page is a tokenized sharing URL, which the approved contract prohibits;
4. no publisher checksum is visible, and actual file-download authority was not exercised because doing so was prohibited.

Resolution requires a new owner decision that explicitly names any revised candidates and separately decides whether to authorize a no-body metadata request or require the publisher to provide stable credential-free object URLs, exact sizes, and checksums. Controls will not be weakened implicitly. Until those decisions and exact fields exist, `acquisition_authorized=false` and no transfer task exists.

## Normalized evidence summary

```text
official_page=https://research.unsw.edu.au/projects/unsw-nb15-dataset
publisher=UNSW Research / UNSW Canberra
page_last_updated=2021-06-02
reviewed_at=2026-07-14T12:49:02Z,2026-07-14T14:50:31Z
terms=free academic research use in perpetuity; commercial use requires author agreement; citation required
official_tabular_names=UNSW-NB15_1.csv,UNSW-NB15_2.csv,UNSW-NB15_3.csv,UNSW-NB15_4.csv
publisher_page_feature_dictionary=UNSW-NB15_features.csv
publisher_folder_feature_dictionary=NUSW-NB15_features.csv
publisher_page_ground_truth=UNSW-NB15_GT.csv
publisher_folder_ground_truth=NUSW-NB15_GT.csv
event_list=UNSW-NB15_LIST_EVENTS.csv
raw_pcap=excluded
prepared_train_test=excluded from authoritative split
download_host=unsw-my.sharepoint.com
browser_metadata_host=unsw-my.sharepoint.com
access_result=read-only shared folder visible; download menu enabled but not exercised
display_sizes=161 MB,158 MB,147 MB,93.1 MB,3.95 KB,82.4 MB,4.53 KB
exact_byte_sizes=unavailable
media_status=CSV indicators; no archive observed for visible candidates
publisher_checksums=unverified
stable_query_free_file_urls=unavailable
acquisition_authorized=false
dataset_bytes_downloaded=0
```

**Normalized evidence SHA-256:** `c59dd2a79a23a2d147039c522e295fe490a33f20077562624d09acaceb097c29`
