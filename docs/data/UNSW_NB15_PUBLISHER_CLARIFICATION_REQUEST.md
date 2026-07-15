# UNSW-NB15 Publisher Clarification Request — Draft Only

**Prepared:** 2026-07-14
**Status:** CANCELLED / DO NOT SEND
**Phase 5A status:** Acquisition remains blocked
**Resolution path:** Option 1 — publisher confirmation

## Recipient source

Proposed recipient: `nour.moustafa@unsw.edu.au`

Source: the Key contact and dataset-contact information published on the official UNSW Research page, `https://research.unsw.edu.au/projects/unsw-nb15-dataset`. The page identifies Associate Professor Nour Moustafa as the key contact and publishes this `unsw.edu.au` address.

No alternate personal address, social-media account, third-party contact directory, mirror operator, or inferred recipient is approved. The address must be rechecked on the official page immediately before a later authorized send. A change or ambiguity blocks sending.

## Exact proposed message

**Subject:** UNSW-NB15 official file metadata and academic-use clarification

```text
Dear Associate Professor Moustafa,

I am preparing an academic/portfolio evaluation of the UNSW-NB15 dataset. I have not downloaded the dataset and am seeking metadata clarification before deciding whether to proceed.

The official UNSW dataset page names these files:
- UNSW-NB15_1.csv
- UNSW-NB15_2.csv
- UNSW-NB15_3.csv
- UNSW-NB15_4.csv
- UNSW-NB15_features.csv
- UNSW-NB15_GT.csv
- UNSW-NB15_LIST_EVENTS.csv

The current publisher-controlled SharePoint folder appears to show NUSW-NB15_features.csv and NUSW-NB15_GT.csv for the feature-description and ground-truth files. Could you please confirm whether those NUSW-prefixed names are the intended current official files or naming errors?

For each intended official file above, could you please confirm:
1. the exact filename and byte size;
2. the media type and whether it is an ordinary CSV rather than an archive;
3. whether an official checksum, preferably SHA-256, is published;
4. whether a stable credential-free and query-free HTTPS file URL is available;
5. whether downloading and retaining it locally for up to 90 days for academic/portfolio review is permitted;
6. the current required citations, commercial-use restriction, and redistribution status.

If stable public URLs or checksums are not available, confirmation of their absence would also be helpful. Please do not send dataset attachments, credentials, access tokens, signed links, or other restricted access material in response.

Thank you for your guidance.

Regards
```

The message deliberately omits the repository URL, workstation details, account identifiers, internal architecture, security controls, and other unnecessary project information. Sending it would necessarily disclose the sender account's address and display name; that disclosure requires explicit owner authorization at send time.

Canonical draft hashes:

- Subject UTF-8 without trailing newline, SHA-256: `997c7a0530b5cb100ca274e5e5d296bb3ae6f62aa0677503b169cbc7696898a4`
- Body UTF-8 exactly as rendered inside the text block above, including its final newline, SHA-256: `c42fbe43508d6fa3591b9736068d516bdcea5ba20fa3dd8dd089b56f37a4f348`

## Evidence checklist

### Before sending

- [ ] Owner explicitly authorizes the exact recipient, subject, message, sender account, and disclosure of the sender address/display name.
- [ ] Recipient is revalidated from the official UNSW dataset page without using a mirror or directory.
- [ ] The message still contains no attachment, tokenized URL, signed URL, credential, repository link, telemetry, secret, local path, or internal account identifier.
- [ ] Acquisition remains blocked and no transfer interface/task is enabled.
- [ ] A sanitized request hash is computed from the exact subject/body; no mail-session metadata enters the project.

### On sending

- [ ] Send once; no bulk recipients, CC, BCC, tracking pixel, read receipt, attachment, or link shortener.
- [ ] Use TLS through the owner's selected mail provider.
- [ ] Record only UTC send time, official recipient, subject hash, body hash, safe outcome, and owner approval reference in the project evidence.
- [ ] Do not copy authentication headers, cookies, session identifiers, mail account settings, or provider URLs into Git or audit metadata.

### On reply

- [ ] Confirm the visible sender address is the official `unsw.edu.au` contact; where the mail provider exposes authentication results, check SPF/DKIM/DMARC without copying raw headers into Git.
- [ ] Treat the reply as untrusted until its provenance and meaning are reviewed.
- [ ] Do not open, preview, save, or execute any attachment.
- [ ] Do not follow or store tokenized/signed links. If any are supplied, redact them from project records and keep acquisition blocked.
- [ ] Record exact confirmed filenames, byte sizes, media/archive status, checksum availability, stable query-free host/path availability, academic-use authority, citations, commercial restrictions, redistribution status, and permitted local retention.
- [ ] Separate explicit publisher statements from inference and unresolved ambiguity.
- [ ] Create a sanitized metadata summary and SHA-256 evidence reference; do not place the full correspondence or unnecessary personal information in public Git.
- [ ] Have a distinct Security Administrator review the sanitized evidence before proposing any exact acquisition manifest.
- [ ] Require another owner approval naming every candidate before any transfer.

### Evidence retention and privacy

- The project repository stores only the sanitized request, sanitized response summary, cryptographic hashes, official contact source, timestamps, decision state, and safe audit outcome.
- Full correspondence, raw mail headers, sender-account metadata, and any personal information remain outside Git and outside application logs.
- If the owner exports the reply for verification, use a controlled local mode-`0600` evidence file, never the dataset artifact volume, and delete it after the Security Administrator verifies the sanitized summary or within 30 days, whichever occurs first.
- Sanitized decision/audit evidence follows the existing 180-day alert/audit retention policy. No exceptional hold is available.
- An unsolicited attachment, credential, access token, or signed URL is not evidence for acquisition and must not be opened or persisted by the project.

## Expected acceptable response

An acceptable publisher response must clearly identify the current intended objects and address every requested metadata/governance field. “Use the SharePoint folder,” an attachment, a signed link, a third-party mirror, or a response that omits exact sizes and filename authority is insufficient to clear the gate.

The publisher may legitimately confirm that no checksum or stable query-free URL exists. Such a response resolves the factual question but does not automatically approve acquisition. The owner must separately decide whether the remaining risk warrants a new threat-modeled acquisition design.

## Remaining risks

1. The contact may not respond, may no longer own the dataset, or may answer only part of the request.
2. Email sender display names can be spoofed; domain authentication improves but does not prove substantive authority.
3. The published page and folder may change between confirmation and later transfer.
4. The `NUSW-...` spellings may be typographical errors, or the objects may differ semantically from the page descriptions.
5. Exact byte sizes can change if the publisher replaces an object; a later acquisition must revalidate them.
6. A publisher statement that no checksum exists leaves integrity dependent on a locally computed post-transfer SHA-256 and separate owner acceptance.
7. A stable query-free URL may not exist. Tokenized-only distribution remains incompatible with the current acquisition contract.
8. Academic-use permission does not imply redistribution, commercial use, or inclusion under the repository MIT license.
9. A 90-day local review-retention request may be rejected or conditioned; the more restrictive confirmed rule must govern.
10. Sending reveals the sender account address/display name to the recipient and mail providers.
11. Mail providers retain metadata outside Aegis control; the project can minimize but not eliminate that external processing.

## Gate disposition

Preparing this draft does not contact the publisher or resolve the source gate. `NUSW-NB15_features.csv` and `NUSW-NB15_GT.csv` remain excluded. Acquisition authorization, manifest creation, HEAD/GET requests, and dataset transfer remain prohibited.

## Send authorization

There is no active send authorization. Owner decision C-29 cancelled publisher outreach. This draft must not be sent unless a later explicit owner decision reopens contact.
