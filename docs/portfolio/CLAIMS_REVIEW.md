# Gate P5 Claims Review

Every portfolio statement must fit one of these categories. The reviewer must
trace allowed claims to the evidence index and reject stronger wording.

| Claim | Status | Required wording/evidence |
|---|---|---|
| Versioned defensive software contracts exist | Allowed | Cite schemas, tests, and accepted hashes |
| Synthetic scenarios exercise deterministic pipelines | Allowed | Say project-generated synthetic; cite Gate 5S-A |
| Offline baseline/anomaly artifacts were evaluated | Allowed with limitation | Never generalize beyond synthetic evidence; cite Gate 5S-B/C and Gate 6 |
| Aggregate monitoring and feedback contracts exist | Allowed with limitation | State metadata-only and offline; cite P1/P2 |
| Local ARM64 Compose setup is reproducible | Allowed | Cite P4 commands and hosted CI |
| Prevention policy produces a simulation preview | Allowed | State that no network or host state changes |
| Real-network detection performance | Prohibited | No numeric or qualitative performance claim |
| UNSW-NB15 performance or evaluation | Prohibited | Acquisition remains blocked |
| Production readiness or enterprise coverage | Prohibited | Not measured or authorized |
| Online inference or active model service | Prohibited | Model activation remains disabled |
| Validated firewall prevention | Prohibited | No adapter or enforcement capability exists |
| Zero-day detection or complete attack coverage | Prohibited | Unsupported by synthetic evidence |

Required language for every metric, card, report, screenshot, recording, and
transcript is the applicable exact limitation contract plus the complete
false-capability flag set. Synthetic labels must retain their `synthetic_*_like`
qualifier.
