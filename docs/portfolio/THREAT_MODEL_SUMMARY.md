# Portfolio Threat-Model Summary

The complete STRIDE register remains authoritative in
[`../threat-model/THREAT_MODEL.md`](../threat-model/THREAT_MODEL.md). Gate P5
adds documentation and demo-material risks without expanding the trust model.

| Threat | P5 control | Blocking condition |
|---|---|---|
| Synthetic evidence presented as real performance | Claim matrix, exact limitation text, false flags, reviewer sign-off | Any overclaim blocks finalization |
| Screenshot/recording leaks secrets or sensitive metadata | Disposable profile, least privilege, redaction scan, restrictive mode, frame review | Reject and delete media |
| Demo script drifts or invokes external services | Fixed local commands, no arbitrary input, two-run hash comparison | `not_evaluable` |
| Documentation implies model activation or enforcement | Diagram/text review and simulation-only scan | Block completion |
| Inherited Sprint 10 material is accidentally published | Diff allowlist and explicit exclusion list | Preserve and exclude |
| Evidence/report retention is exceeded | Expiry metadata, cleanup audit, no exceptional holds | Block finalization |

P5 does not create a new network, capability, model, dataset, or enforcement
trust boundary. Any request that would do so is outside scope and must stop.
