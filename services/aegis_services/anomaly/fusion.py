from __future__ import annotations

from collections.abc import Iterable
from decimal import ROUND_HALF_EVEN, Decimal

from .schema import AnomalyAssessmentV1, FusionInputV1, FusionPolicyV1


def _round_even(value: float) -> int:
    return int(Decimal(str(value)).quantize(Decimal("1"), rounding=ROUND_HALF_EVEN))


def fuse_assessment(
    *,
    assessment_id: str,
    source_identity_hash: str,
    anomaly_detector_hash: str,
    signals: Iterable[FusionInputV1],
    policy: FusionPolicyV1,
) -> AnomalyAssessmentV1:
    items = tuple(signals)
    valid = tuple(item for item in items if item.quality == "valid")
    uncertainty: list[str] = []
    for item in items:
        uncertainty.extend(item.reason_codes)
        if item.quality != "valid":
            uncertainty.append(f"SOURCE_{item.source.value.upper()}_{item.quality.upper()}")
    if not valid:
        uncertainty.append("NO_VALID_SIGNAL")
        return AnomalyAssessmentV1(
            assessment_id=assessment_id,
            source_identity_hash=source_identity_hash,
            policy_hash=policy.policy_hash,
            anomaly_detector_hash=anomaly_detector_hash,
            contributing_signal_ids=(),
            source_scores={},
            risk_score=0,
            confidence=0.0,
            severity="informational",
            category="unusual_behavior",
            uncertainty_codes=tuple(dict.fromkeys(uncertainty)),
            evidence_complete=False,
        )

    if len({item.source for item in valid}) != len(valid):
        raise ValueError("fusion_duplicate_signal_source")
    weighted_total = sum(policy.weights[item.source] * item.score for item in valid)
    weight_total = sum(policy.weights[item.source] for item in valid)
    risk_score = max(0, min(100, _round_even(100.0 * weighted_total / weight_total)))
    provenance_count = sum(item.evidence_hash is not None for item in valid)
    provenance_completeness = provenance_count / len(valid)
    agreement = (
        0.5
        if len(valid) == 1
        else max(0.0, 1.0 - (max(item.score for item in valid) - min(item.score for item in valid)))
    )
    confidence = (
        min(len(valid) / policy.confidence_denominator, 1.0) * provenance_completeness * agreement
    )
    confidence = round(min(1.0, max(0.0, confidence)), 6)
    if len(valid) == 1:
        uncertainty.append("SINGLE_SOURCE")
    if max(item.score for item in valid) - min(item.score for item in valid) > 0.5:
        uncertainty.append("SIGNAL_DISAGREEMENT")
    category = "unusual_behavior"
    for source in policy.category_precedence:
        candidate = next((item for item in valid if item.source == source and item.category), None)
        if candidate is not None and candidate.category is not None:
            category = candidate.category
            break
    severity = next(
        band for band, lower, upper in policy.severity_bands if lower <= risk_score <= upper
    )
    return AnomalyAssessmentV1(
        assessment_id=assessment_id,
        source_identity_hash=source_identity_hash,
        policy_hash=policy.policy_hash,
        anomaly_detector_hash=anomaly_detector_hash,
        contributing_signal_ids=tuple(item.signal_id for item in valid),
        source_scores={item.source.value: item.score for item in valid},
        risk_score=risk_score,
        confidence=confidence,
        severity=severity,  # type: ignore[arg-type]
        category=category,
        uncertainty_codes=tuple(dict.fromkeys(uncertainty)),
        evidence_complete=provenance_completeness == 1.0,
    )


def default_fusion_policy() -> FusionPolicyV1:
    return FusionPolicyV1()
