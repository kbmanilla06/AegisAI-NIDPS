from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_api.config import Settings
from aegis_api.models import (
    AnomalyDetectorVersion,
    AnomalyThresholdVersion,
    AssessmentBatch,
    DecisionAssessment,
    EnsemblePolicyVersion,
)
from aegis_services.anomaly import (
    FusionInputV1,
    FusionPolicyV1,
    SignalSource,
    build_anomaly_candidate,
    fuse_assessment,
)
from aegis_services.features import canonical_hash, feature_schema
from aegis_services.synthetic import build_synthetic_dataset


async def process_anomaly_fit(
    detector_id: UUID, settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> UUID:
    async with session_factory() as db:
        row = await db.get(AnomalyDetectorVersion, detector_id)
        if row is None:
            return detector_id
        if row.status not in {"pending", "failed"}:
            return detector_id
        row.status = "processing"
        await db.commit()
        try:
            schema = feature_schema("sprint4")
            result = build_synthetic_dataset(schema)
            evidence = build_anomaly_candidate(
                result, schema, settings.artifact_root / "models" / "anomaly"
            )
            row.status = "succeeded"
            row.model_object_ref = evidence.model_object_ref
            row.model_sha256 = evidence.detector.model_sha256
            row.model_size_bytes = evidence.detector.model_size_bytes
            row.metadata_object_ref = evidence.metadata_object_ref
            row.metadata_sha256 = evidence.detector_metadata_hash
            row.metadata_size_bytes = evidence.metadata_size_bytes
            row.normal_identity_hash = evidence.detector.normal_identity_hash
            row.manifest_hash = evidence.detector.manifest_hash
            row.threshold_hash = evidence.threshold.threshold_hash
            row.safe_metadata = evidence.detector_metadata
            row.completed_at = datetime.now(UTC)
            db.add(
                AnomalyThresholdVersion(
                    detector_id=row.id,
                    created_by=row.requested_by,
                    detector_manifest_hash=row.manifest_hash,
                    threshold_hash=evidence.threshold.threshold_hash,
                    threshold=evidence.threshold.threshold,
                    validation_identity_hash=evidence.threshold.validation_identity_hash,
                    validation_reference_count=evidence.threshold.validation_reference_count,
                    lifecycle_state="candidate",
                    test_opened_once=True,
                    limitations=evidence.threshold.limitations,
                )
            )
            await db.commit()
        except Exception:
            row.status = "failed"
            row.error_code = "anomaly_fit_failed"
            row.completed_at = datetime.now(UTC)
            await db.commit()
            raise
    return detector_id


async def process_assessment_batch(
    batch_id: UUID, settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> UUID:
    async with session_factory() as db:
        row = await db.get(AssessmentBatch, batch_id)
        if row is None or row.status not in {"pending", "failed"}:
            return batch_id
        row.status = "processing"
        await db.commit()
        try:
            policy_row = await db.scalar(
                select(EnsemblePolicyVersion).where(
                    EnsemblePolicyVersion.policy_hash == row.policy_hash
                )
            )
            if policy_row is None or policy_row.lifecycle_state != "reviewed_synthetic":
                raise ValueError("ensemble_policy_not_found")
            detector_row = await db.scalar(
                select(AnomalyDetectorVersion).where(
                    AnomalyDetectorVersion.manifest_hash == row.anomaly_detector_hash,
                    AnomalyDetectorVersion.lifecycle_state == "reviewed_synthetic",
                    AnomalyDetectorVersion.status == "succeeded",
                )
            )
            if detector_row is None or detector_row.threshold_hash != row.threshold_hash:
                raise ValueError("ensemble_detector_evidence_mismatch")
            schema = feature_schema("sprint4")
            result = build_synthetic_dataset(schema)
            candidate = build_anomaly_candidate(
                result, schema, settings.artifact_root / "models" / "anomaly"
            )
            if row.anomaly_detector_hash != candidate.detector.manifest_hash:
                raise ValueError("ensemble_detector_evidence_mismatch")
            if row.threshold_hash != candidate.threshold.threshold_hash:
                raise ValueError("ensemble_threshold_evidence_mismatch")
            policy = FusionPolicyV1.model_validate(policy_row.definition)
            evidence_hash = candidate.detector.model_sha256
            assessments: list[DecisionAssessment] = []
            severities: dict[str, int] = {}
            risks: list[int] = []
            test_examples = [
                item for item in result.examples if item.target.partition.value == "test"
            ]
            for index, score in enumerate(candidate.test_scores):
                identity_hash = canonical_hash(test_examples[index].target.example_identity_hash)
                decision = fuse_assessment(
                    assessment_id=identity_hash[:32],
                    source_identity_hash=identity_hash,
                    anomaly_detector_hash=candidate.detector.manifest_hash,
                    signals=[
                        FusionInputV1(
                            source=SignalSource.ANOMALY,
                            signal_id=identity_hash[:32],
                            source_version_hash=candidate.detector.manifest_hash,
                            score=score,
                            category="unusual_behavior",
                            evidence_hash=evidence_hash,
                        )
                    ],
                    policy=policy,
                )
                risks.append(decision.risk_score)
                severities[decision.severity] = severities.get(decision.severity, 0) + 1
                assessments.append(
                    DecisionAssessment(
                        batch_id=row.id,
                        source_identity_hash=identity_hash,
                        policy_hash=decision.policy_hash,
                        anomaly_detector_hash=decision.anomaly_detector_hash,
                        source_scores=decision.source_scores,
                        risk_score=decision.risk_score,
                        confidence=decision.confidence,
                        severity=decision.severity,
                        category=decision.category,
                        uncertainty_codes=list(decision.uncertainty_codes),
                        evidence_complete=decision.evidence_complete,
                        limitations=decision.limitations,
                        expires_at=row.expires_at,
                    )
                )
            db.add_all(assessments)
            row.row_count = len(assessments)
            row.aggregate = {
                "rows": row.row_count,
                "anomaly_flagged": int(sum(candidate.test_flags)),
                "risk_mean": round(sum(risks) / len(risks), 6),
                "severity_counts": severities,
                "offline_only": True,
                "signals": {"anomaly": row.row_count},
                "synthetic_demo_only": True,
            }
            row.status = "succeeded"
            row.completed_at = datetime.now(UTC)
            await db.commit()
        except Exception:
            row.status = "failed"
            row.error_code = "ensemble_evaluation_failed"
            row.completed_at = datetime.now(UTC)
            await db.commit()
            raise
    return batch_id


async def cleanup_anomaly_artifacts(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> int:
    async with session_factory() as db:
        rows = (
            await db.scalars(
                select(AnomalyDetectorVersion).where(
                    AnomalyDetectorVersion.expires_at <= datetime.now(UTC),
                    AnomalyDetectorVersion.artifacts_deleted_at.is_(None),
                )
            )
        ).all()
        root = (settings.artifact_root / "models" / "anomaly").resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for row in rows:
            for object_ref, suffix in (
                (row.model_object_ref, "onnx"),
                (row.metadata_object_ref, "candidate.json"),
            ):
                if object_ref is None:
                    continue
                path = (root / f"{object_ref}.{suffix}").resolve()
                if path.parent != root or path.is_symlink():
                    raise ValueError("anomaly_artifact_path_invalid")
                path.unlink(missing_ok=True)
            row.artifacts_deleted_at = datetime.now(UTC)
            row.lifecycle_state = "retired"
        await db.commit()
        return len(rows)
