from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.anomaly_dispatch import get_anomaly_fit_dispatcher, get_assessment_dispatcher
from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import (
    AnomalyDetectorVersion,
    AnomalyThresholdVersion,
    AssessmentBatch,
    EnsemblePolicyVersion,
)
from aegis_api.schemas import (
    AnomalyDetectorOut,
    AnomalyFitCreate,
    AnomalyReview,
    AssessmentBatchCreate,
    AssessmentBatchOut,
    EnsemblePolicyOut,
)
from aegis_api.security.authentication import Principal, require_csrf_permission, require_permission
from aegis_api.security.permissions import PermissionKey
from aegis_services.anomaly import GATE_5SA_HASHES, default_fusion_policy
from aegis_services.synthetic import SYNTHETIC_LIMITATIONS

router = APIRouter(prefix="/api/v1/anomaly")


def _accepted_hashes() -> dict[str, str]:
    return {
        **GATE_5SA_HASHES,
        "feature_artifact": "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9",
    }


@router.get("/detectors", response_model=list[AnomalyDetectorOut])
async def list_detectors(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.MODELS_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[AnomalyDetectorOut]:
    rows = (
        await db.scalars(
            select(AnomalyDetectorVersion)
            .order_by(AnomalyDetectorVersion.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [AnomalyDetectorOut.model_validate(row) for row in rows]


@router.post("/detectors/{detector_id}/review", response_model=AnomalyDetectorOut)
async def review_detector(
    detector_id: UUID,
    payload: AnomalyReview,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.ENSEMBLE_REVIEW))
    ],
) -> AnomalyDetectorOut:
    row = await db.get(AnomalyDetectorVersion, detector_id)
    if row is None:
        raise ApiError(404, "anomaly_detector_not_found", "Detector not found")
    if row.requested_by == principal.user_id:
        raise ApiError(
            409, "anomaly_reviewer_separation", "Creator cannot review the same candidate"
        )
    row.lifecycle_state = "reviewed_synthetic" if payload.approved else "rejected"
    row.reviewed_by = principal.user_id
    row.review_reason = payload.reason
    threshold = await db.scalar(
        select(AnomalyThresholdVersion).where(AnomalyThresholdVersion.detector_id == row.id)
    )
    if threshold is not None:
        threshold.lifecycle_state = "reviewed_synthetic" if payload.approved else "rejected"
        threshold.reviewed_by = principal.user_id
        threshold.review_reason = payload.reason
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="anomaly.detector.review",
        resource_type="anomaly_detector",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"approved": payload.approved, "synthetic_demo_only": True},
    )
    await db.commit()
    return AnomalyDetectorOut.model_validate(row)


@router.post("/detectors/fit", response_model=AnomalyDetectorOut, status_code=202)
async def fit_detector(
    payload: AnomalyFitCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.ANOMALY_FIT))],
    dispatcher: Annotated[Callable[[str], None], Depends(get_anomaly_fit_dispatcher)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> AnomalyDetectorOut:
    existing = await db.scalar(
        select(AnomalyDetectorVersion).where(
            AnomalyDetectorVersion.requested_by == principal.user_id,
            AnomalyDetectorVersion.safe_metadata["idempotency_key"].as_string() == idempotency_key,
        )
    )
    if existing is not None:
        return AnomalyDetectorOut.model_validate(existing)
    hashes = _accepted_hashes()
    now = datetime.now(UTC)
    row = AnomalyDetectorVersion(
        lifecycle_state="unreviewed_candidate",
        status="pending",
        algorithm="isolation_forest",
        feature_schema_hash=hashes["feature_schema"],
        preprocessor_hash=payload.preprocessor_hash,
        dataset_content_hash=hashes["dataset_content"],
        split_manifest_hash=hashes["split_manifest"],
        training_identity_hash=hashes["training_identity"],
        normal_identity_hash="0" * 64,
        safe_metadata={
            "idempotency_key": idempotency_key,
            "synthetic_demo_only": True,
            "limitations": SYNTHETIC_LIMITATIONS,
        },
        requested_by=principal.user_id,
        expires_at=now + timedelta(days=30),
    )
    db.add(row)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="anomaly.fit.request",
        resource_type="anomaly_detector",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"synthetic_demo_only": True},
    )
    await db.commit()
    dispatcher(str(row.id))
    return AnomalyDetectorOut.model_validate(row)


@router.get("/policies", response_model=list[EnsemblePolicyOut])
async def list_policies(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.MODELS_READ))],
) -> list[EnsemblePolicyOut]:
    rows = (
        await db.scalars(
            select(EnsemblePolicyVersion).order_by(EnsemblePolicyVersion.created_at.desc())
        )
    ).all()
    return [EnsemblePolicyOut.model_validate(row) for row in rows]


@router.post("/policies", response_model=EnsemblePolicyOut, status_code=201)
async def create_policy(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.ENSEMBLE_REVIEW))
    ],
) -> EnsemblePolicyOut:
    policy = default_fusion_policy()
    definition = policy.model_dump(mode="json")
    row = EnsemblePolicyVersion(
        version=policy.version,
        definition=definition,
        policy_hash=policy.policy_hash,
        lifecycle_state="draft",
        created_by=principal.user_id,
        limitations=SYNTHETIC_LIMITATIONS,
    )
    db.add(row)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="ensemble.policy.create",
        resource_type="ensemble_policy",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"policy_hash": row.policy_hash, "synthetic_demo_only": True},
    )
    await db.commit()
    return EnsemblePolicyOut.model_validate(row)


@router.post("/policies/{policy_id}/review", response_model=EnsemblePolicyOut)
async def review_policy(
    policy_id: UUID,
    payload: AnomalyReview,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.ENSEMBLE_REVIEW))
    ],
) -> EnsemblePolicyOut:
    row = await db.get(EnsemblePolicyVersion, policy_id)
    if row is None:
        raise ApiError(404, "ensemble_policy_not_found", "Policy not found")
    if row.created_by == principal.user_id:
        raise ApiError(409, "ensemble_reviewer_separation", "Creator cannot review the same policy")
    row.lifecycle_state = "reviewed_synthetic" if payload.approved else "rejected"
    row.reviewed_by = principal.user_id
    row.review_reason = payload.reason
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="ensemble.policy.review",
        resource_type="ensemble_policy",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"approved": payload.approved, "synthetic_demo_only": True},
    )
    await db.commit()
    return EnsemblePolicyOut.model_validate(row)


@router.get("/assessments", response_model=list[AssessmentBatchOut])
async def list_assessments(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.DETECTIONS_READ_METRICS))
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[AssessmentBatchOut]:
    rows = (
        await db.scalars(
            select(AssessmentBatch).order_by(AssessmentBatch.created_at.desc()).limit(limit)
        )
    ).all()
    return [AssessmentBatchOut.model_validate(row) for row in rows]


@router.post("/assessments", response_model=AssessmentBatchOut, status_code=202)
async def create_assessment(
    payload: AssessmentBatchCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.ENSEMBLE_EVALUATE))
    ],
    dispatcher: Annotated[Callable[[str], None], Depends(get_assessment_dispatcher)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> AssessmentBatchOut:
    existing = await db.scalar(
        select(AssessmentBatch).where(
            AssessmentBatch.requested_by == principal.user_id,
            AssessmentBatch.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        return AssessmentBatchOut.model_validate(existing)
    active_batches = await db.scalar(
        select(func.count(AssessmentBatch.id)).where(
            AssessmentBatch.requested_by == principal.user_id,
            AssessmentBatch.status.in_(("pending", "processing")),
        )
    )
    if int(active_batches or 0) >= 3:
        raise ApiError(
            429, "ensemble_resource_limit", "Too many assessment batches are in progress"
        )
    hashes = _accepted_hashes()
    if payload.feature_artifact_hash != hashes["feature_artifact"]:
        raise ApiError(
            409,
            "ensemble_feature_evidence_mismatch",
            "Only accepted synthetic feature evidence is allowed",
        )
    now = datetime.now(UTC)
    row = AssessmentBatch(
        requested_by=principal.user_id,
        idempotency_key=idempotency_key,
        dataset_content_hash=hashes["dataset_content"],
        feature_artifact_hash=payload.feature_artifact_hash,
        anomaly_detector_hash=payload.anomaly_detector_hash,
        threshold_hash=payload.threshold_hash,
        policy_hash=payload.policy_hash,
        status="pending",
        aggregate={},
        limitations=SYNTHETIC_LIMITATIONS,
        expires_at=now + timedelta(days=30),
    )
    db.add(row)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="ensemble.evaluate.request",
        resource_type="assessment_batch",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"synthetic_demo_only": True, "online_inference_allowed": False},
    )
    await db.commit()
    dispatcher(str(row.id))
    return AssessmentBatchOut.model_validate(row)
