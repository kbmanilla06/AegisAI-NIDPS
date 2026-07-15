from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.ml_dispatch import get_training_dispatcher
from aegis_api.models import (
    AuditEvent,
    SyntheticDatasetVersion,
    SyntheticModelCandidate,
    SyntheticRegistryModel,
    SyntheticScoringJob,
    SyntheticTrainingRun,
)
from aegis_api.schemas import (
    SyntheticCandidateOut,
    SyntheticRegistryModelOut,
    SyntheticRegistryReview,
    SyntheticScoringCreate,
    SyntheticScoringJobOut,
    SyntheticTrainingCreate,
    SyntheticTrainingRunOut,
)
from aegis_api.scoring_dispatch import get_scoring_dispatcher
from aegis_api.security.authentication import Principal, require_csrf_permission, require_permission
from aegis_api.security.permissions import PermissionKey
from aegis_services.ml import GATE_5SA_HASHES

router = APIRouter(prefix="/api/v1/models")

ACCEPTED_CANDIDATE_HASHES = {
    (
        "4957e7bd33fb4136ce7e7c8c99c20ac02c411265ca803e6009298ebe6dd34413",
        "c51427b5d6397ed8ec85ae50b51b8f9422140855497dab3815e1bc3a0f3ebdad",
        "77ebe8ad02d63cf2183435ca5b9c5ea5d4b45821c29a464d76b06a328a7a8d11",
        "ed3e27b65fbefa863bd065d4b05a92f0943e2afdfded80cf9af91ed9251f6e1d",
        "5e139acf5e96a7df523bcefceefc8d2132334825b2e1d0294e3de0b48d83be38",
    ),
    (
        "c7f37616e6c4b3720645a01035b4f5bf084ea5421f88d412a75d2b21ede1892b",
        "67aa102c59faf06151edca2d362c1b54911b711414e69a1b391685cffc17f2b4",
        "6a544a654f98edc874349e4b175eda95ebebc4bda1fc328718883cc05f276354",
        "5894865b5d9c8170b98e2a5dcf9452d9b414e719bc0e448f1e700f69572c00cc",
        "3ddb0842af4e260bc24978153bc747db9a01fb1a2d8a936d94d73e85d176623f",
    ),
}


def _is_accepted_synthetic_dataset(dataset: SyntheticDatasetVersion) -> bool:
    manifest = dataset.manifest
    return (
        manifest.get("dataset_kind") == "project_generated_synthetic"
        and manifest.get("synthetic_demo_only") is True
        and manifest.get("real_dataset_used") is False
        and manifest.get("unsw_nb15_acquired") is False
        and manifest.get("unsw_nb15_evaluated") is False
        and manifest.get("canonical_flow_schema") == "1"
        and manifest.get("feature_schema_name") == "flow_features"
        and manifest.get("feature_schema_version") == "1.0.0"
        and manifest.get("scenario_catalog_hash") == GATE_5SA_HASHES["scenario_catalog"]
        and manifest.get("feature_schema_hash") == GATE_5SA_HASHES["feature_schema"]
        and manifest.get("target_manifest_hash") == GATE_5SA_HASHES["target_manifest"]
        and manifest.get("split_manifest_hash") == GATE_5SA_HASHES["split_manifest"]
        and manifest.get("quality_report_hash") == GATE_5SA_HASHES["quality_report"]
        and manifest.get("leakage_report_hash") == GATE_5SA_HASHES["leakage_report"]
        and dataset.flow_sha256 == GATE_5SA_HASHES["canonical_flow_artifact"]
        and dataset.target_sha256 == GATE_5SA_HASHES["target_manifest"]
        and dataset.feature_sha256 == GATE_5SA_HASHES["feature_artifact"]
        and dataset.target_manifest_hash == GATE_5SA_HASHES["target_manifest"]
        and dataset.split_manifest_hash == GATE_5SA_HASHES["split_manifest"]
        and dataset.quality_report_hash == GATE_5SA_HASHES["quality_report"]
        and dataset.leakage_report_hash == GATE_5SA_HASHES["leakage_report"]
        and dataset.split_manifest.get("dataset_content_hash") == GATE_5SA_HASHES["dataset_content"]
    )


@router.get("/training-runs", response_model=list[SyntheticTrainingRunOut])
async def list_runs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.MODELS_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[SyntheticTrainingRunOut]:
    records = (
        await db.scalars(
            select(SyntheticTrainingRun)
            .order_by(SyntheticTrainingRun.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [SyntheticTrainingRunOut.model_validate(item) for item in records]


@router.post("/training-runs", response_model=SyntheticTrainingRunOut, status_code=202)
async def create_run(
    payload: SyntheticTrainingCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.MODELS_TRAIN_SYNTHETIC))
    ],
    dispatcher: Annotated[Callable[[str], None], Depends(get_training_dispatcher)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> SyntheticTrainingRunOut:
    existing = await db.scalar(
        select(SyntheticTrainingRun).where(
            SyntheticTrainingRun.requested_by == principal.user_id,
            SyntheticTrainingRun.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.dataset_version_id != payload.dataset_version_id:
            raise ApiError(409, "ml_idempotency_conflict", "Idempotency key conflicts")
        return SyntheticTrainingRunOut.model_validate(existing)
    dataset = await db.get(SyntheticDatasetVersion, payload.dataset_version_id)
    if (
        dataset is None
        or dataset.lifecycle_state != "accepted_synthetic"
        or dataset.artifacts_deleted_at is not None
    ):
        raise ApiError(409, "ml_dataset_not_accepted", "Synthetic dataset is unavailable")
    now = datetime.now(UTC)
    run = SyntheticTrainingRun(
        dataset_version_id=dataset.id,
        requested_by=principal.user_id,
        idempotency_key=idempotency_key,
        status="pending",
        threshold=0.5,
        retention_days=30,
        expires_at=now + timedelta(days=30),
    )
    db.add(run)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="synthetic.model.train.request",
        resource_type="synthetic_training_run",
        resource_id=str(run.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"dataset_manifest_hash": dataset.manifest_hash, "synthetic_demo_only": True},
    )
    await db.commit()
    dispatcher(str(run.id))
    return SyntheticTrainingRunOut.model_validate(run)


@router.get("/candidates", response_model=list[SyntheticCandidateOut])
async def list_candidates(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.MODELS_READ))],
    training_run_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[SyntheticCandidateOut]:
    statement = select(SyntheticModelCandidate)
    if training_run_id is not None:
        statement = statement.where(SyntheticModelCandidate.training_run_id == training_run_id)
    records = (
        await db.scalars(statement.order_by(SyntheticModelCandidate.created_at.desc()).limit(limit))
    ).all()
    return [SyntheticCandidateOut.model_validate(item) for item in records]


@router.get("/registry", response_model=list[SyntheticRegistryModelOut])
async def list_registry(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.MODELS_READ))],
) -> list[SyntheticRegistryModelOut]:
    records = (
        await db.scalars(
            select(SyntheticRegistryModel)
            .order_by(SyntheticRegistryModel.created_at.desc())
            .limit(100)
        )
    ).all()
    return [SyntheticRegistryModelOut.model_validate(item) for item in records]


@router.post("/candidates/{candidate_id}/review", response_model=SyntheticRegistryModelOut)
async def review_candidate(
    candidate_id: UUID,
    payload: SyntheticRegistryReview,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.MODELS_REVIEW_SYNTHETIC))
    ],
) -> SyntheticRegistryModelOut:
    candidate = await db.get(SyntheticModelCandidate, candidate_id)
    if candidate is None:
        raise ApiError(404, "ml_candidate_not_found", "Candidate is unavailable")
    run = await db.get(SyntheticTrainingRun, candidate.training_run_id)
    if (
        run is None
        or run.requested_by == principal.user_id
        or candidate.lifecycle_state != "unreviewed_candidate"
        or (
            candidate.model_sha256,
            candidate.metadata_sha256,
            candidate.preprocessor_hash,
            candidate.evaluation_hash,
            candidate.model_card_hash,
        )
        not in ACCEPTED_CANDIDATE_HASHES
    ):
        raise ApiError(403, "ml_review_not_allowed", "Candidate review is unavailable")
    existing = await db.scalar(
        select(SyntheticRegistryModel).where(SyntheticRegistryModel.candidate_id == candidate_id)
    )
    if existing is not None:
        return SyntheticRegistryModelOut.model_validate(existing)
    now = datetime.now(UTC)
    registry = SyntheticRegistryModel(
        candidate_id=candidate.id,
        lifecycle_state="reviewed_synthetic" if payload.accepted else "rejected",
        reviewed_by=principal.user_id,
        review_reason=payload.reason,
        evidence_reference=payload.evidence_reference,
        candidate_hash=candidate.model_sha256,
        expires_at=now + timedelta(days=180),
    )
    db.add(registry)
    db.add(
        AuditEvent(
            actor_user_id=principal.user_id,
            action="synthetic.model.review",
            resource_type="synthetic_registry_model",
            resource_id=str(candidate.id),
            outcome="success",
            correlation_id=request.state.correlation_id,
            safe_metadata={
                "accepted": payload.accepted,
                "candidate_hash": candidate.model_sha256,
                "synthetic_demo_only": True,
                "online_inference_allowed": False,
                "alert_side_effects_allowed": False,
                "prevention_allowed": False,
            },
        )
    )
    await db.commit()
    await db.refresh(registry)
    return SyntheticRegistryModelOut.model_validate(registry)


@router.post("/scoring-jobs", response_model=SyntheticScoringJobOut, status_code=202)
async def create_scoring_job(
    payload: SyntheticScoringCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.MODELS_SCORE_SYNTHETIC))
    ],
    dispatcher: Annotated[Callable[[str], None], Depends(get_scoring_dispatcher)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> SyntheticScoringJobOut:
    existing = await db.scalar(
        select(SyntheticScoringJob).where(
            SyntheticScoringJob.requested_by == principal.user_id,
            SyntheticScoringJob.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if (
            existing.registry_model_id != payload.registry_model_id
            or existing.dataset_version_id != payload.dataset_version_id
        ):
            raise ApiError(409, "ml_idempotency_conflict", "Idempotency key conflicts")
        return SyntheticScoringJobOut.model_validate(existing)
    registry = await db.get(SyntheticRegistryModel, payload.registry_model_id)
    dataset = await db.get(SyntheticDatasetVersion, payload.dataset_version_id)
    candidate = await db.get(
        SyntheticModelCandidate, registry.candidate_id if registry is not None else UUID(int=0)
    )
    run = await db.get(
        SyntheticTrainingRun, candidate.training_run_id if candidate is not None else UUID(int=0)
    )
    if (
        registry is None
        or registry.lifecycle_state != "reviewed_synthetic"
        or dataset is None
        or dataset.lifecycle_state != "accepted_synthetic"
        or candidate is None
        or run is None
        or run.dataset_version_id != dataset.id
        or not _is_accepted_synthetic_dataset(dataset)
    ):
        raise ApiError(409, "ml_scoring_compatibility", "Synthetic scoring inputs are unavailable")
    job = SyntheticScoringJob(
        registry_model_id=registry.id,
        dataset_version_id=dataset.id,
        requested_by=principal.user_id,
        idempotency_key=idempotency_key,
        status="pending",
        predicted_counts={},
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    db.add(job)
    await db.flush()
    db.add(
        AuditEvent(
            actor_user_id=principal.user_id,
            action="synthetic.model.score.request",
            resource_type="synthetic_scoring_job",
            resource_id=str(job.id),
            outcome="success",
            correlation_id=request.state.correlation_id,
            safe_metadata={
                "synthetic_demo_only": True,
                "online_inference_allowed": False,
                "alert_side_effects_allowed": False,
                "prevention_allowed": False,
            },
        )
    )
    await db.commit()
    dispatcher(str(job.id))
    return SyntheticScoringJobOut.model_validate(job)


@router.get("/scoring-jobs", response_model=list[SyntheticScoringJobOut])
async def list_scoring_jobs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.MODELS_READ))],
) -> list[SyntheticScoringJobOut]:
    records = (
        await db.scalars(
            select(SyntheticScoringJob).order_by(SyntheticScoringJob.created_at.desc()).limit(100)
        )
    ).all()
    return [SyntheticScoringJobOut.model_validate(item) for item in records]
