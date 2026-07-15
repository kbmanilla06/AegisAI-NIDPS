from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.config import Settings, get_settings
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import (
    FeatureSchemaVersion,
    SyntheticDatasetVersion,
    SyntheticGenerationJob,
)
from aegis_api.schemas import (
    SyntheticDatasetOut,
    SyntheticDatasetReviewRequest,
    SyntheticGenerationCreate,
    SyntheticGenerationJobOut,
)
from aegis_api.security.authentication import (
    Principal,
    require_csrf_permission,
    require_permission,
)
from aegis_api.security.permissions import PermissionKey
from aegis_api.synthetic_dispatch import get_synthetic_dispatcher
from aegis_services.features import FeatureSchemaV1
from aegis_services.synthetic import (
    SYNTHETIC_LIMITATIONS,
    SyntheticDatasetManifestV1,
    SyntheticLeakageReportV1,
    SyntheticQualityReportV1,
    SyntheticScenarioCatalogV1,
    SyntheticSplitManifestV1,
    verify_synthetic_artifact,
)

router = APIRouter(prefix="/api/v1")


@router.get("/synthetic/scenarios")
async def get_synthetic_scenarios(
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.SYNTHETIC_DATASETS_READ))
    ],
) -> dict[str, object]:
    catalog = SyntheticScenarioCatalogV1()
    return {
        "contract": catalog.contract,
        "version": catalog.version,
        "catalog_hash": catalog.catalog_hash,
        "global_seed": catalog.global_seed,
        "families": [item.value for item in catalog.families],
        "labels": [item.value for item in catalog.labels],
        "maximum_flows": catalog.maximum_flows,
        "maximum_groups": catalog.maximum_groups,
        "limitations": SYNTHETIC_LIMITATIONS,
        "synthetic_demo_only": True,
        "real_dataset_used": False,
        "unsw_nb15_acquired": False,
        "unsw_nb15_evaluated": False,
        "network_traffic_generated": False,
        "online_inference_allowed": False,
        "alert_side_effects_allowed": False,
        "prevention_allowed": False,
    }


@router.get("/synthetic/generation-jobs", response_model=list[SyntheticGenerationJobOut])
async def list_synthetic_jobs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.SYNTHETIC_DATASETS_READ))
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[SyntheticGenerationJobOut]:
    records = (
        await db.scalars(
            select(SyntheticGenerationJob)
            .order_by(SyntheticGenerationJob.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [SyntheticGenerationJobOut.model_validate(item) for item in records]


@router.post(
    "/synthetic/generation-jobs",
    response_model=SyntheticGenerationJobOut,
    status_code=202,
)
async def create_synthetic_job(
    payload: SyntheticGenerationCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal,
        Depends(require_csrf_permission(PermissionKey.SYNTHETIC_DATASETS_GENERATE)),
    ],
    dispatcher: Annotated[Callable[[str], None], Depends(get_synthetic_dispatcher)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> SyntheticGenerationJobOut:
    existing = await db.scalar(
        select(SyntheticGenerationJob).where(
            SyntheticGenerationJob.requested_by == principal.user_id,
            SyntheticGenerationJob.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.feature_schema_id != payload.feature_schema_id:
            raise ApiError(409, "synthetic_idempotency_conflict", "Idempotency key conflicts")
        return SyntheticGenerationJobOut.model_validate(existing)
    schema_record = await db.get(FeatureSchemaVersion, payload.feature_schema_id)
    if schema_record is None or schema_record.lifecycle_state != "approved":
        raise ApiError(409, "synthetic_feature_schema_unavailable", "Feature schema unavailable")
    try:
        schema = FeatureSchemaV1.model_validate(schema_record.ordered_definition)
    except ValueError as error:
        raise ApiError(409, "synthetic_feature_schema_invalid", "Feature schema invalid") from error
    if (
        schema.definition_hash != schema_record.definition_hash
        or schema.name != "flow_features"
        or schema.version != "1.0.0"
        or len(schema.features) != 39
    ):
        raise ApiError(409, "synthetic_feature_schema_integrity", "Feature schema incompatible")
    catalog = SyntheticScenarioCatalogV1()
    job = SyntheticGenerationJob(
        requested_by=principal.user_id,
        feature_schema_id=schema_record.id,
        idempotency_key=idempotency_key,
        scenario_catalog_hash=catalog.catalog_hash,
        global_seed=catalog.global_seed,
        requested_flow_count=7200,
        status="pending",
    )
    db.add(job)
    try:
        await db.flush()
    except IntegrityError as error:
        await db.rollback()
        raise ApiError(409, "synthetic_job_conflict", "Synthetic job already exists") from error
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="synthetic.dataset.generate.request",
        resource_type="synthetic_generation_job",
        resource_id=str(job.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "scenario_catalog_hash": catalog.catalog_hash,
            "feature_schema_hash": schema.definition_hash,
            "requested_flow_count": 7200,
            "synthetic_demo_only": True,
        },
    )
    try:
        await db.commit()
        await db.refresh(job)
    except IntegrityError as error:
        await db.rollback()
        raise ApiError(409, "synthetic_job_conflict", "Synthetic job already exists") from error
    try:
        dispatcher(str(job.id))
    except Exception as error:
        job.status = "failed"
        job.error_code = "synthetic_dispatch_failed"
        job.completed_at = datetime.now(UTC)
        await db.commit()
        raise ApiError(503, "synthetic_dispatch_failed", "Synthetic worker unavailable") from error
    return SyntheticGenerationJobOut.model_validate(job)


@router.get("/synthetic/datasets", response_model=list[SyntheticDatasetOut])
async def list_synthetic_datasets(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.SYNTHETIC_DATASETS_READ))
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[SyntheticDatasetOut]:
    records = (
        await db.scalars(
            select(SyntheticDatasetVersion)
            .order_by(SyntheticDatasetVersion.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [SyntheticDatasetOut.model_validate(item) for item in records]


@router.get("/synthetic/datasets/{dataset_id}", response_model=SyntheticDatasetOut)
async def get_synthetic_dataset(
    dataset_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.SYNTHETIC_DATASETS_READ))
    ],
) -> SyntheticDatasetOut:
    record = await db.get(SyntheticDatasetVersion, dataset_id)
    if record is None:
        raise ApiError(404, "synthetic_dataset_not_found", "Synthetic dataset not found")
    return SyntheticDatasetOut.model_validate(record)


@router.post(
    "/synthetic/datasets/{dataset_id}/review",
    response_model=SyntheticDatasetOut,
)
async def review_synthetic_dataset(
    dataset_id: UUID,
    payload: SyntheticDatasetReviewRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    principal: Annotated[
        Principal,
        Depends(require_csrf_permission(PermissionKey.SYNTHETIC_DATASETS_REVIEW)),
    ],
) -> SyntheticDatasetOut:
    record = await db.scalar(
        select(SyntheticDatasetVersion)
        .where(SyntheticDatasetVersion.id == dataset_id)
        .with_for_update()
    )
    if record is None:
        raise ApiError(404, "synthetic_dataset_not_found", "Synthetic dataset not found")
    if record.lifecycle_state != "generated":
        raise ApiError(409, "synthetic_dataset_state", "Synthetic dataset cannot be reviewed")
    if record.created_by == principal.user_id:
        raise ApiError(403, "synthetic_dataset_self_review", "Creator cannot review dataset")
    try:
        manifest = SyntheticDatasetManifestV1.model_validate(record.manifest)
        split = SyntheticSplitManifestV1.model_validate(record.split_manifest)
        quality = SyntheticQualityReportV1.model_validate(record.quality_report)
        leakage = SyntheticLeakageReportV1.model_validate(record.leakage_report)
    except ValueError as error:
        raise ApiError(409, "synthetic_manifest_invalid", "Synthetic manifest invalid") from error
    flow_artifact, target_artifact, feature_artifact = manifest.artifacts
    if (
        manifest.manifest_hash != record.manifest_hash
        or manifest.target_manifest_hash != record.target_manifest_hash
        or manifest.split_manifest_hash != record.split_manifest_hash
        or manifest.quality_report_hash != record.quality_report_hash
        or manifest.leakage_report_hash != record.leakage_report_hash
        or split.manifest_hash != record.split_manifest_hash
        or quality.report_hash != record.quality_report_hash
        or leakage.report_hash != record.leakage_report_hash
        or (flow_artifact.object_ref, flow_artifact.sha256, flow_artifact.size_bytes)
        != (record.flow_object_ref, record.flow_sha256, record.flow_size_bytes)
        or (target_artifact.object_ref, target_artifact.sha256, target_artifact.size_bytes)
        != (record.target_object_ref, record.target_sha256, record.target_size_bytes)
        or (feature_artifact.object_ref, feature_artifact.sha256, feature_artifact.size_bytes)
        != (record.feature_object_ref, record.feature_sha256, record.feature_size_bytes)
    ):
        raise ApiError(409, "synthetic_manifest_integrity", "Synthetic manifest integrity failed")
    try:
        root = settings.artifact_root / "synthetic"
        for artifact, object_ref, suffix in (
            (flow_artifact, record.flow_object_ref, "jsonl"),
            (target_artifact, record.target_object_ref, "targets.json"),
            (feature_artifact, record.feature_object_ref, "parquet"),
        ):
            verify_synthetic_artifact(
                root,
                object_ref,
                suffix,
                expected_sha256=artifact.sha256,
                expected_size=artifact.size_bytes,
                maximum_size=settings.feature_max_output_bytes,
            )
    except ValueError as error:
        raise ApiError(
            409, "synthetic_artifact_integrity", "Synthetic artifact integrity failed"
        ) from error
    record.lifecycle_state = "accepted_synthetic" if payload.accepted else "rejected"
    record.reviewed_by = principal.user_id
    record.reviewed_at = datetime.now(UTC)
    record.review_reason = payload.reason
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="synthetic.dataset.review",
        resource_type="synthetic_dataset",
        resource_id=str(record.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "decision": record.lifecycle_state,
            "manifest_hash": record.manifest_hash,
            "target_manifest_hash": record.target_manifest_hash,
            "split_manifest_hash": record.split_manifest_hash,
            "quality_report_hash": record.quality_report_hash,
            "leakage_report_hash": record.leakage_report_hash,
            "evidence_reference": payload.evidence_reference,
            "synthetic_demo_only": True,
        },
    )
    await db.commit()
    await db.refresh(record)
    return SyntheticDatasetOut.model_validate(record)
