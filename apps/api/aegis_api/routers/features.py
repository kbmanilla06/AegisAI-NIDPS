from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.feature_dispatch import get_feature_dispatcher
from aegis_api.models import (
    DatasetAcquisitionPlan,
    DatasetVersion,
    FeatureArtifact,
    FeatureMaterializationJob,
    FeatureSchemaVersion,
    IngestionJob,
)
from aegis_api.schemas import (
    DatasetAcquisitionPlanOut,
    DatasetReviewRequest,
    DatasetVersionOut,
    FeatureArtifactOut,
    FeatureJobCreate,
    FeatureJobOut,
    FeatureSchemaOut,
    FeatureSchemaReviewRequest,
)
from aegis_api.security.authentication import (
    Principal,
    require_csrf_permission,
    require_permission,
)
from aegis_api.security.permissions import PermissionKey
from aegis_services.datasets import AcquisitionManifestV1, AcquisitionState
from aegis_services.features import DatasetManifestV1, FeatureSchemaV1

router = APIRouter(prefix="/api/v1")


@router.get("/dataset-acquisition-plans", response_model=list[DatasetAcquisitionPlanOut])
async def list_dataset_acquisition_plans(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.DATASETS_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[DatasetAcquisitionPlanOut]:
    records = (
        await db.scalars(
            select(DatasetAcquisitionPlan)
            .order_by(DatasetAcquisitionPlan.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [DatasetAcquisitionPlanOut.model_validate(record) for record in records]


@router.post(
    "/dataset-acquisition-plans",
    response_model=DatasetAcquisitionPlanOut,
    status_code=201,
)
async def create_dataset_acquisition_plan(
    payload: AcquisitionManifestV1,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.DATASETS_ACQUIRE))
    ],
) -> DatasetAcquisitionPlanOut:
    if payload.state != AcquisitionState.PROPOSED:
        raise ApiError(
            403,
            "dataset_acquisition_not_authorized",
            "Only an unapproved acquisition proposal can be recorded",
        )
    record = DatasetAcquisitionPlan(
        dataset_name=payload.dataset_name,
        dataset_version=payload.dataset_version,
        official_page_url=payload.official_page_url,
        source_review_hash=payload.source_review_hash,
        terms_reference_hash=payload.terms_reference_hash,
        manifest=payload.model_dump(mode="json"),
        manifest_hash=payload.manifest_hash,
        state=AcquisitionState.PROPOSED.value,
        combined_byte_limit=payload.limits.combined_bytes,
        file_byte_limit=payload.limits.file_bytes,
        file_count_limit=payload.limits.file_count,
        raw_retention_days=payload.raw_retention_days,
        created_by=principal.user_id,
    )
    db.add(record)
    try:
        await db.flush()
    except IntegrityError as error:
        await db.rollback()
        raise ApiError(
            409, "dataset_acquisition_manifest_conflict", "Acquisition proposal already exists"
        ) from error
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="dataset.acquisition.proposal.create",
        resource_type="dataset_acquisition_plan",
        resource_id=str(record.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "manifest_hash": record.manifest_hash,
            "state": record.state,
            "file_count": len(payload.files),
            "combined_advertised_bytes": sum(item.advertised_size_bytes for item in payload.files),
            "raw_pcap_excluded": payload.raw_pcap_excluded,
        },
    )
    await db.commit()
    await db.refresh(record)
    return DatasetAcquisitionPlanOut.model_validate(record)


def _schema_out(schema: FeatureSchemaVersion) -> FeatureSchemaOut:
    return FeatureSchemaOut.model_validate(schema)


async def _job_out(db: AsyncSession, job: FeatureMaterializationJob) -> FeatureJobOut:
    artifact = await db.scalar(
        select(FeatureArtifact).where(FeatureArtifact.materialization_job_id == job.id)
    )
    return FeatureJobOut(
        id=job.id,
        feature_schema_id=job.feature_schema_id,
        ingestion_job_id=job.ingestion_job_id,
        requested_limit=job.requested_limit,
        status=job.status,
        input_count=job.input_count,
        output_count=job.output_count,
        source_snapshot_hash=job.source_snapshot_hash,
        quality_summary=job.quality_summary,
        error_code=job.error_code,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        artifact=FeatureArtifactOut.model_validate(artifact) if artifact else None,
    )


@router.get("/feature-schemas", response_model=list[FeatureSchemaOut])
async def list_feature_schemas(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.FEATURES_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[FeatureSchemaOut]:
    records = (
        await db.scalars(
            select(FeatureSchemaVersion)
            .order_by(FeatureSchemaVersion.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [_schema_out(record) for record in records]


@router.get("/feature-schemas/{schema_id}", response_model=FeatureSchemaOut)
async def get_feature_schema(
    schema_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.FEATURES_READ))],
) -> FeatureSchemaOut:
    schema = await db.get(FeatureSchemaVersion, schema_id)
    if schema is None:
        raise ApiError(404, "feature_schema_not_found", "Feature schema not found")
    return _schema_out(schema)


@router.post("/feature-schemas/{schema_id}/review", response_model=FeatureSchemaOut)
async def review_feature_schema(
    schema_id: UUID,
    payload: FeatureSchemaReviewRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.FEATURES_REVIEW))
    ],
) -> FeatureSchemaOut:
    schema = await db.scalar(
        select(FeatureSchemaVersion).where(FeatureSchemaVersion.id == schema_id).with_for_update()
    )
    if schema is None:
        raise ApiError(404, "feature_schema_not_found", "Feature schema not found")
    if schema.lifecycle_state != "draft":
        raise ApiError(409, "feature_schema_state", "Feature schema cannot be reviewed")
    try:
        contract = FeatureSchemaV1.model_validate(schema.ordered_definition)
    except ValueError as error:
        raise ApiError(409, "feature_schema_invalid", "Feature schema is invalid") from error
    if contract.definition_hash != schema.definition_hash:
        raise ApiError(409, "feature_schema_integrity", "Feature schema integrity check failed")
    schema.lifecycle_state = "approved" if payload.approved else "retired"
    schema.reviewed_by = principal.user_id
    schema.reviewed_at = datetime.now(UTC)
    schema.review_reason = payload.reason
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="feature.schema.review",
        resource_type="feature_schema",
        resource_id=str(schema.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "decision": schema.lifecycle_state,
            "definition_hash": schema.definition_hash,
            "regression_evidence": payload.regression_evidence,
        },
    )
    await db.commit()
    await db.refresh(schema)
    return _schema_out(schema)


@router.post("/feature-jobs", response_model=FeatureJobOut, status_code=202)
async def create_feature_job(
    payload: FeatureJobCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.FEATURES_MATERIALIZE))
    ],
    dispatcher: Annotated[object, Depends(get_feature_dispatcher)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> FeatureJobOut:
    existing = await db.scalar(
        select(FeatureMaterializationJob).where(
            FeatureMaterializationJob.requested_by == principal.user_id,
            FeatureMaterializationJob.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if (
            existing.feature_schema_id != payload.feature_schema_id
            or existing.ingestion_job_id != payload.ingestion_job_id
            or existing.requested_limit != payload.requested_limit
        ):
            raise ApiError(409, "feature_idempotency_conflict", "Idempotency key conflicts")
        return await _job_out(db, existing)
    schema = await db.get(FeatureSchemaVersion, payload.feature_schema_id)
    if schema is None or schema.lifecycle_state != "approved":
        raise ApiError(409, "feature_schema_unavailable", "Feature schema is unavailable")
    source = await db.get(IngestionJob, payload.ingestion_job_id)
    if source is None or source.status != "succeeded":
        raise ApiError(409, "feature_source_unavailable", "Feature source is unavailable")
    job = FeatureMaterializationJob(
        requested_by=principal.user_id,
        feature_schema_id=schema.id,
        ingestion_job_id=source.id,
        idempotency_key=idempotency_key,
        requested_limit=payload.requested_limit,
    )
    db.add(job)
    try:
        await db.flush()
    except IntegrityError as error:
        await db.rollback()
        raise ApiError(409, "feature_job_conflict", "Feature job already exists") from error
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="feature.materialization.request",
        resource_type="feature_job",
        resource_id=str(job.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "feature_schema_id": str(schema.id),
            "ingestion_job_id": str(source.id),
            "requested_limit": payload.requested_limit,
        },
    )
    await db.commit()
    await db.refresh(job)
    dispatch = dispatcher
    if not callable(dispatch):
        raise RuntimeError("feature dispatcher is not callable")
    dispatch(str(job.id))
    return await _job_out(db, job)


@router.get("/feature-jobs", response_model=list[FeatureJobOut])
async def list_feature_jobs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.FEATURES_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[FeatureJobOut]:
    jobs = (
        await db.scalars(
            select(FeatureMaterializationJob)
            .order_by(FeatureMaterializationJob.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [await _job_out(db, job) for job in jobs]


@router.get("/feature-jobs/{job_id}", response_model=FeatureJobOut)
async def get_feature_job(
    job_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.FEATURES_READ))],
) -> FeatureJobOut:
    job = await db.get(FeatureMaterializationJob, job_id)
    if job is None:
        raise ApiError(404, "feature_job_not_found", "Feature job not found")
    return await _job_out(db, job)


@router.get("/datasets", response_model=list[DatasetVersionOut])
async def list_datasets(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.DATASETS_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[DatasetVersionOut]:
    records = (
        await db.scalars(
            select(DatasetVersion).order_by(DatasetVersion.created_at.desc()).limit(limit)
        )
    ).all()
    return [DatasetVersionOut.model_validate(record) for record in records]


@router.get("/datasets/{dataset_id}", response_model=DatasetVersionOut)
async def get_dataset(
    dataset_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.DATASETS_READ))],
) -> DatasetVersionOut:
    record = await db.get(DatasetVersion, dataset_id)
    if record is None:
        raise ApiError(404, "dataset_not_found", "Dataset metadata not found")
    return DatasetVersionOut.model_validate(record)


@router.post("/datasets", response_model=DatasetVersionOut, status_code=201)
async def create_dataset_proposal(
    payload: DatasetManifestV1,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.DATASETS_MANAGE))
    ],
) -> DatasetVersionOut:
    if payload.acquisition_authorized or payload.files:
        raise ApiError(
            403, "dataset_acquisition_not_authorized", "Dataset acquisition is not authorized"
        )
    record = DatasetVersion(
        name=payload.dataset_name,
        version=payload.dataset_version,
        official_source_url=payload.official_source_url,
        publisher=payload.publisher,
        intended_use=payload.intended_use,
        terms_reference_hash=payload.terms_reference_hash,
        citation_required=payload.citation_required,
        commercial_approval_required=payload.commercial_use_requires_author_agreement,
        acquisition_authorized=False,
        manifest=payload.model_dump(mode="json"),
        manifest_hash=payload.manifest_hash,
        status="proposed",
        created_by=principal.user_id,
    )
    db.add(record)
    try:
        await db.flush()
    except IntegrityError as error:
        await db.rollback()
        raise ApiError(
            409, "dataset_manifest_conflict", "Dataset metadata already exists"
        ) from error
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="dataset.proposal.create",
        resource_type="dataset_version",
        resource_id=str(record.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"manifest_hash": record.manifest_hash, "acquisition_authorized": False},
    )
    await db.commit()
    await db.refresh(record)
    return DatasetVersionOut.model_validate(record)


@router.post("/datasets/{dataset_id}/review", response_model=DatasetVersionOut)
async def review_dataset(
    dataset_id: UUID,
    payload: DatasetReviewRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.DATASETS_MANAGE))
    ],
) -> DatasetVersionOut:
    record = await db.scalar(
        select(DatasetVersion).where(DatasetVersion.id == dataset_id).with_for_update()
    )
    if record is None:
        raise ApiError(404, "dataset_not_found", "Dataset metadata not found")
    if record.status != "proposed":
        raise ApiError(409, "dataset_state", "Dataset metadata cannot be reviewed")
    record.status = "accepted" if payload.accepted else "retired"
    record.reviewed_by = principal.user_id
    record.reviewed_at = datetime.now(UTC)
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="dataset.metadata.review",
        resource_type="dataset_version",
        resource_id=str(record.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "decision": record.status,
            "manifest_hash": record.manifest_hash,
            "reason": payload.reason,
            "acquisition_authorized": False,
        },
    )
    await db.commit()
    await db.refresh(record)
    return DatasetVersionOut.model_validate(record)
