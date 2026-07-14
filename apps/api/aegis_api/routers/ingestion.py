from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import UploadFile

from aegis_api.audit import record_audit
from aegis_api.config import Settings, get_settings
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.ingestion_dispatch import get_ingestion_dispatcher
from aegis_api.ingestion_storage import UploadTooLarge, delete_object, store_chunks, store_upload
from aegis_api.ingestion_throttle import IngestionThrottle, get_ingestion_throttle
from aegis_api.models import Flow, IngestionJob
from aegis_api.schemas import FlowOut, IngestionJobOut, IngestionMetricsOut, IngestionSource
from aegis_api.security.authentication import (
    Principal,
    require_csrf_permission,
    require_permission,
)
from aegis_api.security.permissions import PermissionKey
from aegis_api.security.sensors import SensorPrincipal, get_sensor_principal
from aegis_services.ingestion.adapters import content_matches

router = APIRouter(prefix="/api/v1")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
DETECTED_MEDIA_TYPES = {
    "normalized": "application/x-ndjson; profile=canonical-flow-v1",
    "zeek": "application/x-zeek-log",
    "suricata": "application/x-ndjson; profile=suricata-eve",
    "pcap": "application/vnd.tcpdump.pcap",
}


def _job_out(job: IngestionJob) -> IngestionJobOut:
    return IngestionJobOut.model_validate(job)


def _flow_out(flow: Flow) -> FlowOut:
    return FlowOut(
        id=flow.id,
        event_key=flow.event_key,
        schema_version=flow.schema_version,
        source_type=flow.source_type,
        source_event_id=flow.source_event_id,
        job_id=flow.job_id,
        sensor_id=flow.sensor_id,
        event_time=flow.event_time,
        src_address=flow.src_address,
        dst_address=flow.dst_address,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        protocol=flow.protocol,
        duration_ms=flow.duration_ms,
        packet_count=flow.packet_count,
        byte_count=flow.byte_count,
        state=flow.state,
        metadata=flow.flow_metadata,
    )


@router.post("/ingestion/jobs", response_model=IngestionJobOut, status_code=202)
async def submit_ingestion_job(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.INGESTION_SUBMIT))
    ],
    settings: Annotated[Settings, Depends(get_settings)],
    throttle: Annotated[IngestionThrottle, Depends(get_ingestion_throttle)],
    dispatch: Annotated[Callable[[str], None], Depends(get_ingestion_dispatcher)],
) -> IngestionJobOut:
    await throttle.check(str(principal.user_id))
    try:
        async with request.form(max_files=1, max_fields=2, max_part_size=4096) as form:
            source_value = form.get("source_type")
            upload_value = form.get("file")
            if not isinstance(source_value, str) or not isinstance(upload_value, UploadFile):
                raise ApiError(400, "invalid_upload", "A source type and one file are required")
            try:
                source_type = IngestionSource(source_value).value
            except ValueError as error:
                raise ApiError(422, "unsupported_source", "Unsupported telemetry source") from error
            try:
                stored = await store_upload(
                    upload_value, settings.artifact_root, settings.ingestion_max_upload_bytes
                )
            except UploadTooLarge as error:
                raise ApiError(
                    413, "upload_too_large", "Upload exceeds the configured limit"
                ) from error
    except ApiError:
        raise
    except OSError as error:
        raise ApiError(
            503, "ingestion_storage_unavailable", "Ingestion storage is temporarily unavailable"
        ) from error
    except Exception as error:
        raise ApiError(400, "invalid_multipart", "Upload request is malformed") from error

    now = datetime.now(UTC)
    if stored.size_bytes == 0 or not content_matches(source_type, stored.prefix):
        rejected_ref: str | None = stored.object_ref
        rejected_deleted_at: datetime | None = None
        try:
            delete_object(settings.artifact_root, stored.object_ref)
            rejected_ref = None
            rejected_deleted_at = now
        except (OSError, ValueError):
            pass
        rejected = IngestionJob(
            source_type=source_type,
            status="rejected",
            object_ref=rejected_ref,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            media_type=DETECTED_MEDIA_TYPES[source_type],
            schema_version="1",
            submitted_by=principal.user_id,
            correlation_id=request.state.correlation_id,
            error_code="content_type_mismatch" if stored.size_bytes else "empty_upload",
            rejected_records=1,
            completed_at=now,
            raw_expires_at=now + timedelta(hours=settings.upload_retention_hours)
            if rejected_ref
            else None,
            raw_deleted_at=rejected_deleted_at,
        )
        db.add(rejected)
        await db.flush()
        record_audit(
            db,
            actor_user_id=principal.user_id,
            action="ingestion.submit",
            resource_type="ingestion_job",
            resource_id=str(rejected.id),
            outcome="failure",
            correlation_id=request.state.correlation_id,
            metadata={"source_type": source_type, "error_code": rejected.error_code},
        )
        await db.commit()
        raise ApiError(415, "content_type_mismatch", "Upload content does not match its source")

    job = IngestionJob(
        source_type=source_type,
        status="pending",
        object_ref=stored.object_ref,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        media_type=DETECTED_MEDIA_TYPES[source_type],
        schema_version="1",
        submitted_by=principal.user_id,
        correlation_id=request.state.correlation_id,
        raw_expires_at=now + timedelta(hours=settings.upload_retention_hours),
    )
    db.add(job)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="ingestion.submit",
        resource_type="ingestion_job",
        resource_id=str(job.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"source_type": source_type, "size_bytes": stored.size_bytes},
    )
    await db.commit()
    try:
        dispatch(str(job.id))
    except Exception as error:
        await _handle_dispatch_failure(db, job, principal.user_id, request.state.correlation_id)
        raise ApiError(
            503, "ingestion_unavailable", "Ingestion is temporarily unavailable"
        ) from error
    await db.refresh(job)
    return _job_out(job)


@router.post("/ingestion/sensor/jobs", response_model=IngestionJobOut, status_code=202)
async def submit_sensor_ingestion_job(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[SensorPrincipal, Depends(get_sensor_principal)],
    settings: Annotated[Settings, Depends(get_settings)],
    throttle: Annotated[IngestionThrottle, Depends(get_ingestion_throttle)],
    dispatch: Annotated[Callable[[str], None], Depends(get_ingestion_dispatcher)],
    source_header: Annotated[str | None, Header(alias="X-Aegis-Source")] = None,
) -> IngestionJobOut:
    expected_source = (
        "normalized" if principal.sensor.sensor_type == "flow" else principal.sensor.sensor_type
    )
    await throttle.check(f"sensor:{principal.sensor.id}")
    if source_header != expected_source:
        raise ApiError(422, "sensor_source_mismatch", "Sensor is not authorized for this source")
    try:
        stored = await store_chunks(
            request.stream(), settings.artifact_root, settings.ingestion_max_upload_bytes
        )
    except UploadTooLarge as error:
        raise ApiError(413, "upload_too_large", "Upload exceeds the configured limit") from error
    except OSError as error:
        raise ApiError(
            503, "ingestion_storage_unavailable", "Ingestion storage is temporarily unavailable"
        ) from error

    now = datetime.now(UTC)
    if stored.size_bytes == 0 or not content_matches(expected_source, stored.prefix):
        rejected_ref: str | None = stored.object_ref
        rejected_deleted_at: datetime | None = None
        try:
            delete_object(settings.artifact_root, stored.object_ref)
            rejected_ref = None
            rejected_deleted_at = now
        except (OSError, ValueError):
            pass
        rejected = IngestionJob(
            source_type=expected_source,
            status="rejected",
            object_ref=rejected_ref,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            media_type=DETECTED_MEDIA_TYPES[expected_source],
            schema_version="1",
            sensor_id=principal.sensor.id,
            correlation_id=request.state.correlation_id,
            error_code="content_type_mismatch" if stored.size_bytes else "empty_upload",
            rejected_records=1,
            completed_at=now,
            raw_expires_at=now + timedelta(hours=settings.upload_retention_hours)
            if rejected_ref
            else None,
            raw_deleted_at=rejected_deleted_at,
        )
        db.add(rejected)
        await db.flush()
        record_audit(
            db,
            actor_user_id=None,
            action="sensor.ingestion.submit",
            resource_type="ingestion_job",
            resource_id=str(rejected.id),
            outcome="failure",
            correlation_id=request.state.correlation_id,
            metadata={
                "sensor_id": str(principal.sensor.id),
                "source_type": expected_source,
                "error_code": rejected.error_code,
            },
        )
        await db.commit()
        raise ApiError(415, "content_type_mismatch", "Upload content does not match its source")

    job = IngestionJob(
        source_type=expected_source,
        status="pending",
        object_ref=stored.object_ref,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        media_type=DETECTED_MEDIA_TYPES[expected_source],
        schema_version="1",
        sensor_id=principal.sensor.id,
        correlation_id=request.state.correlation_id,
        raw_expires_at=now + timedelta(hours=settings.upload_retention_hours),
    )
    principal.sensor.last_seen_at = now
    db.add(job)
    await db.flush()
    record_audit(
        db,
        actor_user_id=None,
        action="sensor.ingestion.submit",
        resource_type="ingestion_job",
        resource_id=str(job.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "sensor_id": str(principal.sensor.id),
            "source_type": expected_source,
            "size_bytes": stored.size_bytes,
        },
    )
    await db.commit()
    try:
        dispatch(str(job.id))
    except Exception as error:
        await _handle_dispatch_failure(db, job, None, request.state.correlation_id)
        raise ApiError(
            503, "ingestion_unavailable", "Ingestion is temporarily unavailable"
        ) from error
    await db.refresh(job)
    return _job_out(job)


@router.get("/ingestion/jobs", response_model=list[IngestionJobOut])
async def list_ingestion_jobs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.TELEMETRY_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[IngestionJobOut]:
    jobs = (
        await db.scalars(select(IngestionJob).order_by(IngestionJob.created_at.desc()).limit(limit))
    ).all()
    return [_job_out(job) for job in jobs]


@router.get("/ingestion/jobs/{job_id}", response_model=IngestionJobOut)
async def get_ingestion_job(
    job_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.TELEMETRY_READ))],
) -> IngestionJobOut:
    job = await db.get(IngestionJob, job_id)
    if job is None:
        raise ApiError(404, "ingestion_job_not_found", "Ingestion job not found")
    return _job_out(job)


@router.post("/ingestion/jobs/{job_id}/replay", response_model=IngestionJobOut, status_code=202)
async def replay_ingestion_job(
    job_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.INGESTION_REPLAY))
    ],
    dispatch: Annotated[Callable[[str], None], Depends(get_ingestion_dispatcher)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> IngestionJobOut:
    if idempotency_key is None or not IDEMPOTENCY_KEY.fullmatch(idempotency_key):
        raise ApiError(400, "invalid_idempotency_key", "A valid Idempotency-Key is required")
    existing = await db.scalar(
        select(IngestionJob).where(
            IngestionJob.submitted_by == principal.user_id,
            IngestionJob.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        return _job_out(existing)
    original = await db.get(IngestionJob, job_id)
    if original is None or original.status != "succeeded" or original.accepted_records == 0:
        raise ApiError(409, "job_not_replayable", "Only a successful job can be replayed")
    replay = IngestionJob(
        source_type=original.source_type,
        status="pending",
        object_ref=None,
        sha256=original.sha256,
        size_bytes=0,
        media_type=original.media_type,
        schema_version=original.schema_version,
        submitted_by=principal.user_id,
        replay_of_id=original.id,
        idempotency_key=idempotency_key,
        correlation_id=request.state.correlation_id,
    )
    db.add(replay)
    try:
        await db.flush()
    except IntegrityError as error:
        await db.rollback()
        existing = await db.scalar(
            select(IngestionJob).where(
                IngestionJob.submitted_by == principal.user_id,
                IngestionJob.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            return _job_out(existing)
        raise ApiError(409, "replay_conflict", "Replay request conflicts") from error
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="ingestion.replay",
        resource_type="ingestion_job",
        resource_id=str(replay.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"replay_of_id": str(original.id)},
    )
    await db.commit()
    try:
        dispatch(str(replay.id))
    except Exception as error:
        await _handle_dispatch_failure(db, replay, principal.user_id, request.state.correlation_id)
        raise ApiError(
            503, "ingestion_unavailable", "Ingestion is temporarily unavailable"
        ) from error
    await db.refresh(replay)
    return _job_out(replay)


@router.get("/ingestion/metrics", response_model=IngestionMetricsOut)
async def ingestion_metrics(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.TELEMETRY_READ))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> IngestionMetricsOut:
    grouped = await db.execute(
        select(IngestionJob.status, func.count()).group_by(IngestionJob.status)
    )
    jobs_by_status = {status: int(count) for status, count in grouped.all()}
    totals = (
        await db.execute(
            select(
                func.coalesce(func.sum(IngestionJob.accepted_records), 0),
                func.coalesce(func.sum(IngestionJob.rejected_records), 0),
                func.coalesce(func.sum(IngestionJob.duplicate_records), 0),
            )
        )
    ).one()
    delayed_before = datetime.now(UTC) - timedelta(seconds=settings.ingestion_pending_delay_seconds)
    delayed = await db.scalar(
        select(func.count())
        .select_from(IngestionJob)
        .where(IngestionJob.status == "pending", IngestionJob.created_at < delayed_before)
    )
    return IngestionMetricsOut(
        jobs_by_status=jobs_by_status,
        accepted_records=int(totals[0]),
        rejected_records=int(totals[1]),
        duplicate_records=int(totals[2]),
        delayed_jobs=int(delayed or 0),
        failed_jobs=jobs_by_status.get("failed", 0),
    )


@router.get("/flows", response_model=list[FlowOut])
async def list_flows(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.TELEMETRY_READ))],
    start: datetime,
    end: datetime,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[FlowOut]:
    if start.tzinfo is None or end.tzinfo is None or start >= end:
        raise ApiError(422, "invalid_time_range", "A valid timezone-aware time range is required")
    if end - start > timedelta(days=31):
        raise ApiError(422, "time_range_too_large", "Time range cannot exceed 31 days")
    flows = (
        await db.scalars(
            select(Flow)
            .where(Flow.event_time >= start, Flow.event_time < end)
            .order_by(Flow.event_time.desc(), Flow.id)
            .limit(limit)
        )
    ).all()
    return [_flow_out(flow) for flow in flows]


@router.get("/flows/{flow_id}", response_model=FlowOut)
async def get_flow(
    flow_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.TELEMETRY_READ))],
) -> FlowOut:
    flow = await db.get(Flow, flow_id)
    if flow is None:
        raise ApiError(404, "flow_not_found", "Flow not found")
    return _flow_out(flow)


async def _handle_dispatch_failure(
    db: AsyncSession,
    job: IngestionJob,
    actor_user_id: UUID | None,
    correlation_id: str,
) -> None:
    locked_job = await db.scalar(
        select(IngestionJob).where(IngestionJob.id == job.id).with_for_update()
    )
    if locked_job is None or locked_job.status != "pending":
        return
    locked_job.status = "failed"
    locked_job.error_code = "queue_unavailable"
    locked_job.completed_at = datetime.now(UTC)
    record_audit(
        db,
        actor_user_id=actor_user_id,
        action="ingestion.dispatch",
        resource_type="ingestion_job",
        resource_id=str(locked_job.id),
        outcome="failure",
        correlation_id=correlation_id,
        metadata={"error_code": "queue_unavailable"},
    )
    await db.commit()
