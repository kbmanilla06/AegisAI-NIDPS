from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_api.audit import record_audit
from aegis_api.config import Settings
from aegis_api.ingestion_storage import delete_object, resolve_object_ref
from aegis_api.models import Flow, IngestionJob, ProcessedEvent
from aegis_services.ingestion import FatalIngestionError, ParseLimits, event_key, parse_file
from aegis_services.ingestion.schema import CanonicalFlowV1


async def process_ingestion_job(
    job_id: UUID,
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    delete_after_commit: str | None = None
    async with session_factory() as db:
        async with db.begin():
            job = await _locked_job(db, job_id)
            if job is None or job.status in {"succeeded", "rejected"}:
                return
            job.status = "processing"
            job.started_at = datetime.now(UTC)
            job.error_code = None

            if job.replay_of_id is not None:
                await _process_replay(db, job)
            else:
                delete_after_commit = await _process_upload(db, job, settings)

    if delete_after_commit is not None:
        try:
            delete_object(settings.artifact_root, delete_after_commit)
        except (OSError, ValueError):
            return
        async with session_factory() as db:
            async with db.begin():
                job = await _locked_job(db, job_id)
                if job is not None and job.object_ref == delete_after_commit:
                    job.object_ref = None
                    job.raw_deleted_at = datetime.now(UTC)


async def _locked_job(db: AsyncSession, job_id: UUID) -> IngestionJob | None:
    statement = select(IngestionJob).where(IngestionJob.id == job_id).with_for_update()
    return (await db.execute(statement)).scalar_one_or_none()


async def _process_upload(db: AsyncSession, job: IngestionJob, settings: Settings) -> str | None:
    if job.object_ref is None:
        _fail_job(db, job, "raw_object_missing")
        return None
    try:
        path = resolve_object_ref(settings.artifact_root, job.object_ref)
        if not path.is_file():
            raise OSError
        parsed = list(
            parse_file(
                path,
                job.source_type,
                ParseLimits(
                    max_records=settings.ingestion_max_records,
                    max_unique_flows=settings.ingestion_max_unique_flows,
                    max_seconds=settings.ingestion_max_processing_seconds,
                ),
            )
        )
    except FatalIngestionError as error:
        _fail_job(db, job, error.code)
        return None
    except (OSError, ValueError):
        _fail_job(db, job, "raw_object_unavailable")
        return None

    valid_flows = [item.flow for item in parsed if item.flow is not None]
    job.rejected_records = sum(item.error_code is not None for item in parsed)
    if not valid_flows:
        job.status = "rejected"
        job.error_code = "all_records_rejected"
        job.completed_at = datetime.now(UTC)
        _audit_job(db, job, "ingestion.process", "failure")
        return None

    for flow in valid_flows:
        assert flow is not None
        if await _store_flow(db, job, flow):
            job.accepted_records += 1
        else:
            job.duplicate_records += 1
    job.status = "succeeded"
    job.completed_at = datetime.now(UTC)
    _audit_job(db, job, "ingestion.process", "success")
    return job.object_ref


async def _store_flow(db: AsyncSession, job: IngestionJob, flow: CanonicalFlowV1) -> bool:
    identity = event_key(flow, str(job.sensor_id) if job.sensor_id else None)
    exists = await db.scalar(
        select(ProcessedEvent.id).where(
            ProcessedEvent.event_key == identity,
            ProcessedEvent.schema_version == flow.schema_version,
        )
    )
    if exists is not None:
        return False
    try:
        async with db.begin_nested():
            db.add(
                ProcessedEvent(
                    event_key=identity,
                    schema_version=flow.schema_version,
                    job_id=job.id,
                )
            )
            db.add(
                Flow(
                    event_key=identity,
                    schema_version=flow.schema_version,
                    source_type=flow.source_type,
                    source_event_id=flow.source_event_id,
                    job_id=job.id,
                    sensor_id=job.sensor_id,
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
                    flow_metadata=flow.metadata,
                )
            )
            await db.flush()
    except IntegrityError:
        return False
    return True


async def _process_replay(db: AsyncSession, job: IngestionJob) -> None:
    original_id = job.replay_of_id
    count = await db.scalar(
        select(func.count()).select_from(Flow).where(Flow.job_id == original_id)
    )
    job.duplicate_records = int(count or 0)
    job.status = "succeeded"
    job.completed_at = datetime.now(UTC)
    _audit_job(db, job, "ingestion.replay.process", "success")


def _fail_job(db: AsyncSession, job: IngestionJob, code: str) -> None:
    job.status = "failed"
    job.error_code = code
    job.completed_at = datetime.now(UTC)
    _audit_job(db, job, "ingestion.process", "failure")


def _audit_job(db: AsyncSession, job: IngestionJob, action: str, outcome: str) -> None:
    record_audit(
        db,
        actor_user_id=job.submitted_by,
        action=action,
        resource_type="ingestion_job",
        resource_id=str(job.id),
        outcome=outcome,
        correlation_id=job.correlation_id,
        metadata={
            "source_type": job.source_type,
            "accepted_records": job.accepted_records,
            "rejected_records": job.rejected_records,
            "duplicate_records": job.duplicate_records,
            "error_code": job.error_code or "none",
        },
    )


async def cleanup_expired_uploads(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> int:
    now = datetime.now(UTC)
    async with session_factory() as db:
        jobs = list(
            (
                await db.scalars(
                    select(IngestionJob).where(
                        IngestionJob.object_ref.is_not(None),
                        IngestionJob.raw_expires_at <= now,
                    )
                )
            ).all()
        )
        removed = 0
        for job in jobs:
            try:
                delete_object(settings.artifact_root, job.object_ref)
            except (OSError, ValueError):
                continue
            job.object_ref = None
            job.raw_deleted_at = now
            removed += 1
        if removed:
            record_audit(
                db,
                actor_user_id=None,
                action="retention.raw_upload_delete",
                resource_type="ingestion_job",
                resource_id=None,
                outcome="success",
                correlation_id=f"raw-retention-{now:%Y%m%d%H}",
                metadata={"deleted_objects": removed},
            )
        await db.commit()
        return removed


async def cleanup_expired_flows(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> int:
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=settings.flow_retention_days)
    async with session_factory() as db:
        rows = (
            await db.execute(
                select(Flow.id, Flow.event_key).where(Flow.created_at < cutoff).limit(10_000)
            )
        ).all()
        if not rows:
            return 0
        flow_ids = [row.id for row in rows]
        event_keys = [row.event_key for row in rows]
        await db.execute(delete(ProcessedEvent).where(ProcessedEvent.event_key.in_(event_keys)))
        await db.execute(delete(Flow).where(Flow.id.in_(flow_ids)))
        record_audit(
            db,
            actor_user_id=None,
            action="retention.flow_delete",
            resource_type="flow",
            resource_id=None,
            outcome="success",
            correlation_id=f"flow-retention-{now:%Y%m%d}",
            metadata={
                "deleted_flows": len(flow_ids),
                "retention_days": settings.flow_retention_days,
            },
        )
        await db.commit()
        return len(flow_ids)


async def mark_worker_task_failed(
    job_id: UUID,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as db:
        async with db.begin():
            job = await _locked_job(db, job_id)
            if job is None or job.status in {"succeeded", "rejected"}:
                return
            job.status = "failed"
            job.error_code = "worker_task_failed"
            job.completed_at = datetime.now(UTC)
            _audit_job(db, job, "ingestion.process", "failure")
