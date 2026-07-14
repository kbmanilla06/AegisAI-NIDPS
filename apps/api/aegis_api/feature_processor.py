from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_api.config import Settings
from aegis_api.models import (
    AuditEvent,
    FeatureArtifact,
    FeatureMaterializationJob,
    FeatureSchemaVersion,
    Flow,
)
from aegis_services.features import FeatureInput, FeaturePipeline, FeatureSchemaV1, write_parquet
from aegis_services.ingestion import CanonicalFlowV1


def _safe_feature_root(settings: Settings) -> Path:
    return settings.artifact_root / "features"


async def process_feature_job(
    job_id: UUID,
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as db:
        now = datetime.now(UTC)
        stale_processing_cutoff = now - timedelta(
            seconds=settings.feature_hard_limit_seconds + settings.feature_pending_delay_seconds
        )
        job = await db.scalar(
            select(FeatureMaterializationJob)
            .where(FeatureMaterializationJob.id == job_id)
            .with_for_update()
        )
        if job is None or job.status == "succeeded":
            return
        if job.status == "processing":
            started_at = job.started_at
            if started_at is None:
                return
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=UTC)
            if started_at > stale_processing_cutoff:
                return
        if job.status != "pending":
            if job.status != "processing":
                return
        schema_record = await db.get(FeatureSchemaVersion, job.feature_schema_id)
        if schema_record is None or schema_record.lifecycle_state != "approved":
            job.status = "failed"
            job.error_code = "feature_schema_unavailable"
            job.completed_at = datetime.now(UTC)
            await db.commit()
            return
        job.status = "processing"
        job.started_at = now
        await db.commit()

    written = None
    try:
        schema = FeatureSchemaV1.model_validate(schema_record.ordered_definition)
        if schema.definition_hash != schema_record.definition_hash:
            raise ValueError("feature_schema_integrity_failure")
        if len(schema.features) > settings.feature_max_features:
            raise ValueError("feature_column_limit")
        if len(schema.windows) > settings.feature_max_windows:
            raise ValueError("feature_window_limit")
        async with session_factory() as db:
            flows = (
                await db.scalars(
                    select(Flow)
                    .where(Flow.job_id == job.ingestion_job_id)
                    .order_by(Flow.event_time, Flow.event_key)
                    .limit(min(job.requested_limit, settings.feature_max_flows) + 1)
                )
            ).all()
        if not flows:
            raise ValueError("feature_source_empty")
        if len(flows) > min(job.requested_limit, settings.feature_max_flows):
            raise ValueError("feature_record_limit")
        inputs = tuple(
            FeatureInput(
                event_key=flow.event_key,
                sensor_id=str(flow.sensor_id) if flow.sensor_id else None,
                flow=CanonicalFlowV1(
                    schema_version=flow.schema_version,
                    source_type=flow.source_type,
                    source_event_id=flow.source_event_id,
                    event_time=(
                        flow.event_time.replace(tzinfo=UTC)
                        if flow.event_time.tzinfo is None
                        else flow.event_time
                    ),
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
                ),
            )
            for flow in flows
        )
        vectors = FeaturePipeline(schema).transform_batch(inputs)
        written = write_parquet(
            vectors,
            _safe_feature_root(settings),
            max_output_bytes=settings.feature_max_output_bytes,
        )
        source_snapshot_hash = vectors[0].source_snapshot_hash
        quality_counts: dict[str, int] = {}
        for vector in vectors:
            for flag in vector.quality_flags:
                quality_counts[flag] = quality_counts.get(flag, 0) + 1
        async with session_factory() as db:
            locked = await db.scalar(
                select(FeatureMaterializationJob)
                .where(FeatureMaterializationJob.id == job_id)
                .with_for_update()
            )
            if locked is None:
                raise ValueError("feature_job_missing")
            existing = await db.scalar(
                select(FeatureArtifact).where(FeatureArtifact.materialization_job_id == locked.id)
            )
            if existing is None:
                db.add(
                    FeatureArtifact(
                        id=written.artifact_id,
                        materialization_job_id=locked.id,
                        feature_schema_id=locked.feature_schema_id,
                        object_ref=written.object_ref,
                        media_type=written.media_type,
                        sha256=written.sha256,
                        size_bytes=written.size_bytes,
                        row_count=written.row_count,
                        column_count=written.column_count,
                        source_snapshot_hash=source_snapshot_hash,
                        code_version=schema.code_version,
                        expires_at=datetime.now(UTC)
                        + timedelta(days=settings.feature_retention_days),
                    )
                )
            locked.status = "succeeded"
            locked.input_count = len(inputs)
            locked.output_count = len(vectors)
            locked.source_snapshot_hash = source_snapshot_hash
            locked.quality_summary = {"flags": quality_counts}
            locked.error_code = None
            locked.completed_at = datetime.now(UTC)
            db.add(
                AuditEvent(
                    actor_user_id=locked.requested_by,
                    action="feature.materialization.succeed",
                    resource_type="feature_job",
                    resource_id=str(locked.id),
                    outcome="success",
                    correlation_id=f"feature-job-{locked.id}",
                    safe_metadata={
                        "feature_schema_id": str(locked.feature_schema_id),
                        "source_snapshot_hash": source_snapshot_hash,
                        "artifact_sha256": written.sha256,
                        "input_count": len(inputs),
                        "output_count": len(vectors),
                    },
                )
            )
            await db.commit()
    except Exception:
        if written is not None:
            (_safe_feature_root(settings) / f"{written.object_ref}.parquet").unlink(missing_ok=True)
        async with session_factory() as db:
            retry_job = await db.scalar(
                select(FeatureMaterializationJob)
                .where(FeatureMaterializationJob.id == job_id)
                .with_for_update()
            )
            if retry_job is not None and retry_job.status == "processing":
                retry_job.status = "pending"
                retry_job.error_code = "feature_retry_pending"
                await db.commit()
        raise


async def mark_feature_failed(
    job_id: UUID,
    error_code: str,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as db:
        job = await db.scalar(
            select(FeatureMaterializationJob)
            .where(FeatureMaterializationJob.id == job_id)
            .with_for_update()
        )
        if job is not None and job.status != "succeeded":
            job.status = "failed"
            job.error_code = error_code[:64]
            job.completed_at = datetime.now(UTC)
            db.add(
                AuditEvent(
                    actor_user_id=job.requested_by,
                    action="feature.materialization.fail",
                    resource_type="feature_job",
                    resource_id=str(job.id),
                    outcome="failure",
                    correlation_id=f"feature-job-{job.id}",
                    safe_metadata={"error_code": job.error_code},
                )
            )
            await db.commit()


async def pending_feature_jobs(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> list[UUID]:
    cutoff = datetime.now(UTC) - timedelta(seconds=settings.feature_pending_delay_seconds)
    stale_processing_cutoff = datetime.now(UTC) - timedelta(
        seconds=settings.feature_hard_limit_seconds + settings.feature_pending_delay_seconds
    )
    async with session_factory() as db:
        return list(
            (
                await db.scalars(
                    select(FeatureMaterializationJob.id)
                    .where(
                        or_(
                            and_(
                                FeatureMaterializationJob.status == "pending",
                                FeatureMaterializationJob.created_at <= cutoff,
                            ),
                            and_(
                                FeatureMaterializationJob.status == "processing",
                                FeatureMaterializationJob.started_at.is_not(None),
                                FeatureMaterializationJob.started_at <= stale_processing_cutoff,
                            ),
                        )
                    )
                    .order_by(FeatureMaterializationJob.created_at)
                    .limit(100)
                )
            ).all()
        )


async def cleanup_feature_artifacts(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> int:
    now = datetime.now(UTC)
    async with session_factory() as db:
        artifacts = (
            await db.scalars(
                select(FeatureArtifact)
                .where(
                    FeatureArtifact.status == "available",
                    FeatureArtifact.expires_at <= now,
                )
                .with_for_update()
                .limit(100)
            )
        ).all()
        deleted = 0
        root = _safe_feature_root(settings).resolve()
        for artifact in artifacts:
            try:
                path = (root / f"{UUID(artifact.object_ref)}.parquet").resolve()
                if path.parent == root:
                    path.unlink(missing_ok=True)
            except ValueError:
                pass
            artifact.status = "deleted"
            artifact.deleted_at = now
            db.add(
                AuditEvent(
                    actor_user_id=None,
                    action="feature.artifact.cleanup",
                    resource_type="feature_artifact",
                    resource_id=str(artifact.id),
                    outcome="success",
                    correlation_id=f"feature-cleanup-{artifact.id}",
                    safe_metadata={
                        "sha256": artifact.sha256,
                        "retention_class": artifact.retention_class,
                    },
                )
            )
            deleted += 1
        await db.commit()
        return deleted


async def delete_failed_job_without_artifact(
    job_id: UUID, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Test helper for downgrade inventory; never deletes successful provenance."""
    async with session_factory() as db:
        await db.execute(
            delete(FeatureMaterializationJob).where(
                FeatureMaterializationJob.id == job_id,
                FeatureMaterializationJob.status == "failed",
            )
        )
        await db.commit()
