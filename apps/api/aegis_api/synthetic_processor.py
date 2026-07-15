from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_api.config import Settings
from aegis_api.models import (
    AuditEvent,
    FeatureSchemaVersion,
    SyntheticDatasetVersion,
    SyntheticGenerationJob,
)
from aegis_services.features import FeatureSchemaV1
from aegis_services.synthetic import (
    SyntheticArtifactV1,
    SyntheticDatasetManifestV1,
    SyntheticScenarioCatalogV1,
    build_synthetic_dataset,
    write_synthetic_artifacts,
)


def _synthetic_root(settings: Settings) -> Path:
    return settings.artifact_root / "synthetic"


async def process_synthetic_generation_job(
    job_id: UUID,
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as db:
        now = datetime.now(UTC)
        stale_cutoff = now - timedelta(
            seconds=settings.synthetic_hard_limit_seconds + settings.synthetic_pending_delay_seconds
        )
        job = await db.scalar(
            select(SyntheticGenerationJob)
            .where(SyntheticGenerationJob.id == job_id)
            .with_for_update()
        )
        if job is None or job.status == "succeeded":
            return
        if job.status == "processing" and job.started_at is not None:
            started = (
                job.started_at.replace(tzinfo=UTC)
                if job.started_at.tzinfo is None
                else job.started_at
            )
            if started > stale_cutoff:
                return
        if job.status not in {"pending", "processing"}:
            return
        schema_record = await db.get(FeatureSchemaVersion, job.feature_schema_id)
        if schema_record is None or schema_record.lifecycle_state != "approved":
            job.status = "failed"
            job.error_code = "synthetic_feature_schema_unavailable"
            job.completed_at = now
            await db.commit()
            return
        job.status = "processing"
        job.started_at = now
        await db.commit()

    written = None
    try:
        schema = FeatureSchemaV1.model_validate(schema_record.ordered_definition)
        if schema.definition_hash != schema_record.definition_hash:
            raise ValueError("synthetic_feature_schema_integrity")
        catalog = SyntheticScenarioCatalogV1()
        if job.scenario_catalog_hash != catalog.catalog_hash:
            raise ValueError("synthetic_catalog_integrity")
        result = build_synthetic_dataset(schema, catalog=catalog)
        if len(result.examples) != job.requested_flow_count:
            raise ValueError("synthetic_flow_count_mismatch")
        written = write_synthetic_artifacts(
            result,
            _synthetic_root(settings),
            max_feature_bytes=settings.feature_max_output_bytes,
        )
        flow_artifact, target_artifact, feature_artifact = written
        created_at = datetime.now(UTC)
        artifacts = (
            SyntheticArtifactV1(
                kind="canonical_flows",
                object_ref=flow_artifact.object_ref,
                media_type=flow_artifact.media_type,
                sha256=flow_artifact.sha256,
                size_bytes=flow_artifact.size_bytes,
                row_count=flow_artifact.row_count,
            ),
            SyntheticArtifactV1(
                kind="targets",
                object_ref=target_artifact.object_ref,
                media_type=target_artifact.media_type,
                sha256=target_artifact.sha256,
                size_bytes=target_artifact.size_bytes,
                row_count=target_artifact.row_count,
            ),
            SyntheticArtifactV1(
                kind="features",
                object_ref=feature_artifact.object_ref,
                media_type=feature_artifact.media_type,
                sha256=feature_artifact.sha256,
                size_bytes=feature_artifact.size_bytes,
                row_count=feature_artifact.row_count,
                column_count=feature_artifact.column_count,
            ),
        )
        manifest = SyntheticDatasetManifestV1(
            version="1.0.0",
            scenario_catalog_hash=catalog.catalog_hash,
            feature_schema_hash=schema.definition_hash,
            feature_names=result.vectors[0].ordered_names,
            source_snapshot_hash=result.vectors[0].source_snapshot_hash,
            total_flows=len(result.examples),
            total_groups=result.quality_report.total_groups,
            artifacts=artifacts,
            target_manifest_hash=result.target_manifest_hash,
            split_manifest_hash=result.split_manifest.manifest_hash,
            quality_report_hash=result.quality_report.report_hash,
            leakage_report_hash=result.leakage_report.report_hash,
            code_version=schema.code_version,
            created_at=created_at,
        )
        async with session_factory() as db:
            locked = await db.scalar(
                select(SyntheticGenerationJob)
                .where(SyntheticGenerationJob.id == job_id)
                .with_for_update()
            )
            if locked is None:
                raise ValueError("synthetic_job_missing")
            existing = await db.scalar(
                select(SyntheticDatasetVersion).where(
                    SyntheticDatasetVersion.generation_job_id == job_id
                )
            )
            if existing is None:
                db.add(
                    SyntheticDatasetVersion(
                        generation_job_id=locked.id,
                        created_by=locked.requested_by,
                        feature_schema_id=locked.feature_schema_id,
                        name=manifest.name,
                        version=manifest.version,
                        manifest=manifest.model_dump(mode="json"),
                        manifest_hash=manifest.manifest_hash,
                        target_manifest_hash=result.target_manifest_hash,
                        split_manifest=result.split_manifest.model_dump(mode="json"),
                        split_manifest_hash=result.split_manifest.manifest_hash,
                        quality_report=result.quality_report.model_dump(mode="json"),
                        quality_report_hash=result.quality_report.report_hash,
                        leakage_report=result.leakage_report.model_dump(mode="json"),
                        leakage_report_hash=result.leakage_report.report_hash,
                        flow_object_ref=flow_artifact.object_ref,
                        flow_sha256=flow_artifact.sha256,
                        flow_size_bytes=flow_artifact.size_bytes,
                        target_object_ref=target_artifact.object_ref,
                        target_sha256=target_artifact.sha256,
                        target_size_bytes=target_artifact.size_bytes,
                        feature_object_ref=feature_artifact.object_ref,
                        feature_sha256=feature_artifact.sha256,
                        feature_size_bytes=feature_artifact.size_bytes,
                        feature_column_count=feature_artifact.column_count,
                        flow_count=len(result.examples),
                        group_count=result.quality_report.total_groups,
                        lifecycle_state="generated",
                        retention_days=settings.synthetic_retention_days,
                        expires_at=created_at + timedelta(days=settings.synthetic_retention_days),
                    )
                )
            locked.status = "succeeded"
            locked.generated_flow_count = len(result.examples)
            locked.generated_group_count = result.quality_report.total_groups
            locked.error_code = None
            locked.completed_at = created_at
            db.add(
                AuditEvent(
                    actor_user_id=locked.requested_by,
                    action="synthetic.dataset.generate.succeed",
                    resource_type="synthetic_generation_job",
                    resource_id=str(locked.id),
                    outcome="success",
                    correlation_id=f"synthetic-job-{locked.id}",
                    safe_metadata={
                        "scenario_catalog_hash": catalog.catalog_hash,
                        "manifest_hash": manifest.manifest_hash,
                        "target_manifest_hash": result.target_manifest_hash,
                        "split_manifest_hash": result.split_manifest.manifest_hash,
                        "quality_report_hash": result.quality_report.report_hash,
                        "leakage_report_hash": result.leakage_report.report_hash,
                        "flow_count": len(result.examples),
                        "group_count": result.quality_report.total_groups,
                        "synthetic_demo_only": True,
                    },
                )
            )
            await db.commit()
    except Exception:
        if written is not None:
            flow_artifact, target_artifact, feature_artifact = written
            root = _synthetic_root(settings)
            (root / f"{flow_artifact.object_ref}.jsonl").unlink(missing_ok=True)
            (root / f"{target_artifact.object_ref}.targets.json").unlink(missing_ok=True)
            (root / f"{feature_artifact.object_ref}.parquet").unlink(missing_ok=True)
        async with session_factory() as db:
            retry_job = await db.scalar(
                select(SyntheticGenerationJob)
                .where(SyntheticGenerationJob.id == job_id)
                .with_for_update()
            )
            if retry_job is not None and retry_job.status == "processing":
                retry_job.status = "pending"
                retry_job.error_code = "synthetic_retry_pending"
                await db.commit()
        raise


async def mark_synthetic_failed(
    job_id: UUID,
    error_code: str,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as db:
        job = await db.scalar(
            select(SyntheticGenerationJob)
            .where(SyntheticGenerationJob.id == job_id)
            .with_for_update()
        )
        if job is not None and job.status != "succeeded":
            job.status = "failed"
            job.error_code = error_code[:64]
            job.completed_at = datetime.now(UTC)
            db.add(
                AuditEvent(
                    actor_user_id=job.requested_by,
                    action="synthetic.dataset.generate.fail",
                    resource_type="synthetic_generation_job",
                    resource_id=str(job.id),
                    outcome="failure",
                    correlation_id=f"synthetic-job-{job.id}",
                    safe_metadata={"error_code": job.error_code},
                )
            )
            await db.commit()


async def pending_synthetic_jobs(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> list[UUID]:
    now = datetime.now(UTC)
    pending_cutoff = now - timedelta(seconds=settings.synthetic_pending_delay_seconds)
    stale_cutoff = now - timedelta(
        seconds=settings.synthetic_hard_limit_seconds + settings.synthetic_pending_delay_seconds
    )
    async with session_factory() as db:
        return list(
            (
                await db.scalars(
                    select(SyntheticGenerationJob.id)
                    .where(
                        or_(
                            and_(
                                SyntheticGenerationJob.status == "pending",
                                SyntheticGenerationJob.created_at <= pending_cutoff,
                            ),
                            and_(
                                SyntheticGenerationJob.status == "processing",
                                SyntheticGenerationJob.started_at.is_not(None),
                                SyntheticGenerationJob.started_at <= stale_cutoff,
                            ),
                        )
                    )
                    .order_by(SyntheticGenerationJob.created_at)
                    .limit(100)
                )
            ).all()
        )


async def cleanup_synthetic_artifacts(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> int:
    now = datetime.now(UTC)
    async with session_factory() as db:
        records = (
            await db.scalars(
                select(SyntheticDatasetVersion)
                .where(
                    SyntheticDatasetVersion.expires_at <= now,
                    SyntheticDatasetVersion.artifacts_deleted_at.is_(None),
                )
                .order_by(SyntheticDatasetVersion.expires_at)
                .limit(100)
                .with_for_update(skip_locked=True)
            )
        ).all()
        root = _synthetic_root(settings).resolve()
        deleted = 0
        for record in records:
            for object_ref, suffix in (
                (record.flow_object_ref, "jsonl"),
                (record.target_object_ref, "targets.json"),
                (record.feature_object_ref, "parquet"),
            ):
                candidate = (root / f"{UUID(object_ref)}.{suffix}").resolve()
                if candidate.parent != root:
                    raise ValueError("synthetic_artifact_path_invalid")
                candidate.unlink(missing_ok=True)
            record.artifacts_deleted_at = now
            record.lifecycle_state = "retired"
            db.add(
                AuditEvent(
                    actor_user_id=record.created_by,
                    action="synthetic.dataset.cleanup",
                    resource_type="synthetic_dataset",
                    resource_id=str(record.id),
                    outcome="success",
                    correlation_id=f"synthetic-cleanup-{record.id}",
                    safe_metadata={"manifest_hash": record.manifest_hash},
                )
            )
            deleted += 1
        await db.commit()
        return deleted
