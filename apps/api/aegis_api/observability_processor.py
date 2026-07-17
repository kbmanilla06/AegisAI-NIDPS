from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_api.audit import record_audit
from aegis_api.config import Settings
from aegis_api.models import (
    SyntheticAnalystFeedback,
    SyntheticMonitoringMetric,
    SyntheticMonitoringRun,
    SyntheticObservabilityEvent,
    SyntheticRecoveryRun,
    SyntheticReport,
    SyntheticReportJob,
    SyntheticSLISnapshot,
)
from aegis_services.monitoring import ACCEPTED_SYNTHETIC_ARTIFACT_HASHES
from aegis_services.observability import (
    FALSE_CAPABILITY_FLAGS,
    OBSERVABILITY_LIMITATIONS,
    ReportStatus,
    SyntheticAggregateReportV1,
    canonical_hash,
)

REPORT_RETENTION_DAYS = 30
MIN_DISPLAY_SAMPLES = 30
DEFAULT_SOURCE_HASH = "454a6edc1d4d247f86a1e453cbec6e70ce28b9dd3bca6fe957d54782a101dfb9"


def _source_hashes(runs: list[SyntheticMonitoringRun]) -> list[str]:
    values: set[str] = set()
    for run in runs:
        for value in (run.baseline_snapshot_hash, run.current_snapshot_hash, run.policy_hash):
            if value in ACCEPTED_SYNTHETIC_ARTIFACT_HASHES:
                values.add(value)
    return sorted(values)[:12] or [DEFAULT_SOURCE_HASH]


def _bounded_section(values: dict[str, object], sample_count: int) -> dict[str, object]:
    if sample_count < MIN_DISPLAY_SAMPLES:
        return {
            "status": "not_evaluable",
            "sample_count": sample_count,
            "reason_code": "minimum_sample",
        }
    return {"status": "complete", "sample_count": sample_count, **values}


async def record_observability_event(
    db: AsyncSession,
    *,
    correlation_id: str,
    component: str,
    operation: str,
    status: str,
    duration_ms: float = 0,
    rows: int = 0,
    groups: int = 0,
    tasks: int = 0,
    bytes_count: int = 0,
    actor_role: str = "system",
    safe_error_code: str | None = None,
    evidence_hashes: list[str] | None = None,
    expires_at: datetime | None = None,
) -> SyntheticObservabilityEvent:
    if expires_at is None:
        expires_at = datetime.now(UTC) + timedelta(days=30)
    event = SyntheticObservabilityEvent(
        correlation_id=correlation_id,
        component=component,
        operation=operation,
        status=status,
        duration_ms=duration_ms,
        rows=rows,
        groups_count=groups,
        tasks=tasks,
        bytes_count=bytes_count,
        actor_role=actor_role,
        safe_error_code=safe_error_code,
        policy_version="synthetic-observability/1.0.0",
        evidence_hashes=evidence_hashes or [],
        limitations=OBSERVABILITY_LIMITATIONS,
        false_capability_flags=FALSE_CAPABILITY_FLAGS,
        expires_at=expires_at,
    )
    db.add(event)
    return event


async def _build_report(db: AsyncSession, job: SyntheticReportJob) -> SyntheticAggregateReportV1:
    runs = list(
        (
            await db.scalars(
                select(SyntheticMonitoringRun).where(
                    SyntheticMonitoringRun.created_at >= job.window_start,
                    SyntheticMonitoringRun.created_at <= job.window_end,
                )
            )
        ).all()
    )
    feedback_count = int(
        await db.scalar(
            select(func.count())
            .select_from(SyntheticAnalystFeedback)
            .where(
                SyntheticAnalystFeedback.created_at >= job.window_start,
                SyntheticAnalystFeedback.created_at <= job.window_end,
            )
        )
        or 0
    )
    event_count = int(
        await db.scalar(
            select(func.count())
            .select_from(SyntheticObservabilityEvent)
            .where(
                SyntheticObservabilityEvent.created_at >= job.window_start,
                SyntheticObservabilityEvent.created_at <= job.window_end,
            )
        )
        or 0
    )
    status_counts = Counter(run.status for run in runs)
    metric_status_counts: Counter[str] = Counter()
    for run in runs:
        metrics = list(
            (
                await db.scalars(
                    select(SyntheticMonitoringMetric).where(
                        SyntheticMonitoringMetric.run_id == run.id
                    )
                )
            ).all()
        )
        metric_status_counts.update(metric.status for metric in metrics)
    sample_count = sum(run.sample_count for run in runs)
    source_hashes = _source_hashes(runs)
    common = {
        "run_count": len(runs),
        "run_status_counts": dict(sorted(status_counts.items())),
        "metric_status_counts": dict(sorted(metric_status_counts.items())),
        "feedback_count": feedback_count,
        "event_count": event_count,
    }
    section = _bounded_section(common, sample_count)
    if job.report_type == "synthetic_feedback_summary":
        section = _bounded_section({"feedback_count": feedback_count}, feedback_count)
    elif job.report_type == "synthetic_operations":
        section = {"status": "complete", "event_count": event_count, "run_count": len(runs)}
    elif job.report_type == "synthetic_quality_drift":
        section = _bounded_section(
            {
                "run_status_counts": dict(sorted(status_counts.items())),
                "metric_status_counts": dict(sorted(metric_status_counts.items())),
            },
            sample_count,
        )
    elif job.report_type == "synthetic_retention_recovery":
        section = {
            "status": "complete",
            "event_count": event_count,
            "recovery_evidence": "metadata_only",
        }
    elif job.report_type == "synthetic_gate_evidence":
        section = _bounded_section(
            {"run_count": len(runs), "event_count": event_count}, sample_count
        )
    report_status = "complete" if section["status"] == "complete" else "not_evaluable"
    return SyntheticAggregateReportV1(
        report_type=job.report_type,
        # Bind the report timestamp to the requested evidence window so a repeated
        # run over identical inputs produces the identical canonical hash.
        generated_at=job.window_end,
        window_start=job.window_start,
        window_end=job.window_end,
        policy_version="synthetic-observability/1.0.0",
        source_hashes=source_hashes,
        sections={job.report_type: section},
        status=ReportStatus(report_status),
        limitations=OBSERVABILITY_LIMITATIONS,
        false_capability_flags=FALSE_CAPABILITY_FLAGS,
    )


async def process_report_job(
    job_id: UUID, settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as db:
        job = await db.get(SyntheticReportJob, job_id)
        if job is None or job.status not in {"pending", "processing"}:
            return
        job.status = "processing"
        await db.commit()
        try:
            report = await _build_report(db, job)
            payload = report.model_dump(mode="json")
            report_hash = canonical_hash(payload)
            stored = SyntheticReport(
                report_type=job.report_type,
                status=report.status.value,
                payload=payload,
                report_hash=report_hash,
                source_hashes=report.source_hashes,
                policy_version=report.policy_version,
                limitations=OBSERVABILITY_LIMITATIONS,
                false_capability_flags=FALSE_CAPABILITY_FLAGS,
                expires_at=datetime.now(UTC).replace(microsecond=0),
            )
            stored.expires_at = datetime.now(UTC).replace(microsecond=0)
            from datetime import timedelta

            stored.expires_at += timedelta(days=settings.report_retention_days)
            db.add(stored)
            await db.flush()
            job.report_id = stored.id
            job.status = report.status.value
            job.completed_at = datetime.now(UTC)
            await record_observability_event(
                db,
                correlation_id=str(job.id),
                component="reporting",
                operation="report.generate",
                status="succeeded" if report.status.value == "complete" else "not_evaluable",
                rows=report.sections[job.report_type].get("sample_count", 0)
                if isinstance(report.sections[job.report_type].get("sample_count", 0), int)
                else 0,
                evidence_hashes=report.source_hashes,
                expires_at=stored.expires_at,
            )
            record_audit(
                db,
                actor_user_id=job.requested_by,
                action="synthetic.report.generate.succeed",
                resource_type="synthetic_report",
                resource_id=str(stored.id),
                outcome="success",
                correlation_id=str(job.id),
                metadata={
                    "report_type": job.report_type,
                    "report_hash": report_hash,
                    "synthetic_demo_only": True,
                },
            )
            await db.commit()
        except ValueError:
            job.status = "failed"
            job.error_code = "report_contract_invalid"
            job.completed_at = datetime.now(UTC)
            await db.commit()


async def mark_report_failed(
    job_id: UUID, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as db:
        job = await db.get(SyntheticReportJob, job_id)
        if job is None or job.status in {"complete", "not_evaluable", "failed"}:
            return
        job.status = "failed"
        job.error_code = "report_worker_failed"
        job.completed_at = datetime.now(UTC)
        await db.commit()


async def process_recovery_run(
    run_id: UUID, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as db:
        run = await db.get(SyntheticRecoveryRun, run_id)
        if run is None or run.status not in {"pending", "processing"}:
            return
        run.status = "processing"
        await db.commit()
        try:
            counts = {
                "monitoring_runs": int(
                    await db.scalar(select(func.count()).select_from(SyntheticMonitoringRun)) or 0
                ),
                "monitoring_metrics": int(
                    await db.scalar(select(func.count()).select_from(SyntheticMonitoringMetric))
                    or 0
                ),
                "reports": int(
                    await db.scalar(select(func.count()).select_from(SyntheticReport)) or 0
                ),
            }
            run.status = "succeeded"
            run.outcome = {
                "status": "metadata_only",
                "referential_integrity": "not_checked_external",
                "counts": counts,
                "sha256_revalidated": False,
                "synthetic_demo_only": True,
            }
            run.completed_at = datetime.now(UTC)
            record_audit(
                db,
                actor_user_id=run.requested_by,
                action="synthetic.recovery.verify.succeed",
                resource_type="synthetic_recovery_run",
                resource_id=str(run.id),
                outcome="success",
                correlation_id=run.correlation_id,
                metadata={"synthetic_demo_only": True, "metadata_only": True},
            )
            await db.commit()
        except Exception:
            run.status = "failed"
            run.safe_error_code = "recovery_verification_failed"
            run.completed_at = datetime.now(UTC)
            await db.commit()


async def cleanup_observability(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> int:
    now = datetime.now(UTC)
    async with session_factory() as db:
        counts = 0
        expired_report_ids = select(SyntheticReport.id).where(SyntheticReport.expires_at <= now)
        result = await db.execute(
            delete(SyntheticReportJob).where(SyntheticReportJob.report_id.in_(expired_report_ids))
        )
        counts += int(getattr(result, "rowcount", 0) or 0)
        for model in (SyntheticObservabilityEvent, SyntheticSLISnapshot, SyntheticReport):
            result = await db.execute(delete(model).where(model.expires_at <= now))
            counts += int(getattr(result, "rowcount", 0) or 0)
        result = await db.execute(
            delete(SyntheticRecoveryRun).where(SyntheticRecoveryRun.expires_at <= now)
        )
        counts += int(getattr(result, "rowcount", 0) or 0)
        await db.commit()
        return counts
