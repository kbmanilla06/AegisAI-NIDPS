from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_api.audit import record_audit
from aegis_api.config import Settings
from aegis_api.models import (
    SyntheticAnalystFeedback,
    SyntheticMonitoringMetric,
    SyntheticMonitoringRun,
)
from aegis_services.monitoring import (
    MONITORING_LIMITATIONS,
    SyntheticMonitoringSnapshotV1,
    evaluate_drift,
)

RETENTION_DAYS = 30


async def process_monitoring_run(
    run_id: UUID, settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as db:
        run = await db.get(SyntheticMonitoringRun, run_id)
        if run is None or run.status not in {"pending", "processing"}:
            return
        run.status = "processing"
        run.started_at = datetime.now(UTC)
        await db.commit()
        try:
            baseline = SyntheticMonitoringSnapshotV1.model_validate(run.baseline_snapshot)
            current = SyntheticMonitoringSnapshotV1.model_validate(run.current_snapshot)
            result = evaluate_drift(baseline, current)
            run.status = (
                result.status.value if result.status.value == "not_evaluable" else "succeeded"
            )
            run.result = result.model_dump(mode="json")
            run.baseline_snapshot_hash = result.baseline_snapshot_hash
            run.current_snapshot_hash = result.current_snapshot_hash
            run.policy_hash = result.policy_hash
            run.sample_count = current.sample_count
            run.group_count = current.group_count
            run.warning_count = result.warning_count
            run.critical_count = result.critical_count
            run.limitations = MONITORING_LIMITATIONS
            run.completed_at = datetime.now(UTC)
            for metric in result.metrics:
                db.add(
                    SyntheticMonitoringMetric(
                        run_id=run.id,
                        metric_key=metric.metric_key,
                        baseline_value=metric.baseline_value,
                        current_value=metric.current_value,
                        delta=metric.delta,
                        sample_count=metric.sample_count,
                        status=metric.status.value,
                    )
                )
            record_audit(
                db,
                actor_user_id=run.requested_by,
                action="synthetic.monitoring.evaluate.succeed",
                resource_type="synthetic_monitoring_run",
                resource_id=str(run.id),
                outcome="success",
                correlation_id=str(run.id),
                metadata={
                    "status": run.status,
                    "warning_count": result.warning_count,
                    "critical_count": result.critical_count,
                    "synthetic_demo_only": True,
                    "false_capability_flags": result.false_capability_flags,
                },
            )
            await db.commit()
        except ValueError:
            run.status = "failed"
            run.error_code = "monitoring_contract_invalid"
            run.completed_at = datetime.now(UTC)
            run.limitations = MONITORING_LIMITATIONS
            record_audit(
                db,
                actor_user_id=run.requested_by,
                action="synthetic.monitoring.evaluate.reject",
                resource_type="synthetic_monitoring_run",
                resource_id=str(run.id),
                outcome="rejected",
                correlation_id=str(run.id),
                metadata={"error_code": run.error_code, "synthetic_demo_only": True},
            )
            await db.commit()


async def mark_monitoring_failed(
    run_id: UUID, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as db:
        run = await db.get(SyntheticMonitoringRun, run_id)
        if run is None or run.status in {"succeeded", "not_evaluable", "failed"}:
            return
        run.status = "failed"
        run.error_code = "monitoring_worker_failed"
        run.completed_at = datetime.now(UTC)
        await db.commit()


async def cleanup_monitoring(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> int:
    now = datetime.now(UTC)
    async with session_factory() as db:
        rows = list(
            (
                await db.scalars(
                    select(SyntheticMonitoringRun).where(
                        SyntheticMonitoringRun.expires_at <= now
                    )
                )
            ).all()
        )
        feedback_expired_count = int(
            await db.scalar(
                select(func.count())
                .select_from(SyntheticAnalystFeedback)
                .where(SyntheticAnalystFeedback.expires_at <= now)
            )
            or 0
        )
        await db.execute(
            delete(SyntheticAnalystFeedback).where(SyntheticAnalystFeedback.expires_at <= now)
        )
        if not rows:
            await db.commit()
            return feedback_expired_count
        run_ids = [row.id for row in rows]
        await db.execute(
            delete(SyntheticMonitoringMetric).where(SyntheticMonitoringMetric.run_id.in_(run_ids))
        )
        for row in rows:
            row.result = {"status": "expired", "synthetic_demo_only": True}
            row.baseline_snapshot = {"expired": True}
            row.current_snapshot = {"expired": True}
        await db.commit()
        return len(rows) + feedback_expired_count
