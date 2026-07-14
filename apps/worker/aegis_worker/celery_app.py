import asyncio
import json
import logging
from uuid import UUID, uuid4

from celery import Celery
from celery.app.task import Task
from redis.asyncio import Redis

from aegis_api.config import get_settings
from aegis_api.database import SessionFactory, engine
from aegis_api.detection_processor import (
    cleanup_detection_data,
    mark_detection_failed,
    pending_detection_runs,
    process_detection_run,
)
from aegis_api.feature_processor import (
    cleanup_feature_artifacts,
    mark_feature_failed,
    pending_feature_jobs,
    process_feature_job,
)
from aegis_api.ingestion_processor import (
    cleanup_expired_flows,
    cleanup_expired_uploads,
    mark_worker_task_failed,
    process_ingestion_job,
)

settings = get_settings()
logger = logging.getLogger(__name__)

celery_app = Celery("aegis_worker", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    accept_content=["json"],
    task_serializer="json",
    result_serializer="json",
    task_ignore_result=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_time_limit=settings.ingestion_max_processing_seconds + 15,
    task_soft_time_limit=settings.ingestion_max_processing_seconds,
    task_routes={
        "aegis.ingestion.*": {"queue": "ingestion"},
        "aegis.detection.*": {"queue": "detection"},
        "aegis.features.*": {"queue": "features"},
    },
    beat_schedule={
        "delete-expired-raw-uploads": {
            "task": "aegis.ingestion.cleanup",
            "schedule": 3600.0,
        },
        "delete-expired-flows": {
            "task": "aegis.ingestion.cleanup-flows",
            "schedule": 86400.0,
        },
        "reconcile-pending-detection-runs": {
            "task": "aegis.detection.reconcile",
            "schedule": 60.0,
        },
        "delete-expired-detection-data": {
            "task": "aegis.detection.cleanup",
            "schedule": 86400.0,
        },
        "reconcile-pending-feature-jobs": {
            "task": "aegis.features.reconcile",
            "schedule": 60.0,
        },
        "delete-expired-feature-artifacts": {
            "task": "aegis.features.cleanup",
            "schedule": 86400.0,
        },
    },
)


@celery_app.task(name="aegis.health.ping")  # type: ignore[untyped-decorator]
def ping() -> str:
    """Bounded foundation task used only for worker-health verification."""
    return "ok"


async def _run_process(job_id: UUID) -> UUID | None:
    try:
        return await process_ingestion_job(job_id, settings, SessionFactory)
    finally:
        await engine.dispose()


async def _mark_failed(job_id: UUID) -> None:
    try:
        await mark_worker_task_failed(job_id, SessionFactory)
    finally:
        await engine.dispose()


@celery_app.task(
    bind=True,
    name="aegis.ingestion.process",
    max_retries=2,
)  # type: ignore[untyped-decorator]
def process_ingestion(task: Task, job_id: str) -> None:
    """Process one bounded job; the queue contains only its UUID."""
    parsed_id = UUID(job_id)
    try:
        detection_run_id = asyncio.run(_run_process(parsed_id))
        if detection_run_id is not None:
            evaluate_detection.delay(str(detection_run_id))
    except Exception as error:
        retries = int(task.request.retries)
        if retries < int(task.max_retries or 0):
            raise task.retry(exc=error, countdown=min(2 ** (retries + 1), 10)) from error
        try:
            asyncio.run(_mark_failed(parsed_id))
        except Exception:
            logger.exception(
                "Unable to persist sanitized terminal failure for ingestion job %s",
                parsed_id,
            )
        raise


@celery_app.task(name="aegis.ingestion.cleanup")  # type: ignore[untyped-decorator]
def cleanup_ingestion_uploads() -> int:
    async def run() -> int:
        try:
            return await cleanup_expired_uploads(settings, SessionFactory)
        finally:
            await engine.dispose()

    return asyncio.run(run())


@celery_app.task(name="aegis.ingestion.cleanup-flows")  # type: ignore[untyped-decorator]
def cleanup_ingestion_flows() -> int:
    async def run() -> int:
        try:
            return await cleanup_expired_flows(settings, SessionFactory)
        finally:
            await engine.dispose()

    return asyncio.run(run())


async def _run_detection(run_id: UUID) -> list[UUID]:
    try:
        alert_ids = await process_detection_run(run_id, settings, SessionFactory)
        if alert_ids:
            redis = Redis.from_url(settings.redis_url, decode_responses=True)
            try:
                for alert_id in alert_ids:
                    await redis.publish(
                        "aegis.alerts",
                        json.dumps(
                            {
                                "event": "alert_changed",
                                "alert_id": str(alert_id),
                                "sequence": str(uuid4()),
                            },
                            separators=(",", ":"),
                        ),
                    )
            except Exception:
                logger.warning("Live alert notification unavailable for run %s", run_id)
            finally:
                await redis.aclose()
        return alert_ids
    finally:
        await engine.dispose()


async def _mark_detection_failed(run_id: UUID) -> None:
    try:
        await mark_detection_failed(run_id, "worker_task_failed", SessionFactory)
    finally:
        await engine.dispose()


@celery_app.task(
    bind=True,
    name="aegis.detection.evaluate",
    max_retries=2,
    soft_time_limit=settings.detection_soft_limit_seconds,
    time_limit=settings.detection_hard_limit_seconds,
)  # type: ignore[untyped-decorator]
def evaluate_detection(task: Task, run_id: str) -> None:
    """Evaluate a persisted bounded run; the queue contains only its UUID."""
    parsed_id = UUID(run_id)
    try:
        asyncio.run(_run_detection(parsed_id))
    except Exception as error:
        retries = int(task.request.retries)
        if retries < int(task.max_retries or 0):
            raise task.retry(exc=error, countdown=min(2 ** (retries + 1), 10)) from error
        try:
            asyncio.run(_mark_detection_failed(parsed_id))
        except Exception:
            logger.exception(
                "Unable to persist sanitized terminal failure for detection run %s", parsed_id
            )
        raise


@celery_app.task(name="aegis.detection.reconcile")  # type: ignore[untyped-decorator]
def reconcile_detection_runs() -> int:
    async def run() -> list[UUID]:
        try:
            return await pending_detection_runs(settings, SessionFactory)
        finally:
            await engine.dispose()

    run_ids = asyncio.run(run())
    for run_id in run_ids:
        evaluate_detection.delay(str(run_id))
    return len(run_ids)


@celery_app.task(name="aegis.detection.cleanup")  # type: ignore[untyped-decorator]
def cleanup_detection() -> dict[str, int]:
    async def run() -> dict[str, int]:
        try:
            return await cleanup_detection_data(settings, SessionFactory)
        finally:
            await engine.dispose()

    return asyncio.run(run())


async def _run_feature_job(job_id: UUID) -> None:
    try:
        await process_feature_job(job_id, settings, SessionFactory)
    finally:
        await engine.dispose()


async def _mark_feature_job_failed(job_id: UUID, error_code: str) -> None:
    try:
        await mark_feature_failed(job_id, error_code, SessionFactory)
    finally:
        await engine.dispose()


@celery_app.task(
    bind=True,
    name="aegis.features.materialize",
    max_retries=2,
    soft_time_limit=settings.feature_soft_limit_seconds,
    time_limit=settings.feature_hard_limit_seconds,
)  # type: ignore[untyped-decorator]
def materialize_features(task: Task, job_id: str) -> None:
    """Materialize one persisted bounded job; the queue contains only its UUID."""
    parsed_id = UUID(job_id)
    try:
        asyncio.run(_run_feature_job(parsed_id))
    except Exception as error:
        retries = int(task.request.retries)
        if retries < int(task.max_retries or 0):
            raise task.retry(exc=error, countdown=min(2 ** (retries + 1), 10)) from error
        code = str(error) if str(error).startswith("feature_") else "feature_processing_failed"
        try:
            asyncio.run(_mark_feature_job_failed(parsed_id, code))
        except Exception:
            logger.exception(
                "Unable to persist sanitized terminal failure for feature job %s", parsed_id
            )
        raise


@celery_app.task(name="aegis.features.reconcile")  # type: ignore[untyped-decorator]
def reconcile_feature_jobs() -> int:
    async def run() -> list[UUID]:
        try:
            return await pending_feature_jobs(settings, SessionFactory)
        finally:
            await engine.dispose()

    job_ids = asyncio.run(run())
    for job_id in job_ids:
        materialize_features.delay(str(job_id))
    return len(job_ids)


@celery_app.task(name="aegis.features.cleanup")  # type: ignore[untyped-decorator]
def cleanup_features() -> int:
    async def run() -> int:
        try:
            return await cleanup_feature_artifacts(settings, SessionFactory)
        finally:
            await engine.dispose()

    return asyncio.run(run())
