import asyncio
import logging
from uuid import UUID

from celery import Celery
from celery.app.task import Task

from aegis_api.config import get_settings
from aegis_api.database import SessionFactory, engine
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
    task_routes={"aegis.ingestion.*": {"queue": "ingestion"}},
    beat_schedule={
        "delete-expired-raw-uploads": {
            "task": "aegis.ingestion.cleanup",
            "schedule": 3600.0,
        },
        "delete-expired-flows": {
            "task": "aegis.ingestion.cleanup-flows",
            "schedule": 86400.0,
        },
    },
)


@celery_app.task(name="aegis.health.ping")  # type: ignore[untyped-decorator]
def ping() -> str:
    """Bounded foundation task used only for worker-health verification."""
    return "ok"


async def _run_process(job_id: UUID) -> None:
    try:
        await process_ingestion_job(job_id, settings, SessionFactory)
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
        asyncio.run(_run_process(parsed_id))
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
