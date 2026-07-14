from celery import Celery

from aegis_api.config import get_settings

settings = get_settings()

celery_app = Celery("aegis_worker", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    accept_content=["json"],
    task_serializer="json",
    result_serializer="json",
    task_ignore_result=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
)


@celery_app.task(name="aegis.health.ping")  # type: ignore[untyped-decorator]
def ping() -> str:
    """Bounded foundation task used only for worker-health verification."""
    return "ok"
