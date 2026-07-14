from collections.abc import Callable


def dispatch_ingestion_job(job_id: str) -> None:
    from aegis_worker.celery_app import process_ingestion

    process_ingestion.delay(job_id)


def get_ingestion_dispatcher() -> Callable[[str], None]:
    return dispatch_ingestion_job
