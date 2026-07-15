from collections.abc import Callable


def dispatch_scoring_job(job_id: str) -> None:
    from aegis_worker.celery_app import score_synthetic_batch

    score_synthetic_batch.delay(job_id)


def get_scoring_dispatcher() -> Callable[[str], None]:
    return dispatch_scoring_job
