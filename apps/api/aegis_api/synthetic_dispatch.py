from collections.abc import Callable


def dispatch_synthetic_job(job_id: str) -> None:
    from aegis_worker.celery_app import generate_synthetic_dataset

    generate_synthetic_dataset.delay(job_id)


def get_synthetic_dispatcher() -> Callable[[str], None]:
    return dispatch_synthetic_job
