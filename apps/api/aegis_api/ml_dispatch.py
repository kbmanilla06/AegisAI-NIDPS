from collections.abc import Callable


def dispatch_training_run(run_id: str) -> None:
    from aegis_worker.celery_app import train_synthetic_candidates

    train_synthetic_candidates.delay(run_id)


def get_training_dispatcher() -> Callable[[str], None]:
    return dispatch_training_run
