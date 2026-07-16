from collections.abc import Callable


def dispatch_explanation_batch(batch_id: str) -> None:
    from aegis_worker.celery_app import generate_explanation_batch

    generate_explanation_batch.delay(batch_id)


def get_explanation_dispatcher() -> Callable[[str], None]:
    return dispatch_explanation_batch
