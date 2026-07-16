from collections.abc import Callable


def dispatch_match_batch(batch_id: str) -> None:
    from aegis_worker.celery_app import run_intelligence_match_batch

    run_intelligence_match_batch.delay(batch_id)


def get_match_dispatcher() -> Callable[[str], None]:
    return dispatch_match_batch
