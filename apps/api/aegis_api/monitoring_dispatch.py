from collections.abc import Callable


def dispatch_monitoring_run(run_id: str) -> None:
    from aegis_worker.celery_app import evaluate_monitoring

    evaluate_monitoring.delay(run_id)


def get_monitoring_dispatcher() -> Callable[[str], None]:
    return dispatch_monitoring_run
