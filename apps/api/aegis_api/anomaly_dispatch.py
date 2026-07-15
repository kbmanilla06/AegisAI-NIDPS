from collections.abc import Callable


def dispatch_anomaly_fit(detector_id: str) -> None:
    from aegis_worker.celery_app import fit_anomaly_detector

    fit_anomaly_detector.delay(detector_id)


def dispatch_assessment_batch(batch_id: str) -> None:
    from aegis_worker.celery_app import evaluate_ensemble_batch

    evaluate_ensemble_batch.delay(batch_id)


def get_anomaly_fit_dispatcher() -> Callable[[str], None]:
    return dispatch_anomaly_fit


def get_assessment_dispatcher() -> Callable[[str], None]:
    return dispatch_assessment_batch
