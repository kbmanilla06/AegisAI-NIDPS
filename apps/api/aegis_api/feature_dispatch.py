from collections.abc import Callable


def dispatch_feature_job(job_id: str) -> None:
    from aegis_worker.celery_app import materialize_features

    materialize_features.delay(job_id)


def get_feature_dispatcher() -> Callable[[str], None]:
    return dispatch_feature_job
