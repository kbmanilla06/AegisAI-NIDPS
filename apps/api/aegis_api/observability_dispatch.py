from collections.abc import Callable


def dispatch_report_job(job_id: str) -> None:
    from aegis_worker.celery_app import generate_synthetic_report

    generate_synthetic_report.delay(job_id)


def dispatch_recovery_run(run_id: str) -> None:
    from aegis_worker.celery_app import verify_synthetic_recovery

    verify_synthetic_recovery.delay(run_id)


def get_report_dispatcher() -> Callable[[str], None]:
    return dispatch_report_job


def get_recovery_dispatcher() -> Callable[[str], None]:
    return dispatch_recovery_run
