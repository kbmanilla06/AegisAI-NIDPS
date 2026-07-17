from aegis_worker.celery_app import (
    celery_app,
    evaluate_detection,
    evaluate_monitoring,
    generate_synthetic_dataset,
    materialize_features,
    ping,
    process_ingestion,
)


def test_worker_accepts_json_only() -> None:
    assert celery_app.conf.accept_content == ["json"]
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.result_serializer == "json"


def test_health_task_is_bounded() -> None:
    assert ping.run() == "ok"


def test_ingestion_task_envelope_rejects_non_uuid() -> None:
    try:
        process_ingestion.run("not-a-uuid")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed task identifier must be rejected")


def test_detection_task_envelope_rejects_non_uuid() -> None:
    try:
        evaluate_detection.run("not-a-uuid")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed task identifier must be rejected")


def test_feature_task_envelope_rejects_non_uuid() -> None:
    try:
        materialize_features.run("not-a-uuid")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed task identifier must be rejected")


def test_synthetic_task_envelope_rejects_non_uuid() -> None:
    try:
        generate_synthetic_dataset.run("not-a-uuid")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed task identifier must be rejected")


def test_monitoring_task_envelope_rejects_non_uuid() -> None:
    try:
        evaluate_monitoring.run("not-a-uuid")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed monitoring task identifier must be rejected")
