from aegis_worker.celery_app import celery_app, ping, process_ingestion


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
