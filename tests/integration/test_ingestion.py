from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import select

from aegis_api.config import Settings
from aegis_api.ingestion_processor import (
    cleanup_expired_flows,
    cleanup_expired_uploads,
    process_ingestion_job,
)
from aegis_api.models import AuditEvent, Flow, IngestionJob, User
from conftest import ORIGIN, AppHarness

FIXTURE = Path(__file__).parents[1] / "fixtures" / "telemetry" / "normalized_valid.jsonl"


def _headers(csrf: str) -> dict[str, str]:
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf}


def test_admin_upload_uses_opaque_storage_and_dispatches_only_job_id(
    app_harness: AppHarness,
) -> None:
    _, csrf = app_harness.login("Security Administrator")
    response = app_harness.client.post(
        "/api/v1/ingestion/jobs",
        headers=_headers(csrf),
        data={"source_type": "normalized"},
        files={"file": ("../../attacker-name.sh", FIXTURE.read_bytes(), "application/x-sh")},
    )
    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload["media_type"].startswith("application/x-ndjson")
    assert app_harness.dispatched_jobs == [payload["id"]]

    async def stored(db):  # type: ignore[no-untyped-def]
        return await db.get(IngestionJob, UUID(payload["id"]))

    job = app_harness.run(stored)
    assert job.object_ref is not None
    assert "attacker" not in job.object_ref
    assert (app_harness.artifact_root / job.object_ref).is_file()


def test_content_mismatch_is_rejected_deleted_and_audited(app_harness: AppHarness) -> None:
    _, csrf = app_harness.login("Security Administrator")
    response = app_harness.client.post(
        "/api/v1/ingestion/jobs",
        headers=_headers(csrf),
        data={"source_type": "pcap"},
        files={"file": ("looks-safe.pcap", b"#!/bin/sh\necho no", "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 415
    assert response.json()["code"] == "content_type_mismatch"
    assert not list((app_harness.artifact_root / "uploads").glob("*.bin"))

    async def evidence(db):  # type: ignore[no-untyped-def]
        job = await db.scalar(select(IngestionJob).where(IngestionJob.status == "rejected"))
        audit = await db.scalar(select(AuditEvent).where(AuditEvent.action == "ingestion.submit"))
        return job, audit

    job, audit = app_harness.run(evidence)
    assert job is not None and job.object_ref is None
    assert audit is not None and "#!/bin" not in str(audit.safe_metadata)


def test_sensor_credential_is_scoped_to_sensor_source(app_harness: AppHarness) -> None:
    _, csrf = app_harness.login("Security Administrator")
    created = app_harness.client.post(
        "/api/v1/sensors",
        headers=_headers(csrf),
        json={"name": "flow-sensor", "sensor_type": "flow"},
    ).json()
    credential = created["credential"]
    accepted = app_harness.client.post(
        "/api/v1/ingestion/sensor/jobs",
        headers={
            "Authorization": f"Sensor {credential}",
            "X-Aegis-Source": "normalized",
            "Content-Type": "application/octet-stream",
        },
        content=FIXTURE.read_bytes(),
    )
    assert accepted.status_code == 202, accepted.text
    assert accepted.json()["sensor_id"] == created["sensor"]["id"]

    wrong_source = app_harness.client.post(
        "/api/v1/ingestion/sensor/jobs",
        headers={
            "Authorization": f"Sensor {credential}",
            "X-Aegis-Source": "suricata",
        },
        content=FIXTURE.read_bytes(),
    )
    assert wrong_source.status_code == 422
    assert wrong_source.json()["code"] == "sensor_source_mismatch"

    rejected = app_harness.client.post(
        "/api/v1/ingestion/sensor/jobs",
        headers={
            "Authorization": f"Sensor {created['sensor']['id']}.wrong",
            "X-Aegis-Source": "normalized",
        },
        content=FIXTURE.read_bytes(),
    )
    assert rejected.status_code == 401
    assert rejected.json()["code"] == "invalid_sensor_credential"


def test_request_body_limit_rejects_before_storage(app_harness: AppHarness) -> None:
    _, csrf = app_harness.login("Security Administrator")
    response = app_harness.client.post(
        "/api/v1/ingestion/jobs",
        headers={**_headers(csrf), "Content-Length": "999999"},
        content=b"ignored",
    )
    assert response.status_code == 413
    assert response.json()["code"] == "upload_too_large"


def test_worker_normalizes_deduplicates_replays_and_deletes_raw(
    app_harness: AppHarness,
) -> None:
    _, csrf = app_harness.login("Security Administrator")
    first = app_harness.client.post(
        "/api/v1/ingestion/jobs",
        headers=_headers(csrf),
        data={"source_type": "normalized"},
        files={"file": ("flow.jsonl", FIXTURE.read_bytes(), "application/json")},
    ).json()
    settings = Settings(
        environment="test",
        artifact_root=app_harness.artifact_root,
        database_url="sqlite+aiosqlite:///unused",
        ingestion_max_records=100,
        ingestion_max_unique_flows=50,
        ingestion_max_processing_seconds=10,
    )
    app_harness.run(
        lambda _db: process_ingestion_job(UUID(first["id"]), settings, app_harness.session_factory)
    )

    async def completed(db):  # type: ignore[no-untyped-def]
        job = await db.get(IngestionJob, UUID(first["id"]))
        flows = list((await db.scalars(select(Flow))).all())
        return job, flows

    job, flows = app_harness.run(completed)
    assert job.status == "succeeded"
    assert job.accepted_records == 1
    assert job.object_ref is None and job.raw_deleted_at is not None
    assert len(flows) == 1

    replay = app_harness.client.post(
        f"/api/v1/ingestion/jobs/{first['id']}/replay",
        headers={**_headers(csrf), "Idempotency-Key": "replay-synthetic-001"},
    )
    assert replay.status_code == 202
    replay_id = UUID(replay.json()["id"])
    app_harness.run(
        lambda _db: process_ingestion_job(replay_id, settings, app_harness.session_factory)
    )

    async def replayed(db):  # type: ignore[no-untyped-def]
        replay_job = await db.get(IngestionJob, replay_id)
        flow_count = len(list((await db.scalars(select(Flow))).all()))
        return replay_job, flow_count

    replay_job, flow_count = app_harness.run(replayed)
    assert replay_job.status == "succeeded"
    assert replay_job.duplicate_records == 1
    assert flow_count == 1


def test_expired_failed_raw_upload_is_removed(app_harness: AppHarness) -> None:
    async def prepare(db):  # type: ignore[no-untyped-def]
        user_id = await db.scalar(select(User.id).limit(1))
        upload_root = app_harness.artifact_root / "uploads"
        upload_root.mkdir(parents=True, exist_ok=True)
        object_ref = "uploads/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bin"
        (app_harness.artifact_root / object_ref).write_bytes(b"failed")
        job = IngestionJob(
            source_type="normalized",
            status="failed",
            object_ref=object_ref,
            sha256="0" * 64,
            size_bytes=6,
            media_type="application/x-ndjson",
            schema_version="1",
            submitted_by=user_id,
            correlation_id="cleanup-test",
            error_code="invalid_record",
            raw_expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        db.add(job)
        await db.commit()
        return job.id, object_ref

    job_id, object_ref = app_harness.run(prepare)
    settings = Settings(environment="test", artifact_root=app_harness.artifact_root)
    removed = app_harness.run(
        lambda _db: cleanup_expired_uploads(settings, app_harness.session_factory)
    )
    assert removed == 1
    assert not (app_harness.artifact_root / object_ref).exists()

    async def stored(db):  # type: ignore[no-untyped-def]
        return await db.get(IngestionJob, job_id)

    assert app_harness.run(stored).object_ref is None


def test_flow_retention_removes_canonical_flow_and_idempotency_record(
    app_harness: AppHarness,
) -> None:
    _, csrf = app_harness.login("Security Administrator")
    submitted = app_harness.client.post(
        "/api/v1/ingestion/jobs",
        headers=_headers(csrf),
        data={"source_type": "normalized"},
        files={"file": ("flow.jsonl", FIXTURE.read_bytes(), "application/json")},
    ).json()
    settings = Settings(
        environment="test",
        artifact_root=app_harness.artifact_root,
        flow_retention_days=30,
        ingestion_max_records=100,
        ingestion_max_unique_flows=50,
        ingestion_max_processing_seconds=10,
    )
    app_harness.run(
        lambda _db: process_ingestion_job(
            UUID(submitted["id"]), settings, app_harness.session_factory
        )
    )

    async def age_flow(db):  # type: ignore[no-untyped-def]
        flow = await db.scalar(select(Flow))
        flow.created_at = datetime.now(UTC) - timedelta(days=31)
        await db.commit()

    app_harness.run(age_flow)
    removed = app_harness.run(
        lambda _db: cleanup_expired_flows(settings, app_harness.session_factory)
    )
    assert removed == 1

    async def evidence(db):  # type: ignore[no-untyped-def]
        flows = list((await db.scalars(select(Flow))).all())
        audit = await db.scalar(
            select(AuditEvent).where(AuditEvent.action == "retention.flow_delete")
        )
        return flows, audit

    flows, audit = app_harness.run(evidence)
    assert flows == []
    assert audit is not None and audit.safe_metadata["retention_days"] == 30


def test_future_event_time_cannot_bypass_ingestion_age_retention(
    app_harness: AppHarness,
) -> None:
    _, csrf = app_harness.login("Security Administrator")
    submitted = app_harness.client.post(
        "/api/v1/ingestion/jobs",
        headers=_headers(csrf),
        data={"source_type": "normalized"},
        files={"file": ("flow.jsonl", FIXTURE.read_bytes(), "application/json")},
    ).json()
    settings = Settings(
        environment="test",
        artifact_root=app_harness.artifact_root,
        flow_retention_days=30,
        ingestion_max_records=100,
        ingestion_max_unique_flows=50,
        ingestion_max_processing_seconds=10,
    )
    app_harness.run(
        lambda _db: process_ingestion_job(
            UUID(submitted["id"]), settings, app_harness.session_factory
        )
    )

    async def age_ingestion_but_future_date(db):  # type: ignore[no-untyped-def]
        flow = await db.scalar(select(Flow))
        flow.created_at = datetime.now(UTC) - timedelta(days=31)
        flow.event_time = datetime.now(UTC) + timedelta(days=3650)
        await db.commit()

    app_harness.run(age_ingestion_but_future_date)
    removed = app_harness.run(
        lambda _db: cleanup_expired_flows(settings, app_harness.session_factory)
    )
    assert removed == 1
