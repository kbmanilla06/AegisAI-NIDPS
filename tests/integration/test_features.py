from datetime import UTC, datetime, timedelta
from uuid import UUID

import pyarrow.parquet as pq
from sqlalchemy import select

from aegis_api.config import Settings
from aegis_api.feature_processor import pending_feature_jobs, process_feature_job
from aegis_api.models import (
    AuditEvent,
    FeatureMaterializationJob,
    FeatureSchemaVersion,
    Flow,
    IngestionJob,
)
from conftest import ORIGIN, AppHarness


def _prepare_source(app_harness: AppHarness, actor_id: UUID) -> UUID:
    async def create(db):  # type: ignore[no-untyped-def]
        job = IngestionJob(
            source_type="normalized",
            status="succeeded",
            sha256="a" * 64,
            size_bytes=128,
            media_type="application/jsonl",
            submitted_by=actor_id,
            correlation_id="feature-source",
            accepted_records=2,
        )
        db.add(job)
        await db.flush()
        db.add_all(
            [
                Flow(
                    event_key="1" * 64,
                    source_type="normalized",
                    source_event_id="flow-1",
                    job_id=job.id,
                    event_time=datetime(2026, 7, 14, tzinfo=UTC),
                    src_address="192.0.2.10",
                    dst_address="198.51.100.20",
                    src_port=49152,
                    dst_port=443,
                    protocol="tcp",
                    duration_ms=1000,
                    packet_count=10,
                    byte_count=1000,
                    state="SF",
                    flow_metadata={},
                ),
                Flow(
                    event_key="2" * 64,
                    source_type="normalized",
                    source_event_id="flow-2",
                    job_id=job.id,
                    event_time=datetime(2026, 7, 14, 0, 0, 30, tzinfo=UTC),
                    src_address="192.0.2.10",
                    dst_address="198.51.100.21",
                    src_port=49153,
                    dst_port=22,
                    protocol="tcp",
                    duration_ms=0,
                    packet_count=0,
                    byte_count=0,
                    state="REJ",
                    flow_metadata={},
                ),
            ]
        )
        await db.commit()
        return job.id

    return app_harness.run(create)


def test_feature_schema_job_parquet_and_idempotency(app_harness: AppHarness) -> None:
    auth, csrf = app_harness.login("Security Administrator")
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf, "Idempotency-Key": "feature-test-001"}
    schemas = app_harness.client.get("/api/v1/feature-schemas")
    assert schemas.status_code == 200
    schema = schemas.json()[0]
    assert schema["lifecycle_state"] == "approved"
    actor_id = UUID(str(auth["user"]["id"]))  # type: ignore[index]
    source_id = _prepare_source(app_harness, actor_id)
    payload = {
        "feature_schema_id": schema["id"],
        "ingestion_job_id": str(source_id),
        "requested_limit": 100,
    }
    created = app_harness.client.post("/api/v1/feature-jobs", headers=headers, json=payload)
    assert created.status_code == 202, created.text
    repeated = app_harness.client.post("/api/v1/feature-jobs", headers=headers, json=payload)
    assert repeated.status_code == 202
    assert repeated.json()["id"] == created.json()["id"]
    assert app_harness.dispatched_feature_jobs == [created.json()["id"]]

    settings = Settings(environment="test", artifact_root=app_harness.artifact_root)
    app_harness.run(
        lambda _db: process_feature_job(
            UUID(created.json()["id"]), settings, app_harness.session_factory
        )
    )
    completed = app_harness.client.get(f"/api/v1/feature-jobs/{created.json()['id']}")
    assert completed.status_code == 200
    body = completed.json()
    assert body["status"] == "succeeded"
    assert body["input_count"] == 2
    assert body["output_count"] == 2
    assert body["artifact"]["row_count"] == 2
    assert "object_ref" not in body["artifact"]

    async def artifact_ref(db):  # type: ignore[no-untyped-def]
        job = await db.scalar(
            select(FeatureMaterializationJob).where(
                FeatureMaterializationJob.id == UUID(created.json()["id"])
            )
        )
        assert job is not None
        from aegis_api.models import FeatureArtifact

        artifact = await db.scalar(
            select(FeatureArtifact).where(FeatureArtifact.materialization_job_id == job.id)
        )
        assert artifact is not None
        return artifact.object_ref

    object_ref = app_harness.run(artifact_ref)
    table = pq.read_table(app_harness.artifact_root / "features" / f"{object_ref}.parquet")
    assert table.num_rows == 2
    assert "src_address" not in table.column_names
    assert "dst_address" not in table.column_names
    assert "__aegis_source_event_key" in table.column_names
    assert "__aegis_vector_hash" in table.column_names


def test_feature_and_dataset_rbac_and_csrf(app_harness: AppHarness) -> None:
    for role, feature_status, dataset_status in (
        ("Viewer", 403, 403),
        ("SOC Analyst", 200, 403),
        ("Senior Analyst", 200, 200),
        ("Security Administrator", 200, 200),
        ("System Administrator", 200, 200),
        ("Auditor", 200, 200),
    ):
        app_harness.login(role)
        assert app_harness.client.get("/api/v1/feature-schemas").status_code == feature_status
        assert app_harness.client.get("/api/v1/feature-jobs").status_code == feature_status
        assert app_harness.client.get("/api/v1/datasets").status_code == dataset_status

    _, csrf = app_harness.login("Security Administrator")
    schema_id = app_harness.client.get("/api/v1/feature-schemas").json()[0]["id"]
    missing_origin = app_harness.client.post(
        f"/api/v1/feature-schemas/{schema_id}/review",
        headers={"X-CSRF-Token": csrf},
        json={
            "approved": True,
            "reason": "Synthetic review evidence.",
            "regression_evidence": "tests",
        },
    )
    assert missing_origin.status_code == 403


def test_feature_schema_requires_audited_security_administrator_review(
    app_harness: AppHarness,
) -> None:
    async def reset_to_draft(db):  # type: ignore[no-untyped-def]
        schema = await db.scalar(select(FeatureSchemaVersion))
        assert schema is not None
        schema.lifecycle_state = "draft"
        schema.reviewed_by = None
        schema.reviewed_at = None
        schema.review_reason = None
        await db.commit()
        return schema.id

    schema_id = app_harness.run(reset_to_draft)
    auth, csrf = app_harness.login("Security Administrator")
    response = app_harness.client.post(
        f"/api/v1/feature-schemas/{schema_id}/review",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "approved": True,
            "reason": "Feature v1 synthetic regression evidence passed.",
            "regression_evidence": "tests/unit/test_feature_pipeline.py",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["lifecycle_state"] == "approved"
    assert response.json()["reviewed_by"] == auth["user"]["id"]  # type: ignore[index]

    async def evidence(db):  # type: ignore[no-untyped-def]
        return await db.scalar(
            select(AuditEvent).where(AuditEvent.action == "feature.schema.review")
        )

    audit = app_harness.run(evidence)
    assert audit is not None
    assert audit.actor_user_id == UUID(str(auth["user"]["id"]))  # type: ignore[index]
    assert audit.outcome == "success"
    assert audit.safe_metadata["decision"] == "approved"


def test_dataset_api_never_authorizes_acquisition(app_harness: AppHarness) -> None:
    _, csrf = app_harness.login("Security Administrator")
    response = app_harness.client.post(
        "/api/v1/datasets",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "dataset_name": "UNSW-NB15",
            "dataset_version": "investigation-only",
            "official_source_url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "publisher": "UNSW Canberra at ADFA",
            "reviewed_at": "2026-07-14T00:00:00Z",
            "terms_reference_hash": "a" * 64,
            "acquisition_authorized": True,
        },
    )
    assert response.status_code == 403

    async def audit_actions(db):  # type: ignore[no-untyped-def]
        return list((await db.scalars(select(AuditEvent.action))).all())

    actions = app_harness.run(audit_actions)
    assert "dataset.proposal.create" not in actions


def test_stale_processing_feature_job_is_reconciled_and_reclaimed(
    app_harness: AppHarness,
) -> None:
    auth, _ = app_harness.login("Security Administrator")
    actor_id = UUID(str(auth["user"]["id"]))  # type: ignore[index]
    source_id = _prepare_source(app_harness, actor_id)

    async def create_stale_job(db):  # type: ignore[no-untyped-def]
        schema = await db.scalar(select(FeatureSchemaVersion))
        assert schema is not None
        job = FeatureMaterializationJob(
            requested_by=actor_id,
            feature_schema_id=schema.id,
            ingestion_job_id=source_id,
            idempotency_key="stale-feature-job",
            requested_limit=100,
            status="processing",
            started_at=datetime.now(UTC) - timedelta(minutes=10),
        )
        db.add(job)
        await db.commit()
        return job.id

    job_id = app_harness.run(create_stale_job)
    settings = Settings(
        environment="test",
        artifact_root=app_harness.artifact_root,
        feature_hard_limit_seconds=15,
        feature_pending_delay_seconds=10,
    )
    reconciled = app_harness.run(
        lambda _db: pending_feature_jobs(settings, app_harness.session_factory)
    )
    assert job_id in reconciled
    app_harness.run(lambda _db: process_feature_job(job_id, settings, app_harness.session_factory))

    async def status(db):  # type: ignore[no-untyped-def]
        job = await db.get(FeatureMaterializationJob, job_id)
        assert job is not None
        return job.status

    assert app_harness.run(status) == "succeeded"
