from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from aegis_api.config import Settings
from aegis_api.models import (
    AuditEvent,
    FeatureSchemaVersion,
    SyntheticDatasetVersion,
    SyntheticGenerationJob,
    User,
)
from aegis_api.synthetic_processor import (
    cleanup_synthetic_artifacts,
    pending_synthetic_jobs,
    process_synthetic_generation_job,
)
from aegis_services.synthetic import (
    SYNTHETIC_LIMITATIONS,
    select_model_matrix,
    synthetic_artifact_path,
)
from conftest import ORIGIN, AppHarness


def _schema_id(app_harness: AppHarness) -> str:
    app_harness.login("System Administrator")
    response = app_harness.client.get("/api/v1/feature-schemas")
    assert response.status_code == 200
    return str(response.json()[0]["id"])


def _create_job(app_harness: AppHarness, key: str = "synthetic-gate-001") -> dict[str, object]:
    schema_id = _schema_id(app_harness)
    _, csrf = app_harness.login("System Administrator")
    response = app_harness.client.post(
        "/api/v1/synthetic/generation-jobs",
        headers={
            "Origin": ORIGIN,
            "X-CSRF-Token": csrf,
            "Idempotency-Key": key,
        },
        json={"feature_schema_id": schema_id},
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_gate_5sa_generation_manifest_artifacts_and_distinct_review(
    app_harness: AppHarness,
) -> None:
    created = _create_job(app_harness)
    repeated = _create_job(app_harness)
    assert repeated["id"] == created["id"]
    assert app_harness.dispatched_synthetic_jobs == [created["id"]]

    settings = Settings(environment="test", artifact_root=app_harness.artifact_root)
    app_harness.run(
        lambda _db: process_synthetic_generation_job(
            UUID(str(created["id"])), settings, app_harness.session_factory
        )
    )
    completed = app_harness.client.get("/api/v1/synthetic/generation-jobs").json()[0]
    assert completed["status"] == "succeeded"
    assert completed["generated_flow_count"] == 7_200
    assert completed["generated_group_count"] == 120
    assert completed["limitations"] == SYNTHETIC_LIMITATIONS
    for capability in (
        "real_dataset_used",
        "unsw_nb15_acquired",
        "unsw_nb15_evaluated",
        "network_traffic_generated",
        "online_inference_allowed",
        "alert_side_effects_allowed",
        "prevention_allowed",
    ):
        assert completed[capability] is False

    datasets = app_harness.client.get("/api/v1/synthetic/datasets")
    assert datasets.status_code == 200
    dataset = datasets.json()[0]
    assert dataset["lifecycle_state"] == "generated"
    assert dataset["flow_count"] == 7_200
    assert dataset["group_count"] == 120
    assert dataset["feature_column_count"] == 46
    assert dataset["synthetic_demo_only"] is True
    assert dataset["limitations"] == SYNTHETIC_LIMITATIONS
    assert dataset["real_dataset_used"] is False
    assert dataset["unsw_nb15_acquired"] is False
    assert dataset["unsw_nb15_evaluated"] is False
    assert dataset["network_traffic_generated"] is False
    assert dataset["online_inference_allowed"] is False
    assert dataset["alert_side_effects_allowed"] is False
    assert dataset["prevention_allowed"] is False
    assert "object_ref" not in dataset
    assert "flow_object_ref" not in dataset

    _, csrf = app_harness.login("Security Administrator")
    accepted = app_harness.client.post(
        f"/api/v1/synthetic/datasets/{dataset['id']}/review",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "accepted": True,
            "reason": "Gate 5S-A deterministic, leakage, and integrity evidence passed.",
            "evidence_reference": "GATE-5SA-TESTS-001",
        },
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["lifecycle_state"] == "accepted_synthetic"

    async def evidence(db):  # type: ignore[no-untyped-def]
        record = await db.get(SyntheticDatasetVersion, UUID(str(dataset["id"])))
        audits = list(
            (
                await db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.action.in_(
                            (
                                "synthetic.dataset.generate.request",
                                "synthetic.dataset.generate.succeed",
                                "synthetic.dataset.review",
                            )
                        )
                    )
                )
            ).all()
        )
        assert record is not None
        return record, audits

    record, audits = app_harness.run(evidence)
    assert record.created_by != record.reviewed_by
    assert len(audits) == 3
    assert all(event.safe_metadata.get("synthetic_demo_only") is True for event in audits)
    feature_path = synthetic_artifact_path(
        app_harness.artifact_root / "synthetic", record.feature_object_ref, "parquet"
    )
    names = tuple(record.manifest["feature_names"])
    matrix = select_model_matrix(feature_path, names)
    assert matrix.num_rows == 7_200 and matrix.num_columns == 39


def test_synthetic_rbac_csrf_origin_and_no_general_dataset_authority(
    app_harness: AppHarness,
) -> None:
    expected_read = {
        "Viewer": 403,
        "SOC Analyst": 403,
        "Senior Analyst": 200,
        "Security Administrator": 200,
        "System Administrator": 200,
        "Auditor": 200,
    }
    schema_id = _schema_id(app_harness)
    for role, status in expected_read.items():
        _, csrf = app_harness.login(role)
        assert app_harness.client.get("/api/v1/synthetic/scenarios").status_code == status
        create = app_harness.client.post(
            "/api/v1/synthetic/generation-jobs",
            headers={
                "Origin": ORIGIN,
                "X-CSRF-Token": csrf,
                "Idempotency-Key": f"synthetic-{role.replace(' ', '-').lower()}",
            },
            json={"feature_schema_id": schema_id},
        )
        assert create.status_code == (202 if role == "System Administrator" else 403)

    _, csrf = app_harness.login("System Administrator")
    assert (
        app_harness.client.post(
            "/api/v1/synthetic/generation-jobs",
            headers={"X-CSRF-Token": csrf, "Idempotency-Key": "missing-origin"},
            json={"feature_schema_id": schema_id},
        ).status_code
        == 403
    )
    assert (
        app_harness.client.post(
            "/api/v1/synthetic/generation-jobs",
            headers={
                "Origin": "https://evil.invalid",
                "X-CSRF-Token": csrf,
                "Idempotency-Key": "evil-origin",
            },
            json={"feature_schema_id": schema_id},
        ).status_code
        == 403
    )


def test_synthetic_stale_reconciliation_and_retention_cleanup(app_harness: AppHarness) -> None:
    auth, _ = app_harness.login("System Administrator")
    actor_id = UUID(str(auth["user"]["id"]))  # type: ignore[index]

    async def create_stale(db):  # type: ignore[no-untyped-def]
        schema = await db.scalar(select(FeatureSchemaVersion))
        assert schema is not None
        job = SyntheticGenerationJob(
            requested_by=actor_id,
            feature_schema_id=schema.id,
            idempotency_key="synthetic-stale-job",
            scenario_catalog_hash="a" * 64,
            global_seed=20260714,
            requested_flow_count=7200,
            status="processing",
            started_at=datetime.now(UTC) - timedelta(minutes=10),
        )
        db.add(job)
        await db.commit()
        return job.id

    stale_id = app_harness.run(create_stale)
    settings = Settings(
        environment="test",
        artifact_root=app_harness.artifact_root,
        synthetic_hard_limit_seconds=15,
        synthetic_pending_delay_seconds=10,
    )
    pending = app_harness.run(
        lambda _db: pending_synthetic_jobs(settings, app_harness.session_factory)
    )
    assert stale_id in pending

    created = _create_job(app_harness, "synthetic-cleanup-job")
    app_harness.run(
        lambda _db: process_synthetic_generation_job(
            UUID(str(created["id"])), settings, app_harness.session_factory
        )
    )

    async def expire(db):  # type: ignore[no-untyped-def]
        record = await db.scalar(
            select(SyntheticDatasetVersion).where(
                SyntheticDatasetVersion.generation_job_id == UUID(str(created["id"]))
            )
        )
        assert record is not None
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await db.commit()
        return record.id

    dataset_id = app_harness.run(expire)
    assert (
        app_harness.run(
            lambda _db: cleanup_synthetic_artifacts(settings, app_harness.session_factory)
        )
        == 1
    )

    async def verify(db):  # type: ignore[no-untyped-def]
        return await db.get(SyntheticDatasetVersion, dataset_id)

    cleaned = app_harness.run(verify)
    assert cleaned is not None
    assert cleaned.lifecycle_state == "retired"
    assert cleaned.artifacts_deleted_at is not None


def test_creator_self_review_fails_closed(app_harness: AppHarness) -> None:
    created = _create_job(app_harness, "synthetic-self-review-job")
    settings = Settings(environment="test", artifact_root=app_harness.artifact_root)
    app_harness.run(
        lambda _db: process_synthetic_generation_job(
            UUID(str(created["id"])), settings, app_harness.session_factory
        )
    )

    async def make_creator_security_admin(db):  # type: ignore[no-untyped-def]
        record = await db.scalar(
            select(SyntheticDatasetVersion).where(
                SyntheticDatasetVersion.generation_job_id == UUID(str(created["id"]))
            )
        )
        reviewer = await db.scalar(
            select(User).where(User.email == "security.administrator@example.com")
        )
        assert record is not None and reviewer is not None
        record.created_by = reviewer.id
        await db.commit()
        return record.id

    dataset_id = app_harness.run(make_creator_security_admin)
    _, csrf = app_harness.login("Security Administrator")
    response = app_harness.client.post(
        f"/api/v1/synthetic/datasets/{dataset_id}/review",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "accepted": True,
            "reason": "This self review must be denied by the server.",
            "evidence_reference": "SELF-REVIEW-NEGATIVE",
        },
    )
    assert response.status_code == 403


def test_review_rehashes_controlled_artifacts_at_action_time(app_harness: AppHarness) -> None:
    created = _create_job(app_harness, "synthetic-tamper-review-job")
    settings = Settings(environment="test", artifact_root=app_harness.artifact_root)
    app_harness.run(
        lambda _db: process_synthetic_generation_job(
            UUID(str(created["id"])), settings, app_harness.session_factory
        )
    )

    async def target_ref(db):  # type: ignore[no-untyped-def]
        record = await db.scalar(
            select(SyntheticDatasetVersion).where(
                SyntheticDatasetVersion.generation_job_id == UUID(str(created["id"]))
            )
        )
        assert record is not None
        return record.id, record.target_object_ref

    dataset_id, object_ref = app_harness.run(target_ref)
    target_path = synthetic_artifact_path(
        app_harness.artifact_root / "synthetic", object_ref, "targets.json"
    )
    target_path.write_bytes(b"tampered")

    _, csrf = app_harness.login("Security Administrator")
    response = app_harness.client.post(
        f"/api/v1/synthetic/datasets/{dataset_id}/review",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "accepted": True,
            "reason": "A replaced controlled target artifact must block review.",
            "evidence_reference": "ARTIFACT-TAMPER-NEGATIVE",
        },
    )
    assert response.status_code == 409
    assert response.json()["code"] == "synthetic_artifact_integrity"
