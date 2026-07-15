from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_api.config import Settings
from aegis_api.models import (
    AuditEvent,
    FeatureSchemaVersion,
    SyntheticDatasetVersion,
    SyntheticModelCandidate,
    SyntheticRegistryModel,
    SyntheticTrainingRun,
)
from aegis_services.features import FeatureSchemaV1
from aegis_services.ml import GATE_5SA_HASHES, delete_candidate_artifacts, train_gate_5sb
from aegis_services.synthetic import build_synthetic_dataset, verify_synthetic_artifact


async def process_training_run(
    run_id: UUID, settings: Settings, factory: async_sessionmaker[AsyncSession]
) -> None:
    async with factory() as db:
        run = await db.scalar(
            select(SyntheticTrainingRun).where(SyntheticTrainingRun.id == run_id).with_for_update()
        )
        if run is None or run.status == "succeeded":
            return
        if run.status != "pending":
            return
        dataset = await db.get(SyntheticDatasetVersion, run.dataset_version_id)
        if (
            dataset is None
            or dataset.lifecycle_state != "accepted_synthetic"
            or dataset.artifacts_deleted_at is not None
        ):
            run.status, run.error_code, run.completed_at = (
                "failed",
                "ml_dataset_not_accepted",
                datetime.now(UTC),
            )
            await db.commit()
            return
        schema_record = await db.get(FeatureSchemaVersion, dataset.feature_schema_id)
        if schema_record is None or schema_record.lifecycle_state != "approved":
            run.status, run.error_code, run.completed_at = (
                "failed",
                "ml_feature_schema_unavailable",
                datetime.now(UTC),
            )
            await db.commit()
            return
        run.status, run.started_at = "processing", datetime.now(UTC)
        await db.commit()
    evidence = None
    try:
        schema = FeatureSchemaV1.model_validate(schema_record.ordered_definition)
        expected_metadata = {
            "scenario_catalog_hash": GATE_5SA_HASHES["scenario_catalog"],
            "feature_schema_hash": GATE_5SA_HASHES["feature_schema"],
            "target_manifest_hash": GATE_5SA_HASHES["target_manifest"],
            "split_manifest_hash": GATE_5SA_HASHES["split_manifest"],
            "quality_report_hash": GATE_5SA_HASHES["quality_report"],
            "leakage_report_hash": GATE_5SA_HASHES["leakage_report"],
        }
        actual_metadata = {
            "scenario_catalog_hash": dataset.manifest.get("scenario_catalog_hash"),
            "feature_schema_hash": dataset.manifest.get("feature_schema_hash"),
            "target_manifest_hash": dataset.target_manifest_hash,
            "split_manifest_hash": dataset.split_manifest_hash,
            "quality_report_hash": dataset.quality_report_hash,
            "leakage_report_hash": dataset.leakage_report_hash,
        }
        for key, expected in expected_metadata.items():
            if actual_metadata[key] != expected:
                raise ValueError(f"ml_gate_5sa_{key}_mismatch")
        if dataset.flow_sha256 != GATE_5SA_HASHES["canonical_flow_artifact"]:
            raise ValueError("ml_gate_5sa_flow_hash_mismatch")
        if dataset.target_sha256 != GATE_5SA_HASHES["target_manifest"]:
            raise ValueError("ml_gate_5sa_target_hash_mismatch")
        if dataset.feature_sha256 != GATE_5SA_HASHES["feature_artifact"]:
            raise ValueError("ml_gate_5sa_feature_hash_mismatch")
        synthetic_root = settings.artifact_root / "synthetic"
        for object_ref, suffix, expected_sha, expected_size in (
            (
                dataset.flow_object_ref,
                "jsonl",
                dataset.flow_sha256,
                dataset.flow_size_bytes,
            ),
            (
                dataset.target_object_ref,
                "targets.json",
                dataset.target_sha256,
                dataset.target_size_bytes,
            ),
            (
                dataset.feature_object_ref,
                "parquet",
                dataset.feature_sha256,
                dataset.feature_size_bytes,
            ),
        ):
            verify_synthetic_artifact(
                synthetic_root,
                object_ref,
                suffix,
                expected_sha256=expected_sha,
                expected_size=expected_size,
                maximum_size=settings.feature_max_output_bytes,
            )
        result = build_synthetic_dataset(schema)
        evidence = train_gate_5sb(result, schema, settings.artifact_root / "models")
        async with factory() as db:
            locked = await db.scalar(
                select(SyntheticTrainingRun)
                .where(SyntheticTrainingRun.id == run_id)
                .with_for_update()
            )
            if locked is None or locked.status != "processing":
                raise ValueError("ml_run_state_invalid")
            now = datetime.now(UTC)
            for candidate in evidence.candidates:
                db.add(
                    SyntheticModelCandidate(
                        training_run_id=locked.id,
                        algorithm=candidate.algorithm,
                        model_object_ref=str(candidate.metadata["model_object_ref"]),
                        model_sha256=candidate.model_sha256,
                        model_size_bytes=candidate.model_size_bytes,
                        metadata_object_ref=candidate.metadata_object_ref,
                        metadata_sha256=candidate.metadata_sha256,
                        metadata_size_bytes=candidate.metadata_size_bytes,
                        preprocessor_hash=candidate.preprocessor_hash,
                        evaluation_hash=candidate.evaluation_hash,
                        model_card_hash=candidate.model_card_hash,
                        safe_metadata={
                            "limitations": candidate.metadata["limitations"],
                            "synthetic_demo_only": True,
                            "real_dataset_used": False,
                            "unsw_nb15_acquired": False,
                            "unsw_nb15_evaluated": False,
                            "network_traffic_generated": False,
                            "online_inference_allowed": False,
                            "scoring_allowed": False,
                            "alert_side_effects_allowed": False,
                            "prevention_allowed": False,
                        },
                        selected=candidate.algorithm == evidence.selected_algorithm,
                    )
                )
            locked.status = "succeeded"
            locked.selected_algorithm = evidence.selected_algorithm
            locked.selected_candidate_hash = evidence.selected_candidate_hash
            locked.test_opening_hash = evidence.test_opening_hash
            locked.test_opened_at = now
            locked.completed_at = now
            db.add(
                AuditEvent(
                    actor_user_id=locked.requested_by,
                    action="synthetic.model.test.open_once",
                    resource_type="synthetic_training_run",
                    resource_id=str(locked.id),
                    outcome="success",
                    correlation_id=f"ml-run-{locked.id}",
                    safe_metadata={
                        "test_opening_hash": evidence.test_opening_hash,
                        "selected_candidate_hash": evidence.selected_candidate_hash,
                        "synthetic_demo_only": True,
                    },
                )
            )
            await db.commit()
    except Exception as error:
        if evidence is not None:
            delete_candidate_artifacts(evidence, settings.artifact_root / "models")
        async with factory() as db:
            run = await db.scalar(
                select(SyntheticTrainingRun)
                .where(SyntheticTrainingRun.id == run_id)
                .with_for_update()
            )
            if run is not None and run.status != "succeeded":
                run.status, run.error_code, run.completed_at = (
                    "failed",
                    (str(error) if str(error).startswith("ml_") else "ml_training_failed")[:64],
                    datetime.now(UTC),
                )
                await db.commit()
        raise


async def cleanup_model_candidates(
    settings: Settings, factory: async_sessionmaker[AsyncSession]
) -> int:
    now = datetime.now(UTC)
    async with factory() as db:
        runs = (
            await db.scalars(
                select(SyntheticTrainingRun)
                .where(SyntheticTrainingRun.expires_at <= now)
                .limit(100)
            )
        ).all()
        count = 0
        root = (settings.artifact_root / "models").resolve()
        for run in runs:
            candidates = (
                await db.scalars(
                    select(SyntheticModelCandidate).where(
                        SyntheticModelCandidate.training_run_id == run.id,
                        SyntheticModelCandidate.artifacts_deleted_at.is_(None),
                    )
                )
            ).all()
            for item in candidates:
                registry = await db.scalar(
                    select(SyntheticRegistryModel).where(
                        SyntheticRegistryModel.candidate_id == item.id
                    )
                )
                if (
                    registry is not None
                    and registry.lifecycle_state == "reviewed_synthetic"
                    and registry.expires_at > now
                ):
                    continue
                for object_ref, suffix in (
                    (item.model_object_ref, "onnx"),
                    (item.metadata_object_ref, "candidate.json"),
                ):
                    path = (root / f"{object_ref}.{suffix}").resolve()
                    if path.parent != root:
                        raise ValueError("ml_artifact_path_invalid")
                    path.unlink(missing_ok=True)
                item.artifacts_deleted_at = now
                count += 1
        await db.commit()
        return count
