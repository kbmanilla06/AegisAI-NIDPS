from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_api.config import Settings
from aegis_api.models import (
    AnomalyDetectorVersion,
    Explanation,
    ExplanationBatch,
    ExplanationMethodVersion,
)
from aegis_services.anomaly import build_anomaly_candidate
from aegis_services.explainability import explain_anomaly_batch, explanation_method
from aegis_services.features import feature_schema
from aegis_services.synthetic import build_synthetic_dataset


async def process_explanation_batch(
    batch_id: UUID, settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> UUID:
    async with session_factory() as db:
        row = await db.get(ExplanationBatch, batch_id)
        if row is None or row.status not in {"pending", "failed"}:
            return batch_id
        row.status = "processing"
        await db.commit()
        try:
            method_row = await db.scalar(
                select(ExplanationMethodVersion).where(
                    ExplanationMethodVersion.method_hash == row.method_hash,
                    ExplanationMethodVersion.lifecycle_state == "reviewed",
                )
            )
            if method_row is None:
                raise ValueError("explanation_method_not_found")
            detector_row = await db.scalar(
                select(AnomalyDetectorVersion).where(
                    AnomalyDetectorVersion.manifest_hash == row.target_model_hash,
                    AnomalyDetectorVersion.lifecycle_state == "reviewed_synthetic",
                    AnomalyDetectorVersion.status == "succeeded",
                )
            )
            if detector_row is None:
                raise ValueError("explanation_target_model_not_found")
            schema = feature_schema("sprint4")
            result = build_synthetic_dataset(schema)
            candidate = build_anomaly_candidate(
                result, schema, settings.artifact_root / "models" / "anomaly"
            )
            if candidate.detector.manifest_hash != row.target_model_hash:
                raise ValueError("explanation_target_model_mismatch")
            method = explanation_method(schema, top_k=method_row.top_k)
            if method.method_hash != row.method_hash:
                raise ValueError("explanation_method_mismatch")
            explanations = explain_anomaly_batch(
                candidate, result, schema, top_k=method_row.top_k, max_instances=32
            )
            directions: dict[str, int] = {}
            for explanation in explanations:
                lead = explanation.attributions[0]
                directions[lead.direction.value] = directions.get(lead.direction.value, 0) + 1
                db.add(
                    Explanation(
                        batch_id=row.id,
                        method_id=method_row.id,
                        explanation_hash=explanation.explanation_hash,
                        method_hash=explanation.method_hash,
                        target_model_hash=explanation.target_model_hash,
                        source_identity_hash=explanation.source_identity_hash,
                        subject_score=explanation.subject_score,
                        baseline_score=explanation.baseline_score,
                        attributions=[
                            item.model_dump(mode="json") for item in explanation.attributions
                        ],
                        analyst_summary=explanation.analyst_summary,
                        limitations=explanation.limitations,
                        expires_at=row.expires_at,
                    )
                )
            row.row_count = len(explanations)
            row.aggregate = {
                "rows": row.row_count,
                "lead_direction_counts": directions,
                "offline_only": True,
                "model_activated": False,
                "synthetic_demo_only": True,
            }
            row.status = "succeeded"
            row.completed_at = datetime.now(UTC)
            await db.commit()
        except Exception:
            row.status = "failed"
            row.error_code = "explanation_generation_failed"
            row.completed_at = datetime.now(UTC)
            await db.commit()
            raise
    return batch_id


async def cleanup_explanations(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> int:
    async with session_factory() as db:
        rows = (
            await db.scalars(select(Explanation).where(Explanation.expires_at <= datetime.now(UTC)))
        ).all()
        for row in rows:
            await db.delete(row)
        await db.commit()
        return len(rows)
