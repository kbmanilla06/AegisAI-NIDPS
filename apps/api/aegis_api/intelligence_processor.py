from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_api.config import Settings
from aegis_api.models import (
    Indicator,
    IndicatorMatch,
    IntelligenceMatchBatch,
    IntelligenceSource,
    MitreMapping,
    MitreTechniqueCatalog,
)
from aegis_services.intelligence import (
    IndicatorType,
    IndicatorV1,
    bundled_indicators,
    bundled_intelligence_source,
    bundled_mitre_catalog,
    bundled_mitre_mappings,
    bundled_observations,
    match_indicators,
)


async def import_bundled_fixtures(actor_id: UUID, db: AsyncSession) -> IntelligenceSource:
    """Idempotently persist the bundled synthetic source, indicators, and MITRE data."""
    source_contract = bundled_intelligence_source()
    existing = await db.scalar(
        select(IntelligenceSource).where(
            IntelligenceSource.source_hash == source_contract.source_hash
        )
    )
    if existing is not None:
        return existing
    source = IntelligenceSource(
        name=source_contract.name,
        trust_level=source_contract.trust_level,
        terms_reference_hash=source_contract.terms_reference_hash,
        enabled=source_contract.enabled,
        source_hash=source_contract.source_hash,
        lifecycle_state="imported",
        created_by=actor_id,
        limitations=source_contract.limitations,
    )
    db.add(source)
    await db.flush()
    for indicator in bundled_indicators():
        db.add(
            Indicator(
                source_id=source.id,
                indicator_type=indicator.indicator_type.value,
                value_hash=indicator.value_hash,
                indicator_hash=indicator.indicator_hash,
                confidence=indicator.confidence,
                first_seen=indicator.first_seen,
                last_seen=indicator.last_seen,
                expires_at=indicator.expires_at,
                lifecycle_state="imported",
                created_by=actor_id,
                limitations=indicator.limitations,
            )
        )
    catalog_contract = bundled_mitre_catalog()
    catalog = MitreTechniqueCatalog(
        catalog_version=catalog_contract.catalog_version,
        catalog_hash=catalog_contract.catalog_hash,
        techniques=[item.model_dump(mode="json") for item in catalog_contract.techniques],
        lifecycle_state="draft",
        created_by=actor_id,
    )
    db.add(catalog)
    await db.flush()
    for mapping in bundled_mitre_mappings(catalog_contract):
        db.add(
            MitreMapping(
                catalog_id=catalog.id,
                technique_id=mapping.technique_id,
                evidence_class=mapping.evidence_class,
                catalog_hash=mapping.catalog_hash,
                rationale=mapping.rationale,
                mapping_version=mapping.mapping_version,
                confidence=mapping.confidence,
                lifecycle_state="draft",
                created_by=actor_id,
                limitations=mapping.limitations,
            )
        )
    await db.commit()
    await db.refresh(source)
    return source


async def process_match_batch(
    batch_id: UUID, settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> UUID:
    async with session_factory() as db:
        row = await db.get(IntelligenceMatchBatch, batch_id)
        if row is None or row.status not in {"pending", "failed"}:
            return batch_id
        row.status = "processing"
        await db.commit()
        try:
            source = await db.scalar(
                select(IntelligenceSource).where(IntelligenceSource.source_hash == row.source_hash)
            )
            if source is None:
                raise ValueError("intelligence_source_not_found")
            indicator_rows = (
                await db.scalars(select(Indicator).where(Indicator.source_id == source.id))
            ).all()
            id_by_hash = {item.indicator_hash: item.id for item in indicator_rows}
            contracts = [
                IndicatorV1(
                    indicator_type=IndicatorType(item.indicator_type),
                    value_hash=item.value_hash,
                    source_name=source.name,
                    confidence=item.confidence,
                    first_seen=item.first_seen,
                    last_seen=item.last_seen,
                    expires_at=item.expires_at,
                )
                for item in indicator_rows
            ]
            now = datetime.now(UTC)
            matches = match_indicators(contracts, bundled_observations(), now=now)
            states: dict[str, int] = {}
            for match in matches:
                states[match.state.value] = states.get(match.state.value, 0) + 1
                db.add(
                    IndicatorMatch(
                        batch_id=row.id,
                        indicator_id=id_by_hash[match.indicator_hash],
                        match_id=match.match_id,
                        indicator_hash=match.indicator_hash,
                        source_name=match.source_name,
                        provenance_hash=match.provenance_hash,
                        matched_at=match.matched_at,
                        state=match.state.value,
                        limitations=match.limitations,
                        expires_at=row.expires_at,
                    )
                )
            row.match_count = len(matches)
            row.aggregate = {
                "matches": row.match_count,
                "state_counts": states,
                "confers_authority": False,
                "offline_only": True,
                "external_lookup": False,
                "synthetic_demo_only": True,
            }
            row.status = "succeeded"
            row.completed_at = datetime.now(UTC)
            await db.commit()
        except Exception:
            row.status = "failed"
            row.error_code = "intelligence_match_failed"
            row.completed_at = datetime.now(UTC)
            await db.commit()
            raise
    return batch_id


async def cleanup_intelligence_matches(
    settings: Settings, session_factory: async_sessionmaker[AsyncSession]
) -> int:
    async with session_factory() as db:
        rows = (
            await db.scalars(
                select(IndicatorMatch).where(IndicatorMatch.expires_at <= datetime.now(UTC))
            )
        ).all()
        for row in rows:
            await db.delete(row)
        await db.commit()
        return len(rows)
