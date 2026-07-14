from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_api.audit import record_audit
from aegis_api.config import Settings
from aegis_api.models import (
    Alert,
    AlertEvidence,
    Asset,
    DetectionRun,
    DetectionSignal,
    Flow,
    RuleVersion,
    SignatureEvent,
)
from aegis_services.detection import (
    FlowRecord,
    RuleDefinition,
    canonical_hash,
    evaluate_rule,
)
from aegis_services.detection.rules import bucket_start


class DetectionLimitError(Exception):
    pass


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _definition(rule: RuleVersion) -> RuleDefinition:
    return RuleDefinition(
        rule_key=rule.rule_key,
        name=rule.name,
        description=rule.description,
        category=rule.category,
        evaluator_key=rule.evaluator_key,
        parameters=rule.parameters,
        window_seconds=rule.window_seconds,
        severity=rule.severity,
        false_positive_guidance=rule.false_positive_guidance,
        investigation_guidance=rule.investigation_guidance,
        prevention_recommendation=rule.prevention_recommendation,
        mitre_mappings=tuple(rule.mitre_mappings),
        evidence_contract=rule.evidence_contract,
        change_rationale=rule.change_rationale,
    )


def _flow_record(flow: Flow) -> FlowRecord:
    return FlowRecord(
        event_key=flow.event_key,
        source_type=flow.source_type,
        sensor_id=str(flow.sensor_id) if flow.sensor_id else None,
        event_time=flow.event_time,
        src_address=flow.src_address,
        dst_address=flow.dst_address,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        protocol=flow.protocol,
        byte_count=flow.byte_count,
        state=flow.state,
    )


def _signature_severity(reported: int) -> str:
    return {1: "high", 2: "medium", 3: "low"}.get(reported, "informational")


async def create_detection_run(
    db: AsyncSession, ingestion_job_id: UUID, source_job_id: UUID
) -> UUID:
    existing = await db.scalar(
        select(DetectionRun).where(DetectionRun.ingestion_job_id == ingestion_job_id)
    )
    if existing is not None:
        return existing.id
    run = DetectionRun(ingestion_job_id=ingestion_job_id, source_job_id=source_job_id)
    db.add(run)
    await db.flush()
    return run.id


async def process_detection_run(
    run_id: UUID,
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
) -> list[UUID]:
    changed_alerts: list[UUID] = []
    async with session_factory() as db:
        try:
            async with db.begin():
                run = await db.scalar(
                    select(DetectionRun).where(DetectionRun.id == run_id).with_for_update()
                )
                if run is None or run.status == "succeeded":
                    return []
                run.status = "processing"
                run.started_at = datetime.now(UTC)
                run.error_code = None
                rules = list(
                    (
                        await db.scalars(
                            select(RuleVersion)
                            .where(RuleVersion.is_active.is_(True))
                            .order_by(RuleVersion.rule_key)
                            .limit(settings.detection_max_active_rules + 1)
                        )
                    ).all()
                )
                if len(rules) > settings.detection_max_active_rules:
                    raise DetectionLimitError("active_rule_limit_exceeded")
                run.rule_set_hash = canonical_hash(
                    [{"id": str(rule.id), "hash": rule.definition_hash} for rule in rules]
                )
                source_flows = list(
                    (
                        await db.scalars(
                            select(Flow)
                            .where(Flow.job_id == run.source_job_id)
                            .limit(settings.ingestion_max_records + 1)
                        )
                    ).all()
                )
                source_signatures = list(
                    (
                        await db.scalars(
                            select(SignatureEvent)
                            .where(SignatureEvent.job_id == run.source_job_id)
                            .limit(settings.ingestion_max_records + 1)
                        )
                    ).all()
                )
                if len(source_flows) + len(source_signatures) > settings.ingestion_max_records:
                    raise DetectionLimitError("record_limit_exceeded")

                for event in source_signatures:
                    created, alert_id = await _store_signature_signal(db, run, event, settings)
                    if created:
                        run.signal_count += 1
                        if alert_id is not None:
                            changed_alerts.append(alert_id)
                    else:
                        run.suppressed_count += 1

                for rule in rules:
                    created_alerts = await _evaluate_behavioral_rule(
                        db, run, rule, source_flows, settings
                    )
                    run.signal_count += created_alerts[0]
                    run.suppressed_count += created_alerts[1]
                    changed_alerts.extend(created_alerts[2])

                if run.signal_count > settings.detection_max_signals:
                    raise DetectionLimitError("signal_limit_exceeded")
                if len(set(changed_alerts)) > settings.detection_max_alerts:
                    raise DetectionLimitError("alert_limit_exceeded")
                run.alert_count = len(set(changed_alerts))
                run.status = "succeeded"
                run.completed_at = datetime.now(UTC)
                record_audit(
                    db,
                    actor_user_id=None,
                    action="detection.run",
                    resource_type="detection_run",
                    resource_id=str(run.id),
                    outcome="success",
                    correlation_id=f"detection-{run.id}",
                    metadata={
                        "signals": run.signal_count,
                        "alerts": run.alert_count,
                        "suppressed": run.suppressed_count,
                        "rule_set_hash": run.rule_set_hash or "none",
                    },
                )
        except DetectionLimitError as error:
            await db.rollback()
            await mark_detection_failed(run_id, str(error), session_factory)
            return []
    return list(dict.fromkeys(changed_alerts))


async def _excluded_sources(db: AsyncSession, parameters: dict[str, object]) -> frozenset[str]:
    identifiers = parameters.get("excluded_asset_ids", [])
    if not isinstance(identifiers, list) or not identifiers:
        return frozenset()
    try:
        asset_ids = [UUID(str(identifier)) for identifier in identifiers]
    except ValueError:
        return frozenset()
    addresses = (
        await db.scalars(
            select(Asset.address).where(Asset.id.in_(asset_ids), Asset.address.is_not(None))
        )
    ).all()
    return frozenset(address for address in addresses if address is not None)


async def _evaluate_behavioral_rule(
    db: AsyncSession,
    run: DetectionRun,
    rule: RuleVersion,
    source_flows: list[Flow],
    settings: Settings,
) -> tuple[int, int, list[UUID]]:
    if not source_flows:
        return 0, 0, []
    definition = _definition(rule)
    affected_buckets = {
        bucket_start(flow.event_time, definition.window_seconds) for flow in source_flows
    }
    start = min(affected_buckets)
    end = max(affected_buckets) + timedelta(seconds=definition.window_seconds)
    flows = list(
        (
            await db.scalars(
                select(Flow)
                .where(Flow.event_time >= start, Flow.event_time < end)
                .order_by(Flow.event_time, Flow.event_key)
                .limit(settings.ingestion_max_records + 1)
            )
        ).all()
    )
    if len(flows) > settings.ingestion_max_records:
        raise DetectionLimitError("window_record_limit_exceeded")
    matches = [
        match
        for match in evaluate_rule(
            definition,
            [_flow_record(flow) for flow in flows],
            excluded_sources=await _excluded_sources(db, rule.parameters),
        )
        if match.bucket_start in affected_buckets
    ]
    if len(matches) > settings.detection_max_groups:
        raise DetectionLimitError("group_limit_exceeded")
    created = 0
    suppressed = 0
    alert_ids: list[UUID] = []
    for match in matches:
        series_payload = {
            "source_type": "behavioral_rule",
            "rule_version_id": str(rule.id),
            "group": match.group,
            "bucket_start": match.bucket_start.isoformat(),
            "window_seconds": rule.window_seconds,
        }
        series_key = canonical_hash(series_payload)
        evidence_hash = canonical_hash(list(match.evidence_event_keys))
        semantic_key = canonical_hash({"series": series_key, "evidence": evidence_hash})
        signal = DetectionSignal(
            semantic_key=semantic_key,
            series_key=series_key,
            detection_run_id=run.id,
            source_type="behavioral_rule",
            rule_version_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            sensor_id=_sensor_uuid(match.group.get("sensor_id")),
            bucket_start=match.bucket_start,
            bucket_end=match.bucket_end,
            grouping=match.group,
            observed_value=match.observed_value,
            threshold_value=match.threshold_value,
            evidence_event_keys=list(match.evidence_event_keys),
            evidence_hash=evidence_hash,
            data_quality=list(match.data_quality),
        )
        if not await _insert_signal(db, signal):
            suppressed += 1
            continue
        created += 1
        alert_ids.append(await _aggregate_alert(db, signal, rule, settings))
    return created, suppressed, alert_ids


async def _store_signature_signal(
    db: AsyncSession,
    run: DetectionRun,
    event: SignatureEvent,
    settings: Settings,
) -> tuple[bool, UUID | None]:
    start = bucket_start(event.event_time, 60)
    group = {
        "sensor_id": str(event.sensor_id) if event.sensor_id else "unspecified",
        "src_address": event.src_address,
        "dst_address": event.dst_address,
        "dst_port": event.dst_port if event.dst_port is not None else 0,
        "protocol": event.protocol,
        "signature_id": event.signature_id,
        "signature_revision": event.signature_revision,
    }
    series_key = canonical_hash(
        {
            "source_type": "suricata_signature",
            "group": group,
            "bucket_start": start.isoformat(),
            "window_seconds": 60,
        }
    )
    evidence_hash = canonical_hash([event.event_key])
    signal = DetectionSignal(
        semantic_key=canonical_hash({"series": series_key, "evidence": evidence_hash}),
        series_key=series_key,
        detection_run_id=run.id,
        source_type="suricata_signature",
        signature_event_id=event.id,
        category=event.category,
        severity=_signature_severity(event.reported_severity),
        sensor_id=event.sensor_id,
        bucket_start=start,
        bucket_end=start + timedelta(seconds=60),
        grouping=group,
        observed_value=1,
        threshold_value=1,
        evidence_event_keys=[event.event_key],
        evidence_hash=evidence_hash,
        data_quality=["reported_signature_not_proof"],
    )
    if not await _insert_signal(db, signal):
        return False, None
    return True, await _aggregate_alert(db, signal, None, settings)


def _sensor_uuid(value: object) -> UUID | None:
    if value in {None, "unspecified"}:
        return None
    try:
        return UUID(str(value))
    except ValueError:
        return None


async def _insert_signal(db: AsyncSession, signal: DetectionSignal) -> bool:
    exists = await db.scalar(
        select(DetectionSignal.id).where(DetectionSignal.semantic_key == signal.semantic_key)
    )
    if exists is not None:
        return False
    try:
        async with db.begin_nested():
            db.add(signal)
            await db.flush()
    except IntegrityError:
        return False
    return True


async def _aggregate_alert(
    db: AsyncSession,
    signal: DetectionSignal,
    rule: RuleVersion | None,
    settings: Settings,
) -> UUID:
    fingerprint = canonical_hash(
        {
            "fingerprint_schema": "alert-fingerprint/v1",
            "series_key": signal.series_key,
        }
    )
    alert = await db.scalar(select(Alert).where(Alert.fingerprint == fingerprint).with_for_update())
    created = False
    if alert is None:
        alert = Alert(
            fingerprint=fingerprint,
            source_type=signal.source_type,
            category=signal.category,
            severity=signal.severity,
            rule_version_id=signal.rule_version_id,
            sensor_id=signal.sensor_id,
            grouping=signal.grouping,
            first_seen=signal.bucket_start,
            last_seen=signal.bucket_end,
        )
        try:
            async with db.begin_nested():
                db.add(alert)
                await db.flush()
            created = True
        except IntegrityError:
            alert = await db.scalar(
                select(Alert).where(Alert.fingerprint == fingerprint).with_for_update()
            )
            if alert is None:
                raise
            alert.occurrence_count += 1
            alert.first_seen = min(_utc(alert.first_seen), _utc(signal.bucket_start))
            alert.last_seen = max(_utc(alert.last_seen), _utc(signal.bucket_end))
    else:
        alert.occurrence_count += 1
        alert.first_seen = min(_utc(alert.first_seen), _utc(signal.bucket_start))
        alert.last_seen = max(_utc(alert.last_seen), _utc(signal.bucket_end))

    evidence_count = int(
        await db.scalar(
            select(func.count())
            .select_from(AlertEvidence)
            .where(AlertEvidence.alert_id == alert.id)
        )
        or 0
    )
    snapshot = {
        "evidence_schema": "alert-evidence/v1",
        "source_type": signal.source_type,
        "rule_version_id": str(signal.rule_version_id) if signal.rule_version_id else None,
        "rule_definition_hash": rule.definition_hash if rule else None,
        "group": signal.grouping,
        "bucket_start": signal.bucket_start.isoformat(),
        "bucket_end": signal.bucket_end.isoformat(),
        "observed": signal.observed_value,
        "threshold": signal.threshold_value,
        "event_keys": signal.evidence_event_keys,
        "evidence_hash": signal.evidence_hash,
        "data_quality": signal.data_quality,
    }
    snapshot_hash = canonical_hash(snapshot)
    if evidence_count < settings.detection_max_evidence_per_alert:
        db.add(
            AlertEvidence(
                alert_id=alert.id,
                signal_id=signal.id,
                evidence_snapshot=snapshot,
                evidence_hash=snapshot_hash,
                occurred_at=signal.bucket_start,
            )
        )
    else:
        alert.evidence_overflow_count += 1
        alert.evidence_overflow_hash = canonical_hash(
            [alert.evidence_overflow_hash or "", snapshot_hash]
        )
    if created:
        record_audit(
            db,
            actor_user_id=None,
            action="alert.create",
            resource_type="alert",
            resource_id=str(alert.id),
            outcome="success",
            correlation_id=f"alert-{alert.id}",
            metadata={
                "source_type": alert.source_type,
                "category": alert.category,
                "severity": alert.severity,
                "fingerprint": alert.fingerprint,
            },
        )
    return alert.id


async def mark_detection_failed(
    run_id: UUID,
    error_code: str,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as db:
        async with db.begin():
            run = await db.scalar(
                select(DetectionRun).where(DetectionRun.id == run_id).with_for_update()
            )
            if run is None or run.status == "succeeded":
                return
            run.status = "failed"
            run.error_code = error_code[:64]
            run.completed_at = datetime.now(UTC)
            record_audit(
                db,
                actor_user_id=None,
                action="detection.run",
                resource_type="detection_run",
                resource_id=str(run.id),
                outcome="failure",
                correlation_id=f"detection-{run.id}",
                metadata={"error_code": run.error_code},
            )


async def pending_detection_runs(
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
) -> list[UUID]:
    cutoff = datetime.now(UTC) - timedelta(seconds=settings.detection_pending_delay_seconds)
    async with session_factory() as db:
        return list(
            (
                await db.scalars(
                    select(DetectionRun.id)
                    .where(DetectionRun.status == "pending", DetectionRun.created_at < cutoff)
                    .order_by(DetectionRun.created_at)
                    .limit(100)
                )
            ).all()
        )


async def cleanup_detection_data(
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
) -> dict[str, int]:
    now = datetime.now(UTC)
    alert_cutoff = now - timedelta(days=settings.alert_retention_days)
    transient_cutoff = now - timedelta(days=settings.flow_retention_days)
    async with session_factory() as db:
        expired_alert_ids = list(
            (
                await db.scalars(
                    select(Alert.id).where(Alert.created_at < alert_cutoff).limit(10_000)
                )
            ).all()
        )
        evidence_deleted = 0
        alerts_deleted = 0
        if expired_alert_ids:
            evidence_deleted = int(
                await db.scalar(
                    select(func.count())
                    .select_from(AlertEvidence)
                    .where(AlertEvidence.alert_id.in_(expired_alert_ids))
                )
                or 0
            )
            alerts_deleted = len(expired_alert_ids)
            await db.execute(
                delete(AlertEvidence).where(AlertEvidence.alert_id.in_(expired_alert_ids))
            )
            await db.execute(delete(Alert).where(Alert.id.in_(expired_alert_ids)))
        expired_signal_ids = list(
            (
                await db.scalars(
                    select(DetectionSignal.id)
                    .where(DetectionSignal.created_at < transient_cutoff)
                    .limit(10_000)
                )
            ).all()
        )
        signals_deleted = len(expired_signal_ids)
        if expired_signal_ids:
            await db.execute(
                update(AlertEvidence)
                .where(AlertEvidence.signal_id.in_(expired_signal_ids))
                .values(signal_id=None)
            )
            await db.execute(
                delete(DetectionSignal).where(DetectionSignal.id.in_(expired_signal_ids))
            )
        expired_signature_ids = list(
            (
                await db.scalars(
                    select(SignatureEvent.id)
                    .where(SignatureEvent.created_at < transient_cutoff)
                    .limit(10_000)
                )
            ).all()
        )
        signatures_deleted = len(expired_signature_ids)
        if expired_signature_ids:
            await db.execute(
                delete(SignatureEvent).where(SignatureEvent.id.in_(expired_signature_ids))
            )
        linked_run_ids = select(DetectionSignal.detection_run_id)
        expired_run_ids = list(
            (
                await db.scalars(
                    select(DetectionRun.id)
                    .where(
                        DetectionRun.created_at < transient_cutoff,
                        DetectionRun.id.not_in(linked_run_ids),
                    )
                    .limit(10_000)
                )
            ).all()
        )
        runs_deleted = len(expired_run_ids)
        if expired_run_ids:
            await db.execute(delete(DetectionRun).where(DetectionRun.id.in_(expired_run_ids)))
        counts = {
            "alerts": alerts_deleted,
            "evidence": evidence_deleted,
            "signals": signals_deleted,
            "signature_events": signatures_deleted,
            "runs": runs_deleted,
        }
        if any(counts.values()):
            record_audit(
                db,
                actor_user_id=None,
                action="retention.detection_delete",
                resource_type="detection",
                resource_id=None,
                outcome="success",
                correlation_id=f"detection-retention-{now:%Y%m%d}",
                metadata={**counts, "alert_retention_days": settings.alert_retention_days},
            )
        await db.commit()
        return counts
