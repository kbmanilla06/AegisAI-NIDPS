from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, WebSocket, WebSocketDisconnect
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from aegis_api.audit import record_audit
from aegis_api.config import Settings
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import (
    Alert,
    AlertEvidence,
    DetectionRun,
    DetectionSignal,
    Role,
    RuleActivation,
    RuleVersion,
    Session,
    User,
)
from aegis_api.schemas import (
    AlertDetailOut,
    AlertEvidenceOut,
    AlertSummaryOut,
    DetectionMetricsOut,
    DetectionRunOut,
    RuleActivationRequest,
    RuleReviewRequest,
    RuleRollbackRequest,
    RuleVersionCreate,
    RuleVersionOut,
)
from aegis_api.security.authentication import (
    SESSION_COOKIE_NAME,
    Principal,
    as_utc,
    require_csrf_permission,
    require_permission,
)
from aegis_api.security.permissions import PermissionKey
from aegis_api.security.tokens import hash_secret
from aegis_services.detection import RuleDefinition, canonical_hash, validate_rule_parameters

router = APIRouter(prefix="/api/v1")
ws_router = APIRouter()
RULE_KEY = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)+$")
WEBSOCKET_AUTH_RECHECK_SECONDS = 15.0


class LiveAlertQueueOverflow(Exception):
    pass


def _rule_out(rule: RuleVersion) -> RuleVersionOut:
    return RuleVersionOut.model_validate(rule)


def _redacted_group(grouping: dict[str, object], sensitive: bool) -> dict[str, object]:
    if sensitive:
        return grouping
    return {
        key: value for key, value in grouping.items() if key not in {"src_address", "dst_address"}
    }


def _alert_out(alert: Alert, sensitive: bool) -> AlertSummaryOut:
    return AlertSummaryOut(
        id=alert.id,
        source_type=alert.source_type,
        category=alert.category,
        severity=alert.severity,
        status=alert.status,
        grouping=_redacted_group(alert.grouping, sensitive),
        occurrence_count=alert.occurrence_count,
        evidence_overflow_count=alert.evidence_overflow_count,
        first_seen=alert.first_seen,
        last_seen=alert.last_seen,
        created_at=alert.created_at,
        rule_version_id=alert.rule_version_id,
        assignee_id=alert.assignee_id,
        disposition=alert.disposition,
        closed_at=alert.closed_at,
    )


@router.get("/rules", response_model=list[RuleVersionOut])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.RULES_READ))],
    active_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> list[RuleVersionOut]:
    statement = select(RuleVersion).order_by(RuleVersion.rule_key, RuleVersion.version.desc())
    if active_only:
        statement = statement.where(RuleVersion.is_active.is_(True))
    return [_rule_out(rule) for rule in (await db.scalars(statement.limit(limit))).all()]


@router.get("/rules/{rule_key}/versions", response_model=list[RuleVersionOut])
async def list_rule_versions(
    rule_key: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.RULES_READ))],
) -> list[RuleVersionOut]:
    if not RULE_KEY.fullmatch(rule_key):
        raise ApiError(404, "rule_not_found", "Rule not found")
    versions = (
        await db.scalars(
            select(RuleVersion)
            .where(RuleVersion.rule_key == rule_key)
            .order_by(RuleVersion.version.desc())
            .limit(100)
        )
    ).all()
    if not versions:
        raise ApiError(404, "rule_not_found", "Rule not found")
    return [_rule_out(rule) for rule in versions]


@router.post("/rules/{rule_key}/versions", response_model=RuleVersionOut, status_code=201)
async def create_rule_version(
    rule_key: str,
    payload: RuleVersionCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.RULES_WRITE))],
) -> RuleVersionOut:
    if not RULE_KEY.fullmatch(rule_key):
        raise ApiError(422, "invalid_rule_key", "Rule key is invalid")
    try:
        parameters = validate_rule_parameters(payload.evaluator_key, payload.parameters)
    except ValueError as error:
        raise ApiError(422, "invalid_rule_definition", "Rule definition is invalid") from error
    version = (
        int(
            await db.scalar(
                select(func.coalesce(func.max(RuleVersion.version), 0)).where(
                    RuleVersion.rule_key == rule_key
                )
            )
            or 0
        )
        + 1
    )
    definition = RuleDefinition(
        rule_key=rule_key,
        name=payload.name,
        description=payload.description,
        category=payload.category,
        evaluator_key=payload.evaluator_key,
        parameters=parameters,
        window_seconds=payload.window_seconds,
        severity=payload.severity.value,
        false_positive_guidance=payload.false_positive_guidance,
        investigation_guidance=payload.investigation_guidance,
        prevention_recommendation=payload.prevention_recommendation,
        mitre_mappings=tuple(payload.mitre_mappings),
        evidence_contract={
            "version": "alert-evidence/v1",
            "fields": ["group", "window", "observed", "threshold", "event_keys"],
        },
        change_rationale=payload.change_rationale,
    )
    rule = RuleVersion(
        rule_key=rule_key,
        version=version,
        schema_version="behavioral-rule/v1",
        name=payload.name,
        description=payload.description,
        category=payload.category,
        evaluator_key=payload.evaluator_key,
        parameters=parameters,
        window_seconds=payload.window_seconds,
        severity=payload.severity.value,
        mitre_mappings=payload.mitre_mappings,
        evidence_contract=definition.evidence_contract,
        false_positive_guidance=payload.false_positive_guidance,
        investigation_guidance=payload.investigation_guidance,
        prevention_recommendation=payload.prevention_recommendation,
        change_rationale=payload.change_rationale,
        definition_hash=canonical_hash(definition.canonical_definition()),
        lifecycle_state="draft",
        created_by=principal.user_id,
    )
    db.add(rule)
    try:
        await db.flush()
    except IntegrityError as error:
        await db.rollback()
        raise ApiError(
            409, "rule_version_conflict", "An equivalent or concurrent rule version exists"
        ) from error
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="rule.version.create",
        resource_type="rule_version",
        resource_id=str(rule.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "rule_key": rule_key,
            "version": version,
            "definition_hash": rule.definition_hash,
        },
    )
    await db.commit()
    await db.refresh(rule)
    return _rule_out(rule)


@router.post("/rule-versions/{version_id}/review", response_model=RuleVersionOut)
async def review_rule_version(
    version_id: UUID,
    payload: RuleReviewRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.RULES_REVIEW))],
) -> RuleVersionOut:
    rule = await db.scalar(
        select(RuleVersion).where(RuleVersion.id == version_id).with_for_update()
    )
    if rule is None:
        raise ApiError(404, "rule_version_not_found", "Rule version not found")
    if rule.lifecycle_state != "draft" or rule.is_active:
        raise ApiError(409, "invalid_rule_state", "Rule version cannot be reviewed")
    rule.lifecycle_state = "approved" if payload.approved else "retired"
    rule.reviewed_by = principal.user_id
    rule.reviewed_at = datetime.now(UTC)
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="rule.version.review",
        resource_type="rule_version",
        resource_id=str(rule.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "rule_key": rule.rule_key,
            "version": rule.version,
            "decision": rule.lifecycle_state,
            "reason": payload.reason,
            "regression_evidence": payload.regression_evidence,
        },
    )
    await db.commit()
    await db.refresh(rule)
    return _rule_out(rule)


async def _activate(
    db: AsyncSession,
    principal: Principal,
    request: Request,
    target: RuleVersion,
    payload: RuleActivationRequest,
) -> RuleVersion:
    if target.lifecycle_state != "approved":
        raise ApiError(409, "rule_not_approved", "Only approved rule versions can activate")
    try:
        validate_rule_parameters(target.evaluator_key, target.parameters)
    except ValueError as error:
        raise ApiError(409, "rule_incompatible", "Rule version is incompatible") from error
    current = await db.scalar(
        select(RuleVersion)
        .where(RuleVersion.rule_key == target.rule_key, RuleVersion.is_active.is_(True))
        .with_for_update()
    )
    current_id = current.id if current else None
    if payload.expected_active_version_id != current_id:
        raise ApiError(409, "active_rule_changed", "Active rule version changed")
    if current is not None and current.id == target.id:
        return target
    if current is not None:
        current.is_active = False
    target.is_active = True
    action = "rollback" if current is not None and target.version < current.version else "activate"
    db.add(
        RuleActivation(
            rule_key=target.rule_key,
            rule_version_id=target.id,
            previous_rule_version_id=current_id,
            action=action,
            actor_user_id=principal.user_id,
            reason=payload.reason,
            regression_evidence=payload.regression_evidence,
        )
    )
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action=f"rule.{action}",
        resource_type="rule_version",
        resource_id=str(target.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "rule_key": target.rule_key,
            "version": target.version,
            "previous_version_id": str(current_id) if current_id else "none",
            "regression_evidence": payload.regression_evidence,
        },
    )
    try:
        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        raise ApiError(409, "active_rule_changed", "Active rule version changed") from error
    await db.refresh(target)
    return target


@router.post("/rule-versions/{version_id}/activate", response_model=RuleVersionOut)
async def activate_rule_version(
    version_id: UUID,
    payload: RuleActivationRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.RULES_ACTIVATE))],
) -> RuleVersionOut:
    target = await db.get(RuleVersion, version_id)
    if target is None:
        raise ApiError(404, "rule_version_not_found", "Rule version not found")
    return _rule_out(await _activate(db, principal, request, target, payload))


@router.post("/rules/{rule_key}/deactivate", response_model=RuleVersionOut)
async def deactivate_rule(
    rule_key: str,
    payload: RuleActivationRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.RULES_ACTIVATE))],
) -> RuleVersionOut:
    current = await db.scalar(
        select(RuleVersion)
        .where(RuleVersion.rule_key == rule_key, RuleVersion.is_active.is_(True))
        .with_for_update()
    )
    if current is None:
        raise ApiError(404, "active_rule_not_found", "Active rule not found")
    if payload.expected_active_version_id != current.id:
        raise ApiError(409, "active_rule_changed", "Active rule version changed")
    current.is_active = False
    db.add(
        RuleActivation(
            rule_key=rule_key,
            rule_version_id=None,
            previous_rule_version_id=current.id,
            action="deactivate",
            actor_user_id=principal.user_id,
            reason=payload.reason,
            regression_evidence=payload.regression_evidence,
        )
    )
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="rule.deactivate",
        resource_type="rule_version",
        resource_id=str(current.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"rule_key": rule_key, "version": current.version},
    )
    await db.commit()
    await db.refresh(current)
    return _rule_out(current)


@router.post("/rules/{rule_key}/rollback", response_model=RuleVersionOut)
async def rollback_rule(
    rule_key: str,
    payload: RuleRollbackRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_csrf_permission(PermissionKey.RULES_ACTIVATE))],
) -> RuleVersionOut:
    target = await db.get(RuleVersion, payload.target_version_id)
    if target is None or target.rule_key != rule_key:
        raise ApiError(404, "rule_version_not_found", "Rule version not found")
    return _rule_out(await _activate(db, principal, request, target, payload))


@router.get("/alerts", response_model=list[AlertSummaryOut])
async def list_alerts(
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_permission(PermissionKey.ALERTS_READ))],
    start: datetime | None = None,
    end: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[AlertSummaryOut]:
    now = datetime.now(UTC)
    query_start = start or now - timedelta(days=1)
    query_end = end or now
    if query_start.tzinfo is None or query_end.tzinfo is None or query_start >= query_end:
        raise ApiError(422, "invalid_time_range", "Time range is invalid")
    if query_end - query_start > timedelta(days=31):
        raise ApiError(422, "time_range_too_large", "Time range exceeds 31 days")
    alerts = (
        await db.scalars(
            select(Alert)
            .where(Alert.last_seen >= query_start, Alert.last_seen <= query_end)
            .order_by(Alert.last_seen.desc())
            .limit(limit)
        )
    ).all()
    sensitive = PermissionKey.ALERTS_READ_SENSITIVE in principal.permissions
    return [_alert_out(alert, sensitive) for alert in alerts]


@router.get("/alerts/{alert_id}", response_model=AlertDetailOut)
async def get_alert(
    alert_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_permission(PermissionKey.ALERTS_READ))],
) -> AlertDetailOut:
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise ApiError(404, "alert_not_found", "Alert not found")
    sensitive = PermissionKey.ALERTS_READ_SENSITIVE in principal.permissions
    evidence_rows = (
        await db.scalars(
            select(AlertEvidence)
            .where(AlertEvidence.alert_id == alert.id)
            .order_by(AlertEvidence.occurred_at)
            .limit(100)
        )
    ).all()
    evidence: list[AlertEvidenceOut] = []
    for row in evidence_rows:
        snapshot = dict(row.evidence_snapshot)
        group = snapshot.get("group")
        if isinstance(group, dict):
            snapshot["group"] = _redacted_group(group, sensitive)
        evidence.append(
            AlertEvidenceOut(
                id=row.id,
                evidence_snapshot=snapshot,
                evidence_hash=row.evidence_hash,
                occurred_at=row.occurred_at,
            )
        )
    summary = _alert_out(alert, sensitive)
    return AlertDetailOut(
        **summary.model_dump(),
        fingerprint=alert.fingerprint,
        fingerprint_schema=alert.fingerprint_schema,
        evidence=evidence,
    )


@router.get("/detection/metrics", response_model=DetectionMetricsOut)
async def detection_metrics(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.DETECTIONS_READ_METRICS))
    ],
) -> DetectionMetricsOut:
    statuses = (
        await db.execute(select(DetectionRun.status, func.count()).group_by(DetectionRun.status))
    ).all()
    return DetectionMetricsOut(
        runs_by_status={status: int(count) for status, count in statuses},
        signals=int(await db.scalar(select(func.count()).select_from(DetectionSignal)) or 0),
        alerts=int(await db.scalar(select(func.count()).select_from(Alert)) or 0),
        occurrences=int(
            await db.scalar(select(func.coalesce(func.sum(Alert.occurrence_count), 0))) or 0
        ),
        suppressed=int(
            await db.scalar(select(func.coalesce(func.sum(DetectionRun.suppressed_count), 0))) or 0
        ),
    )


@router.get("/detection/runs/{run_id}", response_model=DetectionRunOut)
async def get_detection_run(
    run_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.DETECTIONS_READ_METRICS))
    ],
) -> DetectionRunOut:
    run = await db.get(DetectionRun, run_id)
    if run is None:
        raise ApiError(404, "detection_run_not_found", "Detection run not found")
    return DetectionRunOut.model_validate(run)


@router.get("/detection/runs", response_model=list[DetectionRunOut])
async def list_detection_runs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[
        Principal, Depends(require_permission(PermissionKey.DETECTIONS_READ_METRICS))
    ],
    source_job_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[DetectionRunOut]:
    statement = select(DetectionRun).order_by(DetectionRun.created_at.desc()).limit(limit)
    if source_job_id is not None:
        statement = statement.where(DetectionRun.source_job_id == source_job_id)
    runs = (await db.scalars(statement)).all()
    return [DetectionRunOut.model_validate(run) for run in runs]


async def _websocket_authorized(
    websocket: WebSocket,
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
) -> bool:
    if websocket.headers.get("origin") not in settings.allowed_origins:
        return False
    token = websocket.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return False
    async with session_factory() as db:
        session = await db.scalar(
            select(Session)
            .where(Session.token_hash == hash_secret(token))
            .options(
                selectinload(Session.user).selectinload(User.roles).selectinload(Role.permissions)
            )
        )
        now = datetime.now(UTC)
        if (
            session is None
            or session.revoked_at is not None
            or as_utc(session.idle_expires_at) <= now
            or as_utc(session.absolute_expires_at) <= now
            or not session.user.is_active
        ):
            return False
        permissions = {
            permission.key for role in session.user.roles for permission in role.permissions
        }
        return PermissionKey.ALERTS_READ in permissions


@ws_router.websocket("/ws/v1/alerts")
async def alert_stream(websocket: WebSocket) -> None:
    settings: Settings = websocket.app.state.settings
    session_factory: async_sessionmaker[AsyncSession] = websocket.app.state.session_factory
    if not await _websocket_authorized(websocket, settings, session_factory):
        await websocket.close(code=4403)
        return
    await websocket.accept()
    await websocket.send_json({"event": "connected"})
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    pubsub = redis.pubsub()
    queue: asyncio.Queue[dict[str, object]] = asyncio.Queue(maxsize=settings.live_alert_queue_size)

    async def receive_alerts() -> None:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message is None:
                continue
            try:
                payload = json.loads(str(message["data"]))
            except (KeyError, TypeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict) or set(payload) - {
                "event",
                "alert_id",
                "sequence",
            }:
                continue
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull as error:
                raise LiveAlertQueueOverflow from error

    receiver: asyncio.Task[None] | None = None
    try:
        await pubsub.subscribe("aegis.alerts")
        receiver = asyncio.create_task(receive_alerts())
        loop = asyncio.get_running_loop()
        next_authorization_check = loop.time() + WEBSOCKET_AUTH_RECHECK_SECONDS
        while True:
            get_next = asyncio.create_task(queue.get())
            done, _pending = await asyncio.wait(
                {receiver, get_next},
                timeout=WEBSOCKET_AUTH_RECHECK_SECONDS,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done or loop.time() >= next_authorization_check:
                if not await _websocket_authorized(websocket, settings, session_factory):
                    get_next.cancel()
                    await websocket.close(code=4403)
                    return
                next_authorization_check = loop.time() + WEBSOCKET_AUTH_RECHECK_SECONDS
            if receiver in done:
                get_next.cancel()
                await receiver
            elif get_next in done:
                await websocket.send_json(get_next.result())
            else:
                get_next.cancel()
                await websocket.send_json({"event": "heartbeat"})
    except WebSocketDisconnect:
        pass
    except LiveAlertQueueOverflow:
        await websocket.close(code=1013, reason="live alert consumer is too slow")
    except Exception:
        await websocket.close(code=1013)
    finally:
        if receiver is not None:
            receiver.cancel()
        await pubsub.aclose()
        await redis.aclose()
