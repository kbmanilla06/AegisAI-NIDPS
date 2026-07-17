from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_api.audit import record_audit
from aegis_api.database import get_db
from aegis_api.errors import ApiError
from aegis_api.models import (
    Alert,
    AllowlistEntry,
    Asset,
    Incident,
    IncidentAlert,
    Indicator,
    PolicyGateResult,
    PreventionExecution,
    PreventionPolicyVersion,
    PreventionPreviewRecord,
    PreventionRequest,
    PreventionRollback,
)
from aegis_api.schemas import (
    _REDACTED_TARGET,
    GateResultOut,
    PreventionExecutionOut,
    PreventionPolicyOut,
    PreventionPreviewOut,
    PreventionRequestCreate,
    PreventionRequestDetailOut,
    PreventionRequestOut,
    PreventionRollbackOut,
)
from aegis_api.security.authentication import Principal, require_csrf_permission, require_permission
from aegis_api.security.permissions import PermissionKey
from aegis_services.prevention import (
    DEFAULT_POLICY_NAME,
    DEFAULT_POLICY_VERSION,
    PREVENTION_LIMITATIONS,
    SIMULATION_MODE,
    GateContext,
    PreventionPreview,
    PreventionRequestStatus,
    evaluate_gates,
    first_failure,
    get_adapter,
    validate_request_transition,
)

router = APIRouter(prefix="/api/v1/prevention")

# Alerts are projected only from deterministic detection sources; any other source is
# treated as model/anomaly-only evidence, which is never sufficient (PREV-006).
_DETERMINISTIC_ALERT_SOURCES = frozenset({"behavioral_rule", "suricata_signature"})


def _sensitive_allowed(principal: Principal) -> bool:
    """Only actors who can author/simulate see the raw target; readers get redaction."""
    return bool(
        {PermissionKey.PREVENTION_SIMULATE, PermissionKey.PREVENTION_MANAGE} & principal.permissions
    )


async def _load_default_policy(db: AsyncSession) -> PreventionPolicyVersion:
    policy = await db.scalar(
        select(PreventionPolicyVersion).where(
            PreventionPolicyVersion.name == DEFAULT_POLICY_NAME,
            PreventionPolicyVersion.version == DEFAULT_POLICY_VERSION,
            PreventionPolicyVersion.lifecycle == "reviewed",
        )
    )
    if policy is None:
        raise ApiError(409, "prevention_policy_unavailable", "No reviewed prevention policy exists")
    return policy


async def _evidence_flags(
    db: AsyncSession, alert_id: UUID | None, incident_id: UUID | None
) -> tuple[bool, bool, bool]:
    """Return (evidence_present, deterministic_corroboration, model_or_anomaly_only)."""
    sources: list[str] = []
    present = False
    if alert_id is not None:
        alert = await db.get(Alert, alert_id)
        if alert is not None:
            present = True
            sources.append(alert.source_type)
    if incident_id is not None:
        incident = await db.get(Incident, incident_id)
        if incident is not None:
            present = True
            member_sources = (
                await db.scalars(
                    select(Alert.source_type)
                    .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
                    .where(IncidentAlert.incident_id == incident_id)
                )
            ).all()
            sources.extend(member_sources)
    corroborated = any(source in _DETERMINISTIC_ALERT_SOURCES for source in sources)
    model_only = present and not corroborated
    return present, corroborated, model_only


async def _intelligence_flags(
    db: AsyncSession, indicator_id: UUID | None, *, corroborated: bool
) -> tuple[bool, bool, bool]:
    """Return (intelligence_used, is_sole_proof, is_fresh) for the freshness gate.

    Intelligence is supplementary only: it is sole proof exactly when it is present
    without deterministic corroboration, and stale when the indicator has expired.
    """
    if indicator_id is None:
        return False, False, True
    indicator = await db.get(Indicator, indicator_id)
    if indicator is None:
        return False, False, True
    expires = indicator.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    is_fresh = expires > datetime.now(UTC)
    return True, not corroborated, is_fresh


async def _allowlist_match(db: AsyncSession, target_type: str, target_value: str) -> bool:
    now = datetime.now(UTC)
    entries = (
        await db.scalars(
            select(AllowlistEntry).where(
                AllowlistEntry.target_type == target_type,
                AllowlistEntry.target_value == target_value,
            )
        )
    ).all()
    for entry in entries:
        expires = entry.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires is None or expires > now:
            return True
    return False


async def _target_is_critical(db: AsyncSession, target_value: str) -> bool:
    asset = await db.scalar(
        select(Asset).where(
            Asset.address == target_value,
            Asset.criticality == "critical",
            Asset.is_active.is_(True),
        )
    )
    return asset is not None


def _redacted_preview(
    preview_row: PreventionPreviewRecord, *, sensitive_allowed: bool
) -> PreventionPreviewOut:
    out = PreventionPreviewOut.model_validate(preview_row)
    if sensitive_allowed:
        return out
    # The representation embeds the target display; redact it so a read-only viewer
    # cannot recover the target through the preview (mirrors request-field redaction).
    representation = deepcopy(out.representation)
    target = representation.get("target")
    if isinstance(target, dict) and "display" in target:
        target["display"] = _REDACTED_TARGET
    return out.model_copy(update={"representation": representation})


async def _build_detail(
    db: AsyncSession, request_row: PreventionRequest, *, sensitive_allowed: bool
) -> PreventionRequestDetailOut:
    gate_rows = (
        await db.scalars(
            select(PolicyGateResult)
            .where(PolicyGateResult.request_id == request_row.id)
            .order_by(PolicyGateResult.created_at.asc())
        )
    ).all()
    preview_row = await db.scalar(
        select(PreventionPreviewRecord).where(PreventionPreviewRecord.request_id == request_row.id)
    )
    execution_row = await db.scalar(
        select(PreventionExecution).where(PreventionExecution.request_id == request_row.id)
    )
    rollback_row = None
    if execution_row is not None:
        rollback_row = await db.scalar(
            select(PreventionRollback).where(PreventionRollback.execution_id == execution_row.id)
        )
    request_out = PreventionRequestOut.model_validate(request_row).redacted(
        allowed=sensitive_allowed
    )
    return PreventionRequestDetailOut(
        request=request_out,
        gate_results=[GateResultOut.model_validate(row) for row in gate_rows],
        preview=(
            _redacted_preview(preview_row, sensitive_allowed=sensitive_allowed)
            if preview_row
            else None
        ),
        execution=(PreventionExecutionOut.model_validate(execution_row) if execution_row else None),
        rollback=PreventionRollbackOut.model_validate(rollback_row) if rollback_row else None,
    )


@router.get("/policies", response_model=list[PreventionPolicyOut])
async def list_policies(
    db: Annotated[AsyncSession, Depends(get_db)],
    _principal: Annotated[Principal, Depends(require_permission(PermissionKey.PREVENTION_READ))],
) -> list[PreventionPolicyOut]:
    rows = (
        await db.scalars(
            select(PreventionPolicyVersion).order_by(PreventionPolicyVersion.created_at.desc())
        )
    ).all()
    return [PreventionPolicyOut.model_validate(row) for row in rows]


@router.post("/requests", response_model=PreventionRequestOut, status_code=201)
async def create_request(
    payload: PreventionRequestCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.PREVENTION_SIMULATE))
    ],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> PreventionRequestOut:
    if not idempotency_key:
        raise ApiError(400, "idempotency_key_required", "Idempotency-Key header is required")
    existing = await db.scalar(
        select(PreventionRequest).where(PreventionRequest.idempotency_key == idempotency_key)
    )
    if existing is not None:
        # Idempotent replay: never create a second request (PREV-005).
        return PreventionRequestOut.model_validate(existing)

    present, _corroborated, _model_only = await _evidence_flags(
        db, payload.alert_id, payload.incident_id
    )
    if not present:
        raise ApiError(404, "prevention_evidence_not_found", "Referenced alert/incident not found")

    if payload.indicator_id is not None and await db.get(Indicator, payload.indicator_id) is None:
        raise ApiError(404, "prevention_indicator_not_found", "Referenced indicator not found")

    policy = await _load_default_policy(db)
    now = datetime.now(UTC)
    row = PreventionRequest(
        idempotency_key=idempotency_key,
        alert_id=payload.alert_id,
        incident_id=payload.incident_id,
        indicator_id=payload.indicator_id,
        policy_version_id=policy.id,
        action_type=payload.action_type.value,
        target_type=payload.target_type.value,
        target_value=payload.target_value,
        reason=payload.reason,
        duration_seconds=payload.duration_seconds,
        expires_at=now + timedelta(seconds=payload.duration_seconds),
        rollback_plan=payload.rollback_plan.model_dump(),
        status=PreventionRequestStatus.DRAFT.value,
        limitations=PREVENTION_LIMITATIONS,
        requested_by=principal.user_id,
    )
    db.add(row)
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="prevention.request.create",
        resource_type="prevention_request",
        resource_id=str(row.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "action_type": row.action_type,
            "target_type": row.target_type,
            "mode": SIMULATION_MODE,
            "prevention_allowed": False,
            "enforcement_authority": False,
        },
    )
    await db.commit()
    await db.refresh(row)
    return PreventionRequestOut.model_validate(row)


@router.post("/requests/{request_id}/preview", response_model=PreventionRequestDetailOut)
async def preview_request(
    request_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.PREVENTION_SIMULATE))
    ],
) -> PreventionRequestDetailOut:
    row = await db.get(PreventionRequest, request_id)
    if row is None:
        raise ApiError(404, "prevention_request_not_found", "Prevention request not found")
    sensitive = _sensitive_allowed(principal)
    if row.status != PreventionRequestStatus.DRAFT.value:
        # Already evaluated: return the existing decision (idempotent, no re-evaluation).
        return await _build_detail(db, row, sensitive_allowed=sensitive)

    policy = await db.get(PreventionPolicyVersion, row.policy_version_id)
    if policy is None:
        raise ApiError(409, "prevention_policy_unavailable", "Policy version missing")
    present, corroborated, model_only = await _evidence_flags(db, row.alert_id, row.incident_id)
    intel_used, intel_sole, intel_fresh = await _intelligence_flags(
        db, row.indicator_id, corroborated=corroborated
    )
    allowlisted = await _allowlist_match(db, row.target_type, row.target_value)
    critical = await _target_is_critical(db, row.target_value)

    context = GateContext(
        environment=SIMULATION_MODE,
        has_simulate_permission=True,
        action_type=row.action_type,
        target_type=row.target_type,
        target_value=row.target_value,
        allowlist_match=allowlisted,
        target_is_critical=critical,
        evidence_present=present,
        evidence_has_deterministic_corroboration=corroborated,
        evidence_is_model_or_anomaly_only=model_only,
        intelligence_used=intel_used,
        intelligence_is_sole_proof=intel_sole,
        intelligence_is_fresh=intel_fresh,
        duration_seconds=row.duration_seconds,
        policy_max_duration_seconds=policy.max_duration_seconds,
        has_expiry=row.expires_at is not None,
        has_rollback_plan=bool(row.rollback_plan),
        duplicate_detected=False,
        cooldown_active=False,
    )
    results = evaluate_gates(context)
    for result in results:
        db.add(
            PolicyGateResult(
                request_id=row.id,
                gate_key=result.key.value,
                passed=result.passed,
                reason_code=result.reason_code,
                evidence_ref=result.evidence_ref,
            )
        )
    validate_request_transition(
        PreventionRequestStatus(row.status), PreventionRequestStatus.EVALUATED
    )
    row.status = PreventionRequestStatus.EVALUATED.value

    failure = first_failure(results)
    if failure is None:
        preview = PreventionPreview(
            request_id=row.id,
            mode=SIMULATION_MODE,
            action_type=row.action_type,
            target_type=row.target_type,
            target_display=row.target_value,
            duration_seconds=row.duration_seconds,
            rollback_summary=str(row.rollback_plan.get("summary", "")),
        )
        representation = get_adapter().preview(preview)
        db.add(
            PreventionPreviewRecord(
                request_id=row.id, adapter=SIMULATION_MODE, representation=representation
            )
        )
        validate_request_transition(
            PreventionRequestStatus.EVALUATED, PreventionRequestStatus.PREVIEWED
        )
        row.status = PreventionRequestStatus.PREVIEWED.value
        outcome_reason = "ok"
    else:
        validate_request_transition(
            PreventionRequestStatus.EVALUATED, PreventionRequestStatus.REJECTED
        )
        row.status = PreventionRequestStatus.REJECTED.value
        outcome_reason = failure.reason_code

    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="prevention.request.preview",
        resource_type="prevention_request",
        resource_id=str(row.id),
        outcome="success" if failure is None else "rejected",
        correlation_id=request.state.correlation_id,
        metadata={
            "status": row.status,
            "reason_code": outcome_reason,
            "mode": SIMULATION_MODE,
            "prevention_allowed": False,
        },
    )
    try:
        await db.commit()
    except IntegrityError:
        # A concurrent preview already evaluated this request (unique gate-result /
        # preview constraints). Fail closed to the persisted decision, never a 500.
        await db.rollback()
        row = await db.get(PreventionRequest, request_id)
        if row is None:
            raise ApiError(
                404, "prevention_request_not_found", "Prevention request not found"
            ) from None
        return await _build_detail(db, row, sensitive_allowed=sensitive)
    await db.refresh(row)
    return await _build_detail(db, row, sensitive_allowed=sensitive)


@router.post("/requests/{request_id}/simulate", response_model=PreventionRequestDetailOut)
async def simulate_request(
    request_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.PREVENTION_SIMULATE))
    ],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> PreventionRequestDetailOut:
    if not idempotency_key:
        raise ApiError(400, "idempotency_key_required", "Idempotency-Key header is required")
    row = await db.get(PreventionRequest, request_id)
    if row is None:
        raise ApiError(404, "prevention_request_not_found", "Prevention request not found")
    sensitive = _sensitive_allowed(principal)

    existing = await db.scalar(
        select(PreventionExecution).where(PreventionExecution.request_id == row.id)
    )
    if existing is not None:
        # Idempotent replay: exactly one execution per request (PREV-005).
        return await _build_detail(db, row, sensitive_allowed=sensitive)

    if row.status != PreventionRequestStatus.PREVIEWED.value:
        raise ApiError(
            409, "prevention_not_previewed", "Request must pass gates and be previewed first"
        )

    adapter = get_adapter()
    preview = PreventionPreview(
        request_id=row.id,
        mode=SIMULATION_MODE,
        action_type=row.action_type,
        target_type=row.target_type,
        target_display=row.target_value,
        duration_seconds=row.duration_seconds,
        rollback_summary=str(row.rollback_plan.get("summary", "")),
    )
    outcome = adapter.execute(preview)
    execution = PreventionExecution(
        request_id=row.id,
        mode=SIMULATION_MODE,
        result=str(outcome["result"]),
        verify=outcome["verify"],
    )
    db.add(execution)
    validate_request_transition(
        PreventionRequestStatus.PREVIEWED, PreventionRequestStatus.SIMULATED
    )
    row.status = PreventionRequestStatus.SIMULATED.value
    await db.flush()
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="prevention.request.simulate",
        resource_type="prevention_execution",
        resource_id=str(execution.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={
            "mode": SIMULATION_MODE,
            "result": execution.result,
            "no_real_side_effect": True,
            "prevention_allowed": False,
        },
    )
    await db.commit()
    await db.refresh(row)
    return await _build_detail(db, row, sensitive_allowed=sensitive)


@router.post("/executions/{execution_id}/rollback", response_model=PreventionRequestDetailOut)
async def rollback_execution(
    execution_id: UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[
        Principal, Depends(require_csrf_permission(PermissionKey.PREVENTION_SIMULATE))
    ],
) -> PreventionRequestDetailOut:
    execution = await db.get(PreventionExecution, execution_id)
    if execution is None:
        raise ApiError(404, "prevention_execution_not_found", "Execution not found")
    row = await db.get(PreventionRequest, execution.request_id)
    assert row is not None
    sensitive = _sensitive_allowed(principal)

    existing = await db.scalar(
        select(PreventionRollback).where(PreventionRollback.execution_id == execution.id)
    )
    if existing is not None:
        # Idempotent: one rollback per execution.
        return await _build_detail(db, row, sensitive_allowed=sensitive)

    if row.status != PreventionRequestStatus.SIMULATED.value:
        # Only a still-simulated request can be rolled back; an expired (or otherwise
        # terminal) request fails closed with a clean conflict, never a 500.
        raise ApiError(
            409, "prevention_not_simulated", "Only a simulated request can be rolled back"
        )

    outcome = get_adapter().rollback(execution.id)
    db.add(PreventionRollback(execution_id=execution.id, result=str(outcome["result"])))
    validate_request_transition(
        PreventionRequestStatus(row.status), PreventionRequestStatus.ROLLED_BACK
    )
    row.status = PreventionRequestStatus.ROLLED_BACK.value
    record_audit(
        db,
        actor_user_id=principal.user_id,
        action="prevention.execution.rollback",
        resource_type="prevention_execution",
        resource_id=str(execution.id),
        outcome="success",
        correlation_id=request.state.correlation_id,
        metadata={"mode": SIMULATION_MODE, "result": "rolled_back", "prevention_allowed": False},
    )
    await db.commit()
    await db.refresh(row)
    return await _build_detail(db, row, sensitive_allowed=sensitive)


@router.get("/requests/{request_id}", response_model=PreventionRequestDetailOut)
async def get_request(
    request_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    principal: Annotated[Principal, Depends(require_permission(PermissionKey.PREVENTION_READ))],
) -> PreventionRequestDetailOut:
    row = await db.get(PreventionRequest, request_id)
    if row is None:
        raise ApiError(404, "prevention_request_not_found", "Prevention request not found")
    sensitive = _sensitive_allowed(principal)
    return await _build_detail(db, row, sensitive_allowed=sensitive)
