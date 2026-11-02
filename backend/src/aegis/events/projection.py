"""Derive security events from audit events.

The audit chain stays the source of truth. A security event is a minimal, normalized view of one
audit event, so projecting the same audit event again must reproduce it. That property is how a
stored event is verified later, so changing a mapping requires a new SCHEMA_VERSION.
"""

from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid5

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from aegis.db.models import ActionRequest, Agent, AuditEvent, SecurityEvent
from aegis.events.schema import SecurityEventRecord

SCHEMA_VERSION = 1
_ID_NAMESPACE = UUID("6f2c1b52-6c1d-4c0a-9a3e-0f6a2d3b7c11")

_HIGH_DENIALS = {
    "UNKNOWN_TOOL",
    "DESTINATION_CLEARANCE_INSUFFICIENT",
    "POLICY_INVALID",
    "POLICY_EVALUATION_ERROR",
}
_LOW_DENIALS = {"INVALID_PARAMETERS", "NO_ACTIVE_POLICY"}


def _as_uuid(value: Any) -> UUID | None:
    return UUID(value) if isinstance(value, str) else None


def _from_action_request(session: Session, audit: AuditEvent) -> dict[str, Any]:
    if audit.correlation_id is None:
        return {}
    request = session.get(ActionRequest, audit.correlation_id)
    if request is None:
        return {}
    return {
        "action_request_id": request.id,
        "correlation_id": request.id,
        "agent_id": request.agent_id,
        "tool": request.tool,
        "action": request.action,
        "resource_id": request.resource_id,
    }


def _decision(session: Session, audit: AuditEvent) -> dict[str, Any] | None:
    payload = audit.payload
    outcome = payload.get("outcome")
    if outcome not in ("DENY", "REQUIRE_APPROVAL"):
        return None
    reason = payload.get("reason_code")
    denied = outcome == "DENY"
    if not denied:
        severity = "info"
    elif reason in _HIGH_DENIALS:
        severity = "high"
    elif reason in _LOW_DENIALS:
        severity = "low"
    else:
        severity = "medium"
    return {
        **_from_action_request(session, audit),
        "event_type": "gateway.action_denied" if denied else "gateway.approval_required",
        "severity": severity,
        "reason_code": reason,
        "decision_id": _as_uuid(payload.get("decision_id")),
        "attributes": (
            {"not_visible_reference": True} if payload.get("not_visible_reference") else {}
        ),
    }


def _approval(event_type: str, severity: str, reason: str):
    def build(session: Session, audit: AuditEvent) -> dict[str, Any]:
        return {
            **_from_action_request(session, audit),
            "event_type": event_type,
            "severity": severity,
            "reason_code": reason,
            "approval_id": audit.subject_id,
        }

    return build


def _approval_cancelled(session: Session, audit: AuditEvent) -> dict[str, Any]:
    reason = audit.payload.get("reason")
    expired = reason == "APPROVAL_EXPIRED"
    return {
        **_from_action_request(session, audit),
        "event_type": "approval.expired" if expired else "approval.invalidated",
        "severity": (
            "low" if expired else "high" if reason == "ACTION_HASH_MISMATCH" else "medium"
        ),
        "reason_code": reason,
        "approval_id": audit.subject_id,
    }


def _execution_refused(session: Session, audit: AuditEvent) -> dict[str, Any]:
    return {
        **_from_action_request(session, audit),
        "event_type": "gateway.execution_refused",
        "severity": "medium",
        "reason_code": audit.payload.get("reason"),
        "approval_id": _as_uuid(audit.payload.get("approval_id")),
    }


def _execution(session: Session, audit: AuditEvent) -> dict[str, Any]:
    failed = audit.event_type == "execution.failed"
    reason = "EXECUTION_SUCCEEDED"
    if failed:
        unexpected = audit.payload.get("error_type") == "UnexpectedToolError"
        reason = "TOOL_ERROR" if unexpected else "TOOL_FAILURE"
    return {
        **_from_action_request(session, audit),
        "event_type": audit.event_type,
        "severity": "low" if failed else "info",
        "reason_code": reason,
        "execution_id": audit.subject_id,
    }


def _suppressed(audit: AuditEvent) -> dict[str, Any]:
    count = audit.payload.get("suppressed_since_last")
    return {"suppressed_since_last": count} if count else {}


def _authentication(event_type: str, severity: str, reason: str):
    def build(session: Session, audit: AuditEvent) -> dict[str, Any]:
        # The credential ID and email hash in the audit payload stay out: both are attacker input.
        return {
            "event_type": event_type,
            "severity": severity,
            "reason_code": reason,
            "attributes": _suppressed(audit),
        }

    return build


def _actor_agent(audit: AuditEvent) -> UUID | None:
    return audit.actor_id if audit.actor_type == "agent" else None


def _authz_denied(session: Session, audit: AuditEvent) -> dict[str, Any]:
    return {
        "event_type": "authz.denied",
        "severity": "medium",
        "reason_code": "ROLE_NOT_PERMITTED",
        "agent_id": _actor_agent(audit),
        "attributes": _suppressed(audit),
    }


def _not_visible(session: Session, audit: AuditEvent) -> dict[str, Any]:
    return {
        "event_type": "access.not_visible",
        "severity": "medium",
        "reason_code": "NOT_VISIBLE",
        "agent_id": _actor_agent(audit),
        "resource_id": audit.subject_id,
        "attributes": {"not_visible_reference": True, **_suppressed(audit)},
    }


def _policy(event_type: str):
    def build(session: Session, audit: AuditEvent) -> dict[str, Any]:
        return {"event_type": event_type, "severity": "medium", "reason_code": "POLICY_CHANGED"}

    return build


def _agent_status(session: Session, audit: AuditEvent) -> dict[str, Any]:
    status = audit.payload.get("status")
    return {
        "event_type": "agent.status_changed",
        "severity": "medium",
        "reason_code": "AGENT_DISABLED" if status == "disabled" else "AGENT_ACTIVATED",
        "agent_id": audit.subject_id,
        "attributes": {"status": status},
    }


def _grant(reason: str):
    def build(session: Session, audit: AuditEvent) -> dict[str, Any]:
        return {
            "event_type": "grant.changed",
            "severity": "medium",
            "reason_code": reason,
            "agent_id": audit.subject_id,
            "tool": audit.payload.get("tool"),
            "resource_id": _as_uuid(audit.payload.get("resource_id")),
        }

    return build


def _credential(reason: str):
    def build(session: Session, audit: AuditEvent) -> dict[str, Any]:
        return {
            "event_type": "credential.changed",
            "severity": "low",
            "reason_code": reason,
            "agent_id": _as_uuid(audit.payload.get("agent_id")),
        }

    return build


def _rule_changed(session: Session, audit: AuditEvent) -> dict[str, Any]:
    return {
        "event_type": "correlation.rule_changed",
        "severity": "medium",
        "reason_code": "RULE_CHANGED",
    }


# incident.* and investigation.* are deliberately absent, so incidents cannot feed correlation.
_BUILDERS: dict[str, Callable[[Session, AuditEvent], dict[str, Any] | None]] = {
    "action.decision": _decision,
    "approval.approved": _approval("approval.approved", "info", "APPROVAL_APPROVED"),
    "approval.rejected": _approval("approval.rejected", "low", "APPROVAL_REJECTED"),
    "approval.cancelled": _approval_cancelled,
    "approval.execution_refused": _execution_refused,
    "execution.succeeded": _execution,
    "execution.failed": _execution,
    "auth.agent_failed": _authentication("auth.agent_failed", "low", "AGENT_CREDENTIAL_INVALID"),
    "auth.login_failed": _authentication("auth.login_failed", "low", "LOGIN_FAILED"),
    "auth.token_rejected": _authentication("auth.token_rejected", "high", "TOKEN_SUBJECT_UNKNOWN"),
    "authz.denied": _authz_denied,
    "access.not_visible": _not_visible,
    "policy.version_created": _policy("policy.version_created"),
    "policy.activated": _policy("policy.activated"),
    "agent.status_changed": _agent_status,
    "grant.tool_added": _grant("GRANT_ADDED"),
    "grant.tool_removed": _grant("GRANT_REMOVED"),
    "grant.resource_added": _grant("GRANT_ADDED"),
    "grant.resource_removed": _grant("GRANT_REMOVED"),
    "credential.issued": _credential("CREDENTIAL_ISSUED"),
    "credential.revoked": _credential("CREDENTIAL_REVOKED"),
    "correlation.rule_version_created": _rule_changed,
}

PROJECTED_AUDIT_TYPES = frozenset(_BUILDERS)


def build_record(session: Session, audit: AuditEvent) -> SecurityEventRecord | None:
    builder = _BUILDERS.get(audit.event_type)
    fields = builder(session, audit) if builder else None
    if fields is None:
        return None
    agent_id = fields.get("agent_id")
    agent = session.get(Agent, agent_id) if agent_id else None
    return SecurityEventRecord(
        id=uuid5(_ID_NAMESPACE, str(audit.id)),
        tenant_id=audit.tenant_id,
        schema_version=SCHEMA_VERSION,
        occurred_at=audit.occurred_at,
        actor_type=audit.actor_type,
        actor_id=audit.actor_id,
        asset_id=agent.asset_id if agent else None,
        source_audit_event_id=audit.id,
        source_event_hash=audit.event_hash,
        **fields,
    )


def project_audit_event(session: Session, audit: AuditEvent) -> bool:
    """Write the event for this audit event. Returns False if unmapped or already present."""
    record = build_record(session, audit)
    if record is None:
        return False
    inserted = session.execute(
        insert(SecurityEvent)
        .values(**record.model_dump())
        .on_conflict_do_nothing()
        .returning(SecurityEvent.id)
    ).first()
    return inserted is not None


def reprojection_matches(session: Session, event: SecurityEvent) -> bool:
    """True only if the source audit event is intact and still produces this exact event."""
    from aegis.audit.chain import compute_event_hash  # chain imports this module to project

    audit = session.get(AuditEvent, event.source_audit_event_id)
    if audit is None or audit.event_hash != event.source_event_hash:
        return False
    if compute_event_hash(audit) != audit.event_hash:
        return False
    record = build_record(session, audit)
    if record is None:
        return False
    return all(getattr(event, name) == value for name, value in record.model_dump().items())
