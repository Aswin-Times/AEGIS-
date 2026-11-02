"""Per-tenant hash-chained audit log.

The chain detects tampering. It does not prevent it, and an attacker with full control of
the database can rewrite a whole chain. See docs/SECURITY_BOUNDARIES.md.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.canonical import canonical_hash
from aegis.db.models import AuditChainHead, AuditEvent
from aegis.events.projection import project_audit_event

GENESIS_HASH = "0" * 64


def _reject_floats(value: Any) -> None:
    """JSONB may rewrite a float's text form, which would break hash verification."""
    if isinstance(value, float):
        raise TypeError("Audit payloads must not contain floats")
    if isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            _reject_floats(item)


def _text_or_none(value: UUID | None) -> str | None:
    return None if value is None else str(value)


def compute_event_hash(event: AuditEvent) -> str:
    return canonical_hash(
        {
            "id": str(event.id),
            "tenant_id": str(event.tenant_id),
            "seq": event.seq,
            "prev_hash": event.prev_hash,
            "event_type": event.event_type,
            "actor_type": event.actor_type,
            "actor_id": _text_or_none(event.actor_id),
            "correlation_id": _text_or_none(event.correlation_id),
            "subject_type": event.subject_type,
            "subject_id": _text_or_none(event.subject_id),
            "policy_version_id": _text_or_none(event.policy_version_id),
            "occurred_at": event.occurred_at.astimezone(UTC).isoformat(),
            "payload": event.payload,
        }
    )


def append_event(
    session: Session,
    tenant_id: UUID,
    *,
    event_type: str,
    actor_type: str,
    actor_id: UUID | None = None,
    correlation_id: UUID | None = None,
    subject_type: str | None = None,
    subject_id: UUID | None = None,
    policy_version_id: UUID | None = None,
    payload: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
) -> AuditEvent:
    """Append in the caller's transaction, so evidence commits with what it describes."""
    payload = payload or {}
    _reject_floats(payload)
    head = session.execute(
        select(AuditChainHead).where(AuditChainHead.tenant_id == tenant_id).with_for_update()
    ).scalar_one()
    event = AuditEvent(
        id=uuid4(),
        tenant_id=tenant_id,
        seq=head.seq + 1,
        prev_hash=head.head_hash,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        correlation_id=correlation_id,
        subject_type=subject_type,
        subject_id=subject_id,
        policy_version_id=policy_version_id,
        occurred_at=occurred_at or datetime.now(UTC),
        payload=payload,
    )
    event.event_hash = compute_event_hash(event)
    session.add(event)
    head.seq = event.seq
    head.head_hash = event.event_hash
    session.flush()
    project_audit_event(session, event)
    return event


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    events_checked: int
    head_seq: int
    head_hash: str
    failure_seq: int | None = None
    failure_reason: str | None = None


def verify_chain(session: Session, tenant_id: UUID) -> ChainVerification:
    """Walk the whole chain. Holding the head lock keeps appends out during the walk."""
    head = session.execute(
        select(AuditChainHead).where(AuditChainHead.tenant_id == tenant_id).with_for_update(
            read=True
        )
    ).scalar_one()

    def result(checked: int, seq: int | None = None, reason: str | None = None):
        return ChainVerification(
            valid=reason is None,
            events_checked=checked,
            head_seq=head.seq,
            head_hash=head.head_hash,
            failure_seq=seq,
            failure_reason=reason,
        )

    expected_seq = 1
    previous_hash = GENESIS_HASH
    checked = 0
    events = session.execute(
        select(AuditEvent)
        .where(AuditEvent.tenant_id == tenant_id)
        .order_by(AuditEvent.seq)
        .execution_options(yield_per=500)
    ).scalars()
    for event in events:
        if event.seq != expected_seq:
            return result(checked, expected_seq, "MISSING_EVENT")
        if event.prev_hash != previous_hash:
            return result(checked, event.seq, "BROKEN_LINK")
        if compute_event_hash(event) != event.event_hash:
            return result(checked, event.seq, "CONTENT_MODIFIED")
        previous_hash = event.event_hash
        expected_seq += 1
        checked += 1

    if checked != head.seq:
        return result(checked, checked + 1, "MISSING_TAIL")
    if previous_hash != head.head_hash:
        return result(checked, head.seq, "HEAD_MISMATCH")
    return result(checked)
