"""Authorized incident state changes. Only human principals can reach this module's writes."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from aegis.audit.chain import append_event, lock_chain_head
from aegis.canonical import sha256_hex
from aegis.db.models import Incident, IncidentTransition
from aegis.db.session import Database
from aegis.errors import Conflict, NotFound, ValidationFailed
from aegis.incidents.state import can_transition
from aegis.security.principals import UserPrincipal


@dataclass(frozen=True)
class Verb:
    target: str
    reason_required: bool = False
    # Narrower than the state machine. Reopening is a distinct act that needs a stated reason, so
    # "investigate" cannot be used to move a resolved incident back.
    allowed_from: frozenset[str] | None = None


VERBS = {
    "acknowledge": Verb("ACKNOWLEDGED"),
    "investigate": Verb("INVESTIGATING", allowed_from=frozenset({"OPEN", "ACKNOWLEDGED"})),
    "resolve": Verb("RESOLVED", reason_required=True),
    "close": Verb("CLOSED", reason_required=True),
    "reopen": Verb("INVESTIGATING", reason_required=True, allowed_from=frozenset({"RESOLVED"})),
}


def transition(
    db: Database,
    user: UserPrincipal,
    incident_id: UUID,
    *,
    verb: str,
    expected_version: int,
    reason: str | None,
    clock: Callable[[], datetime],
) -> Incident:
    definition = VERBS[verb]
    reason = reason.strip() if reason else None
    if definition.reason_required and not reason:
        raise ValidationFailed("A reason is required for this change.")

    with db.tenant_transaction(user.tenant_id) as session:
        lock_chain_head(session, user.tenant_id)
        incident = session.execute(
            select(Incident).where(Incident.id == incident_id).with_for_update()
        ).scalar_one_or_none()
        if incident is None:
            raise NotFound()
        if incident.version != expected_version:
            raise Conflict(
                "This incident changed since you loaded it. Reload and try again.",
                code="INCIDENT_VERSION_CONFLICT",
            )
        previous = incident.status
        permitted = definition.allowed_from is None or previous in definition.allowed_from
        if not permitted or not can_transition(previous, definition.target):
            raise Conflict(
                f"An incident in state {previous} cannot be changed this way.",
                code="INVALID_STATE_TRANSITION",
            )

        now = clock()
        incident.status = definition.target
        incident.version += 1
        incident.updated_at = now
        if incident.assigned_to is None and definition.target in ("ACKNOWLEDGED", "INVESTIGATING"):
            incident.assigned_to = user.id
        try:
            session.flush()
        except IntegrityError as error:
            raise Conflict(
                "A newer active incident already covers this rule and scope.",
                code="ACTIVE_INCIDENT_EXISTS",
            ) from error

        audit = append_event(
            session,
            user.tenant_id,
            event_type="incident.status_changed",
            actor_type="user",
            actor_id=user.id,
            subject_type="incident",
            subject_id=incident.id,
            occurred_at=now,
            payload={
                "from_status": previous,
                "to_status": incident.status,
                # The reason is free text, so the chain binds to it without repeating it.
                **({"reason_sha256": sha256_hex(reason)} if reason else {}),
            },
        )
        session.add(
            IncidentTransition(
                id=uuid4(),
                tenant_id=user.tenant_id,
                incident_id=incident.id,
                from_status=previous,
                to_status=incident.status,
                actor_type="user",
                actor_id=user.id,
                reason=reason,
                occurred_at=now,
                audit_event_id=audit.id,
            )
        )
        session.flush()
        return incident
