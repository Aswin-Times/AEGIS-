"""Turn pending security events into incidents.

Runs after enforcement has committed and has no path back to it. Each event is handled in its
own transaction, so a retry or a crash can only repeat work that was rolled back.

Lock order, shared with incident state changes: the audit chain head, then the incident row.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event, lock_chain_head
from aegis.correlation.rules import find_qualifying_window, matches, scope_key
from aegis.correlation.store import LoadedRule, RuleIntegrityError, load_rules
from aegis.db.models import Incident, IncidentEvent, IncidentTransition, SecurityEvent
from aegis.db.session import Database
from aegis.incidents.state import ACTIVE_STATUSES

logger = logging.getLogger("aegis.correlation")

_MAX_CANDIDATES = 2_000
_MAX_CONFLICT_RETRIES = 5
_AUDITED_EVENT_IDS = 50


@dataclass(frozen=True)
class ProcessResult:
    processed: int
    incidents_created: int
    halted: bool


def pending_tenants(db: Database) -> list[UUID]:
    with db._sessions() as session, session.begin():
        return list(
            session.execute(text("SELECT aegis_tenants_with_pending_events()")).scalars()
        )


def _link(session: Session, incident: Incident, event_id: UUID) -> bool:
    inserted = session.execute(
        insert(IncidentEvent)
        .values(tenant_id=incident.tenant_id, incident_id=incident.id, event_id=event_id)
        .on_conflict_do_nothing()
        .returning(IncidentEvent.event_id)
    ).first()
    return inserted is not None


def _refresh_counts(session: Session, incident: Incident, now: datetime) -> None:
    first, last, count = session.execute(
        select(
            func.min(SecurityEvent.occurred_at),
            func.max(SecurityEvent.occurred_at),
            func.count(),
        )
        .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.id)
        .where(IncidentEvent.incident_id == incident.id)
    ).one()
    incident.first_observed_at = first
    incident.last_observed_at = last
    incident.event_count = count
    incident.updated_at = now
    session.flush()


def _attach(
    session: Session, incident: Incident, event: SecurityEvent, loaded: LoadedRule, now: datetime
) -> None:
    earliest = incident.first_observed_at - timedelta(seconds=loaded.rule.window_seconds)
    if event.occurred_at < earliest:
        return
    if _link(session, incident, event.id):
        _refresh_counts(session, incident, now)
        append_event(
            session,
            incident.tenant_id,
            event_type="incident.event_linked",
            actor_type="system",
            subject_type="incident",
            subject_id=incident.id,
            occurred_at=now,
            payload={"event_id": str(event.id)},
        )


def _create_incident(
    session: Session,
    loaded: LoadedRule,
    key: str,
    window: list[SecurityEvent],
    now: datetime,
) -> Incident:
    incident = Incident(
        id=uuid4(),
        tenant_id=window[0].tenant_id,
        rule_version_id=loaded.version.id,
        rule_key=loaded.version.rule_key,
        rule_version=loaded.version.version,
        scope_type=loaded.rule.scope,
        scope_key=key,
        agent_id=window[0].agent_id if loaded.rule.scope != "tenant" else None,
        title=loaded.rule.title,
        severity=loaded.rule.severity,
        status="OPEN",
        version=1,
        event_count=0,
        first_observed_at=window[0].occurred_at,
        last_observed_at=window[-1].occurred_at,
        created_at=now,
        updated_at=now,
    )
    session.add(incident)
    session.flush()
    for member in window:
        _link(session, incident, member.id)
    _refresh_counts(session, incident, now)
    audit = append_event(
        session,
        incident.tenant_id,
        event_type="incident.created",
        actor_type="system",
        subject_type="incident",
        subject_id=incident.id,
        occurred_at=now,
        payload={
            "rule_key": incident.rule_key,
            "rule_version": incident.rule_version,
            "rule_version_id": str(incident.rule_version_id),
            "event_count": incident.event_count,
            "source_event_ids": [str(member.id) for member in window[:_AUDITED_EVENT_IDS]],
        },
    )
    session.add(
        IncidentTransition(
            id=uuid4(),
            tenant_id=incident.tenant_id,
            incident_id=incident.id,
            from_status=None,
            to_status="OPEN",
            actor_type="system",
            reason=f"{incident.rule_key} v{incident.rule_version} matched",
            occurred_at=now,
            audit_event_id=audit.id,
        )
    )
    session.flush()
    return incident


def _unlinked_candidates(
    session: Session, loaded: LoadedRule, key: str, event: SecurityEvent
) -> list[SecurityEvent]:
    window = timedelta(seconds=loaded.rule.window_seconds)
    already_linked = (
        select(IncidentEvent.event_id)
        .join(Incident, Incident.id == IncidentEvent.incident_id)
        .where(Incident.rule_key == loaded.version.rule_key)
    )
    rows = session.execute(
        select(SecurityEvent)
        .where(
            SecurityEvent.event_type.in_(loaded.rule.match.event_types),
            SecurityEvent.occurred_at >= event.occurred_at - window,
            SecurityEvent.occurred_at <= event.occurred_at + window,
            SecurityEvent.id.not_in(already_linked),
        )
        .order_by(SecurityEvent.occurred_at)
        .limit(_MAX_CANDIDATES)
    ).scalars()
    return [
        row for row in rows if matches(loaded.rule, row) and scope_key(loaded.rule, row) == key
    ]


def _apply_rule(
    session: Session, loaded: LoadedRule, event: SecurityEvent, now: datetime
) -> bool:
    """Returns True if this created an incident."""
    key = scope_key(loaded.rule, event)
    if key is None:
        return False
    active = session.execute(
        select(Incident)
        .where(
            Incident.rule_key == loaded.version.rule_key,
            Incident.scope_key == key,
            Incident.status.in_(ACTIVE_STATUSES),
        )
        .with_for_update()
    ).scalar_one_or_none()
    if active is not None:
        _attach(session, active, event, loaded, now)
        return False

    window = find_qualifying_window(
        loaded.rule, _unlinked_candidates(session, loaded, key, event)
    )
    if window is None:
        return False
    incident = _create_incident(session, loaded, key, window, now)
    if all(member.id != event.id for member in window):
        _attach(session, incident, event, loaded, now)
    return True


def _process_next(db: Database, tenant_id: UUID, clock: Callable[[], datetime]) -> tuple[bool, int]:
    """Handle one pending event. Returns (an event was processed, incidents created)."""
    with db.tenant_transaction(tenant_id) as session:
        event = session.execute(
            select(SecurityEvent)
            .where(SecurityEvent.correlation_processed_at.is_(None))
            .order_by(SecurityEvent.occurred_at, SecurityEvent.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        ).scalar_one_or_none()
        if event is None:
            return False, 0

        lock_chain_head(session, tenant_id)
        now = clock()
        created = 0
        for loaded in load_rules(session, tenant_id, now):
            if loaded.rule.enabled and matches(loaded.rule, event):
                created += _apply_rule(session, loaded, event, now)
        event.correlation_processed_at = now
        session.flush()
        return True, created


def process_tenant(
    db: Database, tenant_id: UUID, *, clock: Callable[[], datetime], limit: int = 1_000
) -> ProcessResult:
    processed = 0
    created = 0
    conflicts = 0
    while processed < limit:
        try:
            handled, incidents = _process_next(db, tenant_id, clock)
        except IntegrityError:
            # Another worker won a race, and the unique index stopped a duplicate. Next time
            # this event finds that incident and attaches to it.
            conflicts += 1
            if conflicts > _MAX_CONFLICT_RETRIES:
                logger.exception("correlation kept conflicting")
                return ProcessResult(processed, created, halted=True)
            continue
        except RuleIntegrityError:
            logger.exception("correlation halted: a stored rule cannot be trusted")
            return ProcessResult(processed, created, halted=True)
        except Exception:
            logger.exception("correlation halted by an unexpected error")
            return ProcessResult(processed, created, halted=True)
        if not handled:
            break
        processed += 1
        created += incidents
    return ProcessResult(processed, created, halted=False)


def process_pending(db: Database, *, clock: Callable[[], datetime]) -> None:
    for tenant_id in pending_tenants(db):
        process_tenant(db, tenant_id, clock=clock)
