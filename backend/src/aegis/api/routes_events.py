"""Security events are read-only over HTTP. They originate only in trusted backend code."""

from collections.abc import Sequence
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.api.dependencies import ContainerDep, LimitQuery, OffsetQuery, UserDep
from aegis.api.schemas import Page, SecurityEventOut
from aegis.db.models import Agent, IncidentEvent, SecurityEvent
from aegis.errors import NotFound
from aegis.events.schema import EventType, Severity

router = APIRouter()


def events_out(session: Session, rows: Sequence[Any]) -> list[SecurityEventOut]:
    """Rows of (event, agent name), with the incidents each event belongs to."""
    links: dict[UUID, list[UUID]] = {}
    for event_id, incident_id in session.execute(
        select(IncidentEvent.event_id, IncidentEvent.incident_id).where(
            IncidentEvent.event_id.in_([row[0].id for row in rows])
        )
    ).all():
        links.setdefault(event_id, []).append(incident_id)
    return [
        SecurityEventOut.model_validate(event).model_copy(
            update={"agent_name": agent_name, "incident_ids": links.get(event.id, [])}
        )
        for event, agent_name in rows
    ]


@router.get("/events", response_model=Page[SecurityEventOut])
def events_list(
    user: UserDep,
    container: ContainerDep,
    event_type: Annotated[EventType | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    conditions = []
    if event_type is not None:
        conditions.append(SecurityEvent.event_type == event_type)
    if severity is not None:
        conditions.append(SecurityEvent.severity == severity)
    if agent_id is not None:
        conditions.append(SecurityEvent.agent_id == agent_id)
    with container.db.tenant_transaction(user.tenant_id) as session:
        rows = session.execute(
            select(SecurityEvent, Agent.name)
            .outerjoin(Agent, Agent.id == SecurityEvent.agent_id)
            .where(*conditions)
            .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = session.execute(
            select(func.count()).select_from(SecurityEvent).where(*conditions)
        ).scalar_one()
        return Page[SecurityEventOut](
            items=events_out(session, rows), total=total, limit=limit, offset=offset
        )


@router.get("/events/{event_id}", response_model=SecurityEventOut)
def events_get(event_id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        row = session.execute(
            select(SecurityEvent, Agent.name)
            .outerjoin(Agent, Agent.id == SecurityEvent.agent_id)
            .where(SecurityEvent.id == event_id)
        ).one_or_none()
        if row is None:
            raise NotFound()
        return events_out(session, [row])[0]
