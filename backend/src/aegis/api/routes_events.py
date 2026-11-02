"""Security events are read-only over HTTP. They originate only in trusted backend code."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from aegis.api.dependencies import ContainerDep, LimitQuery, OffsetQuery, UserDep
from aegis.api.schemas import Page, SecurityEventOut
from aegis.db.models import Agent, SecurityEvent
from aegis.errors import NotFound
from aegis.events.schema import EventType, Severity

router = APIRouter()


def _event_out(event: SecurityEvent, agent_name: str | None) -> SecurityEventOut:
    return SecurityEventOut.model_validate(event).model_copy(update={"agent_name": agent_name})


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
            items=[_event_out(*row) for row in rows], total=total, limit=limit, offset=offset
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
        return _event_out(*row)
