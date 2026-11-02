from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.api.dependencies import (
    AdminDep,
    ContainerDep,
    LimitQuery,
    OffsetQuery,
    ReviewerDep,
    UserDep,
)
from aegis.api.routes_events import events_out
from aegis.api.schemas import (
    CorrelationRuleOut,
    IncidentDetailOut,
    IncidentOut,
    IncidentStatus,
    IncidentTransitionIn,
    IncidentTransitionOut,
    Page,
    RuleVersionIn,
    SecurityEventOut,
)
from aegis.correlation.store import create_rule_version, load_rules, parse_version
from aegis.db.models import (
    Agent,
    CorrelationRuleVersion,
    Incident,
    IncidentEvent,
    IncidentTransition,
    SecurityEvent,
    User,
)
from aegis.errors import NotFound
from aegis.events.schema import Severity
from aegis.incidents import service as incidents

router = APIRouter()


def _incident_or_404(session: Session, incident_id: UUID) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise NotFound()
    return incident


def _incident_fields(incident: Incident, agent_name: str | None, assignee: str | None) -> dict:
    return dict(
        id=incident.id,
        rule_version_id=incident.rule_version_id,
        rule_key=incident.rule_key,
        rule_version=incident.rule_version,
        scope_type=incident.scope_type,
        scope_key=incident.scope_key,
        agent_id=incident.agent_id,
        agent_name=agent_name,
        title=incident.title,
        severity=incident.severity,
        status=incident.status,
        version=incident.version,
        event_count=incident.event_count,
        first_observed_at=incident.first_observed_at,
        last_observed_at=incident.last_observed_at,
        assigned_to=incident.assigned_to,
        assigned_to_email=assignee,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


def _incident_query():
    return (
        select(Incident, Agent.name, User.email)
        .outerjoin(Agent, Agent.id == Incident.agent_id)
        .outerjoin(User, User.id == Incident.assigned_to)
    )


def _detail(session: Session, incident_id: UUID) -> IncidentDetailOut:
    row = session.execute(_incident_query().where(Incident.id == incident_id)).one_or_none()
    if row is None:
        raise NotFound()
    incident = row[0]
    transitions = session.execute(
        select(IncidentTransition)
        .where(IncidentTransition.incident_id == incident_id)
        .order_by(IncidentTransition.occurred_at, IncidentTransition.id)
    ).scalars()
    version = session.get(CorrelationRuleVersion, incident.rule_version_id)
    ordered = sorted(
        (IncidentTransitionOut.model_validate(item) for item in transitions),
        # A new incident's transitions can share a timestamp, so the chain position breaks the tie.
        key=lambda item: (item.occurred_at, item.from_status is not None),
    )
    return IncidentDetailOut(
        **_incident_fields(*row),
        transitions=ordered,
        rule_definition=parse_version(version).model_dump(mode="json", exclude_none=True),
    )


@router.get("/incidents", response_model=Page[IncidentOut])
def incidents_list(
    user: UserDep,
    container: ContainerDep,
    status: Annotated[IncidentStatus | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
    rule_key: Annotated[str | None, Query(max_length=64)] = None,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    conditions = []
    if status is not None:
        conditions.append(Incident.status == status)
    if severity is not None:
        conditions.append(Incident.severity == severity)
    if rule_key is not None:
        conditions.append(Incident.rule_key == rule_key)
    with container.db.tenant_transaction(user.tenant_id) as session:
        rows = session.execute(
            _incident_query()
            .where(*conditions)
            .order_by(Incident.last_observed_at.desc(), Incident.id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = session.execute(
            select(func.count()).select_from(Incident).where(*conditions)
        ).scalar_one()
        return Page[IncidentOut](
            items=[IncidentOut(**_incident_fields(*row)) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut)
def incidents_get(incident_id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _detail(session, incident_id)


@router.get("/incidents/{incident_id}/events", response_model=Page[SecurityEventOut])
def incidents_events(
    incident_id: UUID,
    user: UserDep,
    container: ContainerDep,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    with container.db.tenant_transaction(user.tenant_id) as session:
        incident = _incident_or_404(session, incident_id)
        rows = session.execute(
            select(SecurityEvent, Agent.name)
            .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.id)
            .outerjoin(Agent, Agent.id == SecurityEvent.agent_id)
            .where(IncidentEvent.incident_id == incident_id)
            .order_by(SecurityEvent.occurred_at, SecurityEvent.id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page[SecurityEventOut](
            items=events_out(session, rows),
            total=incident.event_count,
            limit=limit,
            offset=offset,
        )


def _move(
    container: ContainerDep, user, incident_id: UUID, verb: str, body: IncidentTransitionIn
) -> IncidentDetailOut:
    incidents.transition(
        container.db,
        user,
        incident_id,
        verb=verb,
        expected_version=body.expected_version,
        reason=body.reason,
        clock=container.clock,
    )
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _detail(session, incident_id)


@router.post("/incidents/{incident_id}/acknowledge", response_model=IncidentDetailOut)
def incidents_acknowledge(
    incident_id: UUID, body: IncidentTransitionIn, user: ReviewerDep, container: ContainerDep
):
    return _move(container, user, incident_id, "acknowledge", body)


@router.post("/incidents/{incident_id}/investigate", response_model=IncidentDetailOut)
def incidents_investigate(
    incident_id: UUID, body: IncidentTransitionIn, user: ReviewerDep, container: ContainerDep
):
    return _move(container, user, incident_id, "investigate", body)


@router.post("/incidents/{incident_id}/resolve", response_model=IncidentDetailOut)
def incidents_resolve(
    incident_id: UUID, body: IncidentTransitionIn, user: ReviewerDep, container: ContainerDep
):
    return _move(container, user, incident_id, "resolve", body)


@router.post("/incidents/{incident_id}/reopen", response_model=IncidentDetailOut)
def incidents_reopen(
    incident_id: UUID, body: IncidentTransitionIn, user: ReviewerDep, container: ContainerDep
):
    return _move(container, user, incident_id, "reopen", body)


@router.post("/incidents/{incident_id}/close", response_model=IncidentDetailOut)
def incidents_close(
    incident_id: UUID, body: IncidentTransitionIn, user: AdminDep, container: ContainerDep
):
    return _move(container, user, incident_id, "close", body)


# Correlation rules


def _rule_out(version: CorrelationRuleVersion) -> CorrelationRuleOut:
    return CorrelationRuleOut(
        rule_key=version.rule_key,
        version=version.version,
        version_id=version.id,
        content_hash=version.content_hash,
        definition=parse_version(version).model_dump(mode="json", exclude_none=True),
    )


@router.get("/correlation-rules", response_model=Page[CorrelationRuleOut])
def rules_list(user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        items = [
            _rule_out(item.version)
            for item in load_rules(session, user.tenant_id, container.clock())
        ]
        return Page[CorrelationRuleOut](items=items, total=len(items), limit=len(items), offset=0)


@router.post(
    "/correlation-rules/{rule_key}/versions", response_model=CorrelationRuleOut, status_code=201
)
def rules_new_version(
    rule_key: str, body: RuleVersionIn, user: AdminDep, container: ContainerDep
):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _rule_out(
            create_rule_version(session, user, rule_key, body.definition, container.clock())
        )
