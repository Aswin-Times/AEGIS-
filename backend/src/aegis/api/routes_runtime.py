"""Auth, the agent gateway, approvals, and the read side (decisions, audit, overview)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from aegis.api.dependencies import (
    AgentDep,
    ContainerDep,
    LimitQuery,
    OffsetQuery,
    ReviewerDep,
    UserDep,
)
from aegis.api.schemas import (
    ActionIn,
    ActionOut,
    ApprovalDecisionIn,
    ApprovalOut,
    ApprovalStatus,
    AuditEventOut,
    AuditHeadOut,
    AuditVerificationOut,
    DecisionDetailOut,
    DecisionExecutionOut,
    DecisionOut,
    LoginIn,
    MeOut,
    Outcome,
    OverviewOut,
    Page,
    TokenOut,
)
from aegis.approvals import service as approvals
from aegis.audit.chain import verify_chain
from aegis.db.models import (
    Agent,
    AiAsset,
    Approval,
    AuditChainHead,
    AuditEvent,
    Execution,
    PolicyDecision,
    Tenant,
)
from aegis.errors import NotFound
from aegis.gateway import service as gateway
from aegis.security.authentication import login

router = APIRouter()


# Auth


@router.post("/auth/login", response_model=TokenOut)
def auth_login(body: LoginIn, container: ContainerDep):
    token = login(
        container.db,
        container.tokens,
        tenant_slug=body.tenant_slug,
        email=body.email,
        password=body.password,
        now=container.clock(),
    )
    return TokenOut(access_token=token, expires_in=container.tokens.ttl_seconds)


@router.get("/auth/me", response_model=MeOut)
def auth_me(user: UserDep):
    return MeOut(id=user.id, tenant_id=user.tenant_id, email=user.email, role=user.role)


# Gateway


@router.post("/gateway/actions", response_model=ActionOut)
def gateway_submit(body: ActionIn, agent: AgentDep, container: ContainerDep):
    return gateway.submit_action(
        container.db,
        container.tools,
        agent,
        idempotency_key=body.idempotency_key,
        tool=body.tool,
        resource_id=body.resource_id,
        params=body.params,
        clock=container.clock,
        approval_ttl_seconds=container.settings.approval_ttl_seconds,
    )


@router.get("/gateway/actions/{request_id}", response_model=ActionOut)
def gateway_get(request_id: UUID, agent: AgentDep, container: ContainerDep):
    return gateway.get_action(container.db, agent, request_id)


@router.post("/gateway/actions/{request_id}/execute", response_model=ActionOut)
def gateway_execute(request_id: UUID, agent: AgentDep, container: ContainerDep):
    return gateway.execute_approved(
        container.db, container.tools, agent, request_id, clock=container.clock
    )


# Approvals


@router.get("/approvals", response_model=Page[ApprovalOut])
def approvals_list(
    user: UserDep,
    container: ContainerDep,
    status: Annotated[ApprovalStatus | None, Query()] = None,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    with container.db.tenant_transaction(user.tenant_id) as session:
        items, total = approvals.list_approvals(session, status=status, limit=limit, offset=offset)
    return Page[ApprovalOut](
        items=[ApprovalOut.model_validate(item) for item in items],
        total=total, limit=limit, offset=offset,
    )


@router.get("/approvals/{approval_id}", response_model=ApprovalOut)
def approvals_get(approval_id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return ApprovalOut.model_validate(approvals.get_approval(session, approval_id))


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalOut)
def approvals_approve(approval_id: UUID, body: ApprovalDecisionIn, user: ReviewerDep,
                      container: ContainerDep):
    return approvals.decide(
        container.db, user, approval_id, target="APPROVED", comment=body.comment,
        clock=container.clock,
    )


@router.post("/approvals/{approval_id}/reject", response_model=ApprovalOut)
def approvals_reject(approval_id: UUID, body: ApprovalDecisionIn, user: ReviewerDep,
                     container: ContainerDep):
    return approvals.decide(
        container.db, user, approval_id, target="REJECTED", comment=body.comment,
        clock=container.clock,
    )


# Decisions


def _decision_query():
    return (
        select(PolicyDecision, Agent.name, Execution)
        .join(Agent, Agent.id == PolicyDecision.agent_id)
        .outerjoin(Execution, Execution.request_id == PolicyDecision.request_id)
    )


def _decision_fields(decision: PolicyDecision, agent_name: str, execution: Execution | None):
    return dict(
        id=decision.id,
        request_id=decision.request_id,
        agent_id=decision.agent_id,
        agent_name=agent_name,
        resource_id=decision.resource_id,
        tool=decision.tool,
        action=decision.action,
        policy_id=decision.policy_id,
        policy_version_id=decision.policy_version_id,
        policy_version=decision.policy_version,
        outcome=decision.outcome,
        reason_code=decision.reason_code,
        matched_rule_id=decision.matched_rule_id,
        evaluated_at=decision.evaluated_at,
        tool_executed=execution is not None,
        execution=DecisionExecutionOut.model_validate(execution) if execution else None,
    )


@router.get("/decisions", response_model=Page[DecisionOut])
def decisions_list(
    user: UserDep,
    container: ContainerDep,
    outcome: Annotated[Outcome | None, Query()] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    query = _decision_query()
    count = select(func.count()).select_from(PolicyDecision)
    if outcome is not None:
        query = query.where(PolicyDecision.outcome == outcome)
        count = count.where(PolicyDecision.outcome == outcome)
    if agent_id is not None:
        query = query.where(PolicyDecision.agent_id == agent_id)
        count = count.where(PolicyDecision.agent_id == agent_id)
    with container.db.tenant_transaction(user.tenant_id) as session:
        rows = session.execute(
            query.order_by(PolicyDecision.evaluated_at.desc()).limit(limit).offset(offset)
        ).all()
        total = session.execute(count).scalar_one()
        return Page[DecisionOut](
            items=[DecisionOut(**_decision_fields(*row)) for row in rows],
            total=total, limit=limit, offset=offset,
        )


@router.get("/decisions/{decision_id}", response_model=DecisionDetailOut)
def decisions_get(decision_id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        row = session.execute(
            _decision_query().where(PolicyDecision.id == decision_id)
        ).one_or_none()
        if row is None:
            raise NotFound()
        event_ids = session.execute(
            select(AuditEvent.id)
            .where(AuditEvent.correlation_id == row[0].request_id)
            .order_by(AuditEvent.seq)
        ).scalars().all()
        return DecisionDetailOut(
            **_decision_fields(*row), evidence=row[0].evidence, audit_event_ids=list(event_ids)
        )


# Audit. There are deliberately no routes that change events.


@router.get("/audit/events", response_model=Page[AuditEventOut])
def audit_events(user: UserDep, container: ContainerDep, limit: LimitQuery = 50,
                 offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        items = session.execute(
            select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(limit).offset(offset)
        ).scalars()
        total = session.execute(select(func.count()).select_from(AuditEvent)).scalar_one()
        return Page[AuditEventOut](
            items=[AuditEventOut.model_validate(item) for item in items],
            total=total, limit=limit, offset=offset,
        )


@router.get("/audit/head", response_model=AuditHeadOut)
def audit_head(user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return AuditHeadOut.model_validate(session.get(AuditChainHead, user.tenant_id))


@router.post("/audit/verify", response_model=AuditVerificationOut)
def audit_verify(user: ReviewerDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return AuditVerificationOut.model_validate(verify_chain(session, user.tenant_id))


# Overview. Every number is a count of stored records.


@router.get("/overview", response_model=OverviewOut)
def overview(user: UserDep, container: ContainerDep):
    def count(session, model, *conditions) -> int:
        return session.execute(
            select(func.count()).select_from(model).where(*conditions)
        ).scalar_one()

    with container.db.tenant_transaction(user.tenant_id) as session:
        decisions = {"ALLOW": 0, "DENY": 0, "REQUIRE_APPROVAL": 0}
        for outcome, total in session.execute(
            select(PolicyDecision.outcome, func.count()).group_by(PolicyDecision.outcome)
        ).all():
            decisions[outcome] = total
        return OverviewOut(
            assets=count(session, AiAsset),
            synthetic_assets=count(session, AiAsset, AiAsset.is_synthetic.is_(True)),
            agents=count(session, Agent),
            agents_disabled=count(session, Agent, Agent.status == "disabled"),
            decisions=decisions,
            pending_approvals=count(session, Approval, Approval.status == "PENDING"),
            executions=count(session, Execution),
            audit_events=count(session, AuditEvent),
            active_policy_version_id=session.get(
                Tenant, user.tenant_id
            ).active_policy_version_id,
        )
