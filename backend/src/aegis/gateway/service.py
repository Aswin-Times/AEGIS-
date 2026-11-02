"""The protected action flow.

Nothing reaches the tool executor except through a claim, and a claim exists only after the
allow decision, its audit evidence, and the execution row have committed.
"""

import json
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.canonical import canonical_hash, canonical_json, sha256_hex
from aegis.db.models import (
    ActionRequest,
    Agent,
    AgentResourceGrant,
    AgentToolGrant,
    Approval,
    Execution,
    PolicyDecision,
    PolicyVersion,
    Resource,
    Tenant,
)
from aegis.db.session import Database
from aegis.errors import AegisError, Conflict, NotFound, ServiceUnavailable
from aegis.gateway.executor import ExecutionClaim, ToolExecutor
from aegis.gateway.tools import ToolFailure, ToolRegistry
from aegis.policy.engine import (
    ActionFacts,
    AttachmentFacts,
    Evaluation,
    Outcome,
    PolicyUnavailable,
    ResourceFacts,
    evaluate,
)
from aegis.policy.schema import PolicyDocument
from aegis.security.principals import AgentPrincipal

logger = logging.getLogger("aegis.gateway")


@dataclass(frozen=True)
class ExecutionView:
    status: str
    result: dict[str, Any] | None


@dataclass(frozen=True)
class ActionResult:
    request_id: UUID
    outcome: str
    reason_code: str
    decision_id: UUID
    policy_version_id: UUID | None
    approval_id: UUID | None
    approval_status: str | None
    execution: ExecutionView | None


@dataclass(frozen=True)
class LoadedPolicy:
    document: PolicyDocument | PolicyUnavailable
    version: PolicyVersion | None


def compute_action_hash(
    tenant_id: UUID, agent_id: UUID, tool: str, resource_id: UUID | None, params_canonical: str
) -> str:
    """Binds an approval to one exact action. params_canonical is hashed as stored text."""
    return canonical_hash(
        {
            "tenant_id": str(tenant_id),
            "agent_id": str(agent_id),
            "tool": tool,
            "resource_id": None if resource_id is None else str(resource_id),
            "params_sha256": sha256_hex(params_canonical),
        }
    )


def _load_policy(session: Session, tenant_id: UUID) -> LoadedPolicy:
    tenant = session.get(Tenant, tenant_id)
    if tenant is None or tenant.active_policy_version_id is None:
        return LoadedPolicy(PolicyUnavailable("NO_ACTIVE_POLICY"), None)
    version = session.get(PolicyVersion, tenant.active_policy_version_id)
    if version is None or sha256_hex(version.document_canonical) != version.content_hash:
        logger.error("policy content hash mismatch", extra={"tenant_id": str(tenant_id)})
        return LoadedPolicy(PolicyUnavailable("POLICY_INVALID"), version)
    try:
        document = PolicyDocument.model_validate(json.loads(version.document_canonical))
    except (ValidationError, ValueError):
        logger.exception("stored policy failed validation")
        return LoadedPolicy(PolicyUnavailable("POLICY_INVALID"), version)
    return LoadedPolicy(document, version)


def _load_facts(
    session: Session,
    registry: ToolRegistry,
    tenant_id: UUID,
    agent_id: UUID,
    tool_name: str,
    resource_id: UUID | None,
    params: dict[str, Any],
) -> ActionFacts:
    # The share lock stops a concurrent disable from committing during this evaluation.
    agent = session.execute(
        select(Agent).where(Agent.id == agent_id).with_for_update(read=True)
    ).scalar_one_or_none()
    definition = registry.get(tool_name)

    parsed = None
    if definition is not None:
        try:
            parsed = definition.params_model.model_validate(params)
        except ValidationError:
            parsed = None

    def is_granted(resource: UUID) -> bool:
        return session.get(AgentResourceGrant, (tenant_id, agent_id, resource)) is not None

    resource_facts = None
    if resource_id is not None:
        resource = session.get(Resource, resource_id)
        if resource is not None:
            resource_facts = ResourceFacts(
                kind=resource.kind,
                classification=resource.classification,
                clearance=resource.clearance,
                granted=is_granted(resource.id),
            )

    attachment_facts = None
    attachment_id = getattr(parsed, "attachment_resource_id", None)
    if attachment_id is not None:
        # A resource in another tenant looks identical to one that does not exist.
        attachment = session.get(Resource, attachment_id)
        attachment_facts = AttachmentFacts(
            classification=attachment.classification if attachment else None,
            granted=attachment is not None and is_granted(attachment.id),
        )

    return ActionFacts(
        agent_active=agent is not None and agent.status == "active",
        tool=tool_name,
        tool_known=definition is not None,
        action=definition.action if definition else None,
        tool_granted=session.get(AgentToolGrant, (tenant_id, agent_id, tool_name)) is not None,
        params_valid=parsed is not None,
        required_resource_kind=definition.resource_kind if definition else None,
        resource_id_supplied=resource_id is not None,
        resource=resource_facts,
        attachment=attachment_facts,
    )


def _safe_evaluate(facts: ActionFacts, policy: PolicyDocument | PolicyUnavailable) -> Evaluation:
    try:
        return evaluate(facts, policy)
    except Exception:
        logger.exception("policy evaluation failed")
        return Evaluation(Outcome.DENY, "POLICY_EVALUATION_ERROR")


def _references_invisible_id(facts: ActionFacts) -> bool:
    """An ID that may be another tenant's. RLS makes that and a typo indistinguishable."""
    missing_resource = facts.resource_id_supplied and facts.resource is None
    missing_attachment = facts.attachment is not None and facts.attachment.classification is None
    return missing_resource or missing_attachment


def _record_decision(
    session: Session,
    request: ActionRequest,
    facts: ActionFacts,
    loaded: LoadedPolicy,
    evaluation: Evaluation,
    now: datetime,
) -> PolicyDecision:
    version = loaded.version
    decision = PolicyDecision(
        id=uuid4(),
        tenant_id=request.tenant_id,
        request_id=request.id,
        agent_id=request.agent_id,
        resource_id=request.resource_id,
        tool=request.tool,
        action=request.action,
        policy_id=version.policy_id if version else None,
        policy_version_id=version.id if version else None,
        policy_version=version.version if version else None,
        outcome=evaluation.outcome.value,
        reason_code=evaluation.reason_code,
        matched_rule_id=evaluation.matched_rule_id,
        evaluated_at=now,
        evidence={"facts": asdict(facts), "action_hash": request.action_hash},
    )
    session.add(decision)
    session.flush()
    append_event(
        session,
        request.tenant_id,
        event_type="action.decision",
        actor_type="agent",
        actor_id=request.agent_id,
        correlation_id=request.id,
        subject_type="policy_decision",
        subject_id=decision.id,
        policy_version_id=decision.policy_version_id,
        occurred_at=now,
        payload={
            "decision_id": str(decision.id),
            "tool": request.tool,
            "resource_id": None if request.resource_id is None else str(request.resource_id),
            "outcome": decision.outcome,
            "reason_code": decision.reason_code,
            "matched_rule_id": decision.matched_rule_id,
            "action_hash": request.action_hash,
            **({"not_visible_reference": True} if _references_invisible_id(facts) else {}),
        },
    )
    return decision


def _claim_execution(session: Session, request: ActionRequest, now: datetime) -> ExecutionClaim:
    """Writes the row whose unique constraint guarantees at-most-once execution."""
    execution = Execution(
        id=uuid4(),
        tenant_id=request.tenant_id,
        request_id=request.id,
        status="STARTED",
        started_at=now,
    )
    session.add(execution)
    session.flush()
    append_event(
        session,
        request.tenant_id,
        event_type="execution.started",
        actor_type="agent",
        actor_id=request.agent_id,
        correlation_id=request.id,
        subject_type="execution",
        subject_id=execution.id,
        occurred_at=now,
        payload={"tool": request.tool},
    )
    return ExecutionClaim(
        execution_id=execution.id,
        tenant_id=request.tenant_id,
        request_id=request.id,
        tool=request.tool,
        resource_id=request.resource_id,
        params=json.loads(request.params_canonical),
    )


def _run_claim(
    db: Database,
    registry: ToolRegistry,
    claim: ExecutionClaim,
    agent_id: UUID,
    clock: Callable[[], datetime],
) -> ExecutionView:
    executor = ToolExecutor(registry)
    with db.tenant_transaction(claim.tenant_id) as session:
        result = None
        error_type = None
        try:
            # A failing tool rolls back to here, so its partial writes never persist.
            with session.begin_nested():
                result = executor.run(claim, session)
        except ToolFailure:
            error_type = "ToolFailure"
        except Exception:
            logger.exception("tool raised an unexpected error", extra={"tool": claim.tool})
            error_type = "UnexpectedToolError"

        now = clock()
        status = "FAILED" if error_type else "SUCCEEDED"
        execution = session.get(Execution, claim.execution_id)
        execution.status = status
        execution.result = result
        execution.finished_at = now
        append_event(
            session,
            claim.tenant_id,
            event_type=f"execution.{status.lower()}",
            actor_type="agent",
            actor_id=agent_id,
            correlation_id=claim.request_id,
            subject_type="execution",
            subject_id=claim.execution_id,
            occurred_at=now,
            payload={"tool": claim.tool, **({"error_type": error_type} if error_type else {})},
        )
    return ExecutionView(status=status, result=result)


def _load_result(session: Session, request: ActionRequest) -> ActionResult:
    decision = session.execute(
        select(PolicyDecision)
        .where(PolicyDecision.request_id == request.id)
        .order_by(PolicyDecision.evaluated_at.desc())
        .limit(1)
    ).scalar_one()
    approval = session.execute(
        select(Approval).where(Approval.request_id == request.id)
    ).scalar_one_or_none()
    execution = session.execute(
        select(Execution).where(Execution.request_id == request.id)
    ).scalar_one_or_none()
    return ActionResult(
        request_id=request.id,
        outcome=decision.outcome,
        reason_code=decision.reason_code,
        decision_id=decision.id,
        policy_version_id=decision.policy_version_id,
        approval_id=approval.id if approval else None,
        approval_status=approval.status if approval else None,
        execution=ExecutionView(execution.status, execution.result) if execution else None,
    )


def submit_action(
    db: Database,
    registry: ToolRegistry,
    agent: AgentPrincipal,
    *,
    idempotency_key: str,
    tool: str,
    resource_id: UUID | None,
    params: dict[str, Any],
    clock: Callable[[], datetime],
    approval_ttl_seconds: int,
) -> ActionResult:
    params_canonical = canonical_json(params)
    action_hash = compute_action_hash(
        agent.tenant_id, agent.id, tool, resource_id, params_canonical
    )
    try:
        return _decide_and_execute(
            db, registry, agent, idempotency_key, tool, resource_id, params, params_canonical,
            action_hash, clock, approval_ttl_seconds,
        )
    except IntegrityError:
        # A concurrent request with the same key won the race, so return its result.
        replay = _replay(db, agent, idempotency_key, action_hash)
        if replay is None:
            logger.exception("integrity error with no matching request")
            raise ServiceUnavailable() from None
        return replay
    except AegisError:
        raise
    except Exception as error:
        logger.exception("protected action failed closed")
        raise ServiceUnavailable() from error


def _existing_request(
    session: Session, agent: AgentPrincipal, idempotency_key: str, action_hash: str
) -> ActionRequest | None:
    existing = session.execute(
        select(ActionRequest).where(
            ActionRequest.agent_id == agent.id,
            ActionRequest.idempotency_key == idempotency_key,
        )
    ).scalar_one_or_none()
    if existing is not None and existing.action_hash != action_hash:
        raise Conflict(
            "This idempotency key was already used for a different action.",
            code="IDEMPOTENCY_CONFLICT",
        )
    return existing


def _replay(
    db: Database, agent: AgentPrincipal, idempotency_key: str, action_hash: str
) -> ActionResult | None:
    with db.tenant_transaction(agent.tenant_id) as session:
        existing = _existing_request(session, agent, idempotency_key, action_hash)
        return _load_result(session, existing) if existing else None


def _decide_and_execute(
    db, registry, agent, idempotency_key, tool, resource_id, params, params_canonical,
    action_hash, clock, approval_ttl_seconds,
) -> ActionResult:
    claim = None
    with db.tenant_transaction(agent.tenant_id) as session:
        existing = _existing_request(session, agent, idempotency_key, action_hash)
        if existing is not None:
            return _load_result(session, existing)

        now = clock()
        facts = _load_facts(
            session, registry, agent.tenant_id, agent.id, tool, resource_id, params
        )
        loaded = _load_policy(session, agent.tenant_id)
        evaluation = _safe_evaluate(facts, loaded.document)

        request = ActionRequest(
            id=uuid4(),
            tenant_id=agent.tenant_id,
            agent_id=agent.id,
            idempotency_key=idempotency_key,
            tool=tool,
            action=facts.action,
            resource_id=resource_id,
            params_canonical=params_canonical,
            action_hash=action_hash,
        )
        session.add(request)
        session.flush()
        decision = _record_decision(session, request, facts, loaded, evaluation, now)

        approval = None
        if evaluation.outcome is Outcome.REQUIRE_APPROVAL:
            approval = Approval(
                id=uuid4(),
                tenant_id=agent.tenant_id,
                request_id=request.id,
                decision_id=decision.id,
                action_hash=action_hash,
                status="PENDING",
                requested_at=now,
                expires_at=now + timedelta(seconds=approval_ttl_seconds),
            )
            session.add(approval)
            session.flush()
            append_event(
                session,
                agent.tenant_id,
                event_type="approval.requested",
                actor_type="agent",
                actor_id=agent.id,
                correlation_id=request.id,
                subject_type="approval",
                subject_id=approval.id,
                policy_version_id=decision.policy_version_id,
                occurred_at=now,
                payload={"action_hash": action_hash},
            )
        elif evaluation.outcome is Outcome.ALLOW:
            claim = _claim_execution(session, request, now)

    execution = None
    if claim is not None:
        execution = _run_claim(db, registry, claim, agent.id, clock)

    return ActionResult(
        request_id=request.id,
        outcome=decision.outcome,
        reason_code=decision.reason_code,
        decision_id=decision.id,
        policy_version_id=decision.policy_version_id,
        approval_id=approval.id if approval else None,
        approval_status=approval.status if approval else None,
        execution=execution,
    )


def get_action(db: Database, agent: AgentPrincipal, request_id: UUID) -> ActionResult:
    with db.tenant_transaction(agent.tenant_id) as session:
        request = session.get(ActionRequest, request_id)
        if request is None or request.agent_id != agent.id:
            raise NotFound()
        return _load_result(session, request)


def _cancel(
    session: Session, approval: Approval, reason: str, agent_id: UUID, now: datetime
) -> None:
    approval.status = "CANCELLED"
    session.flush()
    append_event(
        session,
        approval.tenant_id,
        event_type="approval.cancelled",
        actor_type="agent",
        actor_id=agent_id,
        correlation_id=approval.request_id,
        subject_type="approval",
        subject_id=approval.id,
        occurred_at=now,
        payload={"reason": reason},
    )


def execute_approved(
    db: Database,
    registry: ToolRegistry,
    agent: AgentPrincipal,
    request_id: UUID,
    *,
    clock: Callable[[], datetime],
) -> ActionResult:
    """Consume an approval. Parameters come only from the stored request."""
    try:
        return _execute_approved(db, registry, agent, request_id, clock)
    except AegisError:
        raise
    except Exception as error:
        logger.exception("approved execution failed closed")
        raise ServiceUnavailable() from error


def _refusal_reason(approval: Approval | None) -> str:
    if approval is None:
        return "NO_APPROVAL"
    return {
        "PENDING": "APPROVAL_PENDING",
        "REJECTED": "APPROVAL_REJECTED",
        "EXECUTED": "APPROVAL_ALREADY_USED",
        "CANCELLED": "APPROVAL_CANCELLED",
    }[approval.status]


def _execute_approved(db, registry, agent, request_id, clock) -> ActionResult:
    refused = None
    claim = None
    with db.tenant_transaction(agent.tenant_id) as session:
        request = session.get(ActionRequest, request_id)
        if request is None or request.agent_id != agent.id:
            raise NotFound()
        # The row lock serializes concurrent decisions and executions of this approval.
        approval = session.execute(
            select(Approval).where(Approval.request_id == request.id).with_for_update()
        ).scalar_one_or_none()
        now = clock()
        if approval is None or approval.status != "APPROVED":
            append_event(
                session,
                agent.tenant_id,
                event_type="approval.execution_refused",
                actor_type="agent",
                actor_id=agent.id,
                correlation_id=request.id,
                subject_type="action_request",
                subject_id=request.id,
                occurred_at=now,
                payload={
                    "reason": _refusal_reason(approval),
                    "approval_id": None if approval is None else str(approval.id),
                },
            )
            refused = "NOT_EXECUTABLE"
        else:
            recomputed = compute_action_hash(
                request.tenant_id, request.agent_id, request.tool, request.resource_id,
                request.params_canonical,
            )
            if now >= approval.expires_at:
                refused = "APPROVAL_EXPIRED"
            elif recomputed != approval.action_hash or recomputed != request.action_hash:
                refused = "ACTION_HASH_MISMATCH"
            else:
                # Re-check against current state: grants, agent status, and the active policy
                # may all have changed since the approval.
                facts = _load_facts(
                    session, registry, request.tenant_id, request.agent_id, request.tool,
                    request.resource_id, json.loads(request.params_canonical),
                )
                loaded = _load_policy(session, request.tenant_id)
                evaluation = _safe_evaluate(facts, loaded.document)
                _record_decision(session, request, facts, loaded, evaluation, now)
                if evaluation.outcome is Outcome.DENY:
                    refused = evaluation.reason_code
            if refused is not None:
                _cancel(session, approval, refused, agent.id, now)

        if refused is None:
            approval.status = "EXECUTED"
            session.flush()
            claim = _claim_execution(session, request, now)

    if refused == "NOT_EXECUTABLE":
        raise Conflict(
            "This action does not have an approval that can be used.",
            code="APPROVAL_NOT_EXECUTABLE",
        )
    if refused is not None:
        raise Conflict(
            "The approval is no longer valid for this action.",
            code="APPROVAL_NOT_EXECUTABLE",
        )

    _run_claim(db, registry, claim, agent.id, clock)
    with db.tenant_transaction(agent.tenant_id) as session:
        return _load_result(session, session.get(ActionRequest, request_id))
