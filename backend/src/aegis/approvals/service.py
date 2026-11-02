import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.approvals.state import can_transition
from aegis.audit.chain import append_event
from aegis.db.models import ActionRequest, Approval
from aegis.db.session import Database
from aegis.errors import Conflict, NotFound
from aegis.security.principals import UserPrincipal


@dataclass(frozen=True)
class ApprovalView:
    id: UUID
    request_id: UUID
    decision_id: UUID
    agent_id: UUID
    tool: str
    action: str | None
    resource_id: UUID | None
    params: dict[str, Any]
    action_hash: str
    status: str
    requested_at: datetime
    expires_at: datetime
    decided_by: UUID | None
    decided_at: datetime | None
    comment: str | None


def _view(approval: Approval, request: ActionRequest) -> ApprovalView:
    return ApprovalView(
        id=approval.id,
        request_id=approval.request_id,
        decision_id=approval.decision_id,
        agent_id=request.agent_id,
        tool=request.tool,
        action=request.action,
        resource_id=request.resource_id,
        params=json.loads(request.params_canonical),
        action_hash=approval.action_hash,
        status=approval.status,
        requested_at=approval.requested_at,
        expires_at=approval.expires_at,
        decided_by=approval.decided_by,
        decided_at=approval.decided_at,
        comment=approval.comment,
    )


def list_approvals(
    session: Session, *, status: str | None, limit: int, offset: int
) -> tuple[list[ApprovalView], int]:
    query = select(Approval, ActionRequest).join(
        ActionRequest, ActionRequest.id == Approval.request_id
    )
    count = select(func.count()).select_from(Approval)
    if status is not None:
        query = query.where(Approval.status == status)
        count = count.where(Approval.status == status)
    rows = session.execute(
        query.order_by(Approval.requested_at.desc()).limit(limit).offset(offset)
    ).all()
    return [_view(*row) for row in rows], session.execute(count).scalar_one()


def get_approval(session: Session, approval_id: UUID) -> ApprovalView:
    approval = session.get(Approval, approval_id)
    if approval is None:
        raise NotFound()
    return _view(approval, session.get(ActionRequest, approval.request_id))


def decide(
    db: Database,
    user: UserPrincipal,
    approval_id: UUID,
    *,
    target: str,
    comment: str | None,
    clock: Callable[[], datetime],
) -> ApprovalView:
    expired = False
    with db.tenant_transaction(user.tenant_id) as session:
        approval = session.execute(
            select(Approval).where(Approval.id == approval_id).with_for_update()
        ).scalar_one_or_none()
        if approval is None:
            raise NotFound()
        if not can_transition(approval.status, target):
            raise Conflict(
                f"An approval in state {approval.status} cannot become {target}.",
                code="INVALID_STATE_TRANSITION",
            )

        now = clock()
        expired = now >= approval.expires_at
        status = "CANCELLED" if expired else target
        approval.status = status
        approval.decided_by = user.id
        approval.decided_at = now
        approval.comment = comment
        session.flush()
        append_event(
            session,
            user.tenant_id,
            event_type=f"approval.{status.lower()}",
            actor_type="user",
            actor_id=user.id,
            correlation_id=approval.request_id,
            subject_type="approval",
            subject_id=approval.id,
            occurred_at=now,
            payload={
                "action_hash": approval.action_hash,
                **({"reason": "APPROVAL_EXPIRED"} if expired else {}),
            },
        )
        view = _view(approval, session.get(ActionRequest, approval.request_id))

    if expired:
        raise Conflict("This approval has expired.", code="APPROVAL_EXPIRED")
    return view
