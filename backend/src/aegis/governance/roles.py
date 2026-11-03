"""The governance_reviewer role. Only an admin grants it, and never to themselves."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.db.models import GovernanceRoleGrant, User
from aegis.errors import Conflict, Forbidden, NotFound, ValidationFailed
from aegis.security.principals import ADMIN, REVIEWER, UserPrincipal

GOVERNANCE_REVIEWER = "governance_reviewer"
ELIGIBLE_USER_ROLES = (ADMIN, REVIEWER)


def _active_grants(user_id: UUID):
    return select(GovernanceRoleGrant.id).where(
        GovernanceRoleGrant.user_id == user_id,
        GovernanceRoleGrant.role == GOVERNANCE_REVIEWER,
        GovernanceRoleGrant.revoked_at.is_(None),
    )


def holds_reviewer(session: Session, user_id: UUID) -> bool:
    """An unrevoked grant counts only while the user is active and still an admin or reviewer."""
    return (
        session.execute(
            _active_grants(user_id)
            .join(User, User.id == GovernanceRoleGrant.user_id)
            .where(User.is_active, User.role.in_(ELIGIBLE_USER_ROLES))
        ).first()
        is not None
    )


def grant_role(session: Session, actor: UserPrincipal, now: datetime, *,
               user_id: UUID) -> GovernanceRoleGrant:
    if user_id == actor.id:
        raise Forbidden("You cannot grant yourself the governance reviewer role.",
                        code="SELF_GRANT_REFUSED")
    grantee = session.get(User, user_id)
    if grantee is None:
        raise NotFound()
    if not grantee.is_active or grantee.role not in ELIGIBLE_USER_ROLES:
        raise ValidationFailed("The role can only be granted to an active admin or reviewer.")
    if session.execute(_active_grants(user_id)).first() is not None:
        raise Conflict("This user already holds the role.", code="ROLE_ALREADY_GRANTED")
    grant = GovernanceRoleGrant(
        id=uuid4(),
        tenant_id=actor.tenant_id,
        user_id=user_id,
        role=GOVERNANCE_REVIEWER,
        granted_by=actor.id,
        granted_at=now,
    )
    session.add(grant)
    session.flush()
    append_event(
        session,
        actor.tenant_id,
        event_type="governance.role_granted",
        actor_type="user",
        actor_id=actor.id,
        subject_type="governance_role_grant",
        subject_id=grant.id,
        occurred_at=now,
        payload={"user_id": str(user_id), "role": GOVERNANCE_REVIEWER},
    )
    return grant


def revoke_grant(session: Session, actor: UserPrincipal, now: datetime,
                 grant_id: UUID) -> GovernanceRoleGrant:
    grant = session.execute(
        select(GovernanceRoleGrant).where(GovernanceRoleGrant.id == grant_id).with_for_update()
    ).scalar_one_or_none()
    if grant is None:
        raise NotFound()
    if grant.revoked_at is not None:
        return grant
    grant.revoked_by = actor.id
    grant.revoked_at = now
    session.flush()
    append_event(
        session,
        actor.tenant_id,
        event_type="governance.role_revoked",
        actor_type="user",
        actor_id=actor.id,
        subject_type="governance_role_grant",
        subject_id=grant.id,
        occurred_at=now,
        payload={"user_id": str(grant.user_id), "role": grant.role},
    )
    return grant


def list_people(session: Session, *, limit: int, offset: int):
    """Users who could hold the role, each with the id of their active grant if they do."""
    eligible = User.role.in_(ELIGIBLE_USER_ROLES) & User.is_active
    active = and_(
        GovernanceRoleGrant.user_id == User.id,
        GovernanceRoleGrant.role == GOVERNANCE_REVIEWER,
        GovernanceRoleGrant.revoked_at.is_(None),
    )
    rows = session.execute(
        select(User, GovernanceRoleGrant.id)
        .outerjoin(GovernanceRoleGrant, active)
        .where(eligible)
        .order_by(User.email)
        .limit(limit)
        .offset(offset)
    ).all()
    total = session.execute(select(func.count()).select_from(User).where(eligible)).scalar_one()
    return rows, total
