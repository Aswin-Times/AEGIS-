"""Scheduled reviews (spec 13). The sweep records a due review as a system reassessment.

The gateway compares expiry with its own clock, so nothing here can change whether an expired
approval is enforced; the sweep brings the recorded status in line. Each asset is handled in its
own transaction, so one failure rolls back only that asset, and the due test is repeated under the
asset's locks, because the listing was read without them.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from aegis.db.models import AiAsset, AssetGovernanceState, GovernanceDecision
from aegis.db.session import Database
from aegis.governance.approvals import require_reassessment
from aegis.governance.assets import APPROVED_STATUSES, lock_asset_state
from aegis.governance.engine.lifecycle import GovernanceStatus

logger = logging.getLogger("aegis.governance.reviews")

_BATCH = 500

# Statuses in which an approval still stands, so its review date is still owed. A suspension,
# rejection, or retirement clears the date; a reassessment and a resubmission keep it until a new
# approval sets the next one.
_STANDING_STATUSES = (
    *APPROVED_STATUSES,
    GovernanceStatus.REASSESSMENT_REQUIRED.value,
    GovernanceStatus.UNDER_REVIEW.value,
)


def _due_by(horizon: datetime) -> ColumnElement[bool]:
    return AssetGovernanceState.next_review_at.is_not(None) & or_(
        AssetGovernanceState.next_review_at <= horizon,
        AssetGovernanceState.valid_until <= horizon,
    )


def is_due(state: AssetGovernanceState, now: datetime) -> bool:
    """An approved asset whose review date or expiry has arrived, as the gateway counts expiry."""
    if state.status not in APPROVED_STATUSES:
        return False
    return ((state.next_review_at is not None and state.next_review_at <= now)
            or (state.valid_until is not None and state.valid_until <= now))


# Reading


@dataclass(frozen=True)
class DueReview:
    asset_id: UUID
    name: str
    governance_status: str
    next_review_at: datetime
    valid_until: datetime | None
    overdue: bool
    expired: bool


def list_due(session: Session, now: datetime, *, window_days: int, limit: int,
             offset: int) -> tuple[list[DueReview], int]:
    """Reviews owed within the window, overdue ones included, soonest first."""
    conditions = (
        AssetGovernanceState.status.in_(_STANDING_STATUSES),
        _due_by(now + timedelta(days=window_days)),
    )
    rows = session.execute(
        select(AssetGovernanceState, AiAsset.name)
        .join(AiAsset, AiAsset.id == AssetGovernanceState.asset_id)
        .where(*conditions)
        .order_by(AssetGovernanceState.next_review_at, AssetGovernanceState.asset_id)
        .limit(limit)
        .offset(offset)
    ).all()
    total = session.execute(
        select(func.count()).select_from(AssetGovernanceState).where(*conditions)
    ).scalar_one()
    return [
        DueReview(
            asset_id=state.asset_id,
            name=name,
            governance_status=state.status,
            next_review_at=state.next_review_at,
            valid_until=state.valid_until,
            overdue=state.next_review_at <= now,
            expired=state.valid_until is not None and state.valid_until <= now,
        )
        for state, name in rows
    ], total


def overdue_count(session: Session, now: datetime) -> int:
    return session.execute(
        select(func.count()).select_from(AssetGovernanceState).where(
            AssetGovernanceState.status.in_(_STANDING_STATUSES), _due_by(now)
        )
    ).scalar_one()


# The sweep


def due_tenants(db: Database, now: datetime) -> list[UUID]:
    with db._sessions() as session, session.begin():
        return list(session.execute(
            text("SELECT aegis_tenants_with_due_governance_reviews(:now)"), {"now": now}
        ).scalars())


def due_asset_ids(session: Session, now: datetime, limit: int) -> list[UUID]:
    return list(session.execute(
        select(AssetGovernanceState.asset_id)
        .where(AssetGovernanceState.status.in_(APPROVED_STATUSES), _due_by(now))
        .order_by(AssetGovernanceState.next_review_at, AssetGovernanceState.asset_id)
        .limit(limit)
    ).scalars())


def review_asset(session: Session, now: datetime, asset_id: UUID) -> GovernanceDecision | None:
    """Require reassessment of one asset if it is still due once its locks are held.

    The locks are those of every status change (spec 11.4), so a concurrent pass, approval, or
    suspension finishes first and this sees its result.
    """
    state = lock_asset_state(session, asset_id)
    if state is None or not is_due(state, now):
        return None
    reason = ("The approval has expired."
              if state.valid_until is not None and state.valid_until <= now
              else "The scheduled review date has passed.")
    return require_reassessment(session, "system", None, now, asset_id, reason=reason)


def process_tenant_reviews(db: Database, tenant_id: UUID, *, clock: Callable[[], datetime],
                           limit: int = _BATCH) -> int:
    """Returns how many reassessments were recorded."""
    with db.tenant_transaction(tenant_id) as session:
        asset_ids = due_asset_ids(session, clock(), limit)
    recorded = 0
    for asset_id in asset_ids:
        try:
            with db.tenant_transaction(tenant_id) as session:
                if review_asset(session, clock(), asset_id) is not None:
                    recorded += 1
        except Exception as error:
            # Only the type: a database error's text can carry row values.
            logger.error("governance review of asset %s failed: %s", asset_id,
                         type(error).__name__)
    return recorded


def process_due_reviews(db: Database, *, clock: Callable[[], datetime]) -> int:
    recorded = 0
    for tenant_id in due_tenants(db, clock()):
        try:
            recorded += process_tenant_reviews(db, tenant_id, clock=clock)
        except Exception as error:
            logger.error("governance reviews of tenant %s failed: %s", tenant_id,
                         type(error).__name__)
    return recorded
