"""The tenant's enforcement mode and the preflight that shows what switching it would change.

A mode switch is not serialized against in-flight evaluations: one action already being decided
may use the old mode, as with policy activation (spec 11.4).
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.db.models import (
    AiAsset,
    AssetGovernanceState,
    GovernanceGatewayCheck,
    GovernanceSettings,
)
from aegis.errors import Conflict, ValidationFailed
from aegis.governance.engine.enforcement import ActionContext, Verdict
from aegis.governance.gateway_check import check_state, get_mode
from aegis.security.principals import UserPrincipal

MODES = ("observe", "enforce")
PREFLIGHT_WINDOW = timedelta(days=7)
# No tool, action, or resource: the verdict an asset gets whatever its agents attempt. A condition
# naming one tool already applies in both modes, so switching mode does not change it.
_ANY_ACTION = ActionContext(tool="", action="", resource_classification=None)


def set_mode(session: Session, user: UserPrincipal, now: datetime, *, mode: str,
             reason: str) -> GovernanceSettings:
    """The caller must be an admin. The change and its reason are in the audit chain."""
    if mode not in MODES:
        raise ValidationFailed(f"mode must be one of {list(MODES)}.")
    reason = reason.strip()
    if not reason:
        raise ValidationFailed("A reason is required.")
    # Two first changes would otherwise both read the default and both record leaving it.
    session.execute(select(func.pg_advisory_xact_lock(
        func.hashtextextended(f"governance_settings:{user.tenant_id}", 0))))
    previous = get_mode(session)
    if previous == mode:
        raise Conflict(f"The enforcement mode is already {mode}.",
                       code="ENFORCEMENT_MODE_UNCHANGED")
    session.execute(
        insert(GovernanceSettings)
        .values(id=uuid4(), tenant_id=user.tenant_id, enforcement_mode=mode)
        .on_conflict_do_update(index_elements=[GovernanceSettings.tenant_id],
                               set_={"enforcement_mode": mode})
    )
    settings = session.execute(
        select(GovernanceSettings).execution_options(populate_existing=True)
    ).scalar_one()
    append_event(
        session,
        user.tenant_id,
        event_type="governance.enforcement_mode_changed",
        actor_type="user",
        actor_id=user.id,
        subject_type="governance_settings",
        subject_id=settings.id,
        occurred_at=now,
        payload={"from_mode": previous, "to_mode": mode, "reason": reason},
    )
    return settings


@dataclass(frozen=True)
class PreflightItem:
    asset_id: UUID
    name: str
    governance_status: str | None
    verdict: str
    reason_code: str
    recent_actions: int
    recent_not_passed: int


@dataclass(frozen=True)
class PreflightView:
    enforcement_mode: str
    since: datetime
    assets_checked: int
    would_deny: int
    would_hold: int
    items: list[PreflightItem]


def preflight(session: Session, now: datetime) -> PreflightView:
    """Every asset that `enforce` would deny or hold, with the checks its agents recorded since
    `since`. Reads only: it writes nothing and takes no lock."""
    since = now - PREFLIGHT_WINDOW
    counts = {
        row.asset_id: (row.total, row.not_passed)
        for row in session.execute(
            select(
                GovernanceGatewayCheck.asset_id,
                func.count().label("total"),
                func.count().filter(GovernanceGatewayCheck.verdict != Verdict.PASS.value)
                .label("not_passed"),
            )
            .where(GovernanceGatewayCheck.checked_at >= since)
            .group_by(GovernanceGatewayCheck.asset_id)
        )
    }
    states = {state.asset_id: state
              for state in session.execute(select(AssetGovernanceState)).scalars()}
    assets = session.execute(
        select(AiAsset.id, AiAsset.name).order_by(AiAsset.created_at, AiAsset.id)
    ).all()

    items = []
    for asset_id, name in assets:
        state = states.get(asset_id)
        result = check_state(session, state, "enforce", _ANY_ACTION, now)
        if result.verdict not in (Verdict.DENY, Verdict.HOLD):
            continue
        total, not_passed = counts.get(asset_id, (0, 0))
        items.append(PreflightItem(
            asset_id=asset_id,
            name=name,
            governance_status=None if state is None else state.status,
            verdict=result.verdict.value,
            reason_code=result.reason_code,
            recent_actions=total,
            recent_not_passed=not_passed,
        ))
    return PreflightView(
        enforcement_mode=get_mode(session),
        since=since,
        assets_checked=len(assets),
        would_deny=sum(item.verdict == Verdict.DENY for item in items),
        would_hold=sum(item.verdict == Verdict.HOLD for item in items),
        items=items,
    )

