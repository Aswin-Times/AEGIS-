"""Asset profiles and the lifecycle state row. Writes run in the caller's tenant transaction."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.canonical import sha256_hex
from aegis.db.models import Agent, AiAsset, AssetGovernanceState, AssetProfileVersion, User
from aegis.errors import Conflict, NotFound, ValidationFailed
from aegis.governance.engine.lifecycle import GovernanceStatus, can_transition
from aegis.governance.profile import AssetProfile, canonical_profile
from aegis.security.principals import UserPrincipal

# The only columns a service may change. Anything else on the state row is identity.
MUTABLE_STATE_COLUMNS = frozenset({
    "current_profile_version_id",
    "latest_assessment_id",
    "current_decision_id",
    "hard_block_decision_id",
    "valid_until",
    "next_review_at",
})


def load_state(session: Session, asset_id: UUID) -> AssetGovernanceState | None:
    return session.execute(
        select(AssetGovernanceState).where(AssetGovernanceState.asset_id == asset_id)
    ).scalar_one_or_none()


def load_state_for_update(session: Session, asset_id: UUID) -> AssetGovernanceState | None:
    """The state row, locked. Every transition runs under this lock (spec 7.1)."""
    return session.execute(
        select(AssetGovernanceState)
        .where(AssetGovernanceState.asset_id == asset_id)
        .with_for_update()
        # The row may have changed while this waited for the lock.
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()


def lock_asset(session: Session, asset_id: UUID) -> None:
    """One lock per asset, for the paths that may insert its state row, which cannot be locked
    before it exists. It is the first lock taken."""
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(str(asset_id), 0))))


def lock_asset_agents(session: Session, asset_id: UUID) -> None:
    """Serializes against in-flight gateway evaluations, which share-lock their agent row.

    FOR NO KEY UPDATE conflicts with that share lock as FOR UPDATE does, but not with the key
    share lock a foreign key check takes. A finishing execution holds the chain head and then
    inserts rows that reference its agent, so FOR UPDATE here would deadlock with it.
    """
    session.execute(
        select(Agent.id).where(Agent.asset_id == asset_id).order_by(Agent.id)
        .with_for_update(key_share=True)
    ).all()


def lock_asset_state(session: Session, asset_id: UUID) -> AssetGovernanceState | None:
    """Every lock a change of status takes, in the order of spec 11.4: the asset, its agent rows,
    then the state row. The review and the chain head come after."""
    lock_asset(session, asset_id)
    lock_asset_agents(session, asset_id)
    return load_state_for_update(session, asset_id)


def require_not_retired(state: AssetGovernanceState | None) -> None:
    if state is not None and state.status == GovernanceStatus.RETIRED:
        raise Conflict("This asset is retired.", code="ASSET_RETIRED")


def _set_columns(state: AssetGovernanceState, columns: dict) -> None:
    unknown = set(columns) - MUTABLE_STATE_COLUMNS
    if unknown:
        raise ValueError(f"not a mutable governance state column: {sorted(unknown)}")
    for name, value in columns.items():
        setattr(state, name, value)


def require_transition(state: AssetGovernanceState, target: GovernanceStatus) -> None:
    if not can_transition(state.status, target):
        raise Conflict(f"An asset cannot move from {state.status} to {target}.",
                       code="INVALID_STATE_TRANSITION")


def transition(session: Session, state: AssetGovernanceState, target: GovernanceStatus,
               now: datetime, **columns) -> None:
    require_transition(state, target)
    _set_columns(state, columns)
    state.status = target.value
    state.version += 1
    state.updated_at = now
    session.flush()


def touch(session: Session, state: AssetGovernanceState, now: datetime, **columns) -> None:
    """A change that leaves the status alone, such as pointing at a newer assessment."""
    _set_columns(state, columns)
    state.version += 1
    state.updated_at = now
    session.flush()


def new_draft_state(session: Session, tenant_id: UUID, asset_id: UUID, now: datetime,
                    profile_version_id: UUID | None = None) -> AssetGovernanceState:
    """The first state row of an asset. The caller holds the asset lock."""
    state = AssetGovernanceState(
        tenant_id=tenant_id,
        asset_id=asset_id,
        status=GovernanceStatus.DRAFT.value,
        version=1,
        current_profile_version_id=profile_version_id,
        updated_at=now,
    )
    session.add(state)
    session.flush()
    return state


def _require_tenant_user(session: Session, user_id: UUID | None, field: str) -> None:
    if user_id is not None and session.get(User, user_id) is None:
        raise ValidationFailed(f"{field} must be a user in this tenant.")


# Statuses in which an approval is in force and a change to what was assessed voids it.
APPROVED_STATUSES = (GovernanceStatus.APPROVED.value, GovernanceStatus.CONDITIONALLY_APPROVED.value)


def save_profile(session: Session, user: UserPrincipal, now: datetime, asset_id: UUID,
                 profile: AssetProfile) -> AssetProfileVersion:
    """Save a new version, unless the profile is what is already current.

    A real change to an approved asset requires reassessment (spec 5), because the approval was of
    a different profile. Saving the current profile again changes nothing, so it cannot be used
    to force one.
    """
    if session.get(AiAsset, asset_id) is None:
        raise NotFound()
    _require_tenant_user(session, profile.business_owner_id, "business_owner_id")
    _require_tenant_user(session, profile.technical_owner_id, "technical_owner_id")
    # Two first saves could otherwise both pick version 1 or both insert the state row, and a
    # status change must serialize against the gateway as every other one does.
    state = lock_asset_state(session, asset_id)
    require_not_retired(state)

    canonical = canonical_profile(profile)
    content_hash = sha256_hex(canonical)
    if state is not None and state.current_profile_version_id is not None:
        current = session.get(AssetProfileVersion, state.current_profile_version_id)
        if current is not None and current.content_hash == content_hash:
            return current

    latest = session.execute(
        select(func.max(AssetProfileVersion.version)).where(
            AssetProfileVersion.asset_id == asset_id
        )
    ).scalar_one()
    version = AssetProfileVersion(
        id=uuid4(),
        tenant_id=user.tenant_id,
        asset_id=asset_id,
        version=(latest or 0) + 1,
        profile_canonical=canonical,
        content_hash=content_hash,
        business_owner_id=profile.business_owner_id,
        technical_owner_id=profile.technical_owner_id,
        created_by=user.id,
        created_at=now,
    )
    session.add(version)
    session.flush()

    forces_reassessment = state is not None and state.status in APPROVED_STATUSES
    if state is None:
        state = new_draft_state(session, user.tenant_id, asset_id, now, version.id)
    else:
        touch(session, state, now, current_profile_version_id=version.id)

    append_event(
        session,
        user.tenant_id,
        event_type="governance.profile_saved",
        actor_type="user",
        actor_id=user.id,
        subject_type="ai_asset",
        subject_id=asset_id,
        occurred_at=now,
        payload={
            "profile_version_id": str(version.id),
            "version": version.version,
            "content_hash": version.content_hash,
            "governance_status": (GovernanceStatus.REASSESSMENT_REQUIRED.value
                                  if forces_reassessment else state.status),
        },
    )
    if forces_reassessment:
        # approvals imports this module, so it cannot be imported at the top.
        from aegis.governance.approvals import require_reassessment

        require_reassessment(session, "user", user.id, now, asset_id,
                             reason="Asset profile changed.")
    return version
