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


def lock_asset_agents(session: Session, asset_id: UUID) -> None:
    """Serializes against in-flight gateway evaluations, which share-lock their agent row."""
    session.execute(
        select(Agent.id).where(Agent.asset_id == asset_id).order_by(Agent.id).with_for_update()
    ).all()


def require_not_retired(state: AssetGovernanceState | None) -> None:
    if state is not None and state.status == GovernanceStatus.RETIRED:
        raise Conflict("This asset is retired.", code="ASSET_RETIRED")


def _set_columns(state: AssetGovernanceState, columns: dict) -> None:
    unknown = set(columns) - MUTABLE_STATE_COLUMNS
    if unknown:
        raise ValueError(f"not a mutable governance state column: {sorted(unknown)}")
    for name, value in columns.items():
        setattr(state, name, value)


def transition(session: Session, state: AssetGovernanceState, target: GovernanceStatus,
               now: datetime, **columns) -> None:
    if not can_transition(state.status, target):
        raise Conflict(f"An asset cannot move from {state.status} to {target}.",
                       code="INVALID_STATE_TRANSITION")
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


def _require_tenant_user(session: Session, user_id: UUID | None, field: str) -> None:
    if user_id is not None and session.get(User, user_id) is None:
        raise ValidationFailed(f"{field} must be a user in this tenant.")


def save_profile(session: Session, user: UserPrincipal, now: datetime, asset_id: UUID,
                 profile: AssetProfile) -> AssetProfileVersion:
    if session.get(AiAsset, asset_id) is None:
        raise NotFound()
    _require_tenant_user(session, profile.business_owner_id, "business_owner_id")
    _require_tenant_user(session, profile.technical_owner_id, "technical_owner_id")
    # Two first saves could otherwise both pick version 1 or both insert the state row.
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(str(asset_id), 0))))
    state = load_state(session, asset_id)
    require_not_retired(state)

    canonical = canonical_profile(profile)
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
        content_hash=sha256_hex(canonical),
        business_owner_id=profile.business_owner_id,
        technical_owner_id=profile.technical_owner_id,
        created_by=user.id,
        created_at=now,
    )
    session.add(version)
    session.flush()

    if state is None:
        state = AssetGovernanceState(
            tenant_id=user.tenant_id,
            asset_id=asset_id,
            status=GovernanceStatus.DRAFT.value,
            version=1,
            current_profile_version_id=version.id,
            updated_at=now,
        )
        session.add(state)
        session.flush()
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
            "governance_status": state.status,
        },
    )
    return version
