"""Risk assessments and methodology versions. Writes run in the caller's tenant transaction.

The engine is pure. This module gathers its inputs from stored rows, runs it, and records the
inputs and the result together, so that a stored assessment can be recomputed later.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.canonical import canonical_json, sha256_hex
from aegis.db.models import (
    Agent,
    AgentResourceGrant,
    AgentToolGrant,
    AiAsset,
    AssetProfileVersion,
    AuditEvent,
    GovernanceSettings,
    Resource,
    RiskAssessment,
    RiskMethodologyEvent,
    RiskMethodologyVersion,
)
from aegis.errors import Conflict, Forbidden, NotFound, ValidationFailed
from aegis.gateway.tools import ToolDefinition, ToolRegistry
from aegis.governance.assets import (
    load_state,
    load_state_for_update,
    lock_asset_agents,
    require_not_retired,
    touch,
    transition,
)
from aegis.governance.engine.lifecycle import GovernanceStatus
from aegis.governance.engine.risk import MAX_LEVEL, Methodology, RiskInputs, assess
from aegis.governance.methodology import BUILT_IN_METHODOLOGY
from aegis.governance.profile import AssetProfile
from aegis.security.principals import UserPrincipal

BUILT_IN_VERSION = 1
# Every factor of the built-in document, with the input it reads. A tenant's document may change
# weights, levels, thresholds, floors, and text, but must keep all of these: a missing factor
# would stop the engine from noticing that its input is missing.
REQUIRED_FACTORS = {factor.id: factor.input for factor in BUILT_IN_METHODOLOGY.factors}
# These classifications can be read without raising a tool's level above 2.
_OPEN_CLASSIFICATIONS = ("public", "internal")
# Statuses from which an assessment asks for a fresh review of the current profile.
_RESTART_STATUSES = (GovernanceStatus.DRAFT.value, GovernanceStatus.REJECTED.value)


class MethodologyIntegrityError(Exception):
    """A stored methodology failed its hash or validation, so no score can be trusted."""


@dataclass(frozen=True)
class AssessmentRecord:
    assessment: RiskAssessment
    methodology_version: int


@dataclass(frozen=True)
class MethodologyView:
    id: UUID
    version: int
    content_hash: str
    created_by: UUID | None
    created_at: datetime
    approved: bool
    approved_by: UUID | None
    approved_at: datetime | None
    active: bool
    document: dict


# Inputs


def _action_level(tool: ToolDefinition, classifications: list[str] | None) -> int:
    """Spec 6: compute 1; read 2, or 3 if any resource it can reach is sensitive; transmit 4.

    `classifications` is None when nothing says what the tool can reach, which is treated as
    sensitive. An action outside the catalog's three is treated as the highest level.
    """
    if tool.action == "compute":
        return 1
    if tool.action == "read":
        if classifications is None:
            return 3
        return 3 if any(item not in _OPEN_CLASSIFICATIONS for item in classifications) else 2
    return MAX_LEVEL


def _grants_level(session: Session, registry: ToolRegistry, asset_id: UUID) -> int | None:
    """The highest level across every agent of the asset, or None if a granted tool is unknown."""
    agents = select(Agent.id).where(Agent.asset_id == asset_id)
    tool_grants = session.execute(
        select(AgentToolGrant.agent_id, AgentToolGrant.tool).where(
            AgentToolGrant.agent_id.in_(agents)
        )
    ).all()
    reachable: dict[UUID, list[tuple[str, str]]] = {}
    for agent_id, kind, classification in session.execute(
        select(AgentResourceGrant.agent_id, Resource.kind, Resource.classification)
        .join(Resource, Resource.id == AgentResourceGrant.resource_id)
        .where(AgentResourceGrant.agent_id.in_(agents))
    ):
        reachable.setdefault(agent_id, []).append((kind, classification))

    level = 0
    for agent_id, tool in tool_grants:
        definition = registry.get(tool)
        if definition is None:
            return None
        classifications = [
            classification
            for kind, classification in reachable.get(agent_id, [])
            if kind == definition.resource_kind
        ]
        level = max(level, _action_level(definition, classifications))
    return level


def _declared_level(registry: ToolRegistry, labels: list[str] | None) -> int | None:
    if labels is None:
        return None
    level = 0
    for label in labels:
        definition = registry.get(label)
        level = max(level, MAX_LEVEL if definition is None else _action_level(definition, None))
    return level


def build_inputs(session: Session, registry: ToolRegistry, asset_id: UUID,
                 profile: AssetProfile) -> RiskInputs:
    """Tool access comes from real grants when the asset has agents, and from the profile if not."""
    has_agents = session.execute(
        select(func.count(Agent.id)).where(Agent.asset_id == asset_id)
    ).scalar_one() > 0
    if has_agents:
        level, source = _grants_level(session, registry, asset_id), "grants"
    else:
        level, source = _declared_level(registry, profile.declared_tool_access), "declared"
    return RiskInputs(
        data_categories=profile.data_categories,
        external_exposure=profile.external_exposure,
        autonomy_level=profile.autonomy_level,
        tool_access_level=level,
        tool_access_source=source if level is not None else None,
        human_oversight=profile.human_oversight,
        impact_level=profile.impact_level,
        deployment_environment=profile.deployment_environment,
        third_party_reliance=profile.third_party_reliance,
    )


def _canonical_inputs(inputs: RiskInputs) -> str:
    return canonical_json(inputs.model_dump(mode="json", exclude_none=True))


def _current_profile(session: Session, state) -> tuple[AssetProfileVersion, AssetProfile]:
    version = (
        session.get(AssetProfileVersion, state.current_profile_version_id)
        if state is not None and state.current_profile_version_id is not None
        else None
    )
    if version is None:
        raise Conflict("This asset has no profile to assess.", code="PROFILE_REQUIRED")
    return version, AssetProfile.model_validate(json.loads(version.profile_canonical))


def current_input_hash(session: Session, registry: ToolRegistry, asset_id: UUID) -> str:
    """The hash an assessment made now would have, to tell whether the latest one is current."""
    _, profile = _current_profile(session, load_state(session, asset_id))
    return sha256_hex(_canonical_inputs(build_inputs(session, registry, asset_id, profile)))


# Methodology versions


def _seed_built_in(session: Session, tenant_id: UUID, now: datetime) -> None:
    if session.execute(
        select(RiskMethodologyVersion.id).where(RiskMethodologyVersion.version == BUILT_IN_VERSION)
    ).first() is not None:
        return
    canonical = _canonical_methodology(BUILT_IN_METHODOLOGY)
    inserted = session.execute(
        insert(RiskMethodologyVersion)
        .values(
            id=uuid4(),
            tenant_id=tenant_id,
            version=BUILT_IN_VERSION,
            document_canonical=canonical,
            content_hash=sha256_hex(canonical),
            created_by=None,
        )
        .on_conflict_do_nothing()
        .returning(RiskMethodologyVersion.id)
    ).first()
    if inserted is not None:
        append_event(
            session,
            tenant_id,
            event_type="governance.methodology_seeded",
            actor_type="system",
            subject_type="risk_methodology_version",
            subject_id=inserted[0],
            occurred_at=now,
            payload={"version": BUILT_IN_VERSION, "content_hash": sha256_hex(canonical)},
        )


def _canonical_methodology(methodology: Methodology) -> str:
    return canonical_json(methodology.model_dump(mode="json"))


def active_methodology(session: Session, tenant_id: UUID, now: datetime) -> RiskMethodologyVersion:
    """The tenant's active version, or the built-in one if none was ever activated."""
    _seed_built_in(session, tenant_id, now)
    active_id = session.execute(
        select(GovernanceSettings.active_methodology_version_id)
    ).scalar_one_or_none()
    if active_id is not None:
        return session.get(RiskMethodologyVersion, active_id)
    return session.execute(
        select(RiskMethodologyVersion).where(RiskMethodologyVersion.version == BUILT_IN_VERSION)
    ).scalar_one()


def parse_methodology(version: RiskMethodologyVersion) -> Methodology:
    if sha256_hex(version.document_canonical) != version.content_hash:
        raise MethodologyIntegrityError(f"methodology v{version.version} failed its hash")
    try:
        return Methodology.model_validate(json.loads(version.document_canonical))
    except (ValidationError, ValueError) as error:
        raise MethodologyIntegrityError(f"methodology v{version.version} is invalid") from error


def _approvals(session: Session, version_ids: list[UUID]) -> dict[UUID, RiskMethodologyEvent]:
    events = session.execute(
        select(RiskMethodologyEvent).where(
            RiskMethodologyEvent.event == "APPROVED",
            RiskMethodologyEvent.version_id.in_(version_ids),
        )
    ).scalars()
    return {event.version_id: event for event in events}


def _view(version: RiskMethodologyVersion, approval: RiskMethodologyEvent | None,
          active_id: UUID) -> MethodologyView:
    return MethodologyView(
        id=version.id,
        version=version.version,
        content_hash=version.content_hash,
        created_by=version.created_by,
        created_at=version.created_at,
        # The built-in document has no creator and counts as approved.
        approved=version.created_by is None or approval is not None,
        approved_by=approval.actor_id if approval is not None else None,
        approved_at=approval.created_at if approval is not None else None,
        active=version.id == active_id,
        document=parse_methodology(version).model_dump(mode="json"),
    )


def _view_of(session: Session, tenant_id: UUID, now: datetime,
             version: RiskMethodologyVersion) -> MethodologyView:
    active = active_methodology(session, tenant_id, now)
    return _view(version, _approvals(session, [version.id]).get(version.id), active.id)


def list_methodologies(session: Session, tenant_id: UUID, now: datetime, *, limit: int,
                       offset: int) -> tuple[list[MethodologyView], int]:
    active = active_methodology(session, tenant_id, now)
    versions = session.execute(
        select(RiskMethodologyVersion)
        .order_by(RiskMethodologyVersion.version.desc())
        .limit(limit)
        .offset(offset)
    ).scalars().all()
    approvals = _approvals(session, [version.id for version in versions])
    total = session.execute(select(func.count(RiskMethodologyVersion.id))).scalar_one()
    return [_view(version, approvals.get(version.id), active.id) for version in versions], total


def _require_every_factor(document: Methodology) -> None:
    kept = {factor.id: factor.input for factor in document.factors}
    missing = [factor for factor, field in REQUIRED_FACTORS.items() if kept.get(factor) != field]
    if missing:
        raise ValidationFailed(
            "A methodology must keep every factor, each reading its own input. "
            f"Missing or changed: {', '.join(missing)}."
        )


def create_methodology_version(session: Session, user: UserPrincipal, now: datetime,
                               document: Methodology) -> MethodologyView:
    _require_every_factor(document)
    _seed_built_in(session, user.tenant_id, now)
    _serialize_methodology_changes(session, user.tenant_id)
    latest = session.execute(select(func.max(RiskMethodologyVersion.version))).scalar_one()
    canonical = _canonical_methodology(document)
    version = RiskMethodologyVersion(
        id=uuid4(),
        tenant_id=user.tenant_id,
        version=latest + 1,
        document_canonical=canonical,
        content_hash=sha256_hex(canonical),
        created_by=user.id,
        created_at=now,
    )
    session.add(version)
    session.flush()
    append_event(
        session,
        user.tenant_id,
        event_type="governance.methodology_created",
        actor_type="user",
        actor_id=user.id,
        subject_type="risk_methodology_version",
        subject_id=version.id,
        occurred_at=now,
        payload={"version": version.version, "content_hash": version.content_hash},
    )
    return _view_of(session, user.tenant_id, now, version)


def _serialize_methodology_changes(session: Session, tenant_id: UUID) -> None:
    """Version rows cannot be row-locked (the runtime role may not update them), so one lock per
    tenant orders creation, approval, and activation."""
    session.execute(
        select(func.pg_advisory_xact_lock(
            func.hashtextextended(f"risk-methodology:{tenant_id}", 0)
        ))
    )


def _locked_version(session: Session, tenant_id: UUID, version_id: UUID) -> RiskMethodologyVersion:
    _serialize_methodology_changes(session, tenant_id)
    version = session.get(RiskMethodologyVersion, version_id)
    if version is None:
        raise NotFound()
    parse_methodology(version)
    return version


def _is_approved(session: Session, version: RiskMethodologyVersion) -> bool:
    return version.created_by is None or version.id in _approvals(session, [version.id])


def _record_event(session: Session, user: UserPrincipal, now: datetime,
                  version: RiskMethodologyVersion, event: str, **payload) -> None:
    audit = append_event(
        session,
        user.tenant_id,
        event_type=f"governance.methodology_{event.lower()}",
        actor_type="user",
        actor_id=user.id,
        subject_type="risk_methodology_version",
        subject_id=version.id,
        occurred_at=now,
        payload={"version": version.version, "content_hash": version.content_hash, **payload},
    )
    session.add(
        RiskMethodologyEvent(
            id=uuid4(),
            tenant_id=user.tenant_id,
            version_id=version.id,
            event=event,
            actor_id=user.id,
            audit_event_id=audit.id,
            created_at=now,
        )
    )
    session.flush()


def approve_methodology_version(session: Session, user: UserPrincipal, now: datetime,
                                version_id: UUID) -> MethodologyView:
    """The caller must already hold governance_reviewer; a creator cannot approve their own."""
    version = _locked_version(session, user.tenant_id, version_id)
    if _is_approved(session, version):
        raise Conflict("This methodology version is already approved.", code="ALREADY_APPROVED")
    if version.created_by == user.id:
        raise Forbidden("You cannot approve a methodology version you created.",
                        code="SELF_APPROVAL_REFUSED")
    _record_event(session, user, now, version, "APPROVED")
    return _view_of(session, user.tenant_id, now, version)


def activate_methodology_version(session: Session, user: UserPrincipal, now: datetime,
                                 version_id: UUID) -> MethodologyView:
    version = _locked_version(session, user.tenant_id, version_id)
    if not _is_approved(session, version):
        raise Conflict("Only an approved methodology version can be activated.",
                       code="METHODOLOGY_NOT_APPROVED")
    previous = active_methodology(session, user.tenant_id, now)
    session.execute(
        insert(GovernanceSettings)
        .values(id=uuid4(), tenant_id=user.tenant_id, active_methodology_version_id=version.id)
        .on_conflict_do_update(
            index_elements=[GovernanceSettings.tenant_id],
            set_={"active_methodology_version_id": version.id},
        )
    )
    _record_event(session, user, now, version, "ACTIVATED", previous_version_id=str(previous.id))
    return _view_of(session, user.tenant_id, now, version)


# Assessments


def run_assessment(session: Session, registry: ToolRegistry, user: UserPrincipal, now: datetime,
                   asset_id: UUID) -> RiskAssessment:
    if session.get(AiAsset, asset_id) is None:
        raise NotFound()
    # Agent rows, then state, then the chain head (spec 11.4), the order suspend will take. The
    # agent lock also keeps the grants read below from changing under an in-flight evaluation.
    lock_asset_agents(session, asset_id)
    state = load_state_for_update(session, asset_id)
    require_not_retired(state)
    profile_version, profile = _current_profile(session, state)

    methodology_version = active_methodology(session, user.tenant_id, now)
    methodology = parse_methodology(methodology_version)
    inputs = build_inputs(session, registry, asset_id, profile)
    result = assess(inputs, methodology)
    input_canonical = _canonical_inputs(inputs)
    result_canonical = canonical_json(result.model_dump(mode="json"))

    assessment_id = uuid4()
    # The audit event comes first, because the row must name it. It names the row by id.
    audit = append_event(
        session,
        user.tenant_id,
        event_type="governance.risk_assessed",
        actor_type="user",
        actor_id=user.id,
        subject_type="risk_assessment",
        subject_id=assessment_id,
        occurred_at=now,
        payload={
            "asset_id": str(asset_id),
            "profile_version_id": str(profile_version.id),
            "methodology_version_id": str(methodology_version.id),
            "methodology_version": methodology_version.version,
            "input_hash": sha256_hex(input_canonical),
            "result_hash": sha256_hex(result_canonical),
            "status": result.status,
            "score": result.score,
            "risk_level": result.risk_level,
            "floor_applied": result.floor_applied,
            "missing": result.missing,
        },
    )
    assessment = RiskAssessment(
        id=assessment_id,
        tenant_id=user.tenant_id,
        asset_id=asset_id,
        profile_version_id=profile_version.id,
        methodology_version_id=methodology_version.id,
        input_canonical=input_canonical,
        input_hash=sha256_hex(input_canonical),
        result_canonical=result_canonical,
        result_hash=sha256_hex(result_canonical),
        status=result.status,
        score=result.score,
        risk_level=result.risk_level,
        assessed_by=user.id,
        audit_event_id=audit.id,
        created_at=now,
    )
    session.add(assessment)
    session.flush()
    if state.status in _RESTART_STATUSES:
        transition(session, state, GovernanceStatus.ASSESSMENT_REQUIRED, now,
                   latest_assessment_id=assessment.id)
    else:
        touch(session, state, now, latest_assessment_id=assessment.id)
    return assessment


def latest_assessment(session: Session, asset_id: UUID) -> AssessmentRecord | None:
    records, _ = list_assessments(session, asset_id, limit=1, offset=0)
    return records[0] if records else None


def list_assessments(session: Session, asset_id: UUID, *, limit: int,
                     offset: int) -> tuple[list[AssessmentRecord], int]:
    """Newest first, by audit sequence, because timestamps can tie."""
    if session.get(AiAsset, asset_id) is None:
        raise NotFound()
    rows = session.execute(
        select(RiskAssessment, RiskMethodologyVersion.version)
        .join(AuditEvent, AuditEvent.id == RiskAssessment.audit_event_id)
        .join(
            RiskMethodologyVersion,
            RiskMethodologyVersion.id == RiskAssessment.methodology_version_id,
        )
        .where(RiskAssessment.asset_id == asset_id)
        .order_by(AuditEvent.seq.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    total = session.execute(
        select(func.count(RiskAssessment.id)).where(RiskAssessment.asset_id == asset_id)
    ).scalar_one()
    return [AssessmentRecord(row[0], row[1]) for row in rows], total


def recomputes_to_stored_result(session: Session, assessment: RiskAssessment) -> bool:
    """Re-run the engine on the stored input and methodology, and compare with what was stored.

    Raises MethodologyIntegrityError if the stored methodology cannot be trusted.
    """
    methodology = parse_methodology(
        session.get(RiskMethodologyVersion, assessment.methodology_version_id)
    )
    if (sha256_hex(assessment.input_canonical) != assessment.input_hash
            or sha256_hex(assessment.result_canonical) != assessment.result_hash):
        return False
    try:
        inputs = RiskInputs.model_validate(json.loads(assessment.input_canonical))
    except (ValidationError, ValueError):
        return False
    result = assess(inputs, methodology)
    return (
        canonical_json(result.model_dump(mode="json")) == assessment.result_canonical
        and (result.status, result.score, result.risk_level)
        == (assessment.status, assessment.score, assessment.risk_level)
    )
