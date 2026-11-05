"""Reviews, decisions, and submission. Writes run in the caller's tenant transaction.

A decision is the record of one thing done to an asset. Its audit event is appended first and named
by the decision row, and the state row names the decision in turn, so a pointer never leads to a
row that does not exist yet. A review freezes what the policy engine asked for at submission, and a
hash over the frozen values is checked wherever the review is read, because a later decision relies
on them and a database edit to them would otherwise change who may approve.
"""

import json
from collections.abc import Iterable, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event, compute_event_hash
from aegis.canonical import canonical_json, sha256_hex
from aegis.db.models import (
    Agent,
    AiAsset,
    AssetGovernanceState,
    AssetProfileVersion,
    AuditEvent,
    GovernanceDecision,
    GovernanceDecisionEvidence,
    GovernanceDecisionPolicyVersion,
    GovernanceReview,
    RiskAssessment,
)
from aegis.errors import Conflict, Forbidden, NotFound, ValidationFailed
from aegis.gateway.tools import ToolRegistry
from aegis.governance.assets import (
    APPROVED_STATUSES,
    load_state,
    load_state_for_update,
    lock_asset_agents,
    lock_asset_state,
    new_draft_state,
    require_not_retired,
    require_transition,
    transition,
)
from aegis.governance.conditions import Conditions, is_enforceable, validate_against_catalog
from aegis.governance.engine.lifecycle import GovernanceStatus
from aegis.governance.engine.policies import PolicyOutcome, evaluate_policies
from aegis.governance.policies import applicable_documents
from aegis.governance.profile import AssetProfile
from aegis.governance.risk import current_input_hash, latest_assessment, recomputes_to_stored_result
from aegis.governance.roles import holds_reviewer
from aegis.security.principals import UserPrincipal

# Statuses from which an asset may be submitted for review (spec 7.1 and 7.4).
_SUBMITTABLE = (GovernanceStatus.ASSESSMENT_REQUIRED, GovernanceStatus.REASSESSMENT_REQUIRED)


class ReviewStatus(StrEnum):
    OPEN = "OPEN"
    INFO_REQUESTED = "INFO_REQUESTED"
    DECIDED = "DECIDED"
    WITHDRAWN = "WITHDRAWN"


OPEN_STATUSES = (ReviewStatus.OPEN, ReviewStatus.INFO_REQUESTED)


class DecisionKind(StrEnum):
    SUBMIT = "SUBMIT"
    ASSIGN_REVIEWER = "ASSIGN_REVIEWER"
    REQUEST_INFORMATION = "REQUEST_INFORMATION"
    APPROVAL_VOTE = "APPROVAL_VOTE"
    APPROVE = "APPROVE"
    APPROVE_CONDITIONAL = "APPROVE_CONDITIONAL"
    REJECT = "REJECT"
    SUSPEND = "SUSPEND"
    REVOKE = "REVOKE"
    REQUIRE_REASSESSMENT = "REQUIRE_REASSESSMENT"
    RETIRE = "RETIRE"


class ReviewIntegrityError(Exception):
    """A stored review failed its hash, so the controls it froze cannot be trusted.

    Callers fail closed: acting on a review whose self-approval flag may have been edited could
    let a submitter approve their own work.
    """


class AssessmentIntegrityError(Exception):
    """The latest assessment does not recompute to what was stored, so it cannot be frozen."""


class ProfileIntegrityError(Exception):
    """A stored profile version does not match its content hash."""


# Decisions


def record_decision(
    session: Session,
    *,
    asset_id: UUID,
    kind: str,
    from_status: str,
    to_status: str,
    actor_type: Literal["user", "system"],
    decided_by: UUID | None,
    now: datetime,
    reason: str,
    review_id: UUID | None = None,
    assessment_id: UUID | None = None,
    conditions: Any = None,
    valid_until: datetime | None = None,
    next_review_at: datetime | None = None,
    policy_version_ids: Iterable[UUID] = (),
    evidence_ids: Iterable[UUID] = (),
    payload_extra: dict[str, str] | None = None,
) -> GovernanceDecision:
    """Append the audit event, then the decision. The caller then moves the state row to it.

    payload_extra adds string facts to the audit payload that the decision row does not carry:
    the frozen hash of a submission, or the reviewer an assignment named.
    """
    if (actor_type == "system") != (decided_by is None):
        raise ValueError("a decision has a user unless the system made it")
    asset = session.get(AiAsset, asset_id)
    if asset is None:
        raise NotFound()
    conditions_canonical = None if conditions is None else canonical_json(conditions)

    decision_id = uuid4()
    audit = append_event(
        session,
        asset.tenant_id,
        event_type="governance.decision",
        actor_type=actor_type,
        actor_id=decided_by,
        subject_type="governance_decision",
        subject_id=decision_id,
        occurred_at=now,
        payload={
            "decision_id": str(decision_id),
            "asset_id": str(asset_id),
            "kind": str(kind),
            "from_status": str(from_status),
            "to_status": str(to_status),
            "assessment_id": None if assessment_id is None else str(assessment_id),
            **(payload_extra or {}),
        },
    )
    decision = GovernanceDecision(
        id=decision_id,
        tenant_id=asset.tenant_id,
        asset_id=asset_id,
        review_id=review_id,
        kind=str(kind),
        from_status=str(from_status),
        to_status=str(to_status),
        actor_type=actor_type,
        decided_by=decided_by,
        decided_at=now,
        reason=reason,
        assessment_id=assessment_id,
        conditions_canonical=conditions_canonical,
        conditions_hash=None if conditions_canonical is None else sha256_hex(conditions_canonical),
        valid_until=valid_until,
        next_review_at=next_review_at,
        audit_event_id=audit.id,
    )
    session.add(decision)
    session.flush()
    for version_id in policy_version_ids:
        session.add(GovernanceDecisionPolicyVersion(
            id=uuid4(), tenant_id=asset.tenant_id, decision_id=decision_id,
            policy_version_id=version_id,
        ))
    for evidence_id in evidence_ids:
        session.add(GovernanceDecisionEvidence(
            id=uuid4(), tenant_id=asset.tenant_id, decision_id=decision_id,
            evidence_id=evidence_id,
        ))
    session.flush()
    return decision


# Frozen values


def _frozen_hash(review: GovernanceReview) -> str:
    """Covers the frozen text and the identity it applies to, so it cannot be moved to another."""
    return sha256_hex(canonical_json({
        "review_id": str(review.id),
        "tenant_id": str(review.tenant_id),
        "asset_id": str(review.asset_id),
        "assessment_id": str(review.assessment_id),
        "profile_version_id": str(review.profile_version_id),
        "submitted_by": str(review.submitted_by),
        "required_controls": review.required_controls_canonical,
        "findings": review.findings_canonical,
        "required_approvers": review.required_approvers,
    }))


def verify_review(review: GovernanceReview) -> GovernanceReview:
    if _frozen_hash(review) != review.frozen_hash:
        raise ReviewIntegrityError(f"governance review {review.id} failed its hash")
    return review


def verify_review_anchored(session: Session, review: GovernanceReview) -> GovernanceReview:
    """verify_review, plus a check against the audit chain for a review read to make a decision.

    The frozen hash is unkeyed, so someone who can edit rows could change a frozen value and
    recompute it. The hash was also written into the audit payload of the review's own SUBMIT
    decision, and that event is covered by the chain, so the stored hash must match it.
    """
    verify_review(review)
    submits = session.execute(
        select(GovernanceDecision).where(
            GovernanceDecision.review_id == review.id, GovernanceDecision.kind == "SUBMIT"
        )
    ).scalars().all()
    audit = session.get(AuditEvent, submits[0].audit_event_id) if len(submits) == 1 else None
    if (audit is None or compute_event_hash(audit) != audit.event_hash
            or audit.payload.get("decision_id") != str(submits[0].id)
            or audit.payload.get("frozen_hash") != review.frozen_hash):
        raise ReviewIntegrityError(f"governance review {review.id} does not match its audit event")
    return review


def _controls_text(outcome: PolicyOutcome) -> str:
    """The whole outcome, including the decision rules a later approval reads."""
    return canonical_json({
        "applicable_version_ids": [str(item) for item in outcome.applicable_version_ids],
        "required_controls": [item.model_dump(mode="json") for item in outcome.required_controls],
        "minimum_approvers": outcome.minimum_approvers,
        "self_approval_permitted": outcome.self_approval_permitted,
        "owner_approval_permitted": outcome.owner_approval_permitted,
    })


def _findings_text(outcome: PolicyOutcome, profile: AssetProfile) -> str:
    findings = [item.model_dump(mode="json") for item in outcome.findings]
    if profile.asset_type is None:
        # Applicability treats an unknown fact as matching nothing, and the asset type is not a
        # risk factor, so an asset that never says what it is could escape a policy unnoticed.
        findings.insert(0, {
            "policy_version_id": None,
            "control": "asset_type",
            "severity": "medium",
            "message": "The asset type is not stated, so policies that apply by asset type "
                       "could not be matched.",
        })
    return canonical_json(findings)


# Submission


def _open_review_for_update(session: Session, asset_id: UUID) -> GovernanceReview | None:
    return session.execute(
        select(GovernanceReview)
        .where(GovernanceReview.asset_id == asset_id,
               GovernanceReview.status.in_([status.value for status in OPEN_STATUSES]))
        .with_for_update()
    ).scalar_one_or_none()


def _not_current() -> Conflict:
    return Conflict("A complete assessment of the current profile and grants is required.",
                    code="ASSESSMENT_NOT_CURRENT")


def _verified_profile(version: AssetProfileVersion) -> AssetProfile:
    if sha256_hex(version.profile_canonical) != version.content_hash:
        raise ProfileIntegrityError(f"profile version {version.id} failed its hash")
    profile = AssetProfile.model_validate(json.loads(version.profile_canonical))
    # The owner columns are not covered by the hash, and separation of duties reads them.
    if (profile.business_owner_id, profile.technical_owner_id) != (
            version.business_owner_id, version.technical_owner_id):
        raise ProfileIntegrityError(f"profile version {version.id} owners do not match")
    return profile


def submit(session: Session, registry: ToolRegistry, user: UserPrincipal, now: datetime,
           asset_id: UUID, *, reason: str) -> GovernanceReview:
    """Open a review, or replace one that is waiting for information.

    The caller must be an admin. Locks are taken in the order of spec 11.4: agent rows, then the
    state row, then (in the audit append) the chain head.
    """
    if session.get(AiAsset, asset_id) is None:
        raise NotFound()
    lock_asset_agents(session, asset_id)
    state = load_state_for_update(session, asset_id)
    require_not_retired(state)

    previous = _open_review_for_update(session, asset_id)
    if previous is not None:
        # Only a review waiting for information is replaced. Prior votes stay with it.
        if (previous.status != ReviewStatus.INFO_REQUESTED or state is None
                or state.status != GovernanceStatus.UNDER_REVIEW):
            raise Conflict("This asset already has a review open.", code="REVIEW_ALREADY_OPEN")
        verify_review_anchored(session, previous)
    elif state is None or state.status == GovernanceStatus.DRAFT:
        raise _not_current()
    elif state.status not in _SUBMITTABLE:
        raise Conflict(f"An asset in {state.status} cannot be submitted for review.",
                       code="INVALID_STATE_TRANSITION")

    record = latest_assessment(session, asset_id)
    assessment = record.assessment if record is not None else None
    if assessment is None:
        raise _not_current()
    # What is frozen below comes from these rows, so they must be what was written. The profile is
    # checked before the input hash, which reads it: an edited risk factor is tampering, not a
    # reason to assess again.
    if not recomputes_to_stored_result(session, assessment):
        raise AssessmentIntegrityError(f"risk assessment {assessment.id} does not recompute")
    profile_version = session.get(AssetProfileVersion, state.current_profile_version_id)
    if profile_version is None:
        raise _not_current()
    profile = _verified_profile(profile_version)
    if (assessment.status != "COMPLETE"
            or assessment.profile_version_id != state.current_profile_version_id
            or assessment.input_hash != current_input_hash(session, registry, asset_id)):
        raise _not_current()

    # Verified evidence arrives with the evidence register.
    outcome = evaluate_policies(applicable_documents(session, now), profile,
                                assessment.risk_level, set())

    if previous is not None:
        previous.status = ReviewStatus.WITHDRAWN.value
        previous.version += 1
        previous.closed_at = now
        session.flush()
    review = GovernanceReview(
        id=uuid4(),
        tenant_id=user.tenant_id,
        asset_id=asset_id,
        assessment_id=assessment.id,
        profile_version_id=profile_version.id,
        submitted_by=user.id,
        assigned_reviewer=previous.assigned_reviewer if previous is not None else None,
        required_controls_canonical=_controls_text(outcome),
        findings_canonical=_findings_text(outcome, profile),
        required_approvers=outcome.minimum_approvers,
        status=ReviewStatus.OPEN.value,
        version=1,
        submitted_at=now,
    )
    review.frozen_hash = _frozen_hash(review)
    session.add(review)
    session.flush()

    record_decision(
        session,
        asset_id=asset_id,
        kind=DecisionKind.SUBMIT,
        from_status=state.status,
        to_status=GovernanceStatus.UNDER_REVIEW,
        actor_type="user",
        decided_by=user.id,
        now=now,
        reason=reason,
        review_id=review.id,
        assessment_id=assessment.id,
        policy_version_ids=outcome.applicable_version_ids,
        payload_extra={"frozen_hash": review.frozen_hash},
    )
    # current_decision_id names the decision that holds authority or a block, and enforced
    # conditions are read from it (spec 11.2), so a submission must not move it: a conditionally
    # approved asset keeps its conditions while it is reassessed.
    if previous is None:
        transition(session, state, GovernanceStatus.UNDER_REVIEW, now)
    return review


# Working a review


def _locked_review(session: Session, review_id: UUID) -> GovernanceReview:
    # Lock order is agents, state, review, chain head. A caller that changes the asset's status
    # must already hold the agent and state locks before calling this.
    review = session.execute(
        select(GovernanceReview)
        .where(GovernanceReview.id == review_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if review is None:
        raise NotFound()
    return verify_review_anchored(session, review)


def _require_open(review: GovernanceReview) -> None:
    if review.status not in OPEN_STATUSES:
        raise Conflict("This review is closed.", code="REVIEW_NOT_OPEN")


def _status_of(session: Session, asset_id: UUID) -> str:
    return load_state(session, asset_id).status


def assign_reviewer(session: Session, user: UserPrincipal, now: datetime, review_id: UUID,
                    reviewer_id: UUID) -> GovernanceReview:
    """The caller must already hold governance_reviewer."""
    review = _locked_review(session, review_id)
    _require_open(review)
    if not holds_reviewer(session, reviewer_id):
        raise ValidationFailed("The assigned reviewer must hold the governance reviewer role.")
    review.assigned_reviewer = reviewer_id
    review.version += 1
    session.flush()
    status = _status_of(session, review.asset_id)
    record_decision(
        session,
        asset_id=review.asset_id,
        kind=DecisionKind.ASSIGN_REVIEWER,
        from_status=status,
        to_status=status,
        actor_type="user",
        decided_by=user.id,
        now=now,
        reason=f"Reviewer assigned: {reviewer_id}.",
        review_id=review.id,
        assessment_id=review.assessment_id,
        payload_extra={"reviewer_id": str(reviewer_id)},
    )
    return review


def request_information(session: Session, user: UserPrincipal, now: datetime, review_id: UUID,
                        *, reason: str) -> GovernanceReview:
    """The caller must already hold governance_reviewer, and be the assigned one if there is one."""
    review = _locked_review(session, review_id)
    if review.status == ReviewStatus.INFO_REQUESTED:
        raise Conflict("Information has already been requested on this review.",
                       code="INFORMATION_ALREADY_REQUESTED")
    _require_open(review)
    if review.assigned_reviewer is not None and review.assigned_reviewer != user.id:
        raise Forbidden("Only the assigned reviewer can do this.", code="NOT_ASSIGNED_REVIEWER")
    review.status = ReviewStatus.INFO_REQUESTED.value
    review.version += 1
    session.flush()
    status = _status_of(session, review.asset_id)
    record_decision(
        session,
        asset_id=review.asset_id,
        kind=DecisionKind.REQUEST_INFORMATION,
        from_status=status,
        to_status=status,
        actor_type="user",
        decided_by=user.id,
        now=now,
        reason=reason,
        review_id=review.id,
        assessment_id=review.assessment_id,
    )
    return review


# Deciding


def _frozen_controls(review: GovernanceReview) -> dict[str, Any]:
    return json.loads(review.required_controls_canonical)


def _owner_ids(session: Session, review: GovernanceReview) -> set[UUID]:
    version = session.get(AssetProfileVersion, review.profile_version_id)
    if version is None:
        raise ProfileIntegrityError(f"profile version {review.profile_version_id} is missing")
    profile = _verified_profile(version)
    return {owner for owner in (profile.business_owner_id, profile.technical_owner_id)
            if owner is not None}


def _require_authority(session: Session, user: UserPrincipal, review: GovernanceReview) -> None:
    """Spec 7.5, in order. The route checks the grant too, but this is the check that counts:
    it runs under the review lock, at the moment of the decision."""
    if not holds_reviewer(session, user.id):
        raise Forbidden()
    if review.assigned_reviewer is not None and review.assigned_reviewer != user.id:
        raise Forbidden("Only the assigned reviewer can do this.", code="NOT_ASSIGNED_REVIEWER")
    # Silence refuses: only a frozen outcome that says so permits these.
    controls = _frozen_controls(review)
    if user.id == review.submitted_by and controls.get("self_approval_permitted") is not True:
        raise Forbidden("You cannot decide a review you submitted unless a policy permits it.",
                        code="SELF_APPROVAL_REFUSED")
    if (user.id in _owner_ids(session, review)
            and controls.get("owner_approval_permitted") is not True):
        raise Forbidden("You cannot decide a review of an asset you own unless a policy "
                        "permits it.", code="SELF_APPROVAL_REFUSED")


def _lock_for_decision(session: Session, user: UserPrincipal,
                       review_id: UUID) -> tuple[GovernanceReview, AssetGovernanceState]:
    """Locks in the order of spec 11.4, then checks who may decide and whether it is open."""
    # Read as a column, so that no stale review is loaded before the locks are held.
    asset_id = session.execute(
        select(GovernanceReview.asset_id).where(GovernanceReview.id == review_id)
    ).scalar_one_or_none()
    if asset_id is None:
        raise NotFound()
    lock_asset_agents(session, asset_id)
    state = load_state_for_update(session, asset_id)
    review = _locked_review(session, review_id)
    _require_authority(session, user, review)
    if (review.status not in OPEN_STATUSES or state is None
            or state.status != GovernanceStatus.UNDER_REVIEW):
        raise Conflict("This review is closed or its asset is not under review.",
                       code="INVALID_STATE_TRANSITION")
    return review, state


def _close(session: Session, review: GovernanceReview, now: datetime) -> None:
    review.status = ReviewStatus.DECIDED.value
    review.version += 1
    review.closed_at = now
    session.flush()


def _frozen_policy_versions(review: GovernanceReview) -> list[UUID]:
    return [UUID(item) for item in _frozen_controls(review)["applicable_version_ids"]]


def _require_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationFailed(f"{name} must include a time zone.")


def _require_dates(now: datetime, valid_until: datetime, next_review_at: datetime) -> None:
    _require_aware(valid_until, "valid_until")
    _require_aware(next_review_at, "next_review_at")
    if valid_until <= now:
        raise ValidationFailed("valid_until must be in the future.")
    if not now < next_review_at <= valid_until:
        raise ValidationFailed("next_review_at must be in the future and not after valid_until.")


def _require_assessment_current(session: Session, registry: ToolRegistry,
                                review: GovernanceReview, state: AssetGovernanceState) -> None:
    """An approval is of the asset as assessed, so the profile and grants must not have moved."""
    assessment = session.get(RiskAssessment, review.assessment_id)
    if (state.current_profile_version_id != review.profile_version_id or assessment is None
            or assessment.input_hash != current_input_hash(session, registry, review.asset_id)):
        raise _not_current()


def approve(session: Session, registry: ToolRegistry, user: UserPrincipal, now: datetime,
            review_id: UUID, *, reason: str, valid_until: datetime, next_review_at: datetime,
            conditions: Conditions | None = None,
            evidence_ids: Sequence[UUID] = ()) -> GovernanceDecision:
    """Record one approval. Short of the required number it is a vote; the last one decides.

    Conditions on a vote are checked and stored but not applied. The final approval's conditions
    are the ones that take effect. Every approval must carry the same conditions as any earlier
    vote on the review, including a vote that no longer counts, so nobody can weaken or drop what
    another approver asked for; conditions may be added when no earlier vote set any. A vote
    counts toward the required number only while its voter still holds the reviewer role.
    """
    review, state = _lock_for_decision(session, user, review_id)
    if review.status == ReviewStatus.INFO_REQUESTED:
        raise Conflict("Information has been requested, so this review cannot be approved yet.",
                       code="REVIEW_AWAITING_INFORMATION")
    _require_assessment_current(session, registry, review, state)
    if evidence_ids:
        # The evidence register arrives later; until then a reference could mean nothing.
        raise ValidationFailed("Evidence cannot be referenced until the evidence register exists.")
    _require_dates(now, valid_until, next_review_at)
    if conditions is not None:
        if not is_enforceable(conditions) and not conditions.advisory_conditions:
            raise ValidationFailed("Conditions were given but contain nothing.")
        validate_against_catalog(conditions, registry)
    document = None if conditions is None else conditions.model_dump(mode="json")

    votes = session.execute(
        select(GovernanceDecision).where(
            GovernanceDecision.review_id == review.id,
            GovernanceDecision.kind == DecisionKind.APPROVAL_VOTE,
        )
    ).scalars().all()
    if any(vote.decided_by == user.id for vote in votes):
        raise Conflict("You have already voted on this review.", code="ALREADY_VOTED")
    # A vote counts only while its voter could still decide, so a revoked or downgraded voter
    # cannot be the one that completes an approval.
    counted = [vote for vote in votes if holds_reviewer(session, vote.decided_by)]
    # Conditions bind on every approval, and against every vote on this review, counted or not:
    # revoking an approver must not shed what they asked for.
    own_hash = None if document is None else sha256_hex(canonical_json(document))
    if any(vote.conditions_hash not in (None, own_hash) for vote in votes):
        raise Conflict("An earlier approver set conditions, and an approval must carry exactly "
                       "those.", code="CONDITIONS_MISMATCH")
    final = len(counted) + 1 >= review.required_approvers

    common = {
        "asset_id": review.asset_id,
        "from_status": state.status,
        "actor_type": "user",
        "decided_by": user.id,
        "now": now,
        "reason": reason,
        "review_id": review.id,
        "assessment_id": review.assessment_id,
        "conditions": document,
        "policy_version_ids": _frozen_policy_versions(review),
        "evidence_ids": evidence_ids,
    }
    if not final:
        return record_decision(session, kind=DecisionKind.APPROVAL_VOTE,
                               to_status=state.status, **common)

    target = (GovernanceStatus.CONDITIONALLY_APPROVED if conditions is not None
              else GovernanceStatus.APPROVED)
    _close(session, review, now)
    decision = record_decision(
        session,
        kind=(DecisionKind.APPROVE_CONDITIONAL if conditions is not None
              else DecisionKind.APPROVE),
        to_status=target, valid_until=valid_until, next_review_at=next_review_at, **common,
    )
    transition(session, state, target, now, current_decision_id=decision.id,
               hard_block_decision_id=None, valid_until=valid_until,
               next_review_at=next_review_at)
    return decision


def reject(session: Session, user: UserPrincipal, now: datetime, review_id: UUID, *,
           reason: str) -> GovernanceDecision:
    """One rejection decides the review, whatever votes came before, and blocks the asset."""
    review, state = _lock_for_decision(session, user, review_id)
    _close(session, review, now)
    decision = record_decision(
        session,
        asset_id=review.asset_id,
        kind=DecisionKind.REJECT,
        from_status=state.status,
        to_status=GovernanceStatus.REJECTED,
        actor_type="user",
        decided_by=user.id,
        now=now,
        reason=reason,
        review_id=review.id,
        assessment_id=review.assessment_id,
        policy_version_ids=_frozen_policy_versions(review),
    )
    # The block outlasts every later status until an approval, and no earlier approval survives.
    transition(session, state, GovernanceStatus.REJECTED, now, current_decision_id=decision.id,
               hard_block_decision_id=decision.id, valid_until=None, next_review_at=None)
    return decision


# Lifecycle actions outside a review


def _stateful(session: Session, tenant_id: UUID, asset_id: UUID,
              now: datetime) -> AssetGovernanceState:
    """The locked state row of an asset, inserting the DRAFT row an ungoverned asset lacks.

    That is the emergency path for an existing asset (spec 7.1): the row cannot be locked before
    it exists, so the asset lock taken first is what makes the insert safe.
    """
    if session.get(AiAsset, asset_id) is None:
        raise NotFound()
    state = lock_asset_state(session, asset_id)
    require_not_retired(state)
    if state is None:
        state = new_draft_state(session, tenant_id, asset_id, now)
    return state


def _withdraw_open_review(session: Session, asset_id: UUID,
                          now: datetime) -> GovernanceReview | None:
    """Close the review an asset leaves behind. No integrity check: an emergency stop must not
    wait on a review row that fails one."""
    review = _open_review_for_update(session, asset_id)
    if review is not None:
        review.status = ReviewStatus.WITHDRAWN.value
        review.version += 1
        review.closed_at = now
        session.flush()
    return review


def suspend(session: Session, user: UserPrincipal, now: datetime, asset_id: UUID, *,
            reason: str, kind: Literal["SUSPEND", "REVOKE"] = "SUSPEND") -> GovernanceDecision:
    """Block an asset until a new approval. The caller must be an admin or a reviewer holder.

    The decision becomes both the block and the current decision, and the approval window is
    cleared, so an earlier approval cannot come back into force (spec 7.2). A revocation is the
    same change, recorded under its own kind.
    """
    if kind not in (DecisionKind.SUSPEND, DecisionKind.REVOKE):
        raise ValueError(f"not a suspension: {kind}")
    state = _stateful(session, user.tenant_id, asset_id, now)
    require_transition(state, GovernanceStatus.SUSPENDED)
    review = _withdraw_open_review(session, asset_id, now)
    decision = record_decision(
        session,
        asset_id=asset_id,
        kind=kind,
        from_status=state.status,
        to_status=GovernanceStatus.SUSPENDED,
        actor_type="user",
        decided_by=user.id,
        now=now,
        reason=reason,
        review_id=None if review is None else review.id,
    )
    transition(session, state, GovernanceStatus.SUSPENDED, now, current_decision_id=decision.id,
               hard_block_decision_id=decision.id, valid_until=None, next_review_at=None)
    return decision


def retire(session: Session, user: UserPrincipal, now: datetime, asset_id: UUID, *,
           reason: str) -> GovernanceDecision:
    """End an asset's life; nothing is accepted for it afterwards. The caller must be an admin.

    A hard block stays, because the trigger lets only an approval clear it.
    """
    state = _stateful(session, user.tenant_id, asset_id, now)
    require_transition(state, GovernanceStatus.RETIRED)
    review = _withdraw_open_review(session, asset_id, now)
    decision = record_decision(
        session,
        asset_id=asset_id,
        kind=DecisionKind.RETIRE,
        from_status=state.status,
        to_status=GovernanceStatus.RETIRED,
        actor_type="user",
        decided_by=user.id,
        now=now,
        reason=reason,
        review_id=None if review is None else review.id,
    )
    transition(session, state, GovernanceStatus.RETIRED, now, current_decision_id=decision.id,
               valid_until=None, next_review_at=None)
    return decision


def _reassessment_decision(session: Session, state: AssetGovernanceState,
                           actor_type: Literal["user", "system"], user_id: UUID | None,
                           now: datetime, reason: str) -> GovernanceDecision:
    """Move a locked state row to REASSESSMENT_REQUIRED and record why.

    Only the status moves. The approval window, the current decision (which holds any conditions),
    and a hard block all stay: a reassessment is not a new approval and not a release.
    """
    require_transition(state, GovernanceStatus.REASSESSMENT_REQUIRED)
    decision = record_decision(
        session,
        asset_id=state.asset_id,
        kind=DecisionKind.REQUIRE_REASSESSMENT,
        from_status=state.status,
        to_status=GovernanceStatus.REASSESSMENT_REQUIRED,
        actor_type=actor_type,
        decided_by=user_id,
        now=now,
        reason=reason,
    )
    transition(session, state, GovernanceStatus.REASSESSMENT_REQUIRED, now)
    return decision


def require_reassessment(session: Session, actor_type: Literal["user", "system"],
                         user_id: UUID | None, now: datetime, asset_id: UUID, *,
                         reason: str) -> GovernanceDecision:
    """The system acts with no user (the review sweep); a user always names themselves."""
    if (actor_type == "system") != (user_id is None):
        raise ValueError("a reassessment has a user unless the system required it")
    if session.get(AiAsset, asset_id) is None:
        raise NotFound()
    state = lock_asset_state(session, asset_id)
    require_not_retired(state)
    if state is None:
        raise Conflict("An asset with no governance state cannot be reassessed.",
                       code="INVALID_STATE_TRANSITION")
    return _reassessment_decision(session, state, actor_type, user_id, now, reason)


def mark_grant_changed(session: Session, user: UserPrincipal, now: datetime,
                       agent_id: UUID) -> None:
    """Called before a tool or resource grant is added. The approval was of what the agent could
    do, so an added grant voids it (spec 5). An asset that is not approved is left alone, and
    removing a grant never calls this.

    The locks are taken here, before the grant row exists, so that a concurrent suspension
    waits for this transaction and not the other way round.
    """
    agent = session.get(Agent, agent_id)
    if agent is None:
        raise NotFound()
    state = lock_asset_state(session, agent.asset_id)
    if state is None or state.status not in APPROVED_STATUSES:
        return
    _reassessment_decision(session, state, "user", user.id, now,
                           "A grant was added to an agent of this asset.")


def decision_references(session: Session,
                        decision: GovernanceDecision) -> tuple[list[UUID], list[UUID]]:
    """The policy versions and evidence a decision names, in a stable order."""
    versions = session.execute(
        select(GovernanceDecisionPolicyVersion.policy_version_id)
        .where(GovernanceDecisionPolicyVersion.decision_id == decision.id)
    ).scalars().all()
    evidence = session.execute(
        select(GovernanceDecisionEvidence.evidence_id)
        .where(GovernanceDecisionEvidence.decision_id == decision.id)
    ).scalars().all()
    return sorted(versions, key=str), sorted(evidence, key=str)


# Reading


def get_review(session: Session, review_id: UUID) -> GovernanceReview:
    review = session.get(GovernanceReview, review_id)
    if review is None:
        raise NotFound()
    return verify_review_anchored(session, review)


def list_reviews(session: Session, *, status: str | None, asset_id: UUID | None, limit: int,
                 offset: int) -> tuple[list[GovernanceReview], int]:
    conditions = []
    if status is not None:
        conditions.append(GovernanceReview.status == status)
    if asset_id is not None:
        conditions.append(GovernanceReview.asset_id == asset_id)
    reviews = session.execute(
        select(GovernanceReview)
        .where(*conditions)
        .order_by(GovernanceReview.submitted_at.desc(), GovernanceReview.id)
        .limit(limit)
        .offset(offset)
    ).scalars().all()
    total = session.execute(
        select(func.count(GovernanceReview.id)).where(*conditions)
    ).scalar_one()
    return [verify_review(review) for review in reviews], total


def outstanding_findings(session: Session) -> int:
    """The findings frozen on open reviews, for the overview."""
    reviews = session.execute(
        select(GovernanceReview).where(
            GovernanceReview.status.in_([status.value for status in OPEN_STATUSES])
        )
    ).scalars().all()
    return sum(len(json.loads(verify_review(review).findings_canonical)) for review in reviews)
