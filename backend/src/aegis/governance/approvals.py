"""Reviews, decisions, and submission. Writes run in the caller's tenant transaction.

A decision is the record of one thing done to an asset. Its audit event is appended first and named
by the decision row, and the state row names the decision in turn, so a pointer never leads to a
row that does not exist yet. A review freezes what the policy engine asked for at submission, and a
hash over the frozen values is checked wherever the review is read, because a later decision relies
on them and a database edit to them would otherwise change who may approve.
"""

import json
from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.canonical import canonical_json, sha256_hex
from aegis.db.models import (
    AiAsset,
    AssetProfileVersion,
    GovernanceDecision,
    GovernanceDecisionEvidence,
    GovernanceDecisionPolicyVersion,
    GovernanceReview,
)
from aegis.errors import Conflict, Forbidden, NotFound, ValidationFailed
from aegis.gateway.tools import ToolRegistry
from aegis.governance.assets import (
    load_state,
    load_state_for_update,
    lock_asset_agents,
    require_not_retired,
    touch,
    transition,
)
from aegis.governance.engine.lifecycle import GovernanceStatus
from aegis.governance.engine.policies import PolicyOutcome, evaluate_policies
from aegis.governance.policies import applicable_documents
from aegis.governance.profile import AssetProfile
from aegis.governance.risk import current_input_hash, latest_assessment
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
) -> GovernanceDecision:
    """Append the audit event, then the decision. The caller then moves the state row to it."""
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
        verify_review(previous)
    elif state is None or state.status == GovernanceStatus.DRAFT:
        raise _not_current()
    elif state.status not in _SUBMITTABLE:
        raise Conflict(f"An asset in {state.status} cannot be submitted for review.",
                       code="INVALID_STATE_TRANSITION")

    record = latest_assessment(session, asset_id)
    assessment = record.assessment if record is not None else None
    if (assessment is None or assessment.status != "COMPLETE"
            or assessment.profile_version_id != state.current_profile_version_id
            or assessment.input_hash != current_input_hash(session, registry, asset_id)):
        raise _not_current()

    profile_version = session.get(AssetProfileVersion, state.current_profile_version_id)
    profile = AssetProfile.model_validate(json.loads(profile_version.profile_canonical))
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

    decision = record_decision(
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
    )
    if previous is not None:
        touch(session, state, now, current_decision_id=decision.id)
    else:
        transition(session, state, GovernanceStatus.UNDER_REVIEW, now,
                   current_decision_id=decision.id)
    return review


# Working a review


def _locked_review(session: Session, review_id: UUID) -> GovernanceReview:
    review = session.execute(
        select(GovernanceReview).where(GovernanceReview.id == review_id).with_for_update()
    ).scalar_one_or_none()
    if review is None:
        raise NotFound()
    return verify_review(review)


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
        reason="Reviewer assigned.",
        review_id=review.id,
        assessment_id=review.assessment_id,
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


# Reading


def get_review(session: Session, review_id: UUID) -> GovernanceReview:
    review = session.get(GovernanceReview, review_id)
    if review is None:
        raise NotFound()
    return verify_review(review)


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
