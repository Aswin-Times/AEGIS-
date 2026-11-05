"""The governance state machine. Pure: the database trigger enforces the same table."""

from enum import StrEnum


class GovernanceStatus(StrEnum):
    DRAFT = "DRAFT"
    ASSESSMENT_REQUIRED = "ASSESSMENT_REQUIRED"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    CONDITIONALLY_APPROVED = "CONDITIONALLY_APPROVED"
    REJECTED = "REJECTED"
    SUSPENDED = "SUSPENDED"
    REASSESSMENT_REQUIRED = "REASSESSMENT_REQUIRED"
    RETIRED = "RETIRED"


S = GovernanceStatus

TRANSITIONS: dict[GovernanceStatus, frozenset[GovernanceStatus]] = {
    S.DRAFT: frozenset({S.ASSESSMENT_REQUIRED, S.SUSPENDED, S.RETIRED}),
    S.ASSESSMENT_REQUIRED: frozenset({S.UNDER_REVIEW, S.SUSPENDED, S.RETIRED}),
    S.UNDER_REVIEW: frozenset(
        {S.APPROVED, S.CONDITIONALLY_APPROVED, S.REJECTED, S.SUSPENDED, S.RETIRED}
    ),
    S.APPROVED: frozenset({S.REASSESSMENT_REQUIRED, S.SUSPENDED, S.RETIRED}),
    S.CONDITIONALLY_APPROVED: frozenset({S.REASSESSMENT_REQUIRED, S.SUSPENDED, S.RETIRED}),
    S.REJECTED: frozenset({S.ASSESSMENT_REQUIRED, S.RETIRED}),
    S.SUSPENDED: frozenset({S.REASSESSMENT_REQUIRED, S.RETIRED}),
    S.REASSESSMENT_REQUIRED: frozenset({S.UNDER_REVIEW, S.SUSPENDED, S.RETIRED}),
    S.RETIRED: frozenset(),
}


def can_transition(old: str, new: str) -> bool:
    try:
        return GovernanceStatus(new) in TRANSITIONS[GovernanceStatus(old)]
    except ValueError:
        return False
