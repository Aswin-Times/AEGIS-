from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from aegis.api.schemas import In, Out
from aegis.governance.conditions import Conditions
from aegis.governance.engine.risk import Methodology
from aegis.governance.policy_schema import (
    GovernancePolicyDocument,
    PolicyCategory,
    PolicyName,
)


class RoleGrantIn(In):
    user_id: UUID


class RoleGrantOut(Out):
    id: UUID
    user_id: UUID
    role: str
    granted_by: UUID
    granted_at: datetime
    revoked_by: UUID | None
    revoked_at: datetime | None


class PersonOut(Out):
    id: UUID
    email: str
    role: str
    reviewer_grant_id: UUID | None


class ProfileVersionOut(Out):
    id: UUID
    asset_id: UUID
    version: int
    profile: dict[str, Any]
    content_hash: str
    created_by: UUID
    created_at: datetime
    governance_status: str


class OwnerOut(Out):
    id: UUID
    email: str


class InventoryRowOut(Out):
    id: UUID
    name: str
    owner: str
    # Declared is the registrant's value. Assessed is the engine's, and null unless the latest
    # assessment is complete.
    declared_risk: str
    assessed_risk: str | None
    last_assessed_at: datetime | None
    governance_status: str | None
    business_owner: OwnerOut | None
    technical_owner: OwnerOut | None
    is_synthetic: bool
    valid_until: datetime | None
    next_review_at: datetime | None
    created_at: datetime


class CurrentProfileOut(Out):
    id: UUID
    version: int
    profile: dict[str, Any]
    content_hash: str
    created_by: UUID
    created_at: datetime


class AssetDetailOut(InventoryRowOut):
    intended_use: str
    state_version: int | None
    state_updated_at: datetime | None
    profile: CurrentProfileOut | None


class OverviewOut(Out):
    total_assets: int
    by_assessed_risk: dict[str, int]
    unassessed: int
    awaiting_approval: int
    conditionally_approved: int
    suspended: int
    overdue_reviews: int
    outstanding_findings: int
    evidence_verified: int
    evidence_total: int
    enforcement_mode: str


class AssessmentSummaryOut(Out):
    id: UUID
    asset_id: UUID
    profile_version_id: UUID
    methodology_version_id: UUID
    methodology_version: int
    input_hash: str
    result_hash: str
    status: str
    score: int | None
    risk_level: str | None
    assessed_by: UUID
    assessed_at: datetime
    audit_event_id: UUID


class AssessmentOut(AssessmentSummaryOut):
    # Null only if the stored text is not a JSON object, which means the row was altered.
    input: dict[str, Any] | None
    result: dict[str, Any] | None


class AssessmentCreatedOut(AssessmentOut):
    governance_status: str


class RiskOut(Out):
    # Both are null for an asset that has never been assessed.
    assessment: AssessmentOut | None
    recomputed_matches: bool | None


class MethodologyIn(In):
    document: Methodology


class MethodologyOut(Out):
    id: UUID
    version: int
    content_hash: str
    created_by: UUID | None
    created_at: datetime
    approved: bool
    approved_by: UUID | None
    approved_at: datetime | None
    active: bool
    document: dict[str, Any]


class PolicyIn(In):
    name: PolicyName
    category: PolicyCategory


class PolicyVersionIn(In):
    document: GovernancePolicyDocument
    # Both must carry a time zone, because a window with no zone has no single meaning.
    effective_from: AwareDatetime
    review_by: AwareDatetime | None = None

    @model_validator(mode="after")
    def review_follows_effect(self) -> "PolicyVersionIn":
        if self.review_by is not None and self.review_by <= self.effective_from:
            raise ValueError("review_by must be after effective_from")
        return self


class PolicyVersionOut(Out):
    id: UUID
    policy_id: UUID
    version: int
    content_hash: str
    effective_from: datetime
    review_by: datetime | None
    created_by: UUID
    created_at: datetime
    approved: bool
    approved_by: UUID | None
    approved_at: datetime | None
    active: bool
    document: dict[str, Any]


class PolicyOut(Out):
    id: UUID
    name: str
    category: str
    created_by: UUID
    created_at: datetime
    versions: list[PolicyVersionOut]


Reason = Annotated[
    str, StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=2000)
]


class SubmitIn(In):
    reason: Reason


class AssignIn(In):
    reviewer_id: UUID


class RequestInformationIn(In):
    reason: Reason


class ReviewOut(Out):
    id: UUID
    asset_id: UUID
    assessment_id: UUID
    profile_version_id: UUID
    submitted_by: UUID
    assigned_reviewer: UUID | None
    required_approvers: int
    status: str
    version: int
    submitted_at: datetime
    closed_at: datetime | None
    # What the policy engine asked for when the review was opened, frozen at that moment.
    required_controls: dict[str, Any]
    findings: list[dict[str, Any]]


class ApproveIn(In):
    reason: Reason
    # Both must carry a time zone, because a date with no zone has no single meaning.
    valid_until: AwareDatetime
    next_review_at: AwareDatetime
    # Optional conditions make the approval conditional.
    conditions: Conditions | None = None
    # Accepted now so the contract does not change; the register that gives them meaning is later.
    evidence_ids: list[UUID] = Field(default_factory=list, max_length=50)


class RejectIn(In):
    reason: Reason


class DecisionOut(Out):
    id: UUID
    asset_id: UUID
    review_id: UUID
    kind: str
    from_status: str
    to_status: str
    decided_by: UUID
    decided_at: datetime
    reason: str
    assessment_id: UUID
    conditions: dict[str, Any] | None
    conditions_hash: str | None
    valid_until: datetime | None
    next_review_at: datetime | None
    audit_event_id: UUID
    policy_version_ids: list[UUID]
    evidence_ids: list[UUID]
    # Where the review and the asset stand after this decision. A vote leaves both open.
    review_status: str
    governance_status: str
