from datetime import datetime
from typing import Any
from uuid import UUID

from aegis.api.schemas import In, Out


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
    # Declared is the registrant's value. Assessed is the engine's, and null until one exists.
    declared_risk: str
    assessed_risk: str | None
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
