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
