from datetime import datetime
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
