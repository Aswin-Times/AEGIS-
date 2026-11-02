from dataclasses import dataclass
from uuid import UUID

ADMIN = "admin"
REVIEWER = "reviewer"
VIEWER = "viewer"


@dataclass(frozen=True)
class UserPrincipal:
    id: UUID
    tenant_id: UUID
    email: str
    role: str


@dataclass(frozen=True)
class AgentPrincipal:
    id: UUID
    tenant_id: UUID
    credential_id: UUID
