"""The strict shape of a security event. Nothing is stored without passing through this."""

from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

EventType = Literal[
    "gateway.action_denied",
    "gateway.approval_required",
    "gateway.execution_refused",
    "approval.approved",
    "approval.rejected",
    "approval.expired",
    "approval.invalidated",
    "execution.succeeded",
    "execution.failed",
    "auth.agent_failed",
    "auth.login_failed",
    "auth.token_rejected",
    "authz.denied",
    "access.not_visible",
    "policy.version_created",
    "policy.activated",
    "agent.status_changed",
    "grant.changed",
    "credential.changed",
    "correlation.rule_changed",
]
Severity = Literal["info", "low", "medium", "high", "critical"]
ActorType = Literal["user", "agent", "system", "anonymous"]
ReasonCode = Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]
ToolName = Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9_]{0,63}$")]
Hash = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]

# Allowlist. A new key is a deliberate decision about what events may hold.
ATTRIBUTE_TYPES: dict[str, type] = {
    "not_visible_reference": bool,
    "suppressed_since_last": int,
    "status": str,
}
_MAX_ATTRIBUTE_TEXT = 32


class SecurityEventRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    tenant_id: UUID
    schema_version: Annotated[int, Field(strict=True, ge=1)]
    event_type: EventType
    occurred_at: AwareDatetime
    actor_type: ActorType
    actor_id: UUID | None = None
    asset_id: UUID | None = None
    agent_id: UUID | None = None
    action_request_id: UUID | None = None
    tool: ToolName | None = None
    action: Literal["read", "compute", "transmit"] | None = None
    resource_id: UUID | None = None
    decision_id: UUID | None = None
    approval_id: UUID | None = None
    execution_id: UUID | None = None
    correlation_id: UUID | None = None
    severity: Severity
    reason_code: ReasonCode
    attributes: dict[str, bool | int | str] = Field(default_factory=dict)
    source_audit_event_id: UUID
    source_event_hash: Hash

    @field_validator("attributes", mode="before")
    @classmethod
    def attributes_are_allowlisted_scalars(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("attributes must be an object")
        for key, item in value.items():
            expected = ATTRIBUTE_TYPES.get(key)
            if expected is None:
                raise ValueError(f"attribute {key!r} is not allowed")
            if type(item) is not expected:
                raise ValueError(f"attribute {key!r} has the wrong type")
            if isinstance(item, str) and len(item) > _MAX_ATTRIBUTE_TEXT:
                raise ValueError(f"attribute {key!r} is too long")
        return value
