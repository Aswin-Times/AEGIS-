"""The only code that invokes tool handlers. A static test enforces this."""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from aegis.gateway.tools import ToolContext, ToolRegistry


@dataclass(frozen=True)
class ExecutionClaim:
    """Proof that an execution row was committed. Only the gateway service creates these."""

    execution_id: UUID
    tenant_id: UUID
    request_id: UUID
    tool: str
    resource_id: UUID | None
    params: dict[str, Any]


class ToolExecutor:
    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    def run(self, claim: ExecutionClaim, session: Session) -> dict[str, Any]:
        definition = self._registry.get(claim.tool)
        parsed = definition.params_model.model_validate(claim.params)
        return definition.handler(
            ToolContext(
                session=session,
                tenant_id=claim.tenant_id,
                request_id=claim.request_id,
                resource_id=claim.resource_id,
                params=parsed,
            )
        )
