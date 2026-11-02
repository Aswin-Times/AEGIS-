"""The closed tool catalog. Every tool is synthetic: no shell, no files, and no network."""

import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt
from sqlalchemy.orm import Session

from aegis.db.models import Resource, SimulatedOutbox


class ToolFailure(Exception):
    """The tool ran and could not complete. Recorded as a FAILED execution."""


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


Number = Annotated[StrictInt | StrictFloat, Field(allow_inf_nan=False)]


class CalculateParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator: Literal["add", "subtract", "multiply", "divide"]
    a: Number
    b: Number


class SendMessageParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: Annotated[str, Field(strict=True, min_length=1, max_length=2000)]
    attachment_resource_id: UUID | None = None


@dataclass(frozen=True)
class ToolContext:
    session: Session
    tenant_id: UUID
    request_id: UUID
    resource_id: UUID | None
    params: Any


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    action: str
    resource_kind: str | None
    params_model: type[BaseModel]
    handler: Callable[[ToolContext], dict[str, Any]]


def _read_document(context: ToolContext) -> dict[str, Any]:
    return {"content": context.session.get(Resource, context.resource_id).content}


def _lookup_customer(context: ToolContext) -> dict[str, Any]:
    return {"record": context.session.get(Resource, context.resource_id).content}


def _calculate(context: ToolContext) -> dict[str, Any]:
    params = context.params
    try:
        value = {
            "add": lambda: params.a + params.b,
            "subtract": lambda: params.a - params.b,
            "multiply": lambda: params.a * params.b,
            "divide": lambda: params.a / params.b,
        }[params.operator]()
    except (ZeroDivisionError, OverflowError) as error:
        raise ToolFailure("The calculation could not be completed") from error
    if not math.isfinite(value):
        raise ToolFailure("The calculation result is not finite")
    return {"value": value}


def _send_message(context: ToolContext) -> dict[str, Any]:
    outbox_id = uuid4()
    context.session.add(
        SimulatedOutbox(
            id=outbox_id,
            tenant_id=context.tenant_id,
            request_id=context.request_id,
            destination_id=context.resource_id,
            body=context.params.body,
            attachment_resource_id=context.params.attachment_resource_id,
        )
    )
    context.session.flush()
    return {"simulated": True, "outbox_id": str(outbox_id)}


class ToolRegistry:
    def __init__(self, definitions: Iterable[ToolDefinition]) -> None:
        self._definitions = {definition.name: definition for definition in definitions}

    def get(self, name: str) -> ToolDefinition | None:
        return self._definitions.get(name)

    def definitions(self) -> list[ToolDefinition]:
        return list(self._definitions.values())


def default_registry() -> ToolRegistry:
    return ToolRegistry(
        [
            ToolDefinition("read_document", "read", "document", NoParams, _read_document),
            ToolDefinition("lookup_customer", "read", "customer_record", NoParams,
                           _lookup_customer),
            ToolDefinition("calculate", "compute", None, CalculateParams, _calculate),
            ToolDefinition("send_message", "transmit", "destination", SendMessageParams,
                           _send_message),
        ]
    )
