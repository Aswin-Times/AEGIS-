"""Conditions on an approval: a closed, typed set that can only restrict (spec 11.3).

The gateway engine imports this module, so the tool registry is named for type checking only.
"""

from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from aegis.errors import ValidationFailed

if TYPE_CHECKING:
    from aegis.gateway.tools import ToolRegistry

Name = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=100)]
Names = Annotated[list[Name], Field(max_length=50)]
Advisory = Annotated[
    str, StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=1000)
]
ResourceClassification = Literal["public", "internal", "sensitive"]


class Conditions(BaseModel):
    """Every field but advisory_conditions is enforced by the gateway; that one is only shown."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    denied_tools: Names = []
    held_tools: Names = []
    denied_actions: Names = []
    hold_all: bool = False
    max_resource_classification: ResourceClassification | None = None
    advisory_conditions: Annotated[list[Advisory], Field(max_length=20)] = []

    @field_validator("denied_tools", "held_tools", "denied_actions")
    @classmethod
    def sorted_unique(cls, names: list[str]) -> list[str]:
        """One spelling per set, so equal conditions have equal canonical text and hash."""
        return sorted(set(names))


def is_enforceable(conditions: Conditions) -> bool:
    """True if the gateway can act on it. Advisory text alone cannot be enforced."""
    return bool(
        conditions.denied_tools
        or conditions.held_tools
        or conditions.denied_actions
        or conditions.hold_all
        or conditions.max_resource_classification is not None
    )


def validate_against_catalog(conditions: Conditions, registry: "ToolRegistry") -> None:
    """Names must exist in the closed tool catalog, or the condition would silently do nothing."""
    definitions = registry.definitions()
    tools = {definition.name for definition in definitions}
    actions = {definition.action for definition in definitions}
    for field, known, label in (("denied_tools", tools, "tool"), ("held_tools", tools, "tool"),
                                ("denied_actions", actions, "action")):
        unknown = sorted(set(getattr(conditions, field)) - known)
        if unknown:
            raise ValidationFailed(f"{field} names {label}s that do not exist: {unknown}.")
    both = sorted(set(conditions.denied_tools) & set(conditions.held_tools))
    if both:
        raise ValidationFailed(f"A tool cannot be both denied and held: {both}.")
