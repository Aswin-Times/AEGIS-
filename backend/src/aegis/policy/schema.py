from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

MAX_RULES = 200

ReasonCode = Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]
RuleId = Annotated[str, StringConstraints(strict=True, pattern=r"^[a-zA-Z0-9_-]{1,64}$")]
Classification = Literal["public", "internal", "sensitive"]
ResourceKind = Literal["document", "customer_record", "destination"]


class RuleMatch(BaseModel):
    """All listed conditions must hold. An absent condition does not constrain the match."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tools: list[str] | None = Field(default=None, min_length=1)
    actions: list[str] | None = Field(default=None, min_length=1)
    resource_classifications: list[Classification] | None = Field(default=None, min_length=1)
    resource_kinds: list[ResourceKind] | None = Field(default=None, min_length=1)
    attachment_classifications: list[Classification] | None = Field(default=None, min_length=1)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: RuleId
    effect: Literal["allow", "deny", "require_approval"]
    match: RuleMatch
    reason_code: ReasonCode


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rules: list[Rule] = Field(max_length=MAX_RULES)

    @model_validator(mode="after")
    def rule_ids_are_unique(self) -> "PolicyDocument":
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("Rule ids must be unique")
        return self
