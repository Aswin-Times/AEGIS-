"""Deterministic policy evaluation: a pure function of the facts and the policy document.

No I/O, no clock, no randomness, and no LLM. Fixed hard checks run first and rules cannot
override them, so a permissive policy can only narrow what grants already permit.
"""

from dataclasses import dataclass
from enum import StrEnum

from aegis.policy.schema import PolicyDocument, Rule, RuleMatch


class Outcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True)
class ResourceFacts:
    kind: str
    classification: str
    clearance: str | None
    granted: bool


@dataclass(frozen=True)
class AttachmentFacts:
    classification: str | None
    granted: bool


@dataclass(frozen=True)
class ActionFacts:
    """Everything the engine may consider. All of it comes from the server, not the caller."""

    agent_active: bool
    tool: str
    tool_known: bool
    action: str | None
    tool_granted: bool
    params_valid: bool
    required_resource_kind: str | None
    resource_id_supplied: bool
    resource: ResourceFacts | None
    attachment: AttachmentFacts | None


@dataclass(frozen=True)
class PolicyUnavailable:
    reason_code: str


@dataclass(frozen=True)
class Evaluation:
    outcome: Outcome
    reason_code: str
    matched_rule_id: str | None = None


_CLASSIFICATION_RANK = {"public": 0, "internal": 1, "sensitive": 2}
_EFFECT_PRECEDENCE = (
    ("deny", Outcome.DENY),
    ("require_approval", Outcome.REQUIRE_APPROVAL),
    ("allow", Outcome.ALLOW),
)


def _hard_check_failure(facts: ActionFacts) -> str | None:
    if not facts.agent_active:
        return "AGENT_DISABLED"
    if not facts.tool_known:
        return "UNKNOWN_TOOL"
    if not facts.tool_granted:
        return "TOOL_NOT_GRANTED"
    if not facts.params_valid:
        return "INVALID_PARAMETERS"

    if facts.required_resource_kind is None:
        if facts.resource_id_supplied:
            return "RESOURCE_NOT_EXPECTED"
    else:
        if not facts.resource_id_supplied:
            return "RESOURCE_REQUIRED"
        if facts.resource is None:
            return "RESOURCE_NOT_FOUND"
        if facts.resource.kind != facts.required_resource_kind:
            return "RESOURCE_KIND_MISMATCH"
        if not facts.resource.granted:
            return "RESOURCE_NOT_GRANTED"

    if facts.attachment is not None:
        if not facts.attachment.granted or facts.attachment.classification is None:
            return "ATTACHMENT_NOT_GRANTED"
        clearance = facts.resource.clearance if facts.resource is not None else None
        if (
            clearance is None
            or _CLASSIFICATION_RANK[clearance]
            < _CLASSIFICATION_RANK[facts.attachment.classification]
        ):
            return "DESTINATION_CLEARANCE_INSUFFICIENT"
    return None


def _matches(match: RuleMatch, facts: ActionFacts) -> bool:
    resource = facts.resource
    attachment = facts.attachment
    return (
        (match.tools is None or facts.tool in match.tools)
        and (match.actions is None or facts.action in match.actions)
        and (
            match.resource_classifications is None
            or (resource is not None and resource.classification in match.resource_classifications)
        )
        and (
            match.resource_kinds is None
            or (resource is not None and resource.kind in match.resource_kinds)
        )
        and (
            match.attachment_classifications is None
            or (
                attachment is not None
                and attachment.classification in match.attachment_classifications
            )
        )
    )


def evaluate(facts: ActionFacts, policy: PolicyDocument | PolicyUnavailable) -> Evaluation:
    failure = _hard_check_failure(facts)
    if failure is not None:
        return Evaluation(Outcome.DENY, failure)
    if isinstance(policy, PolicyUnavailable):
        return Evaluation(Outcome.DENY, policy.reason_code)

    matched: list[Rule] = [rule for rule in policy.rules if _matches(rule.match, facts)]
    for effect, outcome in _EFFECT_PRECEDENCE:
        for rule in matched:
            if rule.effect == effect:
                return Evaluation(outcome, rule.reason_code, rule.id)
    return Evaluation(Outcome.DENY, "NO_MATCHING_RULE")
