"""Correlation rules and the window logic. Pure: no I/O, no clock, and no LLM."""

from datetime import timedelta
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from aegis.events.schema import EventType, ReasonCode, Severity

_THIRTY_DAYS = 60 * 60 * 24 * 30


class RuleMatch(BaseModel):
    """All listed conditions must hold."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_types: list[EventType] = Field(min_length=1)
    reason_codes: list[ReasonCode] | None = Field(default=None, min_length=1)
    actions: list[Literal["read", "compute", "transmit"]] | None = Field(
        default=None, min_length=1
    )
    not_visible_reference: bool | None = None


class CorrelationRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: Annotated[bool, Field(strict=True)]
    title: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=200)]
    severity: Severity
    threshold: Annotated[int, Field(strict=True, ge=1, le=10_000)]
    window_seconds: Annotated[int, Field(strict=True, ge=1, le=_THIRTY_DAYS)]
    scope: Literal["agent", "actor", "tenant"]
    match: RuleMatch
    min_distinct_targets: Annotated[int, Field(strict=True, ge=2)] | None = None

    @model_validator(mode="after")
    def distinct_targets_are_reachable(self) -> "CorrelationRule":
        if self.min_distinct_targets is not None and self.min_distinct_targets > self.threshold:
            raise ValueError("min_distinct_targets cannot exceed threshold")
        return self


_OUTSIDE_PERMISSIONS = [
    "TOOL_NOT_GRANTED",
    "UNKNOWN_TOOL",
    "RESOURCE_NOT_GRANTED",
    "RESOURCE_KIND_MISMATCH",
    "RESOURCE_NOT_EXPECTED",
    "ATTACHMENT_NOT_GRANTED",
]

DEFAULT_RULES: dict[str, CorrelationRule] = {
    "repeated_unauthorized_tools": CorrelationRule(
        enabled=True,
        title="Repeated unauthorized tool attempts",
        severity="high",
        threshold=3,
        window_seconds=300,
        scope="agent",
        match=RuleMatch(
            event_types=["gateway.action_denied"],
            reason_codes=["TOOL_NOT_GRANTED", "UNKNOWN_TOOL"],
        ),
    ),
    "repeated_transfer_denials": CorrelationRule(
        enabled=True,
        title="Repeated denied outbound transfers",
        severity="high",
        threshold=2,
        window_seconds=900,
        scope="agent",
        match=RuleMatch(
            event_types=["gateway.action_denied"],
            actions=["transmit"],
            reason_codes=[
                "DESTINATION_CLEARANCE_INSUFFICIENT",
                "ATTACHMENT_NOT_GRANTED",
                "RESOURCE_NOT_GRANTED",
            ],
        ),
    ),
    "permission_probing": CorrelationRule(
        enabled=True,
        title="Attempts across targets outside registered permissions",
        severity="medium",
        threshold=5,
        window_seconds=3600,
        scope="agent",
        min_distinct_targets=3,
        match=RuleMatch(
            event_types=["gateway.action_denied"], reason_codes=_OUTSIDE_PERMISSIONS
        ),
    ),
    "approval_bypass_attempts": CorrelationRule(
        enabled=True,
        title="Repeated execution without a valid approval",
        severity="high",
        threshold=3,
        window_seconds=3600,
        scope="agent",
        match=RuleMatch(event_types=["gateway.execution_refused"]),
    ),
    "not_visible_references": CorrelationRule(
        enabled=True,
        title="Repeated references to records not visible in this organization",
        severity="high",
        threshold=3,
        window_seconds=900,
        scope="actor",
        match=RuleMatch(
            event_types=["gateway.action_denied", "access.not_visible"],
            not_visible_reference=True,
        ),
    ),
    "authentication_failures": CorrelationRule(
        enabled=True,
        title="Repeated authentication failures against this organization",
        severity="medium",
        threshold=10,
        window_seconds=300,
        scope="tenant",
        match=RuleMatch(
            event_types=["auth.agent_failed", "auth.login_failed", "auth.token_rejected"]
        ),
    ),
}


def matches(rule: CorrelationRule, event: Any) -> bool:
    match = rule.match
    if event.event_type not in match.event_types:
        return False
    if match.reason_codes is not None and event.reason_code not in match.reason_codes:
        return False
    if match.actions is not None and event.action not in match.actions:
        return False
    if match.not_visible_reference is not None:
        flagged = bool(event.attributes.get("not_visible_reference"))
        if flagged is not match.not_visible_reference:
            return False
    return True


def scope_key(rule: CorrelationRule, event: Any) -> str | None:
    """What events must share to correlate. None means this event has no such scope."""
    if rule.scope == "tenant":
        return "tenant"
    identity = event.agent_id if rule.scope == "agent" else event.actor_id
    return None if identity is None else f"{rule.scope}:{identity}"


def _distinct_targets(events: list[Any]) -> int:
    return len({(event.tool, event.resource_id) for event in events})


def find_qualifying_window(rule: CorrelationRule, events: list[Any]) -> list[Any] | None:
    """The earliest window meeting the rule, whole, in time order. Input order is irrelevant."""
    ordered = sorted(events, key=lambda event: (event.occurred_at, str(event.id)))
    window = timedelta(seconds=rule.window_seconds)
    end = 0
    for start, first in enumerate(ordered):
        end = max(end, start)
        while end < len(ordered) and ordered[end].occurred_at - first.occurred_at <= window:
            end += 1
        candidate = ordered[start:end]
        if len(candidate) >= rule.threshold and (
            rule.min_distinct_targets is None
            or _distinct_targets(candidate) >= rule.min_distinct_targets
        ):
            return candidate
    return None
