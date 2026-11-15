"""The gateway's governance check (spec 11.2). Pure: facts in, verdict out.

No I/O, no clock, no randomness, and no LLM. The caller reads the clock and passes it as `now`.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal

from aegis.governance.conditions import Conditions
from aegis.policy.engine import Evaluation, Outcome


class Verdict(StrEnum):
    PASS = "PASS"  # noqa: S105 -- a verdict, not a credential
    RECORDED_DENY = "RECORDED_DENY"
    RECORDED_HOLD = "RECORDED_HOLD"
    DENY = "DENY"
    HOLD = "HOLD"


@dataclass(frozen=True)
class GovernanceFacts:
    mode: Literal["observe", "enforce"]
    status: str | None
    hard_blocked: bool
    conditions: Conditions | None
    conditions_intact: bool
    valid_until: datetime | None
    now: datetime

    def __post_init__(self) -> None:
        for value in (self.valid_until, self.now):
            if value is not None and value.utcoffset() is None:
                raise ValueError("Datetimes must be timezone-aware.")


@dataclass(frozen=True)
class ActionContext:
    tool: str
    action: str
    resource_classification: str | None


@dataclass(frozen=True)
class GovernanceCheck:
    verdict: Verdict
    reason_code: str | None

    def __post_init__(self) -> None:
        if (self.reason_code is None) != (self.verdict is Verdict.PASS):
            raise ValueError("A verdict other than PASS needs a reason code, and PASS has none.")


_CLASSIFICATION_RANK = {"public": 0, "internal": 1, "sensitive": 2}
_REASSESSING = frozenset({"REASSESSMENT_REQUIRED", "UNDER_REVIEW"})
_APPROVED = frozenset({"APPROVED", "CONDITIONALLY_APPROVED"})


def _deny(code: str) -> GovernanceCheck:
    return GovernanceCheck(Verdict.DENY, code)


def _recorded_or_applied(facts: GovernanceFacts, applied: Verdict, code: str) -> GovernanceCheck:
    """Observe records the verdict; every other mode, including an unknown one, applies it."""
    if facts.mode == "observe":
        return GovernanceCheck(
            Verdict.RECORDED_DENY if applied is Verdict.DENY else Verdict.RECORDED_HOLD, code)
    return GovernanceCheck(applied, code)


def _condition_denies(conditions: Conditions, action: ActionContext) -> bool:
    if action.tool in conditions.denied_tools or action.action in conditions.denied_actions:
        return True
    limit = conditions.max_resource_classification
    if limit is None or action.resource_classification is None:
        return False
    # A classification this table does not know is treated as above any limit.
    rank = _CLASSIFICATION_RANK.get(action.resource_classification)
    return rank is None or rank > _CLASSIFICATION_RANK[limit]


def _condition_holds(conditions: Conditions, action: ActionContext) -> bool:
    return conditions.hold_all or action.tool in conditions.held_tools


def check(facts: GovernanceFacts, action: ActionContext) -> GovernanceCheck:
    """Apply the rows of spec 11.2 in order; the first match wins.

    The exception is observe mode: a recorded verdict (rows 4, 5, 7) never shadows a
    person's condition (rows 6, 8), which spec 11.6 says apply in both modes.
    """
    if facts.status == "RETIRED":
        return _deny("GOVERNANCE_RETIRED")
    if facts.hard_blocked:
        return _deny("GOVERNANCE_BLOCKED")
    if not facts.conditions_intact:
        return _deny("GOVERNANCE_INTEGRITY_FAILED")

    recorded: GovernanceCheck | None = None
    if facts.valid_until is not None and facts.now >= facts.valid_until:
        recorded = _recorded_or_applied(facts, Verdict.DENY, "GOVERNANCE_APPROVAL_EXPIRED")
    elif facts.valid_until is None or facts.status not in _APPROVED | _REASSESSING:
        # No state row, no approval in force, or a status that cannot hold one: fail closed.
        recorded = _recorded_or_applied(facts, Verdict.DENY, "GOVERNANCE_NOT_APPROVED")
    if recorded is not None and recorded.verdict is Verdict.DENY:
        return recorded

    conditions = facts.conditions
    if conditions is not None and _condition_denies(conditions, action):
        return _deny("GOVERNANCE_CONDITION_DENIED")
    if recorded is None and facts.status in _REASSESSING:
        recorded = _recorded_or_applied(facts, Verdict.HOLD, "GOVERNANCE_REASSESSMENT_REQUIRED")
        if recorded.verdict is Verdict.HOLD:
            return recorded
    if conditions is not None and _condition_holds(conditions, action):
        return GovernanceCheck(Verdict.HOLD, "GOVERNANCE_CONDITION_HOLD")
    return recorded or GovernanceCheck(Verdict.PASS, None)


def combine(evaluation: Evaluation, result: GovernanceCheck) -> Evaluation:
    """Only ever tightens the policy outcome. Recorded verdicts and a pass change nothing."""
    if evaluation.outcome is Outcome.DENY or result.verdict not in (Verdict.DENY, Verdict.HOLD):
        return evaluation
    assert result.reason_code is not None  # noqa: S101 -- GovernanceCheck guarantees it
    if result.verdict is Verdict.DENY:
        return Evaluation(Outcome.DENY, result.reason_code)
    if evaluation.outcome is Outcome.ALLOW:
        return Evaluation(Outcome.REQUIRE_APPROVAL, result.reason_code)
    return evaluation
