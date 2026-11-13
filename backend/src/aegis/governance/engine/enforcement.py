"""The gateway's governance check (spec 11.2). Pure: facts in, verdict out.

No I/O, no clock, no randomness, and no LLM. The caller reads the clock and passes it as `now`.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

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
    mode: str
    status: str | None
    hard_blocked: bool
    conditions: Conditions | None
    conditions_intact: bool
    valid_until: datetime | None
    now: datetime


@dataclass(frozen=True)
class ActionContext:
    tool: str
    action: str
    resource_classification: str | None


@dataclass(frozen=True)
class GovernanceCheck:
    verdict: Verdict
    reason_code: str | None


_CLASSIFICATION_RANK = {"public": 0, "internal": 1, "sensitive": 2}
_REASSESSING = frozenset({"REASSESSMENT_REQUIRED", "UNDER_REVIEW"})
_APPROVED = frozenset({"APPROVED", "CONDITIONALLY_APPROVED"})


def _deny(code: str) -> GovernanceCheck:
    return GovernanceCheck(Verdict.DENY, code)


def _unless_enforced(facts: GovernanceFacts, enforced: Verdict, code: str) -> GovernanceCheck:
    """Rows that deny or hold only in enforce; in observe the verdict is recorded, not applied."""
    if facts.mode == "enforce":
        return GovernanceCheck(enforced, code)
    recorded = Verdict.RECORDED_DENY if enforced is Verdict.DENY else Verdict.RECORDED_HOLD
    return GovernanceCheck(recorded, code)


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
    """Apply the rows of spec 11.2 in order; the first match wins."""
    if facts.status == "RETIRED":
        return _deny("GOVERNANCE_RETIRED")
    if facts.hard_blocked:
        return _deny("GOVERNANCE_BLOCKED")
    if not facts.conditions_intact:
        return _deny("GOVERNANCE_INTEGRITY_FAILED")
    if facts.valid_until is not None and facts.now >= facts.valid_until:
        return _unless_enforced(facts, Verdict.DENY, "GOVERNANCE_APPROVAL_EXPIRED")
    if facts.valid_until is None or facts.status not in _APPROVED | _REASSESSING:
        # No state row, no approval in force, or a status that cannot hold one: fail closed.
        return _unless_enforced(facts, Verdict.DENY, "GOVERNANCE_NOT_APPROVED")

    conditions = facts.conditions
    if conditions is not None and _condition_denies(conditions, action):
        return _deny("GOVERNANCE_CONDITION_DENIED")
    if facts.status in _REASSESSING:
        return _unless_enforced(facts, Verdict.HOLD, "GOVERNANCE_REASSESSMENT_REQUIRED")
    if conditions is not None and _condition_holds(conditions, action):
        return GovernanceCheck(Verdict.HOLD, "GOVERNANCE_CONDITION_HOLD")
    return GovernanceCheck(Verdict.PASS, None)


def combine(evaluation: Evaluation, result: GovernanceCheck) -> Evaluation:
    """Only ever tightens the policy outcome. Recorded verdicts and a pass change nothing."""
    if evaluation.outcome is Outcome.DENY or result.reason_code is None:
        return evaluation
    if result.verdict is Verdict.DENY:
        return Evaluation(Outcome.DENY, result.reason_code)
    if result.verdict is Verdict.HOLD and evaluation.outcome is Outcome.ALLOW:
        return Evaluation(Outcome.REQUIRE_APPROVAL, result.reason_code)
    return evaluation
