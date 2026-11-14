"""Governance facts for the Security Gateway, read inside the gateway's own transaction (spec 11).

The gateway holds a share lock on the agent row before this runs. Suspend, revoke, and reject take
every agent row of the asset FOR UPDATE before they touch the state row (spec 11.4), so this read
sees either the state from before such a change or the committed change, even for an asset with no
state row yet. The read takes no lock of its own, so a lifecycle change never waits on it.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from aegis.canonical import sha256_hex
from aegis.db.models import (
    Agent,
    AssetGovernanceState,
    GovernanceDecision,
    GovernanceGatewayCheck,
    GovernanceSettings,
    PolicyDecision,
)
from aegis.governance.conditions import Conditions
from aegis.governance.engine.enforcement import (
    ActionContext,
    GovernanceCheck,
    GovernanceFacts,
    Verdict,
    check,
)
from aegis.governance.engine.lifecycle import GovernanceStatus
from aegis.policy.engine import ActionFacts, Evaluation

logger = logging.getLogger("aegis.governance.gateway")

DEFAULT_MODE = "observe"
EVALUATION_ERROR = "GOVERNANCE_EVALUATION_ERROR"
# A resource the gateway could not read. It is not "no resource": the engine ranks a value it does
# not know above every classification limit.
UNKNOWN_CLASSIFICATION = "unknown"
_CLASSIFICATION_RANK = {"public": 0, "internal": 1, "sensitive": 2}
# Only a blocking decision leads to these, and it always sets the hard block. Reading the status
# too means a row that says SUSPENDED or REJECTED without its block still denies (spec 11.2).
_BLOCKING_STATUSES = frozenset({GovernanceStatus.SUSPENDED.value, GovernanceStatus.REJECTED.value})


@dataclass(frozen=True)
class GatewayOutcome:
    check: GovernanceCheck
    mode: str
    observed_status: str | None
    asset_id: UUID | None
    governance_decision_id: UUID | None

    def record(self, policy: Evaluation) -> dict[str, str | None]:
        """The `governance` object of a decision's evidence and audit payload. It keeps the
        policy's own result, so a decision governance changed can still be explained."""
        return {
            "mode": self.mode,
            "observed_status": self.observed_status,
            "verdict": self.check.verdict.value,
            "reason_code": self.check.reason_code,
            "asset_id": None if self.asset_id is None else str(self.asset_id),
            "governance_decision_id": (None if self.governance_decision_id is None
                                       else str(self.governance_decision_id)),
            "policy_outcome": policy.outcome.value,
            "policy_reason_code": policy.reason_code,
        }


def get_mode(session: Session) -> str:
    """No settings row means observe (spec 4)."""
    mode = session.execute(select(GovernanceSettings.enforcement_mode)).scalar_one_or_none()
    return mode or DEFAULT_MODE


def is_hard_blocked(status: str | None, hard_block_decision_id: UUID | None) -> bool:
    return hard_block_decision_id is not None or status in _BLOCKING_STATUSES


def evaluation_error(mode: str) -> GovernanceCheck:
    """A check that failed. Only observe records it; any other mode denies (spec 11.2)."""
    verdict = Verdict.RECORDED_DENY if mode == DEFAULT_MODE else Verdict.DENY
    return GovernanceCheck(verdict, EVALUATION_ERROR)


def action_context(facts: ActionFacts) -> ActionContext:
    """The action as the pure check sees it. The classification is the most sensitive of the
    resource and the attachment, and one that could not be read counts as unknown."""
    seen = []
    if facts.resource_id_supplied:
        seen.append(facts.resource.classification if facts.resource else UNKNOWN_CLASSIFICATION)
    if facts.attachment is not None:
        seen.append(facts.attachment.classification or UNKNOWN_CLASSIFICATION)
    classification = max(
        seen, key=lambda value: _CLASSIFICATION_RANK.get(value, len(_CLASSIFICATION_RANK)),
        default=None,
    )
    # An unknown tool has no action. The policy denies it before this verdict can matter.
    return ActionContext(tool=facts.tool, action=facts.action or "",
                         resource_classification=classification)


def _state_of(session: Session, agent_id: UUID) -> tuple[UUID | None, AssetGovernanceState | None]:
    agent = session.get(Agent, agent_id)
    if agent is None:
        return None, None
    state = session.execute(
        select(AssetGovernanceState)
        .where(AssetGovernanceState.asset_id == agent.asset_id)
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    return agent.asset_id, state


def _conditions(decision: GovernanceDecision | None) -> tuple[Conditions | None, bool]:
    """The conditions of the current decision, and whether they are intact.

    A pointer to a decision that cannot be read, or conditions that fail their hash or no longer
    parse, are not intact: the approval in force may carry restrictions, so they are never
    read as "no conditions".
    """
    if decision is None:
        return None, False
    canonical, stored = decision.conditions_canonical, decision.conditions_hash
    if canonical is None and stored is None:
        # The database requires conditions on a conditional approval.
        return None, decision.kind != "APPROVE_CONDITIONAL"
    if canonical is None or stored is None or sha256_hex(canonical) != stored:
        return None, False
    try:
        return Conditions.model_validate(json.loads(canonical)), True
    except ValueError:
        return None, False


def _facts(session: Session, mode: str, state: AssetGovernanceState | None,
           now: datetime) -> tuple[GovernanceFacts, UUID | None]:
    """The facts, and the governance decision they rest on: the block if there is one."""
    if state is None:
        return GovernanceFacts(mode=mode, status=None, hard_blocked=False, conditions=None,
                               conditions_intact=True, valid_until=None, now=now), None
    current = None
    if state.current_decision_id is not None:
        current = session.get(GovernanceDecision, state.current_decision_id)
        conditions, intact = _conditions(current)
    else:
        conditions, intact = None, True
    facts = GovernanceFacts(
        mode=mode,
        status=state.status,
        hard_blocked=is_hard_blocked(state.status, state.hard_block_decision_id),
        conditions=conditions,
        conditions_intact=intact,
        valid_until=state.valid_until,
        now=now,
    )
    return facts, state.hard_block_decision_id or (current.id if current else None)


def load_facts(session: Session, agent_id: UUID,
               now: datetime) -> tuple[GovernanceFacts, UUID | None]:
    """The facts for an agent's asset, and that asset's id."""
    asset_id, state = _state_of(session, agent_id)
    facts, _ = _facts(session, get_mode(session), state, now)
    return facts, asset_id


def _checked(session: Session, mode: str, state: AssetGovernanceState | None,
             action: ActionContext, now: datetime) -> tuple[GovernanceCheck, UUID | None]:
    try:
        facts, decision_id = _facts(session, mode, state, now)
        return check(facts, action), decision_id
    except SQLAlchemyError:
        # A database failure aborts the transaction and returns 503 in both modes, as today.
        raise
    except Exception:
        logger.exception("governance check failed")
        return evaluation_error(mode), None


def check_state(session: Session, state: AssetGovernanceState | None, mode: str,
                action: ActionContext, now: datetime) -> GovernanceCheck:
    """The verdict for one asset's state, failing as the gateway does."""
    return _checked(session, mode, state, action, now)[0]


def safe_check(session: Session, agent_id: UUID, action: ActionContext,
               now: datetime) -> GatewayOutcome:
    mode = get_mode(session)
    asset_id, state = _state_of(session, agent_id)
    result, decision_id = _checked(session, mode, state, action, now)
    return GatewayOutcome(
        check=result,
        mode=mode,
        observed_status=None if state is None else state.status,
        asset_id=asset_id,
        governance_decision_id=decision_id,
    )


def record_check(session: Session, decision: PolicyDecision, outcome: GatewayOutcome,
                 now: datetime) -> None:
    """One row per policy decision. It adds no audit event: the decision's own carries it."""
    session.add(GovernanceGatewayCheck(
        id=uuid4(),
        tenant_id=decision.tenant_id,
        decision_id=decision.id,
        request_id=decision.request_id,
        agent_id=decision.agent_id,
        asset_id=outcome.asset_id,
        mode=outcome.mode,
        observed_status=outcome.observed_status,
        verdict=outcome.check.verdict.value,
        reason_code=outcome.check.reason_code,
        governance_decision_id=outcome.governance_decision_id,
        checked_at=now,
    ))
    session.flush()
