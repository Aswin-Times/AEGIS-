"""The gateway acting on governance (spec 11). The spy shows whether a tool actually ran."""

import ast
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

import aegis
import aegis.governance.gateway_check as gateway_check
from aegis.governance.approvals import suspend
from aegis.governance.conditions import Conditions
from aegis.governance.engine.enforcement import ActionContext, GovernanceCheck, Verdict
from aegis.policy.engine import ActionFacts, AttachmentFacts, ResourceFacts
from aegis.security.principals import UserPrincipal
from support import ASSETS, assess, error_code, reviewers, submitted

PARAMS = {"operator": "add", "a": 1, "b": 2}
ENFORCEMENT = "/governance/enforcement"
PREFLIGHT = "/governance/enforcement/preflight"
SOURCE_ROOT = Path(aegis.__file__).parent


def calc(agent, key=None):
    response = agent.act("calculate", params=PARAMS, key=key)
    assert response.status_code == 200, response.text
    return response.json()


def lifecycle(tenant, asset_id, action, reason="Synthetic lifecycle change."):
    response = tenant.post(f"{ASSETS}/{asset_id}/{action}", {"reason": reason})
    assert response.status_code == 201, response.text
    return response.json()


def checks(attacker_sql, request_id):
    rows = attacker_sql.execute(
        "SELECT c.decision_id, c.request_id, c.agent_id, c.asset_id, c.mode, c.observed_status, "
        "c.verdict, c.reason_code, c.governance_decision_id "
        "FROM governance_gateway_checks c JOIN policy_decisions d ON d.id = c.decision_id "
        "WHERE c.request_id = %s ORDER BY d.evaluated_at, c.checked_at",
        (request_id,),
    ).fetchall()
    names = ("decision_id", "request_id", "agent_id", "asset_id", "mode", "observed_status",
             "verdict", "reason_code", "governance_decision_id")
    return [dict(zip(names, (str(v) if isinstance(v, UUID) else v for v in row), strict=True))
            for row in rows]


def state_of(attacker_sql, asset_id):
    return attacker_sql.execute(
        "SELECT status, current_decision_id, hard_block_decision_id, valid_until "
        "FROM asset_governance_state WHERE asset_id = %s", (asset_id,)).fetchone()


def outcome(body):
    return body["outcome"], body["reason_code"]


def events_of(tenant, event_type):
    response = tenant.get("/events", limit=100, event_type=event_type)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def approve_action(tenant, approval_id):
    response = tenant.post(f"/approvals/{approval_id}/approve", {}, headers=tenant.reviewer)
    assert response.status_code == 200, response.text


def at(world, moment):
    world.app.state.container.clock = lambda: moment


def tampered(attacker_sql, statement, params):
    """Write as someone who controls the database: triggers and foreign keys do not fire."""
    attacker_sql.execute("SET session_replication_role = replica")
    try:
        attacker_sql.execute(statement, params)
    finally:
        attacker_sql.execute("SET session_replication_role = origin")


# Compatibility


def test_default_mode_leaves_ungoverned_agent_behavior_unchanged(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])

    body = calc(agent)

    assert outcome(body) == ("ALLOW", "ALLOWED_BY_RULE")
    assert body["execution"]["status"] == "SUCCEEDED"
    assert world.spy.calls == ["calculate"]
    (row,) = checks(attacker_sql, body["request_id"])
    assert (row["mode"], row["verdict"], row["reason_code"]) == (
        "observe", "RECORDED_DENY", "GOVERNANCE_NOT_APPROVED")
    assert row["observed_status"] is None and row["governance_decision_id"] is None
    assert tenant.get(ENFORCEMENT).json()["enforcement_mode"] == "observe"


def test_observe_pass_creates_no_security_event(tenant):
    tenant.allow_everything()
    ungoverned = tenant.agent(tools=["calculate"])
    reassessing = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, reassessing.asset_id, "reassess")

    assert outcome(calc(ungoverned)) == ("ALLOW", "ALLOWED_BY_RULE")
    assert outcome(calc(reassessing)) == ("ALLOW", "ALLOWED_BY_RULE")

    assert events_of(tenant, "gateway.action_denied") == []
    assert events_of(tenant, "gateway.approval_required") == []
    assert len(events_of(tenant, "execution.succeeded")) == 2


def test_migration_does_not_authorize_existing_assets(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    tenant.set_enforcement("enforce")

    body = calc(agent)

    assert outcome(body) == ("DENY", "GOVERNANCE_NOT_APPROVED")
    assert body["execution"] is None
    assert world.spy.calls == []
    # Being checked gives an existing asset no governance state.
    assert state_of(attacker_sql, agent.asset_id) is None


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_new_tables_add_no_chain_events_per_action(tenant, mode):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    if mode == "enforce":
        tenant.set_enforcement("enforce")

    body = calc(agent)

    assert body["execution"]["status"] == "SUCCEEDED"
    types = [item["event_type"] for item in sorted(tenant.audit_events(), key=lambda e: e["seq"])
             if item["correlation_id"] == body["request_id"]]
    assert types == ["action.decision", "execution.started", "execution.succeeded"]
    decision = next(item for item in tenant.audit_events("action.decision")
                    if item["correlation_id"] == body["request_id"])
    assert decision["payload"]["governance"]["verdict"] == "PASS"
    assert tenant.verify_audit()["valid"] is True


# Missing, expired, suspended, revoked


def test_missing_status_enforce_denies(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"], approve=False)
    assert state_of(attacker_sql, agent.asset_id)[0] == "ASSESSMENT_REQUIRED"
    tenant.set_enforcement("enforce")

    body = calc(agent)

    assert outcome(body) == ("DENY", "GOVERNANCE_NOT_APPROVED")
    assert world.spy.calls == []
    (row,) = checks(attacker_sql, body["request_id"])
    assert (row["observed_status"], row["verdict"]) == ("ASSESSMENT_REQUIRED", "DENY")


def test_expired_approval_enforce_denies_observe_records(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"], valid_days=1)
    later = datetime.now(UTC) + timedelta(days=2)

    at(world, later)
    observed = calc(agent)
    assert outcome(observed) == ("ALLOW", "ALLOWED_BY_RULE")
    (row,) = checks(attacker_sql, observed["request_id"])
    assert (row["verdict"], row["reason_code"]) == ("RECORDED_DENY", "GOVERNANCE_APPROVAL_EXPIRED")
    # Expiry comes from the clock inside the gateway: the status still reads approved.
    assert row["observed_status"] == "APPROVED"

    world.app.state.container.clock = lambda: datetime.now(UTC)
    tenant.set_enforcement("enforce")
    at(world, later)
    enforced = calc(agent)
    assert outcome(enforced) == ("DENY", "GOVERNANCE_APPROVAL_EXPIRED")
    assert world.spy.calls == ["calculate"]


def test_exact_expiry_instant_is_expired(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    tenant.set_enforcement("enforce")
    valid_until = state_of(attacker_sql, agent.asset_id)[3]

    at(world, valid_until - timedelta(microseconds=1))
    assert outcome(calc(agent)) == ("ALLOW", "ALLOWED_BY_RULE")
    at(world, valid_until)
    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_APPROVAL_EXPIRED")
    assert world.spy.calls == ["calculate"]


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_suspended_denies_in_both_modes_and_tool_never_runs(world, tenant, attacker_sql, mode):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    decision = lifecycle(tenant, agent.asset_id, "suspend")
    if mode == "enforce":
        tenant.set_enforcement("enforce")

    body = calc(agent)

    assert outcome(body) == ("DENY", "GOVERNANCE_BLOCKED")
    assert body["execution"] is None and world.spy.calls == []
    (row,) = checks(attacker_sql, body["request_id"])
    assert (row["mode"], row["verdict"], row["governance_decision_id"]) == (
        mode, "DENY", decision["id"])


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_revoked_denies_in_both_modes(world, tenant, mode):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, agent.asset_id, "revoke")
    if mode == "enforce":
        tenant.set_enforcement("enforce")

    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_BLOCKED")
    assert world.spy.calls == []


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_rejected_denies_in_both_modes(world, tenant, mode):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"], approve=False)
    holder = reviewers(tenant)
    review = submitted(tenant, agent.asset_id)
    rejected = tenant.post(f"/governance/approvals/{review['id']}/reject",
                           {"reason": "Synthetic rejection."}, headers=holder)
    assert rejected.status_code == 201, rejected.text
    if mode == "enforce":
        tenant.set_enforcement("enforce")

    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_BLOCKED")
    # Assessing again moves a rejected asset on, but its block stays until a new approval.
    assess(tenant, agent.asset_id)
    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_BLOCKED")
    assert world.spy.calls == []


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_retired_denies_in_both_modes(world, tenant, mode):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, agent.asset_id, "retire")
    if mode == "enforce":
        tenant.set_enforcement("enforce")

    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_RETIRED")
    assert world.spy.calls == []


def test_suspended_stays_denied_through_reassessment_in_observe(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, agent.asset_id, "suspend")

    lifecycle(tenant, agent.asset_id, "reassess")
    assert state_of(attacker_sql, agent.asset_id)[0] == "REASSESSMENT_REQUIRED"
    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_BLOCKED")

    assess(tenant, agent.asset_id)
    review = submitted(tenant, agent.asset_id)
    assert state_of(attacker_sql, agent.asset_id)[0] == "UNDER_REVIEW"
    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_BLOCKED")
    assert world.spy.calls == []

    approved = tenant.post(f"/governance/approvals/{review['id']}/approve",
                           {"reason": "Fixed.", "valid_until": _days(30),
                            "next_review_at": _days(10)}, headers=reviewers(tenant))
    assert approved.status_code == 201, approved.text
    assert outcome(calc(agent)) == ("ALLOW", "ALLOWED_BY_RULE")
    assert world.spy.calls == ["calculate"]


def _days(count):
    return (datetime.now(UTC) + timedelta(days=count)).isoformat()


def test_reassessment_required_holds_in_enforce(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, agent.asset_id, "reassess")

    observed = calc(agent)
    assert outcome(observed) == ("ALLOW", "ALLOWED_BY_RULE")
    (row,) = checks(attacker_sql, observed["request_id"])
    assert (row["verdict"], row["reason_code"]) == (
        "RECORDED_HOLD", "GOVERNANCE_REASSESSMENT_REQUIRED")

    tenant.set_enforcement("enforce")
    held = calc(agent)
    assert outcome(held) == ("REQUIRE_APPROVAL", "GOVERNANCE_REASSESSMENT_REQUIRED")
    assert held["approval_status"] == "PENDING" and held["execution"] is None
    assert world.spy.calls == ["calculate"]


def test_under_review_with_approval_in_force_holds(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, agent.asset_id, "reassess")
    assess(tenant, agent.asset_id)
    submitted(tenant, agent.asset_id)
    status, _, _, valid_until = state_of(attacker_sql, agent.asset_id)
    assert status == "UNDER_REVIEW" and valid_until is not None
    tenant.set_enforcement("enforce")

    body = calc(agent)

    assert outcome(body) == ("REQUIRE_APPROVAL", "GOVERNANCE_REASSESSMENT_REQUIRED")
    assert world.spy.calls == []


def test_approved_passes_in_enforce(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    tenant.set_enforcement("enforce")

    body = calc(agent)

    assert outcome(body) == ("ALLOW", "ALLOWED_BY_RULE")
    assert body["execution"]["result"] == {"value": 3}
    assert world.spy.calls == ["calculate"]
    (row,) = checks(attacker_sql, body["request_id"])
    assert (row["mode"], row["observed_status"], row["verdict"], row["reason_code"]) == (
        "enforce", "APPROVED", "PASS", None)


# Conditions


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_condition_denied_tool_denies_in_both_modes(world, tenant, mode):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate", "read_document"],
                                  conditions={"denied_tools": ["calculate"]})
    if mode == "enforce":
        tenant.set_enforcement("enforce")

    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_CONDITION_DENIED")
    assert world.spy.calls == []


def test_condition_held_tool_creates_action_approval(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"], conditions={"held_tools": ["calculate"]})

    # A person's condition applies in observe mode too.
    body = calc(agent)
    assert outcome(body) == ("REQUIRE_APPROVAL", "GOVERNANCE_CONDITION_HOLD")
    assert body["approval_status"] == "PENDING" and world.spy.calls == []

    approve_action(tenant, body["approval_id"])
    executed = agent.execute(body["request_id"])
    assert executed.status_code == 200, executed.text
    assert executed.json()["execution"]["status"] == "SUCCEEDED"
    assert world.spy.calls == ["calculate"]
    rows = checks(attacker_sql, body["request_id"])
    assert [(row["verdict"], row["reason_code"]) for row in rows] == [
        ("HOLD", "GOVERNANCE_CONDITION_HOLD"), ("HOLD", "GOVERNANCE_CONDITION_HOLD")]


def test_condition_deny_survives_reassessment(world, tenant):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate", "read_document"],
                                  conditions={"denied_tools": ["calculate"]})
    lifecycle(tenant, agent.asset_id, "reassess")
    tenant.set_enforcement("enforce")

    # Row 6 precedes row 7, so a denied tool does not become approvable during reassessment.
    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_CONDITION_DENIED")
    assert world.spy.calls == []


def test_classification_condition_denies_a_more_sensitive_resource(world, tenant):
    tenant.allow_everything()
    public, internal = tenant.document("public"), tenant.document("internal")
    agent = tenant.governed_agent(tools=["read_document"], resources=[public, internal],
                                  conditions={"max_resource_classification": "public"})

    assert agent.act("read_document", public).json()["outcome"] == "ALLOW"
    body = agent.act("read_document", internal).json()
    assert outcome(body) == ("DENY", "GOVERNANCE_CONDITION_DENIED")
    assert world.spy.calls == ["read_document"]


# Only tightens


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_policy_deny_keeps_reason_on_suspended_asset(world, tenant, attacker_sql, mode):
    tenant.activate([{"id": "deny-calc", "effect": "deny", "match": {"tools": ["calculate"]},
                      "reason_code": "CALCULATION_FORBIDDEN"},
                     {"id": "allow", "effect": "allow", "match": {},
                      "reason_code": "ALLOWED_BY_RULE"}])
    agent = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, agent.asset_id, "suspend")
    if mode == "enforce":
        tenant.set_enforcement("enforce")

    body = calc(agent)

    assert outcome(body) == ("DENY", "CALCULATION_FORBIDDEN")
    assert world.spy.calls == []
    # The governance verdict is still recorded beside the policy decision.
    (row,) = checks(attacker_sql, body["request_id"])
    assert (row["verdict"], row["reason_code"]) == ("DENY", "GOVERNANCE_BLOCKED")


def test_hard_check_deny_keeps_reason_on_approved_asset(world, tenant):
    tenant.allow_everything()
    granted, other = tenant.document(), tenant.document()
    agent = tenant.governed_agent(tools=["read_document"], resources=[granted])
    tenant.set_enforcement("enforce")

    assert outcome(agent.act("read_document", other).json()) == ("DENY", "RESOURCE_NOT_GRANTED")
    assert outcome(agent.act("send_message", params={}).json()) == ("DENY", "TOOL_NOT_GRANTED")
    assert world.spy.calls == []


def test_hard_check_deny_keeps_reason_on_suspended_asset(world, tenant):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, agent.asset_id, "suspend")

    body = agent.act("run_shell_command", params={"command": "x"}).json()
    assert outcome(body) == ("DENY", "UNKNOWN_TOOL")


def test_approved_governance_does_not_loosen_runtime_policy(world, tenant):
    agent = tenant.governed_agent(tools=["calculate"])
    tenant.set_enforcement("enforce")
    assert outcome(calc(agent)) == ("DENY", "NO_ACTIVE_POLICY")

    tenant.hold_tool("calculate")
    held = calc(agent)
    assert outcome(held) == ("REQUIRE_APPROVAL", "APPROVAL_REQUIRED_BY_RULE")
    assert world.spy.calls == []


# Time of check


def _held_and_approved(tenant):
    """An approved asset whose action the runtime policy held and a person then approved."""
    tenant.hold_tool("calculate")
    agent = tenant.governed_agent(tools=["calculate"])
    tenant.set_enforcement("enforce")
    body = calc(agent)
    assert outcome(body) == ("REQUIRE_APPROVAL", "APPROVAL_REQUIRED_BY_RULE")
    approve_action(tenant, body["approval_id"])
    return agent, body


def test_suspend_after_action_approval_cancels_it(world, tenant, attacker_sql):
    agent, body = _held_and_approved(tenant)
    lifecycle(tenant, agent.asset_id, "suspend")

    response = agent.execute(body["request_id"])

    assert (response.status_code, error_code(response)) == (409, "APPROVAL_NOT_EXECUTABLE")
    assert world.spy.calls == []
    assert tenant.get(f"/approvals/{body['approval_id']}").json()["status"] == "CANCELLED"
    (cancelled,) = [item for item in tenant.audit_events("approval.cancelled")
                    if item["subject_id"] == body["approval_id"]]
    assert cancelled["payload"]["reason"] == "GOVERNANCE_BLOCKED"
    rows = checks(attacker_sql, body["request_id"])
    assert [row["verdict"] for row in rows] == ["PASS", "DENY"]


def test_hold_at_reevaluation_does_not_block_human_approved_action(world, tenant, attacker_sql):
    agent, body = _held_and_approved(tenant)
    lifecycle(tenant, agent.asset_id, "reassess")

    response = agent.execute(body["request_id"])

    assert response.status_code == 200, response.text
    assert response.json()["execution"]["status"] == "SUCCEEDED"
    assert world.spy.calls == ["calculate"]
    rows = checks(attacker_sql, body["request_id"])
    assert [(row["verdict"], row["reason_code"]) for row in rows] == [
        ("PASS", None), ("HOLD", "GOVERNANCE_REASSESSMENT_REQUIRED")]


def _seq(attacker_sql, subject_id):
    return attacker_sql.execute(
        "SELECT seq FROM audit_events WHERE subject_id = %s", (subject_id,)).fetchone()[0]


def test_concurrent_suspend_and_action_on_stateless_asset(world, tenant, attacker_sql):
    """Either the action was decided before the suspension committed, or it was denied."""
    tenant.allow_everything()
    seen = set()
    for _ in range(6):
        agent = tenant.agent(tools=["calculate"])
        barrier = threading.Barrier(2)

        def suspending(agent=agent, barrier=barrier):
            barrier.wait(timeout=30)
            return tenant.post(f"{ASSETS}/{agent.asset_id}/suspend", {"reason": "Race."})

        def acting(agent=agent, barrier=barrier):
            barrier.wait(timeout=30)
            return agent.act("calculate", params=PARAMS)

        with ThreadPoolExecutor(max_workers=2) as pool:
            suspended, acted = pool.submit(suspending), pool.submit(acting)
            suspension, action = suspended.result(timeout=90), acted.result(timeout=90)
        assert suspension.status_code == 201, suspension.text
        assert action.status_code == 200, action.text
        body = action.json()
        decided, blocked = _seq(attacker_sql, body["decision_id"]), _seq(
            attacker_sql, suspension.json()["id"])
        if body["outcome"] == "ALLOW":
            assert decided < blocked, "an action was allowed after the suspension committed"
        else:
            assert outcome(body) == ("DENY", "GOVERNANCE_BLOCKED") and decided > blocked
        seen.add(body["outcome"])
    assert seen <= {"ALLOW", "DENY"}
    assert tenant.verify_audit()["valid"] is True


def test_action_waits_for_an_uncommitted_suspension(world, tenant, db, urls):
    """The gateway's share lock on the agent row orders its governance read after a suspension
    that holds the asset's agent rows, so it reads the committed block."""
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    admin = UserPrincipal(id=UUID(tenant.user_id("admin")), tenant_id=tenant.id,
                          email="admin", role="admin")
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        with psycopg.connect(urls.superuser, autocommit=True) as observer:
            with db.tenant_transaction(tenant.id) as session:
                suspend(session, admin, datetime.now(UTC), UUID(agent.asset_id),
                        reason="Held open.")
                future = pool.submit(lambda: agent.act("calculate", params=PARAMS))
                waiting, deadline = 0, time.monotonic() + 15
                while not waiting and time.monotonic() < deadline:
                    waiting = observer.execute(
                        "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                        "AND query LIKE '%FROM agents%' AND pid <> pg_backend_pid()"
                    ).fetchone()[0]
                    time.sleep(0.05)
                assert waiting, "the action did not wait for the agent rows"
                assert not future.done()
        body = future.result(timeout=30).json()
    finally:
        pool.shutdown(wait=True)
    assert outcome(body) == ("DENY", "GOVERNANCE_BLOCKED")
    assert world.spy.calls == []


def test_suspend_does_not_deadlock_with_a_finishing_execution(tenant, attacker_sql, urls):
    """A finishing execution holds the chain head, then inserts rows whose foreign keys take a key
    share lock on its agent. A suspension holding the agent rows must not block that."""
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        with psycopg.connect(urls.superuser, autocommit=True) as observer:
            with attacker_sql.transaction():
                attacker_sql.execute("SELECT 1 FROM audit_chain_heads WHERE tenant_id = %s "
                                     "FOR UPDATE", (tenant.id,))
                future = pool.submit(lambda: tenant.post(f"{ASSETS}/{agent.asset_id}/suspend",
                                                         {"reason": "Racing an execution."}))
                waiting, deadline = 0, time.monotonic() + 15
                while not waiting and time.monotonic() < deadline:
                    waiting = observer.execute(
                        "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                        "AND query LIKE '%audit_chain_heads%' AND pid <> pg_backend_pid()"
                    ).fetchone()[0]
                    time.sleep(0.05)
                assert waiting, "the suspension did not reach the chain head"
                attacker_sql.execute("SET LOCAL lock_timeout = '2s'")
                attacker_sql.execute("SELECT 1 FROM agents WHERE id = %s FOR KEY SHARE",
                                     (agent.id,))
            assert future.result(timeout=30).status_code == 201
    finally:
        pool.shutdown(wait=True)


def test_gateway_takes_no_lock_on_governance_state(world, tenant, attacker_sql):
    """A lock held on the state row does not stop an action, so the gateway cannot form a lock
    cycle with a lifecycle change that holds it."""
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        with attacker_sql.transaction():
            attacker_sql.execute("SELECT 1 FROM asset_governance_state WHERE asset_id = %s "
                                 "FOR UPDATE", (agent.asset_id,))
            body = pool.submit(lambda: calc(agent)).result(timeout=30)
    finally:
        pool.shutdown(wait=True)
    assert outcome(body) == ("ALLOW", "ALLOWED_BY_RULE")


def test_replay_after_suspension_returns_stored_result(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    tenant.set_enforcement("enforce")
    first = calc(agent, key="replayed-key")
    assert outcome(first) == ("ALLOW", "ALLOWED_BY_RULE")
    lifecycle(tenant, agent.asset_id, "suspend")

    replay = calc(agent, key="replayed-key")

    assert replay == first
    assert world.spy.calls == ["calculate"]
    assert len(checks(attacker_sql, first["request_id"])) == 1
    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_BLOCKED")


# Failure


def _broken_check(*args, **kwargs):
    raise RuntimeError("synthetic governance failure")


def test_check_failure_denies_in_enforce(world, tenant, attacker_sql, monkeypatch):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    tenant.set_enforcement("enforce")
    monkeypatch.setattr(gateway_check, "check", _broken_check)

    body = calc(agent)

    assert outcome(body) == ("DENY", "GOVERNANCE_EVALUATION_ERROR")
    assert world.spy.calls == []
    (row,) = checks(attacker_sql, body["request_id"])
    assert (row["verdict"], row["reason_code"]) == ("DENY", "GOVERNANCE_EVALUATION_ERROR")
    assert row["asset_id"] == agent.asset_id and row["observed_status"] == "APPROVED"


def test_check_failure_does_not_block_in_observe(world, tenant, attacker_sql, monkeypatch):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    monkeypatch.setattr(gateway_check, "check", _broken_check)

    body = calc(agent)

    assert outcome(body) == ("ALLOW", "ALLOWED_BY_RULE")
    assert world.spy.calls == ["calculate"]
    (row,) = checks(attacker_sql, body["request_id"])
    assert (row["verdict"], row["reason_code"]) == (
        "RECORDED_DENY", "GOVERNANCE_EVALUATION_ERROR")


def test_check_failure_at_reevaluation_cancels_in_enforce(world, tenant, monkeypatch):
    agent, body = _held_and_approved(tenant)
    monkeypatch.setattr(gateway_check, "check", _broken_check)

    response = agent.execute(body["request_id"])

    assert (response.status_code, error_code(response)) == (409, "APPROVAL_NOT_EXECUTABLE")
    assert world.spy.calls == []


def test_database_failure_in_the_check_returns_503(world, tenant, monkeypatch):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])

    def failing(session):
        session.execute(text("SELECT * FROM no_such_table"))

    monkeypatch.setattr(gateway_check, "get_mode", failing)
    response = agent.act("calculate", params=PARAMS)

    assert response.status_code == 503
    assert world.spy.calls == []


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_tampered_conditions_deny_in_both_modes(world, tenant, attacker_sql, mode):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate", "read_document"],
                                  conditions={"denied_tools": ["read_document"]})
    if mode == "enforce":
        tenant.set_enforcement("enforce")
    current = state_of(attacker_sql, agent.asset_id)[1]
    # Dropping the condition without recomputing its hash.
    tampered(attacker_sql, "UPDATE governance_decisions SET conditions_canonical = %s "
             "WHERE id = %s", ('{"advisory_conditions":["x"]}', current))

    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_INTEGRITY_FAILED")
    assert world.spy.calls == []


def test_conditions_with_a_matching_hash_but_invalid_content_deny(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"], conditions={"held_tools": ["calculate"]})
    current = state_of(attacker_sql, agent.asset_id)[1]
    forged = '{"max_resource_classification":"secret"}'
    from aegis.canonical import sha256_hex

    tampered(attacker_sql, "UPDATE governance_decisions SET conditions_canonical = %s, "
             "conditions_hash = %s WHERE id = %s", (forged, sha256_hex(forged), current))

    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_INTEGRITY_FAILED")


def test_a_current_decision_that_cannot_be_found_denies_in_observe(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"], conditions={"held_tools": ["calculate"]})
    tampered(attacker_sql, "UPDATE asset_governance_state SET current_decision_id = %s "
             "WHERE asset_id = %s", (uuid4(), agent.asset_id))

    # The conditions of the approval in force cannot be read, so they cannot be skipped.
    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_INTEGRITY_FAILED")
    assert world.spy.calls == []


@pytest.mark.parametrize("status", ["SUSPENDED", "REJECTED"])
def test_blocking_status_without_its_block_still_denies_in_observe(world, tenant, attacker_sql,
                                                                    status):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, agent.asset_id, "suspend")
    tampered(attacker_sql, "UPDATE asset_governance_state SET status = %s, "
             "hard_block_decision_id = NULL WHERE asset_id = %s", (status, agent.asset_id))

    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_BLOCKED")
    assert world.spy.calls == []


# Traceability


def test_check_links_decision_and_governance_decision(tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    current = str(state_of(attacker_sql, agent.asset_id)[1])

    body = calc(agent)

    (row,) = checks(attacker_sql, body["request_id"])
    assert row["decision_id"] == body["decision_id"]
    assert row["agent_id"] == agent.id and row["asset_id"] == agent.asset_id
    assert row["governance_decision_id"] == current
    evidence = attacker_sql.execute(
        "SELECT evidence FROM policy_decisions WHERE id = %s", (body["decision_id"],)
    ).fetchone()[0]
    payload = next(item for item in tenant.audit_events("action.decision")
                   if item["subject_id"] == body["decision_id"])["payload"]
    expected = {"mode": "observe", "observed_status": "APPROVED", "verdict": "PASS",
                "reason_code": None, "asset_id": agent.asset_id,
                "governance_decision_id": current, "policy_outcome": "ALLOW",
                "policy_reason_code": "ALLOWED_BY_RULE"}
    assert evidence["governance"] == expected
    assert payload["governance"] == expected


def test_gov_deny_appears_as_security_event_with_reason(tenant):
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, agent.asset_id, "suspend")

    body = calc(agent)

    (event,) = events_of(tenant, "gateway.action_denied")
    assert (event["reason_code"], event["severity"]) == ("GOVERNANCE_BLOCKED", "high")
    assert event["decision_id"] == body["decision_id"]
    assert event["asset_id"] == agent.asset_id

    reassessing = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, reassessing.asset_id, "reassess")
    tenant.set_enforcement("enforce")
    calc(reassessing)
    (held,) = events_of(tenant, "gateway.approval_required")
    assert held["reason_code"] == "GOVERNANCE_REASSESSMENT_REQUIRED"


def test_gov_deny_feeds_correlation(world, tenant, db):
    from aegis.correlation.engine import process_tenant

    tenant.allow_everything()
    rules = tenant.get("/correlation-rules").json()["items"]
    rule = next(item for item in rules if item["rule_key"] == "repeated_unauthorized_tools")
    definition = {**rule["definition"], "match": {"event_types": ["gateway.action_denied"],
                                                  "reason_codes": ["GOVERNANCE_BLOCKED"]}}
    created = tenant.post("/correlation-rules/repeated_unauthorized_tools/versions",
                          {"definition": definition})
    assert created.status_code == 201, created.text
    agent = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, agent.asset_id, "suspend")

    denials = [calc(agent) for _ in range(3)]

    container = world.app.state.container
    assert process_tenant(container.db, tenant.id, clock=container.clock).incidents_created == 1
    (incident,) = tenant.get("/incidents").json()["items"]
    assert incident["agent_id"] == agent.id
    linked = tenant.get(f"/incidents/{incident['id']}/events", limit=100).json()["items"]
    assert {item["decision_id"] for item in linked} == {item["decision_id"] for item in denials}
    assert {item["reason_code"] for item in linked} == {"GOVERNANCE_BLOCKED"}


def test_checks_are_append_only(db, tenant, attacker_sql):
    tenant.allow_everything()
    body = calc(tenant.agent(tools=["calculate"]))
    assert len(checks(attacker_sql, body["request_id"])) == 1

    for statement in ("UPDATE governance_gateway_checks SET verdict = 'PASS', reason_code = NULL",
                      "DELETE FROM governance_gateway_checks",
                      "TRUNCATE governance_gateway_checks"):
        with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
            session.execute(text(statement))
        with pytest.raises(psycopg.Error):
            attacker_sql.execute(statement)
    assert len(checks(attacker_sql, body["request_id"])) == 1


def test_check_row_refuses_a_verdict_that_disagrees_with_its_reason(tenant, attacker_sql):
    tenant.allow_everything()
    body = calc(tenant.agent(tools=["calculate"]))
    row = attacker_sql.execute(
        "SELECT tenant_id, decision_id, request_id, agent_id FROM governance_gateway_checks "
        "WHERE request_id = %s", (body["request_id"],)).fetchone()
    with pytest.raises(psycopg.Error, match="check"):
        attacker_sql.execute(
            "INSERT INTO governance_gateway_checks (id, tenant_id, decision_id, request_id, "
            "agent_id, mode, verdict, reason_code, checked_at) "
            "VALUES (%s, %s, %s, %s, %s, 'observe', 'PASS', 'GOVERNANCE_BLOCKED', now())",
            (uuid4(), *row))


# Mode


def test_only_admin_can_change_mode(tenant):
    holder = tenant.login_as("holding-reviewer", "reviewer")
    tenant.grant_governance("holding-reviewer")
    body = {"mode": "enforce", "reason": "Synthetic."}
    for headers in (tenant.viewer, tenant.reviewer, holder):
        response = tenant.post(ENFORCEMENT, body, headers=headers)
        assert response.status_code == 403, response.text
    assert tenant.get(ENFORCEMENT).json()["enforcement_mode"] == "observe"
    assert tenant.audit_events("governance.enforcement_mode_changed") == []

    response = tenant.post(ENFORCEMENT, body)
    assert response.status_code == 200, response.text
    assert response.json()["enforcement_mode"] == "enforce"


def test_mode_change_is_audited_and_reversible(tenant):
    admin_id = tenant.user_id("admin")
    for invalid in ({"mode": "enforce"}, {"mode": "enforce", "reason": "  "},
                    {"mode": "strict", "reason": "x"}):
        assert tenant.post(ENFORCEMENT, invalid).status_code == 422
    unchanged = tenant.post(ENFORCEMENT, {"mode": "observe", "reason": "Already."})
    assert (unchanged.status_code, error_code(unchanged)) == (409, "ENFORCEMENT_MODE_UNCHANGED")

    tenant.set_enforcement("enforce", reason="Inventory reviewed.")
    assert tenant.get(ENFORCEMENT, headers=tenant.viewer).json()["enforcement_mode"] == "enforce"
    assert tenant.get("/governance/overview").json()["enforcement_mode"] == "enforce"
    tenant.set_enforcement("observe", reason="Rolling back.")
    assert tenant.get("/governance/overview").json()["enforcement_mode"] == "observe"

    events = sorted(tenant.audit_events("governance.enforcement_mode_changed"),
                    key=lambda item: item["seq"])
    assert [(item["payload"]["from_mode"], item["payload"]["to_mode"], item["payload"]["reason"])
            for item in events] == [("observe", "enforce", "Inventory reviewed."),
                                    ("enforce", "observe", "Rolling back.")]
    assert {item["actor_id"] for item in events} == {admin_id}
    assert tenant.verify_audit()["valid"] is True


def _counts(attacker_sql, tenant_id):
    return tuple(attacker_sql.execute(f"SELECT count(*) FROM {table} WHERE tenant_id = %s",  # noqa: S608
                                      (tenant_id,)).fetchone()[0]
                 for table in ("audit_events", "governance_gateway_checks",
                               "asset_governance_state", "governance_settings", "approvals"))


def test_preflight_lists_what_would_be_blocked(world, tenant, attacker_sql):
    tenant.allow_everything()
    ungoverned = tenant.agent(tools=["calculate"])
    approved = tenant.governed_agent(tools=["calculate"])
    suspended = tenant.governed_agent(tools=["calculate"])
    reassessing = tenant.governed_agent(tools=["calculate"])
    lifecycle(tenant, suspended.asset_id, "suspend")
    lifecycle(tenant, reassessing.asset_id, "reassess")
    for agent, times in ((ungoverned, 2), (approved, 1), (suspended, 3), (reassessing, 1)):
        for _ in range(times):
            calc(agent)
    before = _counts(attacker_sql, tenant.id)

    response = tenant.get(PREFLIGHT)

    assert response.status_code == 200, response.text
    view = response.json()
    assert _counts(attacker_sql, tenant.id) == before
    assert view["enforcement_mode"] == "observe"
    items = {item["asset_id"]: item for item in view["items"]}
    assert approved.asset_id not in items
    expected = {ungoverned.asset_id: ("DENY", "GOVERNANCE_NOT_APPROVED", None),
                suspended.asset_id: ("DENY", "GOVERNANCE_BLOCKED", "SUSPENDED"),
                reassessing.asset_id: ("HOLD", "GOVERNANCE_REASSESSMENT_REQUIRED",
                                       "REASSESSMENT_REQUIRED")}
    for asset_id, (verdict, reason, status) in expected.items():
        item = items[asset_id]
        assert (item["verdict"], item["reason_code"], item["governance_status"]) == (
            verdict, reason, status)
        actual = attacker_sql.execute(
            "SELECT count(*), count(*) FILTER (WHERE verdict <> 'PASS') "
            "FROM governance_gateway_checks WHERE asset_id = %s AND checked_at >= %s",
            (asset_id, datetime.fromisoformat(view["since"]))).fetchone()
        assert (item["recent_actions"], item["recent_not_passed"]) == actual
    assert items[ungoverned.asset_id]["recent_actions"] == 2
    assert items[suspended.asset_id]["recent_actions"] == 3
    assert (view["would_deny"], view["would_hold"]) == (2, 1)
    assert view["assets_checked"] == attacker_sql.execute(
        "SELECT count(*) FROM ai_assets WHERE tenant_id = %s", (tenant.id,)).fetchone()[0]


def test_preflight_reports_tampered_conditions(tenant, attacker_sql):
    agent = tenant.governed_agent(tools=["calculate"], conditions={"held_tools": ["calculate"]})
    current = state_of(attacker_sql, agent.asset_id)[1]
    tampered(attacker_sql, "UPDATE governance_decisions SET conditions_canonical = %s "
             "WHERE id = %s", ('{"hold_all":false}', current))

    (item,) = tenant.get(PREFLIGHT).json()["items"]
    assert (item["asset_id"], item["reason_code"]) == (agent.asset_id,
                                                       "GOVERNANCE_INTEGRITY_FAILED")


def test_agent_cannot_reach_mode_or_preflight(tenant):
    agent = tenant.agent()
    client = tenant.client
    for method, path in (("get", ENFORCEMENT), ("get", PREFLIGHT), ("post", ENFORCEMENT)):
        response = client.request(method, f"/api/v1{path}", headers=agent.headers,
                                  json={"mode": "enforce", "reason": "agent"})
        assert response.status_code == 401, (path, response.text)
    assert tenant.get(ENFORCEMENT).json()["enforcement_mode"] == "observe"


# The values handed to the pure check


def _facts(**overrides):
    base = dict(agent_active=True, tool="read_document", tool_known=True, action="read",
                tool_granted=True, params_valid=True, required_resource_kind="document",
                resource_id_supplied=False, resource=None, attachment=None)
    return ActionFacts(**{**base, **overrides})


@pytest.mark.parametrize("facts,expected", [
    (_facts(), None),
    (_facts(resource_id_supplied=True,
            resource=ResourceFacts("document", "public", None, True)), "public"),
    # A resource that could not be read is not "no resource".
    (_facts(resource_id_supplied=True, resource=None), "unknown"),
    (_facts(attachment=AttachmentFacts(None, False)), "unknown"),
    (_facts(resource_id_supplied=True, resource=ResourceFacts("destination", "public", "x", True),
            attachment=AttachmentFacts("sensitive", True)), "sensitive"),
    (_facts(resource_id_supplied=True, resource=ResourceFacts("destination", "internal", "x",
                                                                True),
            attachment=AttachmentFacts("public", True)), "internal"),
    (_facts(resource_id_supplied=True, resource=ResourceFacts("destination", "public", "x", True),
            attachment=AttachmentFacts(None, False)), "unknown"),
])
def test_action_context_classification(facts, expected):
    assert gateway_check.action_context(facts).resource_classification == expected


def test_action_context_of_an_unknown_tool_has_an_action():
    context = gateway_check.action_context(_facts(tool="nope", tool_known=False, action=None))
    assert isinstance(context, ActionContext) and context.action == ""


def test_unknown_classification_is_denied_by_a_classification_limit():
    from aegis.governance.engine.enforcement import GovernanceFacts, check

    now = datetime.now(UTC)
    facts = GovernanceFacts(mode="observe", status="CONDITIONALLY_APPROVED", hard_blocked=False,
                            conditions=Conditions(max_resource_classification="sensitive"),
                            conditions_intact=True, valid_until=now + timedelta(days=1),
                            now=now)
    result = check(facts, ActionContext("read_document", "read", "unknown"))
    assert result == GovernanceCheck(Verdict.DENY, "GOVERNANCE_CONDITION_DENIED")


@pytest.mark.parametrize("status,block,expected", [
    ("APPROVED", None, False), ("SUSPENDED", None, True), ("REJECTED", None, True),
    ("REASSESSMENT_REQUIRED", uuid4(), True), ("ASSESSMENT_REQUIRED", uuid4(), True),
    (None, None, False),
])
def test_hard_block_follows_the_block_and_the_status(status, block, expected):
    assert gateway_check.is_hard_blocked(status, block) is expected


def test_conditions_refuse_an_unknown_classification_limit():
    with pytest.raises(ValidationError):
        Conditions(max_resource_classification="secret")
    with pytest.raises(ValidationError):
        Conditions.model_validate({"max_resource_classification": "secret"})


def test_evaluation_error_check_agrees_with_its_verdict():
    for mode, verdict in (("observe", Verdict.RECORDED_DENY), ("enforce", Verdict.DENY),
                          ("unexpected", Verdict.DENY)):
        assert gateway_check.evaluation_error(mode) == GovernanceCheck(
            verdict, "GOVERNANCE_EVALUATION_ERROR")


def test_governance_modules_do_not_import_llm_clients():
    forbidden = {"openai", "anthropic", "langchain", "litellm", "cohere", "mistralai", "ollama"}
    for path in (SOURCE_ROOT / "governance").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in forbidden, f"{path} imports {name}"
                assert not name.startswith("aegis.llm"), f"{path} imports {name}"
