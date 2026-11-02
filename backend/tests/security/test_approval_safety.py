"""Approval lifecycle: holds, replay, binding, races, and time-of-check attacks."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy.exc import DBAPIError, IntegrityError

from aegis.approvals.state import ALLOWED_TRANSITIONS, can_transition
from aegis.db.models import Approval, Execution
from aegis.db.session import Database

PARAMS = {"operator": "add", "a": 1, "b": 2}


def held_action(tenant, tool="calculate"):
    tenant.hold_tool(tool)
    agent = tenant.agent(tools=[tool])
    body = agent.act(tool, params=PARAMS).json()
    assert body["outcome"] == "REQUIRE_APPROVAL"
    return agent, body


def approve(tenant, approval_id, headers=None):
    return tenant.post(f"/approvals/{approval_id}/approve", {}, headers=headers or tenant.reviewer)


def reject(tenant, approval_id, headers=None):
    return tenant.post(f"/approvals/{approval_id}/reject", {}, headers=headers or tenant.reviewer)


def test_state_machine_definition_matches_spec():
    assert ALLOWED_TRANSITIONS == {
        "PENDING": {"APPROVED", "REJECTED", "CANCELLED"},
        "APPROVED": {"EXECUTED", "CANCELLED"},
        "REJECTED": set(),
        "EXECUTED": set(),
        "CANCELLED": set(),
    }
    assert can_transition("PENDING", "APPROVED")
    assert not can_transition("REJECTED", "EXECUTED")


def test_pending_action_does_not_execute(world, tenant):
    agent, body = held_action(tenant)
    assert body["execution"] is None
    assert body["approval_id"]
    assert world.spy.calls == []
    assert tenant.get(f"/approvals/{body['approval_id']}").json()["status"] == "PENDING"


def test_execute_while_pending_is_refused(world, tenant):
    agent, body = held_action(tenant)
    response = agent.execute(body["request_id"])
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "APPROVAL_NOT_EXECUTABLE"
    assert world.spy.calls == []


def test_approved_action_executes_exactly_once(world, tenant):
    agent, body = held_action(tenant)
    assert approve(tenant, body["approval_id"]).json()["status"] == "APPROVED"
    assert world.spy.calls == []

    first = agent.execute(body["request_id"])
    assert first.status_code == 200
    assert first.json()["execution"]["result"] == {"value": 3}
    assert world.spy.calls == ["calculate"]

    second = agent.execute(body["request_id"])
    assert second.status_code == 409
    assert world.spy.calls == ["calculate"]
    assert tenant.get(f"/approvals/{body['approval_id']}").json()["status"] == "EXECUTED"


def test_rejected_action_never_executes(world, tenant):
    agent, body = held_action(tenant)
    assert reject(tenant, body["approval_id"]).json()["status"] == "REJECTED"
    assert agent.execute(body["request_id"]).status_code == 409
    assert world.spy.calls == []


def test_only_reviewers_and_admins_can_decide(tenant):
    agent, body = held_action(tenant)
    assert approve(tenant, body["approval_id"], tenant.viewer).status_code == 403
    assert reject(tenant, body["approval_id"], tenant.viewer).status_code == 403
    assert approve(tenant, body["approval_id"], agent.headers).status_code == 401
    assert tenant.get(f"/approvals/{body['approval_id']}").json()["status"] == "PENDING"
    assert approve(tenant, body["approval_id"], tenant.admin).status_code == 200


def test_decision_records_the_reviewer(tenant):
    _, body = held_action(tenant)
    me = tenant.client.get("/api/v1/auth/me", headers=tenant.reviewer).json()
    decided = approve(tenant, body["approval_id"]).json()
    assert decided["decided_by"] == me["id"]
    events = tenant.audit_events("approval.approved")
    assert events[0]["actor_id"] == me["id"]
    assert events[0]["actor_type"] == "user"


def test_approval_cannot_be_decided_twice(tenant):
    _, body = held_action(tenant)
    assert approve(tenant, body["approval_id"]).status_code == 200
    second = approve(tenant, body["approval_id"])
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "INVALID_STATE_TRANSITION"
    assert reject(tenant, body["approval_id"]).status_code == 409


def test_approval_cannot_be_reused_for_a_different_action(world, tenant):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])

    other = agent.act("calculate", params={"operator": "multiply", "a": 1000, "b": 1000}).json()

    assert other["outcome"] == "REQUIRE_APPROVAL"
    assert other["approval_id"] != body["approval_id"]
    assert agent.execute(other["request_id"]).status_code == 409
    assert world.spy.calls == []


def test_approval_cannot_be_used_by_a_different_agent(world, tenant):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])
    other_agent = tenant.agent(tools=["calculate"])
    assert other_agent.execute(body["request_id"]).status_code == 404
    assert world.spy.calls == []


def test_execute_takes_no_parameters(world, tenant):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])
    response = tenant.client.post(
        f"/api/v1/gateway/actions/{body['request_id']}/execute",
        headers=agent.headers,
        json={"params": {"operator": "multiply", "a": 1000, "b": 1000}},
    )
    # Whatever the body says, only the approved parameters may run.
    assert response.status_code == 200
    assert response.json()["execution"]["result"] == {"value": 3}


def test_resubmitting_a_held_key_with_new_parameters_is_refused(world, tenant):
    tenant.hold_tool("calculate")
    agent = tenant.agent(tools=["calculate"])
    agent.act("calculate", params=PARAMS, key="key-1")
    response = agent.act("calculate", params={"operator": "add", "a": 9, "b": 9}, key="key-1")
    assert response.status_code == 409
    assert world.spy.calls == []


def test_parameters_changed_in_the_database_after_approval_cancel_it(
    world, tenant, attacker_sql
):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])
    attacker_sql.execute(
        "UPDATE action_requests SET params_canonical = %s WHERE id = %s",
        ('{"a":1000,"b":1000,"operator":"multiply"}', body["request_id"]),
    )

    response = agent.execute(body["request_id"])

    assert response.status_code == 409
    assert world.spy.calls == []
    assert tenant.get(f"/approvals/{body['approval_id']}").json()["status"] == "CANCELLED"
    cancelled = tenant.audit_events("approval.cancelled")
    assert cancelled[0]["payload"]["reason"] == "ACTION_HASH_MISMATCH"


def test_disabling_agent_after_approval_cancels(world, tenant):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])
    tenant.post(f"/agents/{agent.id}/status", {"status": "disabled"})

    response = agent.execute(body["request_id"])

    assert response.status_code == 409
    assert world.spy.calls == []
    assert tenant.get(f"/approvals/{body['approval_id']}").json()["status"] == "CANCELLED"
    assert tenant.audit_events("approval.cancelled")[0]["payload"]["reason"] == "AGENT_DISABLED"


def test_removing_grant_after_approval_cancels(world, tenant):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])
    response = tenant.client.delete(
        f"/api/v1/agents/{agent.id}/tool-grants/calculate", headers=tenant.admin
    )
    assert response.status_code == 204

    assert agent.execute(body["request_id"]).status_code == 409
    assert world.spy.calls == []


def test_policy_changed_to_deny_after_approval_cancels(world, tenant):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])
    tenant.activate(
        [{"id": "stop", "effect": "deny", "match": {}, "reason_code": "DENIED_BY_RULE"}]
    )

    assert agent.execute(body["request_id"]).status_code == 409
    assert world.spy.calls == []


def test_execution_records_a_fresh_decision_against_the_current_policy(tenant):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])
    current = tenant.hold_tool("calculate")

    agent.execute(body["request_id"])

    decisions = tenant.get("/decisions", limit=100).json()["items"]
    mine = [item for item in decisions if item["request_id"] == body["request_id"]]
    assert len(mine) == 2
    assert {item["policy_version_id"] for item in mine} >= {current["id"]}


def test_expired_approval_cannot_be_decided_or_executed(world, tenant):
    agent, body = held_action(tenant)
    reviewer = tenant.reviewer  # Log in first: tokens are issued from the same clock.
    later = datetime.now(UTC) + timedelta(days=2)
    world.app.state.container.clock = lambda: later

    response = approve(tenant, body["approval_id"], reviewer)

    assert response.status_code == 409
    assert tenant.get(f"/approvals/{body['approval_id']}").json()["status"] == "CANCELLED"
    assert world.spy.calls == []


def test_approval_expiring_between_approval_and_execution_is_refused(world, tenant):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])
    later = datetime.now(UTC) + timedelta(days=2)
    world.app.state.container.clock = lambda: later

    assert agent.execute(body["request_id"]).status_code == 409
    assert world.spy.calls == []
    assert tenant.get(f"/approvals/{body['approval_id']}").json()["status"] == "CANCELLED"


def test_concurrent_approve_and_reject_produce_one_outcome(tenant):
    _, body = held_action(tenant)
    headers = tenant.reviewer
    barrier = Barrier(8)

    def decide(index):
        barrier.wait()
        action = approve if index % 2 else reject
        return action(tenant, body["approval_id"], headers).status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(decide, range(8)))

    assert sorted(codes) == [200] + [409] * 7
    final = tenant.get(f"/approvals/{body['approval_id']}").json()["status"]
    assert final in {"APPROVED", "REJECTED"}
    assert tenant.verify_audit()["valid"] is True


def test_concurrent_executes_run_the_tool_once(world, tenant):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])
    barrier = Barrier(8)

    def execute(_):
        barrier.wait()
        return agent.execute(body["request_id"]).status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(execute, range(8)))

    assert sorted(codes) == [200] + [409] * 7
    assert world.spy.calls == ["calculate"]
    assert tenant.verify_audit()["valid"] is True


def test_concurrent_submissions_with_one_key_run_the_tool_once(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    barrier = Barrier(8)

    def submit(_):
        barrier.wait()
        return agent.act("calculate", params=PARAMS, key="shared-key").json()["request_id"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        request_ids = list(pool.map(submit, range(8)))

    assert len(set(request_ids)) == 1
    assert world.spy.calls == ["calculate"]


def test_database_refuses_invalid_transition_even_if_the_application_is_wrong(world, tenant):
    _, body = held_action(tenant)
    reject(tenant, body["approval_id"])

    database = Database(world.urls.app, pool_size=1, max_overflow=0)
    try:
        with pytest.raises(DBAPIError, match="invalid approval transition"):
            with database.tenant_transaction(tenant.id) as session:
                session.get(Approval, body["approval_id"]).status = "EXECUTED"
    finally:
        database.dispose()


def test_database_refuses_changing_what_an_approval_is_bound_to(world, tenant):
    _, body = held_action(tenant)
    database = Database(world.urls.app, pool_size=1, max_overflow=0)
    try:
        with pytest.raises(DBAPIError):
            with database.tenant_transaction(tenant.id) as session:
                session.get(Approval, body["approval_id"]).action_hash = uuid4().hex
    finally:
        database.dispose()


def test_database_refuses_a_second_execution_for_a_request(world, tenant):
    """The unique constraint holds even if application locking were wrong."""
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    body = agent.act("calculate", params=PARAMS).json()
    assert body["execution"]["status"] == "SUCCEEDED"

    database = Database(world.urls.app, pool_size=1, max_overflow=0)
    try:
        with pytest.raises(IntegrityError):
            with database.tenant_transaction(tenant.id) as session:
                session.add(
                    Execution(
                        id=uuid4(),
                        tenant_id=tenant.id,
                        request_id=body["request_id"],
                        status="STARTED",
                        started_at=datetime.now(UTC),
                    )
                )
                session.flush()
    finally:
        database.dispose()


def test_database_refuses_a_second_approval_for_a_request(world, tenant):
    _, body = held_action(tenant)
    database = Database(world.urls.app, pool_size=1, max_overflow=0)
    try:
        with pytest.raises(IntegrityError):
            with database.tenant_transaction(tenant.id) as session:
                session.add(
                    Approval(
                        id=uuid4(),
                        tenant_id=tenant.id,
                        request_id=body["request_id"],
                        decision_id=body["decision_id"],
                        action_hash="0" * 64,
                        status="APPROVED",
                        requested_at=datetime.now(UTC),
                        expires_at=datetime.now(UTC),
                    )
                )
                session.flush()
    finally:
        database.dispose()


def test_there_is_no_route_that_executes_on_behalf_of_a_user(world):
    paths = world.app.openapi()["paths"]
    assert [path for path in paths if path.endswith("/execute")] == [
        "/api/v1/gateway/actions/{request_id}/execute"
    ]
    assert not [path for path in paths if "execut" in path and "approvals" in path]


def test_user_token_cannot_call_execute(world, tenant):
    agent, body = held_action(tenant)
    approve(tenant, body["approval_id"])
    response = tenant.client.post(
        f"/api/v1/gateway/actions/{body['request_id']}/execute", headers=tenant.admin
    )
    assert response.status_code == 401
    assert world.spy.calls == []
