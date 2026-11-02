"""Authorization at the gateway. The spy shows whether a tool actually ran."""

import json

import pytest
from sqlalchemy import select

import aegis.gateway.service as gateway_service
from aegis.db.models import Execution, PolicyDecision, PolicyVersion, SimulatedOutbox
from aegis.policy.engine import ActionFacts, AttachmentFacts, Outcome, ResourceFacts, evaluate
from aegis.policy.schema import PolicyDocument


def _executions(world, tenant, request_id):
    from aegis.db.session import Database

    database = Database(world.urls.app, pool_size=1, max_overflow=0)
    try:
        with database.tenant_transaction(tenant.id) as session:
            return session.execute(
                select(Execution).where(Execution.request_id == request_id)
            ).scalars().all()
    finally:
        database.dispose()


def _outbox(world, tenant):
    from aegis.db.session import Database

    database = Database(world.urls.app, pool_size=1, max_overflow=0)
    try:
        with database.tenant_transaction(tenant.id) as session:
            return session.execute(select(SimulatedOutbox)).scalars().all()
    finally:
        database.dispose()


def test_authorized_document_read_succeeds(world, tenant):
    tenant.allow_everything()
    document = tenant.document(content={"title": "Synthetic handbook"})
    agent = tenant.agent(tools=["read_document"], resources=[document])

    body = agent.act("read_document", document).json()

    assert body["outcome"] == "ALLOW"
    assert body["reason_code"] == "ALLOWED_BY_RULE"
    assert body["execution"]["status"] == "SUCCEEDED"
    assert body["execution"]["result"] == {"content": {"title": "Synthetic handbook"}}
    assert world.spy.calls == ["read_document"]


def test_unauthorized_document_read_is_denied_before_execution(world, tenant):
    tenant.allow_everything()
    granted, other = tenant.document(), tenant.document()
    agent = tenant.agent(tools=["read_document"], resources=[granted])

    response = agent.act("read_document", other)

    body = response.json()
    assert response.status_code == 200
    assert body["outcome"] == "DENY"
    assert body["reason_code"] == "RESOURCE_NOT_GRANTED"
    assert body["execution"] is None
    assert "content" not in response.text
    assert world.spy.calls == []
    assert _executions(world, tenant, body["request_id"]) == []


def test_ungranted_tool_never_reaches_executor(world, tenant):
    tenant.allow_everything()
    document = tenant.document()
    agent = tenant.agent(tools=["calculate"], resources=[document])

    body = agent.act("read_document", document).json()

    assert (body["outcome"], body["reason_code"]) == ("DENY", "TOOL_NOT_GRANTED")
    assert world.spy.calls == []


def test_unknown_tool_is_denied_and_recorded(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    body = agent.act("run_shell_command").json()
    assert (body["outcome"], body["reason_code"]) == ("DENY", "UNKNOWN_TOOL")
    assert world.spy.calls == []
    assert tenant.audit_events("action.decision")[0]["payload"]["tool"] == "run_shell_command"


def test_granting_an_unknown_tool_is_rejected(tenant):
    agent = tenant.agent()
    response = tenant.post(f"/agents/{agent.id}/tool-grants", {"tool": "run_shell_command"})
    assert response.status_code == 422


def test_disabled_agent_cannot_execute(world, tenant):
    tenant.allow_everything()
    document = tenant.document()
    agent = tenant.agent(tools=["read_document"], resources=[document])
    assert tenant.post(f"/agents/{agent.id}/status", {"status": "disabled"}).status_code == 200

    body = agent.act("read_document", document).json()

    assert (body["outcome"], body["reason_code"]) == ("DENY", "AGENT_DISABLED")
    assert world.spy.calls == []


def test_reenabled_agent_can_execute_again(world, tenant):
    tenant.allow_everything()
    document = tenant.document()
    agent = tenant.agent(tools=["read_document"], resources=[document])
    tenant.post(f"/agents/{agent.id}/status", {"status": "disabled"})
    tenant.post(f"/agents/{agent.id}/status", {"status": "active"})
    assert agent.act("read_document", document).json()["outcome"] == "ALLOW"


def test_sensitive_attachment_to_unapproved_destination_denied(world, tenant):
    tenant.allow_everything()
    sensitive = tenant.document("sensitive")
    destination = tenant.destination(clearance="internal")
    agent = tenant.agent(tools=["send_message"], resources=[destination, sensitive])

    body = agent.act(
        "send_message",
        destination,
        {"body": "see attached", "attachment_resource_id": sensitive},
    ).json()

    assert (body["outcome"], body["reason_code"]) == (
        "DENY",
        "DESTINATION_CLEARANCE_INSUFFICIENT",
    )
    assert world.spy.calls == []
    assert _outbox(world, tenant) == []


def test_message_to_ungranted_destination_denied(world, tenant):
    tenant.allow_everything()
    destination = tenant.destination(clearance="sensitive")
    agent = tenant.agent(tools=["send_message"])
    body = agent.act("send_message", destination, {"body": "hello"}).json()
    assert body["reason_code"] == "RESOURCE_NOT_GRANTED"
    assert _outbox(world, tenant) == []


def test_attachment_without_a_grant_denied(world, tenant):
    tenant.allow_everything()
    sensitive = tenant.document("sensitive")
    destination = tenant.destination(clearance="sensitive")
    agent = tenant.agent(tools=["send_message"], resources=[destination])
    body = agent.act(
        "send_message", destination, {"body": "x", "attachment_resource_id": sensitive}
    ).json()
    assert body["reason_code"] == "ATTACHMENT_NOT_GRANTED"
    assert world.spy.calls == []


def test_message_to_cleared_destination_goes_to_simulated_outbox(world, tenant):
    tenant.allow_everything()
    sensitive = tenant.document("sensitive")
    destination = tenant.destination(clearance="sensitive")
    agent = tenant.agent(tools=["send_message"], resources=[destination, sensitive])

    body = agent.act(
        "send_message", destination, {"body": "report", "attachment_resource_id": sensitive}
    ).json()

    assert body["execution"]["status"] == "SUCCEEDED"
    assert body["execution"]["result"]["simulated"] is True
    assert [row.body for row in _outbox(world, tenant)] == ["report"]


def test_documented_limitation_free_text_body_is_not_inspected(world, tenant):
    """Records threat T3 path (b): sensitive text in a body is not blocked."""
    tenant.allow_everything()
    destination = tenant.destination(clearance="public")
    agent = tenant.agent(tools=["send_message"], resources=[destination])
    body = agent.act(
        "send_message", destination, {"body": "Synthetic customer SSN 000-00-0000"}
    ).json()
    assert body["outcome"] == "ALLOW"


def test_calculate_runs_without_a_resource(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    body = agent.act("calculate", params={"operator": "multiply", "a": 6, "b": 7}).json()
    assert body["execution"]["result"] == {"value": 42}


def test_idempotent_replay_does_not_reexecute(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    params = {"operator": "add", "a": 1, "b": 2}

    first = agent.act("calculate", params=params, key="key-1").json()
    second = agent.act("calculate", params=params, key="key-1").json()

    assert second["request_id"] == first["request_id"]
    assert second["execution"] == first["execution"]
    assert world.spy.calls == ["calculate"]
    assert len(tenant.audit_events("execution.succeeded")) == 1


def test_idempotency_key_with_different_content_conflicts(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    agent.act("calculate", params={"operator": "add", "a": 1, "b": 2}, key="key-1")
    response = agent.act("calculate", params={"operator": "add", "a": 1, "b": 3}, key="key-1")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    assert world.spy.calls == ["calculate"]


def test_idempotency_keys_are_scoped_per_agent(world, tenant):
    tenant.allow_everything()
    first, second = tenant.agent(tools=["calculate"]), tenant.agent(tools=["calculate"])
    params = {"operator": "add", "a": 1, "b": 2}
    one = first.act("calculate", params=params, key="same").json()
    two = second.act("calculate", params=params, key="same").json()
    assert one["request_id"] != two["request_id"]
    assert world.spy.calls == ["calculate", "calculate"]


def test_failed_tool_is_recorded_without_leaking_details(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])

    response = agent.act("calculate", params={"operator": "divide", "a": 1, "b": 0})

    body = response.json()
    assert body["outcome"] == "ALLOW"
    assert body["execution"] == {"status": "FAILED", "result": None}
    assert "ZeroDivision" not in response.text
    assert world.spy.calls == ["calculate"]
    events = tenant.audit_events("execution.failed")
    assert len(events) == 1
    assert events[0]["correlation_id"] == body["request_id"]
    assert events[0]["payload"]["error_type"] == "ToolFailure"


def test_agent_sees_only_its_own_requests(tenant):
    tenant.allow_everything()
    first, second = tenant.agent(tools=["calculate"]), tenant.agent(tools=["calculate"])
    request_id = first.act(
        "calculate", params={"operator": "add", "a": 1, "b": 2}
    ).json()["request_id"]

    assert (
        tenant.client.get(f"/api/v1/gateway/actions/{request_id}", headers=first.headers)
        .status_code
        == 200
    )
    assert (
        tenant.client.get(f"/api/v1/gateway/actions/{request_id}", headers=second.headers)
        .status_code
        == 404
    )


def test_every_decision_produces_audit_evidence_with_policy_version(tenant):
    version = tenant.allow_everything()
    document = tenant.document()
    agent = tenant.agent(resources=[document])

    body = agent.act("read_document", document).json()

    assert body["policy_version_id"] == version["id"]
    events = [
        event
        for event in tenant.audit_events("action.decision")
        if event["correlation_id"] == body["request_id"]
    ]
    assert len(events) == 1
    assert events[0]["policy_version_id"] == version["id"]
    assert events[0]["payload"]["outcome"] == "DENY"
    assert events[0]["payload"]["reason_code"] == "TOOL_NOT_GRANTED"
    assert events[0]["payload"]["decision_id"] == body["decision_id"]
    assert tenant.verify_audit()["valid"] is True


def test_denial_evidence_shows_no_execution(tenant):
    tenant.allow_everything()
    document = tenant.document()
    agent = tenant.agent(resources=[document])
    body = agent.act("read_document", document).json()

    decision = tenant.get(f"/decisions/{body['decision_id']}").json()

    assert decision["outcome"] == "DENY"
    assert decision["tool_executed"] is False
    assert decision["execution"] is None
    assert decision["audit_event_ids"]
    correlated = [
        event["event_type"]
        for event in tenant.audit_events()
        if event["correlation_id"] == body["request_id"]
    ]
    assert correlated == ["action.decision"]


def test_decision_can_be_reproduced_from_its_recorded_evidence(world, tenant):
    tenant.hold_tool("send_message")
    document = tenant.document()
    agent = tenant.agent(tools=["read_document"], resources=[document])
    body = agent.act("read_document", document).json()

    from aegis.db.session import Database

    database = Database(world.urls.app, pool_size=1, max_overflow=0)
    try:
        with database.tenant_transaction(tenant.id) as session:
            decision = session.get(PolicyDecision, body["decision_id"])
            evidence = decision.evidence
            document = json.loads(
                session.get(PolicyVersion, decision.policy_version_id).document_canonical
            )
    finally:
        database.dispose()

    facts_data = dict(evidence["facts"])
    if facts_data["resource"]:
        facts_data["resource"] = ResourceFacts(**facts_data["resource"])
    if facts_data["attachment"]:
        facts_data["attachment"] = AttachmentFacts(**facts_data["attachment"])
    policy = PolicyDocument.model_validate(document)
    replayed = evaluate(ActionFacts(**facts_data), policy)

    assert replayed.outcome is Outcome(body["outcome"])
    assert replayed.reason_code == body["reason_code"]


def test_no_active_policy_denies(world, tenant):
    agent = tenant.agent(tools=["calculate"])
    body = agent.act("calculate", params={"operator": "add", "a": 1, "b": 2}).json()
    assert (body["outcome"], body["reason_code"]) == ("DENY", "NO_ACTIVE_POLICY")
    assert world.spy.calls == []


def test_audit_write_failure_blocks_execution(world, tenant, monkeypatch):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic audit outage")

    monkeypatch.setattr(gateway_service, "append_event", fail)
    response = agent.act("calculate", params={"operator": "add", "a": 1, "b": 2})
    monkeypatch.undo()

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SERVICE_UNAVAILABLE"
    assert "synthetic audit outage" not in response.text
    assert world.spy.calls == []


def test_request_cannot_claim_a_different_identity(tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    for extra in ({"agent_id": agent.id}, {"tenant_id": str(tenant.id)}, {"action": "read"},
                  {"approved": True}):
        response = tenant.client.post(
            "/api/v1/gateway/actions",
            headers=agent.headers,
            json={
                "idempotency_key": "k",
                "tool": "calculate",
                "resource_id": None,
                "params": {"operator": "add", "a": 1, "b": 2},
                **extra,
            },
        )
        assert response.status_code == 422, extra


@pytest.mark.parametrize("tool", ["read_document", "lookup_customer"])
def test_resource_of_the_wrong_kind_is_denied(world, tenant, tool):
    tenant.allow_everything()
    destination = tenant.destination()
    agent = tenant.agent(tools=[tool], resources=[destination])
    assert agent.act(tool, destination).json()["reason_code"] == "RESOURCE_KIND_MISMATCH"
    assert world.spy.calls == []
