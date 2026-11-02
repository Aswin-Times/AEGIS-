"""Tenant isolation as seen through the API. Database-level tests are in the _db module."""

from uuid import uuid4

import pytest


@pytest.fixture
def pair(world):
    return world.tenant(), world.tenant()


def test_tenant_a_cannot_retrieve_tenant_b_assets(pair):
    a, b = pair
    asset = b.asset()
    listing = a.get("/assets").json()
    assert asset["id"] not in [item["id"] for item in listing["items"]]
    assert listing["total"] == 0
    assert a.get(f"/assets/{asset['id']}").status_code == 404


def test_tenant_a_cannot_read_tenant_b_agents(pair):
    a, b = pair
    agent = b.agent()
    assert a.get(f"/agents/{agent.id}").status_code == 404
    assert a.get("/agents").json()["total"] == 0


def test_tenant_a_cannot_modify_tenant_b_agents(pair):
    a, b = pair
    agent = b.agent()
    assert a.post(f"/agents/{agent.id}/status", {"status": "disabled"}).status_code == 404
    assert a.post(f"/agents/{agent.id}/tool-grants", {"tool": "calculate"}).status_code == 404
    assert a.post(f"/agents/{agent.id}/credentials", {}).status_code == 404
    assert a.post(f"/agents/{agent.id}/credentials/{agent.credential_id}/revoke").status_code == 404
    assert b.get(f"/agents/{agent.id}").json()["status"] == "active"


def test_tenant_a_cannot_access_tenant_b_policies(pair):
    a, b = pair
    version = b.allow_everything()
    assert a.get("/policies").json()["total"] == 0
    assert (
        a.post(f"/policies/{version['policy_id']}/versions", {"document": {"rules": []}})
        .status_code
        == 404
    )


def test_tenant_a_cannot_activate_tenant_b_policy_version(pair):
    a, b = pair
    version_b = b.allow_everything()
    own = a.created("/policies", {"name": "own"})
    response = a.post(f"/policies/{own['id']}/activate", {"version_id": version_b["id"]})
    assert response.status_code == 404


def test_tenant_a_cannot_approve_tenant_b_action(world, pair):
    a, b = pair
    b.hold_tool("calculate")
    agent = b.agent(tools=["calculate"])
    body = agent.act("calculate", params={"operator": "add", "a": 1, "b": 2}).json()

    assert a.get(f"/approvals/{body['approval_id']}", headers=a.reviewer).status_code == 404
    assert (
        a.post(f"/approvals/{body['approval_id']}/approve", {}, headers=a.reviewer).status_code
        == 404
    )
    assert a.get("/approvals").json()["total"] == 0
    assert b.get(f"/approvals/{body['approval_id']}").json()["status"] == "PENDING"
    assert world.spy.calls == []


def test_tenant_a_cannot_read_tenant_b_decisions_or_audit(pair):
    a, b = pair
    b.allow_everything()
    agent = b.agent(tools=["calculate"])
    body = agent.act("calculate", params={"operator": "add", "a": 1, "b": 2}).json()

    assert a.get(f"/decisions/{body['decision_id']}").status_code == 404
    assert a.get("/decisions").json()["total"] == 0
    tenant_a_ids = {str(event["id"]) for event in a.audit_events()}
    tenant_b_ids = {str(event["id"]) for event in b.audit_events()}
    assert tenant_a_ids.isdisjoint(tenant_b_ids)


def test_agent_cannot_access_another_tenants_resource(world, pair):
    a, b = pair
    a.allow_everything()
    secret = b.document("sensitive", content={"marker": "tenant-b-secret"})
    agent = a.agent(tools=["read_document"])

    response = agent.act("read_document", secret)

    body = response.json()
    assert (body["outcome"], body["reason_code"]) == ("DENY", "RESOURCE_NOT_FOUND")
    assert "tenant-b-secret" not in response.text
    assert world.spy.calls == []


def test_cannot_grant_another_tenants_resource(pair):
    a, b = pair
    secret = b.document()
    agent = a.agent()
    response = a.post(f"/agents/{agent.id}/resource-grants", {"resource_id": secret})
    assert response.status_code == 404


def test_another_tenants_resource_as_attachment_is_denied(world, pair):
    a, b = pair
    a.allow_everything()
    secret = b.document("sensitive")
    destination = a.destination(clearance="sensitive")
    agent = a.agent(tools=["send_message"], resources=[destination])
    body = agent.act(
        "send_message", destination, {"body": "x", "attachment_resource_id": secret}
    ).json()
    assert body["reason_code"] == "ATTACHMENT_NOT_GRANTED"
    assert world.spy.calls == []


def test_agent_cannot_read_another_tenants_request(pair):
    a, b = pair
    b.allow_everything()
    victim = b.agent(tools=["calculate"])
    attacker = a.agent()
    body = victim.act("calculate", params={"operator": "add", "a": 1, "b": 2}).json()
    response = a.client.get(f"/api/v1/gateway/actions/{body['request_id']}",
                            headers=attacker.headers)
    assert response.status_code == 404
    assert attacker.execute(body["request_id"]).status_code == 404


@pytest.mark.parametrize("field", ["tenant_id", "tenant", "tid"])
def test_tenant_identifier_in_a_body_is_rejected(pair, field):
    a, b = pair
    response = a.post(
        "/assets",
        {
            "name": "x",
            "owner": "o",
            "risk_classification": "low",
            "intended_use": "u",
            "is_synthetic": True,
            field: str(b.id),
        },
    )
    assert response.status_code == 422


def test_tenant_identifier_in_query_or_header_is_ignored(pair):
    a, b = pair
    asset = b.asset()
    response = a.client.get(
        "/api/v1/assets",
        headers={**a.admin, "X-Tenant-Id": str(b.id)},
        params={"tenant_id": str(b.id)},
    )
    assert asset["id"] not in response.text


def test_same_name_is_allowed_across_tenants(pair):
    a, b = pair
    body = {"name": "shared-name"}
    assert a.post("/policies", body).status_code == 201
    assert b.post("/policies", body).status_code == 201


def test_duplicate_name_in_a_tenant_conflicts(pair):
    a, _ = pair
    assert a.post("/policies", {"name": "dup"}).status_code == 201
    response = a.post("/policies", {"name": "dup"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ALREADY_EXISTS"


def test_overview_counts_only_this_tenant(pair):
    a, b = pair
    b.agent()
    assert a.get("/overview").json()["agents"] == 0
    assert b.get("/overview").json()["agents"] == 1


def test_random_ids_return_not_found_rather_than_errors(pair):
    a, _ = pair
    for path in ("/assets", "/agents", "/approvals", "/decisions"):
        assert a.get(f"{path}/{uuid4()}").status_code == 404
