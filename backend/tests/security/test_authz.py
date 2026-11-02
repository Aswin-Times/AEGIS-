"""Authorization: role limits, and agents being kept out of the control plane."""

from uuid import uuid4

import pytest


def admin_only_routes(tenant, agent_id, policy_id, version_id, resource_id, credential_id):
    return [
        ("POST", "/assets", {"name": "x", "owner": "o", "risk_classification": "low",
                             "intended_use": "u", "is_synthetic": True}),
        ("POST", "/agents", {"asset_id": str(uuid4()), "name": "x", "owner": "o"}),
        ("POST", f"/agents/{agent_id}/status", {"status": "disabled"}),
        ("POST", f"/agents/{agent_id}/credentials", {}),
        ("POST", f"/agents/{agent_id}/credentials/{credential_id}/revoke", None),
        ("POST", f"/agents/{agent_id}/tool-grants", {"tool": "calculate"}),
        ("DELETE", f"/agents/{agent_id}/tool-grants/calculate", None),
        ("POST", f"/agents/{agent_id}/resource-grants", {"resource_id": resource_id}),
        ("DELETE", f"/agents/{agent_id}/resource-grants/{resource_id}", None),
        ("POST", "/resources", {"kind": "document", "name": "x", "classification": "public",
                                "clearance": None, "content": {}, "is_synthetic": True}),
        ("POST", "/policies", {"name": "x"}),
        ("POST", f"/policies/{policy_id}/versions", {"document": {"rules": []}}),
        ("POST", f"/policies/{policy_id}/activate", {"version_id": version_id}),
    ]


@pytest.fixture
def fixtures(tenant):
    version = tenant.allow_everything()
    resource = tenant.document()
    agent = tenant.agent()
    return tenant, agent, version, resource


def _call(tenant, method, path, body, headers):
    return tenant.client.request(method, f"/api/v1{path}", json=body, headers=headers)


@pytest.mark.parametrize("role", ["viewer", "reviewer"])
def test_non_admins_cannot_perform_admin_actions(fixtures, role):
    tenant, agent, version, resource = fixtures
    headers = tenant.login(role)
    routes = admin_only_routes(
        tenant, agent.id, version["policy_id"], version["id"], resource, agent.credential_id
    )
    before = len(tenant.audit_events())
    for method, path, body in routes:
        response = _call(tenant, method, path, body, headers)
        assert response.status_code == 403, f"{role} {method} {path}: {response.status_code}"
    # Refused actions change nothing: the only new audit events record the refusals themselves.
    new_events = tenant.audit_events()[: len(tenant.audit_events()) - before]
    assert [event["event_type"] for event in new_events] == ["authz.denied"] * len(routes)


def test_agent_key_is_refused_on_every_control_plane_route(fixtures):
    tenant, agent, version, resource = fixtures
    routes = admin_only_routes(
        tenant, agent.id, version["policy_id"], version["id"], resource, agent.credential_id
    )
    routes += [("GET", path, None) for path in ("/assets", "/agents", "/policies", "/approvals",
                                                "/decisions", "/audit/events", "/overview")]
    for method, path, body in routes:
        response = _call(tenant, method, path, body, agent.headers)
        assert response.status_code == 401, f"{method} {path}: {response.status_code}"


def test_agent_cannot_grant_itself_a_tool(world, fixtures):
    tenant, agent, _, _ = fixtures
    response = _call(
        tenant, "POST", f"/agents/{agent.id}/tool-grants", {"tool": "send_message"}, agent.headers
    )
    assert response.status_code == 401
    grants = tenant.get(f"/agents/{agent.id}").json()["tool_grants"]
    assert grants == []


def test_user_token_is_refused_on_the_gateway(world, fixtures):
    tenant, _, _, _ = fixtures
    response = tenant.client.post(
        "/api/v1/gateway/actions",
        headers=tenant.admin,
        json={"idempotency_key": "k", "tool": "calculate", "resource_id": None, "params": {}},
    )
    assert response.status_code == 401
    assert world.spy.calls == []


def test_viewer_can_read_but_not_verify_audit(fixtures):
    tenant, _, _, _ = fixtures
    assert tenant.get("/audit/events", headers=tenant.viewer).status_code == 200
    assert tenant.post("/audit/verify", headers=tenant.viewer).status_code == 403


def test_permission_changes_are_audited(fixtures):
    tenant, agent, _, resource = fixtures
    tenant.post(f"/agents/{agent.id}/tool-grants", {"tool": "calculate"})
    tenant.post(f"/agents/{agent.id}/resource-grants", {"resource_id": resource})
    tenant.client.delete(f"/api/v1/agents/{agent.id}/tool-grants/calculate", headers=tenant.admin)
    tenant.post(f"/agents/{agent.id}/status", {"status": "disabled"})
    for event_type in ("grant.tool_added", "grant.resource_added", "grant.tool_removed",
                       "agent.status_changed"):
        events = tenant.audit_events(event_type)
        assert events, event_type
        assert events[0]["actor_type"] == "user"


def test_resource_listing_does_not_expose_content(fixtures):
    tenant, _, _, _ = fixtures
    tenant.document(content={"secret_marker": "synthetic-content"})
    response = tenant.get("/resources", headers=tenant.viewer)
    assert response.status_code == 200
    assert "synthetic-content" not in response.text


def test_decision_listing_does_not_expose_tool_results(fixtures):
    tenant, _, _, _ = fixtures
    document = tenant.document(content={"marker": "synthetic-result"})
    agent = tenant.agent(tools=["read_document"], resources=[document])
    body = agent.act("read_document", document).json()
    assert "synthetic-result" in str(body["execution"])
    assert "synthetic-result" not in tenant.get("/decisions", headers=tenant.viewer).text
    assert "synthetic-result" not in tenant.get(
        f"/decisions/{body['decision_id']}", headers=tenant.viewer
    ).text
