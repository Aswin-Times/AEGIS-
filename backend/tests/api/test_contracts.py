"""API contracts: error shape, pagination, and registry behavior."""

import pytest

import aegis.api.routes_registry as routes_registry


def test_error_shape_includes_a_request_id(world):
    response = world.client.get("/api/v1/assets")
    error = response.json()["error"]
    assert set(error) >= {"code", "message", "request_id"}
    assert response.headers["X-Request-Id"] == error["request_id"]


def test_validation_errors_do_not_echo_input(tenant):
    response = tenant.post(
        "/assets",
        {
            "name": "x",
            "owner": "o",
            "risk_classification": "secret-marker-value",
            "intended_use": "u",
            "is_synthetic": True,
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert "secret-marker-value" not in response.text


def test_internal_errors_are_generic(world, tenant, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("password=synthetic-internal-detail")

    monkeypatch.setattr(routes_registry, "list_assets", explode)
    response = tenant.get("/assets")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "synthetic-internal-detail" not in response.text
    assert "Traceback" not in response.text


def test_pagination(tenant):
    for _ in range(3):
        tenant.asset()
    first = tenant.get("/assets", limit=2, offset=0).json()
    second = tenant.get("/assets", limit=2, offset=2).json()
    assert first["total"] == 3
    assert (len(first["items"]), len(second["items"])) == (2, 1)
    assert {item["id"] for item in first["items"]}.isdisjoint(
        item["id"] for item in second["items"]
    )


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 101}, {"offset": -1}])
def test_pagination_limits_are_enforced(tenant, params):
    assert tenant.get("/assets", **params).status_code == 422


def test_register_agent_flow(tenant):
    asset = tenant.asset()
    agent = tenant.created(
        "/agents", {"asset_id": asset["id"], "name": "research", "owner": "synthetic-owner"}
    )
    assert agent["status"] == "active"
    tenant.created(f"/agents/{agent['id']}/tool-grants", {"tool": "read_document"})

    detail = tenant.get(f"/agents/{agent['id']}").json()
    assert detail["tool_grants"] == ["read_document"]
    assert detail["resource_grants"] == []


def test_agent_requires_an_existing_asset(tenant):
    response = tenant.post(
        "/agents",
        {"asset_id": "00000000-0000-0000-0000-000000000000", "name": "x", "owner": "o"},
    )
    assert response.status_code == 404


def test_duplicate_grant_conflicts(tenant):
    agent = tenant.agent(tools=["calculate"])
    response = tenant.post(f"/agents/{agent.id}/tool-grants", {"tool": "calculate"})
    assert response.status_code == 409


def test_destination_requires_clearance(tenant):
    response = tenant.post(
        "/resources",
        {"kind": "destination", "name": "x", "classification": "internal", "clearance": None,
         "content": {}, "is_synthetic": True},
    )
    assert response.status_code == 422


def test_non_destination_rejects_clearance(tenant):
    response = tenant.post(
        "/resources",
        {"kind": "document", "name": "x", "classification": "internal", "clearance": "internal",
         "content": {}, "is_synthetic": True},
    )
    assert response.status_code == 422


def test_overview_counts_are_derived_from_records(tenant):
    tenant.allow_everything()
    document = tenant.document()
    agent = tenant.agent(tools=["read_document"], resources=[document])
    agent.act("read_document", document)
    agent.act("read_document", tenant.document())
    overview = tenant.get("/overview").json()
    assert overview["agents"] == 1
    assert overview["assets"] == 1
    assert overview["decisions"] == {"ALLOW": 1, "DENY": 1, "REQUIRE_APPROVAL": 0}
    assert overview["pending_approvals"] == 0
    assert overview["executions"] == 1


def test_approval_listing_shows_the_exact_action(tenant):
    tenant.hold_tool("calculate")
    agent = tenant.agent(tools=["calculate"])
    params = {"operator": "add", "a": 1, "b": 2}
    agent.act("calculate", params=params)
    item = tenant.get("/approvals", status="PENDING").json()["items"][0]
    assert item["tool"] == "calculate"
    assert item["params"] == params
    assert item["agent_id"] == agent.id
    assert len(item["action_hash"]) == 64


def test_approval_status_filter_is_validated(tenant):
    assert tenant.get("/approvals", status="NOT_A_STATUS").status_code == 422


def test_healthz_reveals_nothing(world):
    response = world.client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi_docs_are_disabled_outside_development(world):
    assert world.client.get("/docs").status_code == 404
