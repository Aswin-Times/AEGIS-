"""Helpers that drive the system through its public API, as a real client would."""

from dataclasses import dataclass, replace
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient

from aegis.gateway.tools import ToolDefinition, ToolRegistry, default_registry
from aegis.provisioning import create_user

PASSWORD = "synthetic-test-password"


class ToolSpy:
    """Records real invocations, so 'the tool never ran' is measured and not assumed."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def wrap(self, definition: ToolDefinition) -> ToolDefinition:
        original = definition.handler

        def spying(context):
            self.calls.append(definition.name)
            return original(context)

        return replace(definition, handler=spying)

    def registry(self) -> ToolRegistry:
        return ToolRegistry([self.wrap(item) for item in default_registry().definitions()])


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@dataclass
class AgentHandle:
    id: str
    key: str
    tenant: "TenantWorld"
    credential_id: str

    @property
    def headers(self) -> dict[str, str]:
        return bearer(self.key)

    def act(self, tool: str, resource_id=None, params: dict | None = None, key: str | None = None):
        return self.tenant.client.post(
            "/api/v1/gateway/actions",
            headers=self.headers,
            json={
                "idempotency_key": key or uuid4().hex,
                "tool": tool,
                "resource_id": resource_id,
                "params": params or {},
            },
        )

    def execute(self, request_id: str):
        return self.tenant.client.post(
            f"/api/v1/gateway/actions/{request_id}/execute", headers=self.headers
        )


class TenantWorld:
    def __init__(self, client: TestClient, urls, tenant_id, slug: str) -> None:
        self.client = client
        self.urls = urls
        self.id = tenant_id
        self.slug = slug
        self._tokens: dict[str, str] = {}
        self._counter = 0

    def _unique(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter}"

    def login(self, role: str) -> dict[str, str]:
        if role not in self._tokens:
            email = f"{role}@{self.slug}.example.test"
            create_user(self.urls.owner, self.id, email=email, password=PASSWORD, role=role)
            response = self.client.post(
                "/api/v1/auth/login",
                json={"tenant_slug": self.slug, "email": email, "password": PASSWORD},
            )
            assert response.status_code == 200, response.text
            self._tokens[role] = response.json()["access_token"]
        return bearer(self._tokens[role])

    @property
    def admin(self) -> dict[str, str]:
        return self.login("admin")

    @property
    def reviewer(self) -> dict[str, str]:
        return self.login("reviewer")

    @property
    def viewer(self) -> dict[str, str]:
        return self.login("viewer")

    def post(self, path: str, body: dict[str, Any] | None = None, headers=None):
        return self.client.post(f"/api/v1{path}", json=body, headers=headers or self.admin)

    def get(self, path: str, headers=None, **params):
        return self.client.get(f"/api/v1{path}", headers=headers or self.admin, params=params)

    def created(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        response = self.post(path, body)
        assert response.status_code == 201, response.text
        return response.json()

    def asset(self) -> dict[str, Any]:
        return self.created(
            "/assets",
            {
                "name": self._unique("asset"),
                "owner": "synthetic-owner",
                "risk_classification": "medium",
                "intended_use": "automated test fixture",
                "is_synthetic": True,
            },
        )

    def resource(self, kind: str, classification="internal", clearance=None, content=None):
        return self.created(
            "/resources",
            {
                "kind": kind,
                "name": self._unique(kind),
                "classification": classification,
                "clearance": clearance,
                "content": content or {"synthetic": True},
                "is_synthetic": True,
            },
        )["id"]

    def document(self, classification="internal", content=None) -> str:
        return self.resource("document", classification, content=content)

    def customer(self, classification="sensitive") -> str:
        return self.resource(
            "customer_record", classification, content={"name": "Synthetic Customer"}
        )

    def destination(self, clearance="internal") -> str:
        return self.resource("destination", "internal", clearance=clearance)

    def agent(self, tools=(), resources=()) -> AgentHandle:
        asset = self.asset()
        agent = self.created(
            "/agents",
            {"asset_id": asset["id"], "name": self._unique("agent"), "owner": "synthetic-owner"},
        )
        for tool in tools:
            self.created(f"/agents/{agent['id']}/tool-grants", {"tool": tool})
        for resource in resources:
            self.created(f"/agents/{agent['id']}/resource-grants", {"resource_id": resource})
        credential = self.created(f"/agents/{agent['id']}/credentials", {})
        return AgentHandle(agent["id"], credential["key"], self, credential["id"])

    def activate(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        policy = self.created("/policies", {"name": self._unique("policy")})
        return self.activate_version(policy["id"], rules)

    def activate_version(self, policy_id: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
        version = self.created(f"/policies/{policy_id}/versions", {"document": {"rules": rules}})
        response = self.post(f"/policies/{policy_id}/activate", {"version_id": version["id"]})
        assert response.status_code == 200, response.text
        return version

    def allow_everything(self) -> dict[str, Any]:
        return self.activate(
            [{"id": "allow", "effect": "allow", "match": {}, "reason_code": "ALLOWED_BY_RULE"}]
        )

    def hold_tool(self, tool: str) -> dict[str, Any]:
        return self.activate(
            [
                {
                    "id": "hold",
                    "effect": "require_approval",
                    "match": {"tools": [tool]},
                    "reason_code": "APPROVAL_REQUIRED_BY_RULE",
                },
                {"id": "allow", "effect": "allow", "match": {}, "reason_code": "ALLOWED_BY_RULE"},
            ]
        )

    def audit_events(self, event_type: str | None = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        offset = 0
        while True:
            page = self.get("/audit/events", limit=100, offset=offset).json()
            items.extend(page["items"])
            offset += 100
            if offset >= page["total"]:
                break
        if event_type:
            return [item for item in items if item["event_type"] == event_type]
        return items

    def verify_audit(self) -> dict[str, Any]:
        response = self.post("/audit/verify")
        assert response.status_code == 200, response.text
        return response.json()
