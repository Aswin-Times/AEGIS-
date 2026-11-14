"""Helpers that drive the system through its public API, as a real client would."""

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

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
    asset_id: str | None = None

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
        self._named: dict[str, tuple[str, dict[str, str]]] = {}
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

    def login_as(self, name: str, role: str) -> dict[str, str]:
        """An additional, distinct user, for tests that need a second admin or reviewer."""
        if name not in self._named:
            email = f"{name}@{self.slug}.example.test"
            create_user(self.urls.owner, self.id, email=email, password=PASSWORD, role=role)
            response = self.client.post(
                "/api/v1/auth/login",
                json={"tenant_slug": self.slug, "email": email, "password": PASSWORD},
            )
            assert response.status_code == 200, response.text
            self._named[name] = (role, bearer(response.json()["access_token"]))
        return self._named[name][1]

    def _headers_for(self, who: str) -> dict[str, str]:
        return self._named[who][1] if who in self._named else self.login(who)

    def user_id(self, role: str) -> str:
        """The id of the user logged in as a role, or as a name given to login_as."""
        response = self.client.get("/api/v1/auth/me", headers=self._headers_for(role))
        assert response.status_code == 200, response.text
        return response.json()["id"]

    def grant_governance(self, role: str, by: str = "admin") -> dict[str, Any]:
        """Give the governance_reviewer role to the user logged in as `role`, granted by `by`."""
        response = self.post(
            "/governance/role-grants",
            {"user_id": self.user_id(role)},
            headers=self._headers_for(by),
        )
        assert response.status_code == 201, response.text
        return response.json()

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
        return AgentHandle(agent["id"], credential["key"], self, credential["id"], asset["id"])

    def governed_agent(self, tools=(), resources=(), approve=True, conditions=None,
                       valid_days=30) -> AgentHandle:
        """An agent whose asset went through the real flow: profile, assessment, submission by
        the admin, and approval by a second admin holding governance_reviewer."""
        agent = self.agent(tools, resources)
        save_profile(self, agent.asset_id)
        assess(self, agent.asset_id)
        if approve:
            holder = reviewers(self)
            review = submitted(self, agent.asset_id)
            response = approve_review(self, review["id"], holder, conditions=conditions,
                                      **window(valid_days, valid_days))
            assert response.status_code == 201, response.text
        return agent

    def set_enforcement(self, mode: str, reason: str = "Synthetic mode change."):
        response = self.post("/governance/enforcement", {"mode": mode, "reason": reason})
        assert response.status_code == 200, response.text
        return response.json()

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


def insert_decision(connection, tenant_id, asset_id, *, kind="SUSPEND", from_status="DRAFT",
                    to_status="SUSPENDED", review_id=None, decided_by=None) -> UUID:
    """A real decision row, written as the database owner, for tests that need one to point at.

    It names the tenant's first audit event, because a decision must reference a real one.
    """
    audit_event_id = connection.execute(
        "SELECT id FROM audit_events WHERE tenant_id = %s ORDER BY seq LIMIT 1", (tenant_id,)
    ).fetchone()[0]
    if decided_by is None:
        decided_by = connection.execute(
            "SELECT id FROM users WHERE tenant_id = %s ORDER BY email LIMIT 1", (tenant_id,)
        ).fetchone()[0]
    decision_id = uuid4()
    connection.execute(
        """
        INSERT INTO governance_decisions (id, tenant_id, asset_id, review_id, kind, from_status,
            to_status, actor_type, decided_by, decided_at, reason, audit_event_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 'user', %s, now(), 'synthetic test decision', %s)
        """,
        (decision_id, tenant_id, asset_id, review_id, kind, from_status, to_status, decided_by,
         audit_event_id),
    )
    return decision_id


# Governance review flow, shared by the approval and separation tests


ASSETS = "/governance/assets"


APPROVALS = "/governance/approvals"


POLICIES = "/governance/policies"


PROFILE = {
    "asset_type": "ai_application",
    "data_categories": ["internal"],
    "external_exposure": "none",
    "autonomy_level": "advisory",
    "declared_tool_access": [],
    "human_oversight": "in_the_loop",
    "impact_level": "negligible",
    "deployment_environment": "development",
    "third_party_reliance": "none",
}


def save_profile(tenant, asset_id, body=None):
    response = tenant.post(f"{ASSETS}/{asset_id}/profile", PROFILE if body is None else body)
    assert response.status_code == 201, response.text
    return response.json()


def assess(tenant, asset_id):
    response = tenant.post(f"{ASSETS}/{asset_id}/assess")
    assert response.status_code == 201, response.text
    return response.json()


def assessed_asset(tenant, profile=None) -> str:
    asset_id = tenant.asset()["id"]
    save_profile(tenant, asset_id, profile)
    assess(tenant, asset_id)
    return asset_id


def submit(tenant, asset_id, reason="Ready for review.", headers=None):
    body = {} if reason is None else {"reason": reason}
    return tenant.post(f"{ASSETS}/{asset_id}/submit", body, headers=headers)


def submitted(tenant, asset_id=None, **kwargs) -> dict:
    response = submit(tenant, asset_id or assessed_asset(tenant), **kwargs)
    assert response.status_code == 201, response.text
    return response.json()


def reviewers(tenant) -> dict:
    """The first admin and a second admin, who each hold governance_reviewer. Returns the second."""
    second = tenant.login_as("second-admin", "admin")
    if not getattr(tenant, "reviewers_granted", False):
        tenant.grant_governance("admin", by="second-admin")
        tenant.grant_governance("second-admin", by="admin")
        tenant.reviewers_granted = True
    return second


def activate_policy(tenant, severity="medium", applicability=None, **controls) -> str:
    second = reviewers(tenant)
    policy = tenant.post(POLICIES, {"name": f"policy-{uuid4().hex[:8]}",
                                    "category": "general"}).json()
    version = tenant.post(
        f"{POLICIES}/{policy['id']}/versions",
        {
            "document": {"description": "synthetic", "severity": severity,
                         "applicability": applicability or {}, "controls": controls},
            "effective_from": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        },
    ).json()
    path = f"{POLICIES}/{policy['id']}/versions/{version['id']}"
    assert tenant.post(f"{path}/approve", headers=second).status_code == 200
    assert tenant.post(f"{path}/activate").status_code == 200
    return version["id"]


def assign(tenant, review_id, reviewer_id, headers):
    return tenant.post(f"{APPROVALS}/{review_id}/assign", {"reviewer_id": reviewer_id},
                       headers=headers)


def review_of(tenant, review_id) -> dict:
    response = tenant.get(f"{APPROVALS}/{review_id}")
    assert response.status_code == 200, response.text
    return response.json()


def detail_status(tenant, asset_id) -> str:
    return tenant.get(f"{ASSETS}/{asset_id}").json()["governance_status"]


def error_code(response) -> str:
    return response.json()["error"]["code"]


def decisions_of(attacker_sql, asset_id):
    return attacker_sql.execute(
        "SELECT d.kind, d.from_status, d.to_status, d.review_id, d.reason, d.id "
        "FROM governance_decisions d JOIN audit_events a ON a.id = d.audit_event_id "
        "WHERE d.asset_id = %s ORDER BY a.seq",
        (asset_id,),
    ).fetchall()


def window(valid_days=365, review_days=180) -> dict:
    now = datetime.now(UTC)
    return {"valid_until": (now + timedelta(days=valid_days)).isoformat(),
            "next_review_at": (now + timedelta(days=review_days)).isoformat()}


def approve(tenant, review_id, headers, reason="Controls are adequate.", conditions=None,
            **overrides):
    body = {"reason": reason, **window(), **overrides}
    if conditions is not None:
        body["conditions"] = conditions
    return tenant.post(f"{APPROVALS}/{review_id}/approve", body, headers=headers)


# TenantWorld.governed_agent has a parameter named approve.
approve_review = approve


def reject(tenant, review_id, headers, reason="The risks are not mitigated."):
    return tenant.post(f"{APPROVALS}/{review_id}/reject", {"reason": reason}, headers=headers)


def another_holder(tenant, name):
    """A further admin holding governance_reviewer, granted by the second admin."""
    headers = tenant.login_as(name, "admin")
    tenant.grant_governance(name, by="second-admin")
    return headers


def review_status_of(attacker_sql, review_id):
    return attacker_sql.execute(
        "SELECT status FROM governance_reviews WHERE id = %s", (review_id,)).fetchone()[0]


def assert_review_untouched(tenant, attacker_sql, review, assigned=False):
    """Nothing was decided: the review open, the asset still under review, no new decision."""
    kinds = ["SUBMIT", "ASSIGN_REVIEWER"] if assigned else ["SUBMIT"]
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == kinds
    assert review_status_of(attacker_sql, review["id"]) == "OPEN"
    assert detail_status(tenant, review["asset_id"]) == "UNDER_REVIEW"
    assert tenant.verify_audit()["valid"] is True


def revoke_governance(tenant, name):
    """Revoke the governance_reviewer grant of the user logged in as `name`."""
    people = tenant.get("/governance/people").json()["items"]
    grant_id = next(p["reviewer_grant_id"] for p in people if p["id"] == tenant.user_id(name))
    assert tenant.post(f"/governance/role-grants/{grant_id}/revoke").status_code == 200
