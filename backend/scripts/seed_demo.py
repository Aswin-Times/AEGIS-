"""Seed a clearly synthetic demo tenant by driving the real API.

Nothing is inserted directly except the tenant and its users, which have no API yet. Decisions,
denials, and audit records are produced by the actual gateway, so what the dashboard shows is
real enforcement of synthetic actions. Governance data (assets at several lifecycle stages,
evidence, a reviewer grant) comes from seed_governance.py, also through the API.

Running it again is safe: an existing tenant and its login are reused, and each part first checks
what already exists. It never prints or regenerates the demo password.
"""

import json
import secrets
from pathlib import Path

import httpx
from seed_governance import seed_governance

from aegis.provisioning import create_user, provision_tenant

SLUG = "synthetic-demo"
DEMO_USERS = {"admin": "admin", "reviewer": "reviewer", "viewer": "viewer"}
GATEWAY_ASSET = "Synthetic Research Assistant"


def _login(email: str, password: str) -> dict:
    return {"tenant_slug": SLUG, "email": email, "password": password}


def seed(base_url: str, owner_url: str, credentials_path: Path) -> None:
    if credentials_path.exists():
        password = json.loads(credentials_path.read_text(encoding="utf-8"))["password"]
    else:
        tenant_id = provision_tenant(owner_url, slug=SLUG, name="Synthetic Demo Organization")
        password = secrets.token_urlsafe(18)
        for role in DEMO_USERS:
            create_user(
                owner_url, tenant_id, email=f"{role}@synthetic.example.test", password=password,
                role=role,
            )
        credentials_path.write_text(
            json.dumps(
                {
                    "tenant": SLUG,
                    "users": [f"{role}@synthetic.example.test" for role in DEMO_USERS],
                    "password": password,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    admin_login = _login("admin@synthetic.example.test", password)
    with httpx.Client(base_url=f"{base_url}/api/v1", timeout=30) as client:
        token = client.post("/auth/login", json=admin_login).raise_for_status().json()
        admin = {"Authorization": f"Bearer {token['access_token']}"}
        assets = client.get("/assets", params={"limit": 100}, headers=admin).raise_for_status()
        if not any(item["name"] == GATEWAY_ASSET for item in assets.json()["items"]):
            _seed_gateway_demo(client, admin)
    seed_governance(base_url, admin_login, _login("reviewer@synthetic.example.test", password))


def _seed_gateway_demo(client: httpx.Client, admin: dict) -> None:
    """The asset, agent, policy, and actions that fill the enforcement dashboards."""

    def create(path: str, body: dict) -> dict:
        return client.post(path, json=body, headers=admin).raise_for_status().json()

    asset = create(
        "/assets",
        {
            "name": GATEWAY_ASSET,
            "owner": "Synthetic Platform Team",
            "risk_classification": "medium",
            "intended_use": "Demonstration of AEGIS enforcement. Not a real system.",
            "is_synthetic": True,
        },
    )
    agent = create(
        "/agents",
        {
            "asset_id": asset["id"],
            "name": "synthetic-research-agent",
            "owner": "Synthetic Platform Team",
        },
    )

    def resource(kind, name, classification, clearance=None, content=None) -> str:
        return create(
            "/resources",
            {
                "kind": kind,
                "name": name,
                "classification": classification,
                "clearance": clearance,
                "content": content or {"synthetic": True},
                "is_synthetic": True,
            },
        )["id"]

    handbook = resource("document", "Synthetic Handbook", "internal",
                        content={"title": "Synthetic Handbook", "body": "Synthetic text."})
    salaries = resource("document", "Synthetic Salary Table", "sensitive",
                        content={"title": "Synthetic Salary Table"})
    partner = resource("destination", "Synthetic Partner Inbox", "internal",
                       clearance="internal")
    unknown = resource("destination", "Synthetic Unapproved Inbox", "internal",
                       clearance="public")

    for tool in ("read_document", "calculate", "send_message"):
        create(f"/agents/{agent['id']}/tool-grants", {"tool": tool})
    for granted in (handbook, partner):
        create(f"/agents/{agent['id']}/resource-grants", {"resource_id": granted})

    policy = create("/policies", {"name": "Synthetic Baseline Policy"})
    version = create(
        f"/policies/{policy['id']}/versions",
        {
            "document": {
                "rules": [
                    {
                        "id": "hold-outbound",
                        "effect": "require_approval",
                        "match": {"tools": ["send_message"]},
                        "reason_code": "OUTBOUND_REQUIRES_APPROVAL",
                    },
                    {
                        "id": "allow-granted",
                        "effect": "allow",
                        "match": {},
                        "reason_code": "ALLOWED_BY_RULE",
                    },
                ]
            }
        },
    )
    create(f"/policies/{policy['id']}/activate", {"version_id": version["id"]})
    key = create(f"/agents/{agent['id']}/credentials", {})["key"]
    agent_headers = {"Authorization": f"Bearer {key}"}

    actions = [
        ("read-granted", "read_document", handbook, {}),
        ("read-ungranted", "read_document", salaries, {}),
        ("tool-ungranted", "lookup_customer", salaries, {}),
        ("shell-attempt", "run_shell_command", None, {"command": "whoami"}),
        ("math", "calculate", None, {"operator": "multiply", "a": 6, "b": 7}),
        ("send-unapproved", "send_message", unknown, {"body": "Synthetic message"}),
        ("send-held", "send_message", partner, {"body": "Synthetic weekly summary"}),
    ]
    for key_name, tool, resource_id, params in actions:
        client.post(
            "/gateway/actions",
            headers=agent_headers,
            json={
                "idempotency_key": key_name,
                "tool": tool,
                "resource_id": resource_id,
                "params": params,
            },
        ).raise_for_status()
