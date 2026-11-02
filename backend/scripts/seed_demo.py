"""Seed a clearly synthetic demo tenant by driving the real API.

Nothing is inserted directly except the tenant and its users, which have no API yet. Decisions,
denials, and audit records are produced by the actual gateway, so what the dashboard shows is
real enforcement of synthetic actions.
"""

import json
import secrets
from pathlib import Path

import httpx

from aegis.provisioning import create_user, provision_tenant

SLUG = "synthetic-demo"
DEMO_USERS = {"admin": "admin", "reviewer": "reviewer", "viewer": "viewer"}


def seed(base_url: str, owner_url: str, credentials_path: Path) -> None:
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

    with httpx.Client(base_url=f"{base_url}/api/v1", timeout=30) as client:
        token = client.post(
            "/auth/login",
            json={
                "tenant_slug": SLUG,
                "email": "admin@synthetic.example.test",
                "password": password,
            },
        ).raise_for_status().json()["access_token"]
        admin = {"Authorization": f"Bearer {token}"}

        def create(path: str, body: dict) -> dict:
            return client.post(path, json=body, headers=admin).raise_for_status().json()

        asset = create(
            "/assets",
            {
                "name": "Synthetic Research Assistant",
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
