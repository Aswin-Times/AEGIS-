"""Policy versions: immutable, validated, and correctly referenced by decisions."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

ALLOW = [{"id": "allow", "effect": "allow", "match": {}, "reason_code": "ALLOWED_BY_RULE"}]
DENY = [{"id": "deny", "effect": "deny", "match": {}, "reason_code": "DENIED_BY_RULE"}]


def test_versions_increment(tenant):
    policy = tenant.created("/policies", {"name": "main"})
    first = tenant.created(f"/policies/{policy['id']}/versions", {"document": {"rules": ALLOW}})
    second = tenant.created(f"/policies/{policy['id']}/versions", {"document": {"rules": DENY}})
    assert (first["version"], second["version"]) == (1, 2)
    assert first["content_hash"] != second["content_hash"]


@pytest.mark.parametrize(
    "document",
    [
        {"rules": "all"},
        {"rules": [{"id": "x", "effect": "permit", "match": {}, "reason_code": "SOME_CODE"}]},
        {"rules": [], "default_effect": "allow"},
    ],
)
def test_invalid_policy_documents_are_rejected(tenant, document):
    policy = tenant.created("/policies", {"name": "main"})
    response = tenant.post(f"/policies/{policy['id']}/versions", {"document": document})
    assert response.status_code == 422


def test_creating_a_version_does_not_activate_it(world, tenant):
    tenant.activate(DENY)
    policy = tenant.created("/policies", {"name": "draft"})
    tenant.created(f"/policies/{policy['id']}/versions", {"document": {"rules": ALLOW}})
    agent = tenant.agent(tools=["calculate"])
    body = agent.act("calculate", params={"operator": "add", "a": 1, "b": 2}).json()
    assert body["outcome"] == "DENY"
    assert world.spy.calls == []


def test_decision_references_the_version_active_at_evaluation(tenant):
    policy = tenant.created("/policies", {"name": "main"})
    deny_version = tenant.activate_version(policy["id"], DENY)
    agent = tenant.agent(tools=["calculate"])
    params = {"operator": "add", "a": 1, "b": 2}

    denied = agent.act("calculate", params=params).json()
    allow_version = tenant.activate_version(policy["id"], ALLOW)
    allowed = agent.act("calculate", params=params).json()

    assert denied["policy_version_id"] == deny_version["id"]
    assert allowed["policy_version_id"] == allow_version["id"]
    assert denied["outcome"] == "DENY"
    assert allowed["outcome"] == "ALLOW"
    decisions = {
        item["id"]: item for item in tenant.get("/decisions", limit=100).json()["items"]
    }
    assert decisions[denied["decision_id"]]["policy_version"] == 1
    assert decisions[allowed["decision_id"]]["policy_version"] == 2


def test_activation_is_audited(tenant):
    version = tenant.allow_everything()
    events = tenant.audit_events("policy.activated")
    assert len(events) == 1
    assert events[0]["policy_version_id"] == version["id"]
    assert events[0]["actor_type"] == "user"


def test_runtime_role_cannot_edit_a_version(db, tenant):
    version = tenant.allow_everything()
    with pytest.raises(ProgrammingError), db.tenant_transaction(tenant.id) as session:
        session.execute(
            text("UPDATE policy_versions SET document_canonical = '{}' WHERE id = :id"),
            {"id": version["id"]},
        )


def test_runtime_role_cannot_delete_a_version(db, tenant):
    version = tenant.allow_everything()
    with pytest.raises(ProgrammingError), db.tenant_transaction(tenant.id) as session:
        session.execute(text("DELETE FROM policy_versions WHERE id = :id"), {"id": version["id"]})


def test_decisions_are_append_only_for_the_runtime_role(db, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    agent.act("calculate", params={"operator": "add", "a": 1, "b": 2})
    with pytest.raises(ProgrammingError), db.tenant_transaction(tenant.id) as session:
        session.execute(text("UPDATE policy_decisions SET outcome = 'ALLOW'"))
    with pytest.raises(ProgrammingError), db.tenant_transaction(tenant.id) as session:
        session.execute(text("DELETE FROM policy_decisions"))


def test_activating_a_version_of_a_different_policy_is_refused(tenant):
    first = tenant.created("/policies", {"name": "first"})
    second = tenant.created("/policies", {"name": "second"})
    version = tenant.created(f"/policies/{first['id']}/versions", {"document": {"rules": ALLOW}})
    response = tenant.post(f"/policies/{second['id']}/activate", {"version_id": version["id"]})
    assert response.status_code == 404
