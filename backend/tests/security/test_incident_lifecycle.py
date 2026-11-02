"""Incident lifecycle: allowed transitions, authorization, conflicts, and audit."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

import aegis.incidents.service as incident_service
from aegis.correlation.engine import process_tenant
from aegis.db.models import Incident
from aegis.db.session import Database
from aegis.incidents.state import ALLOWED_TRANSITIONS, can_transition


def make_incident(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    for _ in range(3):
        agent.act("run_shell_command")
    container = world.app.state.container
    process_tenant(container.db, tenant.id, clock=container.clock)
    items = tenant.get("/incidents", rule_key="repeated_unauthorized_tools").json()["items"]
    assert len(items) == 1
    return items[0]


def move(tenant, incident_id, verb, version, reason=None, headers=None):
    body = {"expected_version": version}
    if reason is not None:
        body["reason"] = reason
    return tenant.post(
        f"/incidents/{incident_id}/{verb}", body, headers=headers or tenant.reviewer
    )


def current(tenant, incident_id):
    return tenant.get(f"/incidents/{incident_id}").json()


def test_state_machine_matches_the_documented_lifecycle():
    assert ALLOWED_TRANSITIONS == {
        "OPEN": {"ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"},
        "ACKNOWLEDGED": {"INVESTIGATING", "RESOLVED"},
        "INVESTIGATING": {"RESOLVED"},
        "RESOLVED": {"CLOSED", "INVESTIGATING"},
        "CLOSED": set(),
    }
    assert can_transition("OPEN", "RESOLVED")
    assert not can_transition("CLOSED", "OPEN")
    assert not can_transition("NOT_A_STATE", "OPEN")


def test_full_lifecycle_records_every_change(world, tenant):
    incident = make_incident(world, tenant)
    identity = incident["id"]
    reviewer = tenant.get("/auth/me", headers=tenant.reviewer).json()
    admin = tenant.get("/auth/me").json()

    steps = [
        ("acknowledge", None, tenant.reviewer, "ACKNOWLEDGED", reviewer),
        ("investigate", None, tenant.reviewer, "INVESTIGATING", reviewer),
        ("resolve", "Synthetic: grant corrected", tenant.reviewer, "RESOLVED", reviewer),
        ("close", "Synthetic: review complete", tenant.admin, "CLOSED", admin),
    ]
    version = incident["version"]
    for verb, reason, headers, expected, _actor in steps:
        response = move(tenant, identity, verb, version, reason, headers)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == expected
        assert response.json()["version"] == version + 1
        version += 1

    transitions = current(tenant, identity)["transitions"]
    assert [item["to_status"] for item in transitions] == [
        "OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"
    ]
    assert [item["from_status"] for item in transitions] == [
        None, "OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"
    ]
    for item, (_, reason, _, _, actor) in zip(transitions[1:], steps, strict=True):
        assert item["actor_type"] == "user"
        assert item["actor_id"] == actor["id"]
        assert item["reason"] == reason
        assert item["occurred_at"]

    audit = {event["id"]: event for event in tenant.audit_events("incident.status_changed")}
    assert len(audit) == 4
    for item in transitions[1:]:
        event = audit[item["audit_event_id"]]
        assert event["subject_id"] == identity
        assert event["actor_id"] == item["actor_id"]
        assert event["payload"]["from_status"] == item["from_status"]
        assert event["payload"]["to_status"] == item["to_status"]
    assert tenant.verify_audit()["valid"] is True


@pytest.mark.parametrize(
    "path, verb, reason",
    [
        ([], "close", "x"),
        ([("acknowledge", None)], "acknowledge", None),
        ([("acknowledge", None), ("investigate", None)], "acknowledge", None),
        ([("investigate", None)], "investigate", None),
        ([("resolve", "x")], "acknowledge", None),
        ([("resolve", "x")], "resolve", "x"),
        ([("acknowledge", None)], "reopen", "x"),
        ([], "reopen", "x"),
    ],
)
def test_invalid_transitions_are_refused(world, tenant, path, verb, reason):
    incident = make_incident(world, tenant)
    version = incident["version"]
    for step, step_reason in path:
        assert move(tenant, incident["id"], step, version, step_reason).status_code == 200
        version += 1
    before = current(tenant, incident["id"])

    response = move(tenant, incident["id"], verb, version, reason, tenant.admin)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVALID_STATE_TRANSITION"
    assert current(tenant, incident["id"]) == before


def test_closed_is_terminal(world, tenant):
    incident = make_incident(world, tenant)
    assert move(tenant, incident["id"], "resolve", 1, "x").status_code == 200
    assert move(tenant, incident["id"], "close", 2, "x", tenant.admin).status_code == 200
    for verb in ("acknowledge", "investigate", "resolve", "close", "reopen"):
        assert move(tenant, incident["id"], verb, 3, "x", tenant.admin).status_code == 409


def test_resolved_incident_can_be_reopened_with_a_reason(world, tenant):
    incident = make_incident(world, tenant)
    move(tenant, incident["id"], "resolve", 1, "x")
    response = move(tenant, incident["id"], "reopen", 2, "New evidence")
    assert response.status_code == 200
    assert response.json()["status"] == "INVESTIGATING"


def test_reopening_is_refused_while_a_new_active_incident_exists(world, tenant):
    incident = make_incident(world, tenant)
    move(tenant, incident["id"], "resolve", 1, "x")
    agent_id = incident["agent_id"]
    assert agent_id
    agents = tenant.get("/agents").json()["items"]
    assert [item["id"] for item in agents] == [agent_id]
    key = tenant.created(f"/agents/{agent_id}/credentials", {})["key"]
    for _ in range(3):
        tenant.client.post(
            "/api/v1/gateway/actions",
            headers={"Authorization": f"Bearer {key}"},
            json={"idempotency_key": uuid4().hex, "tool": "run_shell_command",
                  "resource_id": None, "params": {}},
        )
    container = world.app.state.container
    process_tenant(container.db, tenant.id, clock=container.clock)

    response = move(tenant, incident["id"], "reopen", 2, "x")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ACTIVE_INCIDENT_EXISTS"
    assert current(tenant, incident["id"])["status"] == "RESOLVED"


@pytest.mark.parametrize(
    "verb, role",
    [("resolve", "reviewer"), ("close", "admin"), ("reopen", "reviewer")],
)
@pytest.mark.parametrize("reason", [None, "", "   "])
def test_reason_is_required_where_documented(world, tenant, verb, role, reason):
    incident = make_incident(world, tenant)
    version = 1
    if verb in ("close", "reopen"):
        move(tenant, incident["id"], "resolve", 1, "x")
        version = 2
    before = current(tenant, incident["id"])

    response = move(tenant, incident["id"], verb, version, reason, tenant.login(role))

    assert response.status_code == 422
    assert current(tenant, incident["id"]) == before


def test_oversized_reason_is_rejected(world, tenant):
    incident = make_incident(world, tenant)
    assert move(tenant, incident["id"], "resolve", 1, "x" * 2001).status_code == 422


def test_body_cannot_change_other_fields(world, tenant):
    incident = make_incident(world, tenant)
    for extra in ({"severity": "low"}, {"status": "CLOSED"}, {"rule_key": "x"},
                  {"tenant_id": str(uuid4())}, {"actor_id": str(uuid4())}):
        response = tenant.post(
            f"/incidents/{incident['id']}/acknowledge",
            {"expected_version": 1, **extra},
            headers=tenant.reviewer,
        )
        assert response.status_code == 422, extra
    assert current(tenant, incident["id"])["severity"] == "high"
    assert current(tenant, incident["id"])["status"] == "OPEN"


def test_expected_version_is_required(world, tenant):
    incident = make_incident(world, tenant)
    response = tenant.post(
        f"/incidents/{incident['id']}/acknowledge", {}, headers=tenant.reviewer
    )
    assert response.status_code == 422


def test_stale_version_is_refused(world, tenant):
    incident = make_incident(world, tenant)
    assert move(tenant, incident["id"], "acknowledge", 1).status_code == 200

    response = move(tenant, incident["id"], "investigate", 1)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INCIDENT_VERSION_CONFLICT"
    assert current(tenant, incident["id"])["status"] == "ACKNOWLEDGED"


def test_concurrent_transitions_produce_one_winner(world, tenant):
    incident = make_incident(world, tenant)
    headers = tenant.reviewer
    barrier = Barrier(8)

    def attempt(index):
        barrier.wait()
        verb = "acknowledge" if index % 2 else "investigate"
        return move(tenant, incident["id"], verb, 1, None, headers).status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(attempt, range(8)))

    assert sorted(codes) == [200] + [409] * 7
    state = current(tenant, incident["id"])
    assert state["version"] == 2
    assert len(state["transitions"]) == 2
    assert tenant.verify_audit()["valid"] is True


def test_transitions_and_correlation_can_run_together(world, tenant):
    """Both touch the incident and the audit chain, so a bad lock order would deadlock."""
    incident = make_incident(world, tenant)
    agents = tenant.get("/agents").json()["items"]
    key = tenant.created(f"/agents/{agents[0]['id']}/credentials", {})["key"]
    headers = tenant.reviewer
    container = world.app.state.container
    for _ in range(15):
        tenant.client.post(
            "/api/v1/gateway/actions",
            headers={"Authorization": f"Bearer {key}"},
            json={"idempotency_key": uuid4().hex, "tool": "run_shell_command",
                  "resource_id": None, "params": {}},
        )
    barrier = Barrier(2)

    def correlate():
        barrier.wait()
        return process_tenant(container.db, tenant.id, clock=container.clock)

    def transition():
        barrier.wait()
        codes = []
        version = 1
        for verb in ("acknowledge", "investigate"):
            codes.append(move(tenant, incident["id"], verb, version, None, headers).status_code)
            version += 1
        return codes

    with ThreadPoolExecutor(max_workers=2) as pool:
        correlated = pool.submit(correlate)
        moved = pool.submit(transition)
        assert moved.result(timeout=60) == [200, 200]
        assert correlated.result(timeout=60).halted is False

    process_tenant(container.db, tenant.id, clock=container.clock)
    assert current(tenant, incident["id"])["event_count"] == 18
    assert tenant.verify_audit()["valid"] is True


@pytest.mark.parametrize("verb", ["acknowledge", "investigate", "resolve", "close", "reopen"])
def test_viewers_cannot_change_incidents(world, tenant, verb):
    incident = make_incident(world, tenant)
    response = move(tenant, incident["id"], verb, 1, "x", tenant.viewer)
    assert response.status_code == 403
    assert current(tenant, incident["id"])["status"] == "OPEN"


def test_reviewers_cannot_close(world, tenant):
    incident = make_incident(world, tenant)
    move(tenant, incident["id"], "resolve", 1, "x")
    assert move(tenant, incident["id"], "close", 2, "x", tenant.reviewer).status_code == 403
    assert current(tenant, incident["id"])["status"] == "RESOLVED"


@pytest.mark.parametrize("verb", ["acknowledge", "investigate", "resolve", "close", "reopen"])
def test_agents_and_anonymous_callers_cannot_change_incidents(world, tenant, verb):
    incident = make_incident(world, tenant)
    agent = tenant.agent()
    body = {"expected_version": 1, "reason": "x"}
    assert tenant.client.post(
        f"/api/v1/incidents/{incident['id']}/{verb}", json=body, headers=agent.headers
    ).status_code == 401
    assert tenant.client.post(
        f"/api/v1/incidents/{incident['id']}/{verb}", json=body
    ).status_code == 401
    assert current(tenant, incident["id"])["status"] == "OPEN"


def test_one_tenant_cannot_change_anothers_incident(world):
    a, b = world.tenant(), world.tenant()
    incident = make_incident(world, b)
    for verb in ("acknowledge", "investigate", "resolve", "close", "reopen"):
        assert move(a, incident["id"], verb, 1, "x", a.admin).status_code == 404
    assert current(b, incident["id"])["status"] == "OPEN"
    assert len(a.audit_events("incident.status_changed")) == 0


def test_acknowledging_assigns_the_incident_once(world, tenant):
    incident = make_incident(world, tenant)
    reviewer = tenant.get("/auth/me", headers=tenant.reviewer).json()
    move(tenant, incident["id"], "acknowledge", 1)
    state = current(tenant, incident["id"])
    assert state["assigned_to"] == reviewer["id"]
    assert state["assigned_to_email"] == reviewer["email"]

    move(tenant, incident["id"], "investigate", 2, None, tenant.admin)
    assert current(tenant, incident["id"])["assigned_to"] == reviewer["id"]


def test_audit_failure_rolls_back_the_transition(world, tenant, monkeypatch):
    incident = make_incident(world, tenant)
    headers = tenant.reviewer

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic audit outage")

    monkeypatch.setattr(incident_service, "append_event", fail)
    response = move(tenant, incident["id"], "acknowledge", 1, None, headers)
    monkeypatch.undo()

    assert response.status_code >= 500
    state = current(tenant, incident["id"])
    assert state["status"] == "OPEN"
    assert len(state["transitions"]) == 1


def _as_runtime(world, tenant, statement):
    database = Database(world.urls.app, pool_size=1, max_overflow=0)
    try:
        with database.tenant_transaction(tenant.id) as session:
            session.execute(text(statement))
    finally:
        database.dispose()


def test_database_refuses_an_invalid_transition(world, tenant):
    make_incident(world, tenant)
    with pytest.raises(DBAPIError, match="invalid incident transition"):
        _as_runtime(world, tenant, "UPDATE incidents SET status = 'CLOSED', version = version + 1")


def test_database_requires_the_version_to_advance_with_the_status(world, tenant):
    make_incident(world, tenant)
    with pytest.raises(DBAPIError, match="version"):
        _as_runtime(world, tenant, "UPDATE incidents SET status = 'ACKNOWLEDGED'")
    with pytest.raises(DBAPIError, match="version"):
        _as_runtime(world, tenant, "UPDATE incidents SET version = version + 1")


def test_database_requires_new_incidents_to_start_open(world, tenant):
    incident = make_incident(world, tenant)
    move(tenant, incident["id"], "resolve", 1, "x")
    database = Database(world.urls.app, pool_size=1, max_overflow=0)
    try:
        with pytest.raises(DBAPIError, match="must start"):
            with database.tenant_transaction(tenant.id) as session:
                existing = session.get(Incident, incident["id"])
                session.add(
                    Incident(
                        id=uuid4(),
                        tenant_id=existing.tenant_id,
                        rule_version_id=existing.rule_version_id,
                        rule_key=existing.rule_key,
                        rule_version=existing.rule_version,
                        scope_type=existing.scope_type,
                        scope_key="agent:other",
                        title=existing.title,
                        severity=existing.severity,
                        status="CLOSED",
                        version=1,
                        event_count=0,
                        first_observed_at=existing.first_observed_at,
                        last_observed_at=existing.last_observed_at,
                    )
                )
                session.flush()
    finally:
        database.dispose()
