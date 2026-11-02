"""Correlation against real PostgreSQL: scenarios, idempotency, races, order, and isolation."""

import ast
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

import aegis
from aegis.api.app import create_app
from aegis.config import Settings
from aegis.correlation.engine import pending_tenants, process_tenant
from aegis.db.models import Incident, IncidentEvent, SecurityEvent
from aegis.db.session import Database
from aegis.security.agent_keys import format_key, parse_key
from support import bearer

SOURCE_ROOT = Path(aegis.__file__).parent
T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
PARAMS = {"operator": "add", "a": 1, "b": 2}


def correlate(world, tenant):
    container = world.app.state.container
    return process_tenant(container.db, tenant.id, clock=container.clock)


def incidents_of(tenant, **params):
    response = tenant.get("/incidents", limit=100, **params)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def detail(tenant, incident):
    response = tenant.get(f"/incidents/{incident['id']}")
    assert response.status_code == 200, response.text
    return response.json()


def attempt_forbidden_tool(agent, count=1):
    return [agent.act("run_shell_command", params={"command": "x"}).json() for _ in range(count)]


def at(world, moment):
    world.app.state.container.clock = lambda: moment


def incident_events(tenant, incident):
    return tenant.get(f"/incidents/{incident['id']}/events", limit=100).json()["items"]


# The complete workflow


def test_repeated_unauthorized_actions_become_an_evidenced_incident(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])

    denials = attempt_forbidden_tool(agent, 3)
    assert {item["outcome"] for item in denials} == {"DENY"}
    assert world.spy.calls == []

    result = correlate(world, tenant)
    assert result.incidents_created == 1

    incidents = incidents_of(tenant)
    assert len(incidents) == 1
    incident = detail(tenant, incidents[0])
    assert incident["rule_key"] == "repeated_unauthorized_tools"
    assert incident["rule_version"] == 1
    assert incident["rule_version_id"]
    assert incident["severity"] == "high"
    assert incident["status"] == "OPEN"
    assert incident["agent_id"] == agent.id
    assert incident["event_count"] == 3
    assert incident["version"] == 1
    assert incident["first_observed_at"] <= incident["last_observed_at"]

    linked = incident_events(tenant, incident)
    assert {item["decision_id"] for item in linked} == {item["decision_id"] for item in denials}
    assert {item["reason_code"] for item in linked} == {"UNKNOWN_TOOL"}

    transitions = incident["transitions"]
    assert len(transitions) == 1
    assert transitions[0]["from_status"] is None
    assert transitions[0]["to_status"] == "OPEN"
    assert transitions[0]["actor_type"] == "system"
    assert transitions[0]["audit_event_id"]

    created = tenant.audit_events("incident.created")
    assert len(created) == 1
    assert created[0]["subject_id"] == incident["id"]
    assert created[0]["actor_type"] == "system"
    assert tenant.verify_audit()["valid"] is True
    assert world.spy.calls == []


def test_below_threshold_creates_nothing(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    attempt_forbidden_tool(agent, 2)
    assert correlate(world, tenant).incidents_created == 0
    assert incidents_of(tenant) == []


def test_events_outside_the_window_do_not_correlate(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    for minutes in (0, 10, 20):
        at(world, T0 + timedelta(minutes=minutes))
        attempt_forbidden_tool(agent)
    correlate(world, tenant)
    assert incidents_of(tenant) == []


def test_each_agent_is_counted_separately(world, tenant):
    tenant.allow_everything()
    first, second = tenant.agent(), tenant.agent()
    attempt_forbidden_tool(first, 2)
    attempt_forbidden_tool(second, 2)
    correlate(world, tenant)
    assert incidents_of(tenant) == []


def test_allowed_actions_do_not_count(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    for _ in range(5):
        agent.act("calculate", params=PARAMS)
    correlate(world, tenant)
    assert incidents_of(tenant) == []


# Scenarios


def test_scenario_a_ungranted_known_tool(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    for _ in range(3):
        agent.act("calculate", params=PARAMS)
    correlate(world, tenant)
    assert [item["rule_key"] for item in incidents_of(tenant)] == ["repeated_unauthorized_tools"]


def test_scenario_b_repeated_transfer_denials(world, tenant):
    tenant.allow_everything()
    sensitive = tenant.document("sensitive")
    destination = tenant.destination(clearance="public")
    agent = tenant.agent(tools=["send_message"], resources=[destination, sensitive])
    for _ in range(2):
        body = agent.act(
            "send_message", destination, {"body": "x", "attachment_resource_id": sensitive}
        ).json()
        assert body["reason_code"] == "DESTINATION_CLEARANCE_INSUFFICIENT"

    correlate(world, tenant)

    incidents = incidents_of(tenant, rule_key="repeated_transfer_denials")
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "high"
    assert world.spy.calls == []


def test_scenario_b_ignores_denied_reads(world, tenant):
    tenant.allow_everything()
    document = tenant.document("sensitive")
    agent = tenant.agent(tools=["read_document"])
    for _ in range(2):
        agent.act("read_document", document)
    correlate(world, tenant)
    assert incidents_of(tenant, rule_key="repeated_transfer_denials") == []


def test_scenario_c_probing_needs_varied_targets(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["read_document"])
    only = tenant.document()
    for _ in range(5):
        agent.act("read_document", only)
    correlate(world, tenant)
    assert incidents_of(tenant, rule_key="permission_probing") == []


def test_scenario_c_probing_across_targets(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["read_document"])
    for _ in range(5):
        agent.act("read_document", tenant.document())
    correlate(world, tenant)
    incidents = incidents_of(tenant, rule_key="permission_probing")
    assert len(incidents) == 1
    assert incidents[0]["event_count"] == 5


def test_scenario_d_executing_without_a_valid_approval(world, tenant):
    tenant.hold_tool("calculate")
    agent = tenant.agent(tools=["calculate"])
    request_id = agent.act("calculate", params=PARAMS).json()["request_id"]
    for _ in range(3):
        assert agent.execute(request_id).status_code == 409

    correlate(world, tenant)

    incidents = incidents_of(tenant, rule_key="approval_bypass_attempts")
    assert len(incidents) == 1
    assert world.spy.calls == []
    linked = incident_events(tenant, incidents[0])
    assert {item["reason_code"] for item in linked} == {"APPROVAL_PENDING"}


def test_scenario_e_agent_references_to_other_tenants(world):
    attacker, victim = world.tenant(), world.tenant()
    attacker.allow_everything()
    agent = attacker.agent(tools=["read_document"])
    secrets = [victim.document("sensitive") for _ in range(3)]
    for secret in secrets:
        agent.act("read_document", secret)

    correlate(world, attacker)
    correlate(world, victim)

    incidents = incidents_of(attacker, rule_key="not_visible_references")
    assert len(incidents) == 1
    assert incidents_of(victim) == []
    assert world.spy.calls == []


def test_scenario_e_user_references_to_other_tenants(world):
    attacker, victim = world.tenant(), world.tenant()
    target = victim.agent()
    for _ in range(3):
        assert attacker.get(f"/agents/{target.id}").status_code == 404

    correlate(world, attacker)

    incidents = incidents_of(attacker, rule_key="not_visible_references")
    assert len(incidents) == 1
    assert incidents[0]["scope_key"].startswith("actor:")
    assert target.key not in str(detail(attacker, incidents[0]))


def test_authentication_failures_correlate_per_tenant(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    parsed = parse_key(agent.key)
    forged = bearer(format_key(parsed.tenant_id, parsed.credential_id, "wrong"))
    action = {"idempotency_key": "k", "tool": "calculate", "resource_id": None, "params": PARAMS}
    for _ in range(10):
        world.client.post("/api/v1/gateway/actions", headers=forged, json=action)

    correlate(world, tenant)

    incidents = incidents_of(tenant, rule_key="authentication_failures")
    assert len(incidents) == 1
    assert incidents[0]["scope_key"] == "tenant"


# Idempotency and duplicates


def test_processing_again_changes_nothing(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    attempt_forbidden_tool(agent, 3)
    correlate(world, tenant)
    before = detail(tenant, incidents_of(tenant)[0])

    result = correlate(world, tenant)

    assert result.processed == 0
    assert result.incidents_created == 0
    assert detail(tenant, incidents_of(tenant)[0]) == before


def test_further_events_attach_to_the_active_incident(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    attempt_forbidden_tool(agent, 3)
    correlate(world, tenant)
    attempt_forbidden_tool(agent, 2)

    assert correlate(world, tenant).incidents_created == 0

    incidents = incidents_of(tenant, rule_key="repeated_unauthorized_tools")
    assert len(incidents) == 1
    assert incidents[0]["event_count"] == 5
    assert incidents[0]["version"] == 1  # new evidence never invalidates a reviewer's view


def test_an_event_can_support_several_rules_without_duplicating_incidents(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["read_document"])
    for _ in range(5):
        agent.act("calculate", params=PARAMS)
    for _ in range(3):
        agent.act("run_shell_command")
    agent.act("read_document", tenant.document())
    correlate(world, tenant)
    keys = sorted(item["rule_key"] for item in incidents_of(tenant))
    assert keys == ["permission_probing", "repeated_unauthorized_tools"]


def test_database_refuses_a_second_active_incident(world, tenant, db):
    tenant.allow_everything()
    attempt_forbidden_tool(tenant.agent(), 3)
    correlate(world, tenant)
    with db.tenant_transaction(tenant.id) as session:
        existing = session.execute(select(Incident)).scalars().first()
        values = {
            "tenant_id": existing.tenant_id,
            "rule_version_id": existing.rule_version_id,
            "rule_key": existing.rule_key,
            "rule_version": existing.rule_version,
            "scope_type": existing.scope_type,
            "scope_key": existing.scope_key,
            "agent_id": existing.agent_id,
            "title": existing.title,
            "severity": existing.severity,
            "first_observed_at": existing.first_observed_at,
            "last_observed_at": existing.last_observed_at,
        }
    with pytest.raises(IntegrityError, match="incidents_one_active"):
        with db.tenant_transaction(tenant.id) as session:
            session.add(Incident(id=uuid4(), status="OPEN", event_count=0, version=1, **values))
            session.flush()


def test_concurrent_processing_creates_one_incident(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    attempt_forbidden_tool(agent, 20)
    container = world.app.state.container
    barrier = Barrier(8)

    def run(_):
        barrier.wait()
        return process_tenant(container.db, tenant.id, clock=container.clock)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, range(8)))

    assert sum(item.incidents_created for item in results) == 1
    assert sum(item.processed for item in results) == len(
        tenant.get("/events", limit=100).json()["items"]
    )
    incidents = incidents_of(tenant, rule_key="repeated_unauthorized_tools")
    assert len(incidents) == 1
    assert incidents[0]["event_count"] == 20
    assert tenant.get("/overview").json()["pending_correlation"] == 0
    assert tenant.verify_audit()["valid"] is True


def test_a_conflicting_incident_is_retried_rather_than_lost(world, tenant, db, monkeypatch):
    """If the unique index fires anyway, the event is reprocessed and attaches."""
    import aegis.correlation.engine as engine

    tenant.allow_everything()
    attempt_forbidden_tool(tenant.agent(), 3)

    real = engine._apply_rule
    raised = []

    def conflict_once(*args, **kwargs):
        if not raised:
            raised.append(True)
            raise IntegrityError("synthetic", {}, Exception("incidents_one_active"))
        return real(*args, **kwargs)

    monkeypatch.setattr(engine, "_apply_rule", conflict_once)
    correlate(world, tenant)
    monkeypatch.undo()

    assert raised
    assert len(incidents_of(tenant)) == 1
    assert tenant.get("/overview").json()["pending_correlation"] == 0


# Out-of-order events


def test_events_arriving_in_reverse_order_still_correlate(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    for seconds in (120, 60, 0):
        at(world, T0 + timedelta(seconds=seconds))
        attempt_forbidden_tool(agent)
        correlate(world, tenant)

    incidents = incidents_of(tenant)
    assert len(incidents) == 1
    assert incidents[0]["event_count"] == 3
    assert incidents[0]["first_observed_at"].startswith("2026-01-01T12:00:00")
    assert incidents[0]["last_observed_at"].startswith("2026-01-01T12:02:00")


def test_a_late_event_within_the_limit_attaches_and_extends_the_incident(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    for seconds in (300, 310, 320):
        at(world, T0 + timedelta(seconds=seconds))
        attempt_forbidden_tool(agent)
    correlate(world, tenant)

    at(world, T0 + timedelta(seconds=100))  # 200s before the first event; the window is 300s
    attempt_forbidden_tool(agent)
    correlate(world, tenant)

    incident = incidents_of(tenant)[0]
    assert incident["event_count"] == 4
    assert incident["first_observed_at"].startswith("2026-01-01T12:01:40")


def test_an_event_later_than_the_limit_is_processed_but_not_linked(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    for seconds in (1000, 1010, 1020):
        at(world, T0 + timedelta(seconds=seconds))
        attempt_forbidden_tool(agent)
    correlate(world, tenant)

    at(world, T0)
    attempt_forbidden_tool(agent)
    correlate(world, tenant)

    assert incidents_of(tenant)[0]["event_count"] == 3
    assert tenant.get("/overview").json()["pending_correlation"] == 0


def test_correlation_uses_occurrence_time_not_recording_time(world, tenant, db):
    tenant.allow_everything()
    agent = tenant.agent()
    for hours in (0, 5, 10):
        at(world, T0 + timedelta(hours=hours))
        attempt_forbidden_tool(agent)
    correlate(world, tenant)
    with db.tenant_transaction(tenant.id) as session:
        recorded = session.execute(
            select(SecurityEvent.recorded_at).where(
                SecurityEvent.event_type == "gateway.action_denied"
            )
        ).scalars().all()
    # Recorded within moments of each other, but they happened hours apart.
    assert max(recorded) - min(recorded) < timedelta(minutes=5)
    assert incidents_of(tenant) == []


# After resolution


def _resolve(tenant, incident):
    current = detail(tenant, incident)
    response = tenant.post(
        f"/incidents/{incident['id']}/resolve",
        {"expected_version": current["version"], "reason": "Synthetic resolution"},
        headers=tenant.reviewer,
    )
    assert response.status_code == 200, response.text


def test_resolved_incident_events_never_count_again(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    attempt_forbidden_tool(agent, 3)
    correlate(world, tenant)
    _resolve(tenant, incidents_of(tenant)[0])

    attempt_forbidden_tool(agent, 2)
    assert correlate(world, tenant).incidents_created == 0
    assert len(incidents_of(tenant)) == 1

    attempt_forbidden_tool(agent, 1)
    assert correlate(world, tenant).incidents_created == 1
    incidents = incidents_of(tenant)
    assert len(incidents) == 2
    newest = next(item for item in incidents if item["status"] == "OPEN")
    assert newest["event_count"] == 3


# Rule versions


def test_rule_change_creates_a_new_version_and_incidents_stay_traceable(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    attempt_forbidden_tool(agent, 3)
    correlate(world, tenant)
    first = incidents_of(tenant)[0]
    assert first["rule_version"] == 1
    _resolve(tenant, first)

    rules = tenant.get("/correlation-rules").json()["items"]
    current = next(item for item in rules if item["rule_key"] == "repeated_unauthorized_tools")
    changed = {**current["definition"], "threshold": 5}
    response = tenant.post(
        "/correlation-rules/repeated_unauthorized_tools/versions", {"definition": changed}
    )
    assert response.status_code == 201, response.text
    assert response.json()["version"] == 2
    assert tenant.audit_events("correlation.rule_version_created")
    assert tenant.get("/events", event_type="correlation.rule_changed").json()["total"] == 1

    attempt_forbidden_tool(agent, 4)
    assert correlate(world, tenant).incidents_created == 0
    attempt_forbidden_tool(agent, 1)
    assert correlate(world, tenant).incidents_created == 1

    second = next(item for item in incidents_of(tenant) if item["status"] == "OPEN")
    assert second["rule_version"] == 2
    assert second["rule_version_id"] != first["rule_version_id"]
    assert detail(tenant, first)["rule_version"] == 1
    assert detail(tenant, first)["rule_definition"]["threshold"] == 3
    assert detail(tenant, second)["rule_definition"]["threshold"] == 5


def test_disabled_rule_creates_nothing(world, tenant):
    tenant.allow_everything()
    rules = tenant.get("/correlation-rules").json()["items"]
    current = next(item for item in rules if item["rule_key"] == "repeated_unauthorized_tools")
    assert tenant.post(
        "/correlation-rules/repeated_unauthorized_tools/versions",
        {"definition": {**current["definition"], "enabled": False}},
    ).status_code == 201

    attempt_forbidden_tool(tenant.agent(), 3)
    correlate(world, tenant)
    assert incidents_of(tenant, rule_key="repeated_unauthorized_tools") == []


@pytest.mark.parametrize(
    "definition",
    [
        {"threshold": 0},
        {"window_seconds": -1},
        {"match": {"event_types": ["made.up"]}},
    ],
)
def test_invalid_rule_versions_are_rejected(tenant, definition):
    rules = tenant.get("/correlation-rules").json()["items"]
    current = next(item for item in rules if item["rule_key"] == "permission_probing")
    response = tenant.post(
        "/correlation-rules/permission_probing/versions",
        {"definition": {**current["definition"], **definition}},
    )
    assert response.status_code == 422


def test_unknown_rule_key_is_not_found(tenant):
    rules = tenant.get("/correlation-rules").json()["items"]
    response = tenant.post(
        "/correlation-rules/not_a_rule/versions", {"definition": rules[0]["definition"]}
    )
    assert response.status_code == 404


def test_only_admins_can_change_rules(tenant):
    rules = tenant.get("/correlation-rules").json()["items"]
    for headers in (tenant.reviewer, tenant.viewer):
        assert tenant.post(
            f"/correlation-rules/{rules[0]['rule_key']}/versions",
            {"definition": rules[0]["definition"]},
            headers=headers,
        ).status_code == 403


def test_rule_versions_are_immutable_for_the_runtime_role(world, tenant, db):
    tenant.get("/correlation-rules")
    for statement in (
        "UPDATE correlation_rule_versions SET definition_canonical = '{}'",
        "DELETE FROM correlation_rule_versions",
    ):
        with pytest.raises(ProgrammingError), db.tenant_transaction(tenant.id) as session:
            session.execute(text(statement))


def test_tampered_rule_stops_correlation_and_leaves_a_visible_backlog(
    world, tenant, attacker_sql
):
    tenant.allow_everything()
    tenant.get("/correlation-rules")
    attempt_forbidden_tool(tenant.agent(), 3)
    attacker_sql.execute("ALTER TABLE correlation_rule_versions DISABLE TRIGGER USER")
    try:
        attacker_sql.execute(
            """
            UPDATE correlation_rule_versions
            SET definition_canonical = replace(definition_canonical, '"threshold":3',
                                               '"threshold":1000000')
            WHERE tenant_id = %s AND rule_key = 'repeated_unauthorized_tools'
            """,
            (tenant.id,),
        )
    finally:
        attacker_sql.execute("ALTER TABLE correlation_rule_versions ENABLE TRIGGER USER")

    result = correlate(world, tenant)

    assert result.halted is True
    assert result.processed == 0
    assert incidents_of(tenant) == []
    assert tenant.get("/overview").json()["pending_correlation"] > 0


# Isolation


def test_events_in_different_tenants_never_correlate(world):
    a, b = world.tenant(), world.tenant()
    a.allow_everything()
    b.allow_everything()
    attempt_forbidden_tool(a.agent(), 2)
    attempt_forbidden_tool(b.agent(), 2)
    correlate(world, a)
    correlate(world, b)
    assert incidents_of(a) == []
    assert incidents_of(b) == []


def test_processing_one_tenant_leaves_the_other_pending(world):
    a, b = world.tenant(), world.tenant()
    a.allow_everything()
    b.allow_everything()
    attempt_forbidden_tool(a.agent(), 3)
    attempt_forbidden_tool(b.agent(), 3)

    correlate(world, a)

    assert len(incidents_of(a)) == 1
    assert incidents_of(b) == []
    assert b.get("/overview").json()["pending_correlation"] > 0


def test_tenant_a_cannot_read_tenant_b_incidents(world):
    a, b = world.tenant(), world.tenant()
    b.allow_everything()
    attempt_forbidden_tool(b.agent(), 3)
    correlate(world, b)
    incident = incidents_of(b)[0]

    assert incidents_of(a) == []
    assert a.get(f"/incidents/{incident['id']}").status_code == 404
    assert a.get(f"/incidents/{incident['id']}/events").status_code == 404
    assert a.get(f"/incidents/{incident['id']}/timeline").status_code == 404


def test_database_refuses_linking_another_tenants_event(world, db):
    a, b = world.tenant(), world.tenant()
    a.allow_everything()
    b.allow_everything()
    attempt_forbidden_tool(a.agent(), 3)
    correlate(world, a)
    attempt_forbidden_tool(b.agent(), 1)
    incident_id = incidents_of(a)[0]["id"]
    foreign_event = b.get("/events", event_type="gateway.action_denied").json()["items"][0]["id"]

    with pytest.raises(IntegrityError), db.tenant_transaction(a.id) as session:
        session.add(IncidentEvent(tenant_id=a.id, incident_id=incident_id, event_id=foreign_event))
        session.flush()


def test_pending_tenant_lookup_returns_only_ids_with_pending_events(world, db):
    busy, idle = world.tenant(), world.tenant()
    busy.allow_everything()
    attempt_forbidden_tool(busy.agent(), 1)
    tenants = pending_tenants(db)
    assert busy.id in tenants
    assert idle.id not in tenants


def test_links_and_incident_history_are_append_only(world, tenant, db):
    tenant.allow_everything()
    attempt_forbidden_tool(tenant.agent(), 3)
    correlate(world, tenant)
    for statement in (
        "DELETE FROM incident_events",
        "UPDATE incident_events SET linked_at = now()",
        "DELETE FROM incident_transitions",
        "UPDATE incident_transitions SET reason = 'forged'",
        "DELETE FROM incidents",
        "UPDATE incidents SET severity = 'low'",
        "UPDATE incidents SET rule_key = 'forged'",
    ):
        with pytest.raises(ProgrammingError), db.tenant_transaction(tenant.id) as session:
            session.execute(text(statement))


def test_incident_binding_is_protected_even_from_the_owner(world, tenant, urls):
    tenant.allow_everything()
    attempt_forbidden_tool(tenant.agent(), 3)
    correlate(world, tenant)
    owner = Database(urls.owner, pool_size=1, max_overflow=0)
    try:
        for statement in (
            "UPDATE incidents SET severity = 'low'",
            "UPDATE incidents SET rule_version = 99",
            "DELETE FROM incidents",
        ):
            with pytest.raises(DBAPIError), owner.tenant_transaction(tenant.id) as session:
                session.execute(text(statement))
    finally:
        owner.dispose()


# Correlation has no enforcement power


def test_incident_does_not_change_enforcement(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    attempt_forbidden_tool(agent, 3)
    correlate(world, tenant)
    assert len(incidents_of(tenant)) == 1

    body = agent.act("calculate", params=PARAMS).json()

    assert body["outcome"] == "ALLOW"
    assert world.spy.calls == ["calculate"]
    assert tenant.get(f"/agents/{agent.id}").json()["status"] == "active"


def test_a_correlation_outage_does_not_affect_enforcement(world, tenant, monkeypatch):
    import aegis.correlation.engine as engine

    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])

    def explode(*args, **kwargs):
        raise RuntimeError("synthetic correlation fault")

    monkeypatch.setattr(engine, "_apply_rule", explode)
    attempt_forbidden_tool(agent, 3)
    result = correlate(world, tenant)
    assert result.halted is True
    assert agent.act("calculate", params=PARAMS).json()["outcome"] == "ALLOW"
    monkeypatch.undo()

    correlate(world, tenant)
    assert len(incidents_of(tenant)) == 1


@pytest.mark.parametrize("package", ["correlation", "incidents", "investigation", "llm", "events"])
def test_analysis_modules_cannot_reach_enforcement_code(package):
    forbidden = (
        "aegis.gateway",
        "aegis.approvals",
        "aegis.policy",
        "aegis.registry",
    )
    directory = SOURCE_ROOT / package
    for path in directory.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert not name.startswith(forbidden), f"{path} imports {name}"


def test_incident_audit_events_do_not_feed_correlation(world, tenant):
    tenant.allow_everything()
    attempt_forbidden_tool(tenant.agent(), 3)
    correlate(world, tenant)
    before = tenant.get("/events").json()["total"]
    assert correlate(world, tenant).processed == 0
    assert tenant.get("/events").json()["total"] == before
    assert tenant.get("/overview").json()["pending_correlation"] == 0


def test_there_is_no_route_to_create_an_incident(tenant):
    assert tenant.post("/incidents", {"title": "forged"}).status_code == 405


def test_incident_reads_are_open_to_viewers_but_not_agents(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    attempt_forbidden_tool(agent, 3)
    correlate(world, tenant)
    assert tenant.get("/incidents", headers=tenant.viewer).status_code == 200
    assert tenant.client.get("/api/v1/incidents", headers=agent.headers).status_code == 401


def test_incident_filters_and_pagination(world, tenant):
    tenant.allow_everything()
    attempt_forbidden_tool(tenant.agent(), 3)
    attempt_forbidden_tool(tenant.agent(), 3)
    correlate(world, tenant)
    assert tenant.get("/incidents", limit=1).json()["total"] == 2
    assert len(tenant.get("/incidents", limit=1).json()["items"]) == 1
    assert tenant.get("/incidents", status="OPEN").json()["total"] == 2
    assert tenant.get("/incidents", status="CLOSED").json()["total"] == 0
    assert tenant.get("/incidents", severity="low").json()["total"] == 0
    assert tenant.get("/incidents", status="NOPE").status_code == 422
    assert tenant.get("/incidents", limit=101).status_code == 422


def test_events_show_their_incident(world, tenant):
    tenant.allow_everything()
    attempt_forbidden_tool(tenant.agent(), 3)
    correlate(world, tenant)
    incident = incidents_of(tenant)[0]
    denied = tenant.get("/events", event_type="gateway.action_denied").json()["items"]
    assert all(incident["id"] in item["incident_ids"] for item in denied)
    assert tenant.get(f"/events/{denied[0]['id']}").json()["incident_ids"] == [incident["id"]]


def test_the_worker_processes_events_without_being_asked(urls, jwt_key_path):
    from aegis.provisioning import provision_tenant
    from support import TenantWorld, ToolSpy

    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=urls.app,
        jwt_private_key_path=jwt_key_path,
        correlation_worker_enabled=True,
        correlation_poll_seconds=0.1,
    )
    app = create_app(settings, tools=ToolSpy().registry())
    with TestClient(app, raise_server_exceptions=False) as client:
        slug = f"t-{uuid4().hex[:16]}"
        tenant_id = provision_tenant(urls.owner, slug=slug, name="Synthetic")
        tenant = TenantWorld(client, urls, tenant_id, slug)
        tenant.allow_everything()
        attempt_forbidden_tool(tenant.agent(), 3)

        deadline = time.monotonic() + 15
        incidents = []
        while time.monotonic() < deadline and not incidents:
            incidents = incidents_of(tenant)
            time.sleep(0.1)

    assert len(incidents) == 1
