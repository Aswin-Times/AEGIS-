"""Investigations: every fact has real evidence, and gaps are stated rather than filled."""

import ast
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

import aegis
from aegis.correlation.engine import process_tenant
from aegis.db.models import (
    FindingEvidence,
    Incident,
    InvestigationFinding,
    InvestigationRun,
    SecurityEvent,
)
from aegis.db.session import Database
from aegis.investigation.evidence import (
    EvidenceError,
    EvidenceRef,
    add_finding,
    collect_evidence,
)

SOURCE_ROOT = Path(aegis.__file__).parent
PARAMS = {"operator": "add", "a": 1, "b": 2}
VERIFIED_KINDS = {"observed_fact", "rule_result"}


def correlate(world, tenant):
    container = world.app.state.container
    return process_tenant(container.db, tenant.id, clock=container.clock)


def make_incident(world, tenant, agent=None, count=3):
    tenant.allow_everything()
    agent = agent or tenant.agent(tools=["calculate"])
    denials = [agent.act("run_shell_command").json() for _ in range(count)]
    correlate(world, tenant)
    incident = tenant.get("/incidents", rule_key="repeated_unauthorized_tools").json()["items"][0]
    return incident, agent, denials


def investigate(tenant, incident, headers=None):
    response = tenant.post(
        f"/incidents/{incident['id']}/investigation-runs", {}, headers=headers or tenant.reviewer
    )
    assert response.status_code == 201, response.text
    return response.json()


def findings_of(tenant, incident, **params):
    response = tenant.get(f"/incidents/{incident['id']}/findings", **params)
    assert response.status_code == 200, response.text
    return response.json()


def of_kind(findings, kind):
    return [item for item in findings["findings"] if item["kind"] == kind]


def timeline_of(tenant, incident):
    response = tenant.get(f"/incidents/{incident['id']}/timeline")
    assert response.status_code == 200, response.text
    return response.json()["items"]


# Timeline


def test_timeline_is_reconstructed_from_stored_records(world, tenant):
    incident, _, denials = make_incident(world, tenant)
    items = timeline_of(tenant, incident)

    times = [item["occurred_at"] for item in items]
    assert times == sorted(times)
    by_type = {}
    for item in items:
        by_type.setdefault(item["evidence"]["type"], []).append(item["evidence"]["id"])
    assert set(by_type["policy_decision"]) == {denial["decision_id"] for denial in denials}
    assert len(by_type["security_event"]) == 3
    assert "execution" not in by_type
    assert any(
        item["kind"] == "incident.created" and item["evidence"]["type"] == "audit_event"
        for item in items
    )


def test_every_timeline_entry_links_to_a_readable_record(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    for item in timeline_of(tenant, incident):
        evidence = item["evidence"]
        response = tenant.get(f"/evidence/{evidence['type']}/{evidence['id']}")
        assert response.status_code == 200, evidence
        assert response.json()["id"] == evidence["id"]
        assert response.json()["type"] == evidence["type"]


def test_timeline_includes_approvals_and_executions(world, tenant):
    tenant.hold_tool("calculate")
    agent = tenant.agent(tools=["calculate"])
    body = agent.act("calculate", params=PARAMS).json()
    for _ in range(3):
        agent.execute(body["request_id"])
    tenant.post(f"/approvals/{body['approval_id']}/approve", {}, headers=tenant.reviewer)
    assert agent.execute(body["request_id"]).status_code == 200
    correlate(world, tenant)
    incident = tenant.get("/incidents", rule_key="approval_bypass_attempts").json()["items"][0]

    types = {item["evidence"]["type"] for item in timeline_of(tenant, incident)}
    assert {"security_event", "approval", "execution", "audit_event"} <= types


def test_timeline_and_evidence_exclude_sensitive_content(world, tenant):
    tenant.allow_everything()
    document = tenant.document("sensitive", content={"marker": "doc-content-marker"})
    destination = tenant.destination(clearance="public")
    agent = tenant.agent(tools=["send_message", "read_document"], resources=[destination, document])
    agent.act("read_document", document)
    for _ in range(2):
        agent.act(
            "send_message",
            destination,
            {"body": "message-body-marker", "attachment_resource_id": document},
        )
    correlate(world, tenant)
    incident = tenant.get("/incidents", rule_key="repeated_transfer_denials").json()["items"][0]
    investigate(tenant, incident)

    seen = [tenant.get(f"/incidents/{incident['id']}/timeline").text]
    seen.append(tenant.get(f"/incidents/{incident['id']}/findings").text)
    for item in timeline_of(tenant, incident):
        evidence = item["evidence"]
        seen.append(tenant.get(f"/evidence/{evidence['type']}/{evidence['id']}").text)
    combined = " ".join(seen)
    assert "doc-content-marker" not in combined
    assert "message-body-marker" not in combined


def test_execution_evidence_omits_the_tool_result(world, tenant):
    tenant.allow_everything()
    document = tenant.document(content={"marker": "result-marker"})
    agent = tenant.agent(tools=["read_document"], resources=[document])
    body = agent.act("read_document", document).json()
    events = tenant.get("/events", event_type="execution.succeeded").json()["items"]
    assert events[0]["correlation_id"] == body["request_id"]

    response = tenant.get(f"/evidence/execution/{events[0]['execution_id']}")

    assert response.status_code == 200
    assert "result-marker" not in response.text
    assert response.json()["fields"]["status"] == "SUCCEEDED"


# Findings


def test_investigation_works_without_any_llm_provider(world, tenant):
    assert world.app.state.container.llm is None
    incident, _, _ = make_incident(world, tenant)

    run = investigate(tenant, incident)

    assert run["llm_status"] == "not_configured"
    findings = findings_of(tenant, incident)
    assert of_kind(findings, "observed_fact")
    assert of_kind(findings, "rule_result")
    assert of_kind(findings, "evidence_gap")
    assert of_kind(findings, "recommended_action")
    assert of_kind(findings, "ai_hypothesis") == []


def test_every_verified_finding_cites_real_evidence(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    investigate(tenant, incident)
    findings = findings_of(tenant, incident)
    verified = [item for item in findings["findings"] if item["kind"] in VERIFIED_KINDS]
    assert verified
    for finding in verified:
        assert finding["verified"] is True
        assert finding["source"] == "deterministic"
        assert finding["evidence"], finding["statement"]
        for ref in finding["evidence"]:
            assert tenant.get(f"/evidence/{ref['type']}/{ref['id']}").status_code == 200


def test_rule_result_states_the_exact_rule_version(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    investigate(tenant, incident)
    results = of_kind(findings_of(tenant, incident), "rule_result")
    assert len(results) == 1
    statement = results[0]["statement"]
    assert "repeated_unauthorized_tools" in statement
    assert "version 1" in statement
    assert "3" in statement and "300" in statement


def test_denied_actions_are_stated_as_not_executed(world, tenant):
    incident, _, denials = make_incident(world, tenant)
    investigate(tenant, incident)
    facts = of_kind(findings_of(tenant, incident), "observed_fact")
    not_run = [item for item in facts if "no execution record" in item["statement"].lower()]
    assert len(not_run) == 1
    cited = {ref["id"] for ref in not_run[0]["evidence"] if ref["type"] == "policy_decision"}
    assert cited == {denial["decision_id"] for denial in denials}


def test_denied_transfer_is_not_presented_as_exposure(world, tenant):
    tenant.allow_everything()
    sensitive = tenant.document("sensitive")
    destination = tenant.destination(clearance="public")
    agent = tenant.agent(tools=["send_message"], resources=[destination, sensitive])
    for _ in range(2):
        agent.act("send_message", destination, {"body": "x", "attachment_resource_id": sensitive})
    correlate(world, tenant)
    incident = tenant.get("/incidents", rule_key="repeated_transfer_denials").json()["items"][0]

    investigate(tenant, incident)

    findings = findings_of(tenant, incident)
    for fact in of_kind(findings, "observed_fact"):
        assert "exposed" not in fact["statement"].lower()
        assert "leaked" not in fact["statement"].lower()
    gaps = " ".join(item["statement"] for item in of_kind(findings, "evidence_gap"))
    assert "does not show whether data left" in gaps


def test_not_visible_rule_states_it_cannot_confirm_another_tenant(world):
    attacker, victim = world.tenant(), world.tenant()
    attacker.allow_everything()
    agent = attacker.agent(tools=["read_document"])
    for _ in range(3):
        agent.act("read_document", victim.document())
    correlate(world, attacker)
    incident = attacker.get("/incidents", rule_key="not_visible_references").json()["items"][0]

    investigate(attacker, incident)

    gaps = " ".join(
        item["statement"] for item in of_kind(findings_of(attacker, incident), "evidence_gap")
    )
    assert "cannot confirm" in gaps.lower()
    assert str(victim.id) not in str(findings_of(attacker, incident))
    assert victim.slug not in str(findings_of(attacker, incident))


def test_unknown_intent_is_stated_as_a_gap(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    investigate(tenant, incident)
    gaps = " ".join(item["statement"] for item in of_kind(findings_of(tenant, incident),
                                                          "evidence_gap"))
    assert "why" in gaps.lower()
    assert "gateway" in gaps.lower()


def test_recommendations_are_not_verified_and_change_nothing(world, tenant):
    incident, agent, _ = make_incident(world, tenant)
    investigate(tenant, incident)
    for item in of_kind(findings_of(tenant, incident), "recommended_action"):
        assert item["verified"] is False
    assert tenant.get(f"/agents/{agent.id}").json()["status"] == "active"
    assert tenant.get(f"/incidents/{incident['id']}").json()["status"] == "OPEN"
    assert tenant.get(f"/agents/{agent.id}").json()["tool_grants"] == ["calculate"]


def test_runs_over_the_same_evidence_are_identical(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    first = investigate(tenant, incident)
    second = investigate(tenant, incident)

    assert first["id"] != second["id"]
    assert first["input_fingerprint"] == second["input_fingerprint"]

    def statements(run):
        return [
            (item["kind"], item["statement"], item["evidence"])
            for item in findings_of(tenant, incident, run_id=run["id"])["findings"]
        ]

    assert statements(first) == statements(second)


def test_new_evidence_changes_the_fingerprint_and_keeps_old_runs(world, tenant):
    incident, agent, _ = make_incident(world, tenant)
    first = investigate(tenant, incident)
    before = findings_of(tenant, incident, run_id=first["id"])
    agent.act("run_shell_command")
    correlate(world, tenant)

    second = investigate(tenant, incident)

    assert first["input_fingerprint"] != second["input_fingerprint"]
    assert findings_of(tenant, incident, run_id=first["id"]) == before
    assert findings_of(tenant, incident)["run"]["id"] == second["id"]


def test_latest_run_is_returned_and_no_run_is_handled(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    empty = findings_of(tenant, incident)
    assert empty["run"] is None
    assert empty["findings"] == []
    run = investigate(tenant, incident)
    assert findings_of(tenant, incident)["run"]["id"] == run["id"]
    assert tenant.get(f"/incidents/{incident['id']}/investigation-runs").json()["total"] == 1


def test_run_from_another_incident_is_not_found(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    run = investigate(tenant, incident)
    other = {"id": str(uuid4())}
    assert tenant.get(
        f"/incidents/{other['id']}/findings", run_id=run["id"]
    ).status_code == 404
    assert tenant.get(
        f"/incidents/{incident['id']}/findings", run_id=str(uuid4())
    ).status_code == 404


def test_investigating_does_not_change_the_incident(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    before = tenant.get(f"/incidents/{incident['id']}").json()
    investigate(tenant, incident)
    assert tenant.get(f"/incidents/{incident['id']}").json() == before


def test_investigation_is_audited(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    run = investigate(tenant, incident)
    events = tenant.audit_events("investigation.completed")
    assert len(events) == 1
    assert events[0]["subject_id"] == run["id"]
    assert events[0]["payload"]["incident_id"] == incident["id"]
    assert events[0]["payload"]["input_fingerprint"] == run["input_fingerprint"]
    assert tenant.verify_audit()["valid"] is True


def test_investigation_does_not_feed_correlation(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    investigate(tenant, incident)
    assert tenant.get("/overview").json()["pending_correlation"] == 0


# Tampering


def _tamper_event(attacker_sql, event_id):
    attacker_sql.execute("ALTER TABLE security_events DISABLE TRIGGER USER")
    try:
        attacker_sql.execute(
            "UPDATE security_events SET reason_code = 'FORGED_REASON' WHERE id = %s", (event_id,)
        )
    finally:
        attacker_sql.execute("ALTER TABLE security_events ENABLE TRIGGER USER")


def test_a_tampered_event_is_reported_and_not_used_as_fact(world, tenant, attacker_sql):
    incident, _, _ = make_incident(world, tenant)
    events = tenant.get(f"/incidents/{incident['id']}/events").json()["items"]
    tampered = events[0]["id"]
    _tamper_event(attacker_sql, tampered)

    investigate(tenant, incident)

    findings = findings_of(tenant, incident)
    for fact in of_kind(findings, "observed_fact") + of_kind(findings, "rule_result"):
        assert tampered not in [ref["id"] for ref in fact["evidence"]]
        assert "FORGED_REASON" not in fact["statement"]
    gaps = of_kind(findings, "evidence_gap")
    flagged = [item for item in gaps if tampered in [ref["id"] for ref in item["evidence"]]]
    assert len(flagged) == 1
    assert "failed verification" in flagged[0]["statement"]


def test_a_tampered_audit_chain_is_reported(world, tenant, attacker_sql):
    incident, _, _ = make_incident(world, tenant)
    attacker_sql.execute("ALTER TABLE audit_events DISABLE TRIGGER USER")
    try:
        attacker_sql.execute(
            "UPDATE audit_events SET payload = '{\"forged\": true}' "
            "WHERE tenant_id = %s AND seq = 1",
            (tenant.id,),
        )
    finally:
        attacker_sql.execute("ALTER TABLE audit_events ENABLE TRIGGER USER")

    investigate(tenant, incident)

    gaps = " ".join(item["statement"] for item in of_kind(findings_of(tenant, incident),
                                                          "evidence_gap"))
    assert "audit chain failed verification" in gaps.lower()


def test_tampered_rule_is_reported_and_incident_stays_readable(world, tenant, attacker_sql):
    incident, _, _ = make_incident(world, tenant)
    attacker_sql.execute("ALTER TABLE correlation_rule_versions DISABLE TRIGGER USER")
    try:
        attacker_sql.execute(
            "UPDATE correlation_rule_versions SET content_hash = %s WHERE id = %s",
            ("0" * 64, incident["rule_version_id"]),
        )
    finally:
        attacker_sql.execute("ALTER TABLE correlation_rule_versions ENABLE TRIGGER USER")

    detail = tenant.get(f"/incidents/{incident['id']}")
    assert detail.status_code == 200
    assert detail.json()["rule_definition"] is None

    investigate(tenant, incident)
    findings = findings_of(tenant, incident)
    assert of_kind(findings, "rule_result") == []
    assert "rule" in " ".join(item["statement"] for item in of_kind(findings, "evidence_gap"))


def test_execution_stuck_in_started_is_a_gap_not_an_outcome(world, tenant, attacker_sql):
    tenant.hold_tool("calculate")
    agent = tenant.agent(tools=["calculate"])
    body = agent.act("calculate", params=PARAMS).json()
    for _ in range(3):
        agent.execute(body["request_id"])
    tenant.post(f"/approvals/{body['approval_id']}/approve", {}, headers=tenant.reviewer)
    agent.execute(body["request_id"])
    attacker_sql.execute("ALTER TABLE executions DISABLE TRIGGER USER")
    try:
        attacker_sql.execute(
            "UPDATE executions SET status = 'STARTED', finished_at = NULL WHERE request_id = %s",
            (body["request_id"],),
        )
    finally:
        attacker_sql.execute("ALTER TABLE executions ENABLE TRIGGER USER")
    correlate(world, tenant)
    incident = tenant.get("/incidents", rule_key="approval_bypass_attempts").json()["items"][0]

    investigate(tenant, incident)

    findings = findings_of(tenant, incident)
    gaps = " ".join(item["statement"] for item in of_kind(findings, "evidence_gap"))
    assert "no recorded outcome" in gaps
    facts = " ".join(item["statement"] for item in of_kind(findings, "observed_fact"))
    assert "succeeded" not in facts.lower()


# Evidence validation


def _collected(db, tenant, incident):
    return db.tenant_transaction(tenant.id), incident["id"]


def test_evidence_set_contains_only_this_incidents_records(world, db):
    tenant = world.tenant()
    incident, _, denials = make_incident(world, tenant)
    with db.tenant_transaction(tenant.id) as session:
        evidence = collect_evidence(session, session.get(Incident, incident["id"]))
        refs = evidence.allowed_refs
    assert EvidenceRef("policy_decision", denials[0]["decision_id"]) in refs
    assert EvidenceRef("policy_decision", str(uuid4())) not in refs


def _run_row(session, tenant_id, incident_id):
    run = InvestigationRun(
        id=uuid4(),
        tenant_id=tenant_id,
        incident_id=incident_id,
        started_by=None,
        engine_version=1,
        input_fingerprint="0" * 64,
        llm_status="not_configured",
        llm_rejected_count=0,
    )
    session.add(run)
    session.flush()
    return run


def _add(session, tenant, incident, refs, kind="observed_fact", source="deterministic",
         statement="Synthetic statement"):
    entity = session.get(Incident, incident["id"])
    evidence = collect_evidence(session, entity)
    run = _run_row(session, tenant.id, entity.id)
    return add_finding(session, run, evidence.allowed_refs, kind=kind, source=source,
                       statement=statement, refs=refs, position=0)


def test_nonexistent_evidence_is_rejected(world, db, tenant):
    incident, _, _ = make_incident(world, tenant)
    with pytest.raises(EvidenceError), db.tenant_transaction(tenant.id) as session:
        _add(session, tenant, incident, [EvidenceRef("security_event", str(uuid4()))])


def test_evidence_from_another_tenant_is_rejected(world, db):
    a, b = world.tenant(), world.tenant()
    incident_a, _, _ = make_incident(world, a)
    _, _, denials_b = make_incident(world, b)
    foreign = EvidenceRef("policy_decision", denials_b[0]["decision_id"])
    with pytest.raises(EvidenceError), db.tenant_transaction(a.id) as session:
        _add(session, a, incident_a, [foreign])


def test_evidence_from_another_incident_in_this_tenant_is_rejected(world, db, tenant):
    tenant.allow_everything()
    first = tenant.agent()
    second = tenant.agent()
    denials = [first.act("run_shell_command").json() for _ in range(3)]
    for _ in range(3):
        second.act("run_shell_command")
    correlate(world, tenant)
    items = tenant.get("/incidents", rule_key="repeated_unauthorized_tools").json()["items"]
    other = next(item for item in items if item["agent_id"] == second.id)
    foreign = EvidenceRef("policy_decision", denials[0]["decision_id"])
    with pytest.raises(EvidenceError), db.tenant_transaction(tenant.id) as session:
        _add(session, tenant, other, [foreign])


def test_a_fact_without_evidence_is_rejected(world, db, tenant):
    incident, _, _ = make_incident(world, tenant)
    for kind in ("observed_fact", "rule_result"):
        with pytest.raises(EvidenceError), db.tenant_transaction(tenant.id) as session:
            _add(session, tenant, incident, [], kind=kind)


def test_a_hypothesis_cannot_be_recorded_as_deterministic_or_a_fact_as_llm(world, db, tenant):
    incident, _, denials = make_incident(world, tenant)
    ref = EvidenceRef("policy_decision", denials[0]["decision_id"])
    for kind, source in (("ai_hypothesis", "deterministic"), ("observed_fact", "llm"),
                         ("rule_result", "llm"), ("recommended_action", "llm")):
        with pytest.raises(EvidenceError), db.tenant_transaction(tenant.id) as session:
            _add(session, tenant, incident, [ref], kind=kind, source=source)


def _finding_row(session, tenant_id, run_id, kind="observed_fact", source="deterministic"):
    finding = InvestigationFinding(
        id=uuid4(),
        tenant_id=tenant_id,
        run_id=run_id,
        kind=kind,
        source=source,
        statement="Direct insert",
        position=0,
    )
    session.add(finding)
    session.flush()
    return finding


def test_database_refuses_a_fact_with_no_evidence_at_commit(world, db, tenant):
    incident, _, _ = make_incident(world, tenant)
    with pytest.raises(DBAPIError, match="requires evidence"):
        with db.tenant_transaction(tenant.id) as session:
            run = _run_row(session, tenant.id, incident["id"])
            _finding_row(session, tenant.id, run.id)


def test_database_refuses_llm_output_stored_as_fact(world, db, tenant):
    incident, _, _ = make_incident(world, tenant)
    with pytest.raises(IntegrityError):
        with db.tenant_transaction(tenant.id) as session:
            run = _run_row(session, tenant.id, incident["id"])
            _finding_row(session, tenant.id, run.id, source="llm")


def _evidence_row(session, tenant_id, finding_id, **columns):
    session.add(FindingEvidence(id=uuid4(), tenant_id=tenant_id, finding_id=finding_id, **columns))
    session.flush()


def test_database_refuses_evidence_that_does_not_exist(world, db, tenant):
    incident, _, _ = make_incident(world, tenant)
    with pytest.raises(IntegrityError), db.tenant_transaction(tenant.id) as session:
        run = _run_row(session, tenant.id, incident["id"])
        finding = _finding_row(session, tenant.id, run.id, kind="evidence_gap")
        _evidence_row(session, tenant.id, finding.id, security_event_id=uuid4())


def test_database_refuses_evidence_from_another_tenant(world, db):
    a, b = world.tenant(), world.tenant()
    incident_a, _, _ = make_incident(world, a)
    _, _, denials_b = make_incident(world, b)
    with pytest.raises(IntegrityError), db.tenant_transaction(a.id) as session:
        run = _run_row(session, a.id, incident_a["id"])
        finding = _finding_row(session, a.id, run.id, kind="evidence_gap")
        _evidence_row(session, a.id, finding.id, decision_id=denials_b[0]["decision_id"])


def test_database_refuses_a_reference_to_two_records_at_once(world, db, tenant):
    incident, _, denials = make_incident(world, tenant)
    with db.tenant_transaction(tenant.id) as session:
        event_id = session.execute(
            select(SecurityEvent.id).where(SecurityEvent.decision_id == denials[0]["decision_id"])
        ).scalar_one()
    with pytest.raises(IntegrityError), db.tenant_transaction(tenant.id) as session:
        run = _run_row(session, tenant.id, incident["id"])
        finding = _finding_row(session, tenant.id, run.id, kind="evidence_gap")
        _evidence_row(session, tenant.id, finding.id, security_event_id=event_id,
                      decision_id=denials[0]["decision_id"])


def test_findings_are_append_only(world, db, tenant):
    incident, _, _ = make_incident(world, tenant)
    investigate(tenant, incident)
    for statement in (
        "UPDATE investigation_findings SET statement = 'forged'",
        "UPDATE investigation_findings SET kind = 'observed_fact'",
        "DELETE FROM investigation_findings",
        "DELETE FROM finding_evidence",
        "UPDATE finding_evidence SET security_event_id = NULL",
        "DELETE FROM investigation_runs",
        "UPDATE investigation_runs SET input_fingerprint = 'forged'",
    ):
        with pytest.raises(ProgrammingError), db.tenant_transaction(tenant.id) as session:
            session.execute(text(statement))


def test_owner_cannot_rewrite_findings(world, tenant, urls):
    incident, _, _ = make_incident(world, tenant)
    investigate(tenant, incident)
    owner = Database(urls.owner, pool_size=1, max_overflow=0)
    try:
        for statement in (
            "UPDATE investigation_findings SET statement = 'forged'",
            "DELETE FROM investigation_findings",
            "DELETE FROM finding_evidence",
        ):
            with pytest.raises(DBAPIError), owner.tenant_transaction(tenant.id) as session:
                session.execute(text(statement))
    finally:
        owner.dispose()


# Evidence route and access


@pytest.mark.parametrize(
    "kind", ["security_event", "policy_decision", "approval", "execution", "audit_event"]
)
def test_evidence_route_is_tenant_isolated(world, kind):
    a = world.tenant()
    assert a.get(f"/evidence/{kind}/{uuid4()}").status_code == 404


def test_another_tenants_evidence_is_not_found(world):
    a, b = world.tenant(), world.tenant()
    _, _, denials = make_incident(world, b)
    assert a.get(f"/evidence/policy_decision/{denials[0]['decision_id']}").status_code == 404


def test_unknown_evidence_type_is_rejected(tenant):
    assert tenant.get(f"/evidence/users/{uuid4()}").status_code == 422


def test_only_reviewers_and_admins_can_run_an_investigation(world, tenant):
    incident, agent, _ = make_incident(world, tenant)
    path = f"/incidents/{incident['id']}/investigation-runs"
    assert tenant.post(path, {}, headers=tenant.viewer).status_code == 403
    assert tenant.client.post(f"/api/v1{path}", json={}, headers=agent.headers).status_code == 401
    assert tenant.client.post(f"/api/v1{path}", json={}).status_code == 401
    assert tenant.post(path, {}, headers=tenant.admin).status_code == 201


def test_another_tenant_cannot_investigate_or_read_findings(world):
    a, b = world.tenant(), world.tenant()
    incident, _, _ = make_incident(world, b)
    investigate(b, incident)
    path = f"/incidents/{incident['id']}"
    assert a.post(f"{path}/investigation-runs", {}).status_code == 404
    assert a.get(f"{path}/findings").status_code == 404
    assert a.get(f"{path}/investigation-runs").status_code == 404


def test_viewers_can_read_findings_and_timeline(world, tenant):
    incident, _, _ = make_incident(world, tenant)
    investigate(tenant, incident)
    headers = tenant.viewer
    assert tenant.get(f"/incidents/{incident['id']}/findings", headers=headers).status_code == 200
    assert tenant.get(f"/incidents/{incident['id']}/timeline", headers=headers).status_code == 200


def test_investigation_code_cannot_change_incidents():
    forbidden = {"aegis.incidents.service", "aegis.gateway", "aegis.registry", "aegis.approvals"}
    for path in (SOURCE_ROOT / "investigation").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not any(node.module.startswith(name) for name in forbidden), path
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                assert not (node.value.id == "incident" and node.attr == "severity" and
                            isinstance(getattr(node, "ctx", None), ast.Store)), path
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        assert target.attr not in {"status", "severity"} or not (
                            isinstance(target.value, ast.Name) and target.value.id == "incident"
                        ), path
