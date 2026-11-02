"""Security events: trusted sources only, minimal content, append-only, tenant-isolated."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

import aegis.audit.chain as chain
from aegis.audit.chain import append_event
from aegis.config import Settings
from aegis.db.bootstrap import ensure_roles_and_database, run_migrations
from aegis.db.models import AuditEvent, SecurityEvent
from aegis.db.session import Database
from aegis.events.backfill import backfill_tenant
from aegis.events.projection import project_audit_event, reprojection_matches
from aegis.events.schema import SecurityEventRecord
from aegis.provisioning import create_user, provision_tenant
from aegis.security.agent_keys import format_key, parse_key
from aegis.security.tokens import TokenService
from support import PASSWORD, bearer

PARAMS = {"operator": "add", "a": 1, "b": 2}


def events_of(tenant, event_type=None):
    params = {"limit": 100}
    if event_type:
        params["event_type"] = event_type
    response = tenant.get("/events", **params)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def test_denied_action_produces_a_structured_event(tenant):
    version = tenant.allow_everything()
    document = tenant.document()
    agent = tenant.agent(resources=[document])

    body = agent.act("read_document", document).json()

    events = events_of(tenant, "gateway.action_denied")
    assert len(events) == 1
    event = events[0]
    assert event["reason_code"] == "TOOL_NOT_GRANTED"
    assert event["severity"] == "medium"
    assert event["schema_version"] == 1
    assert event["actor_type"] == "agent"
    assert event["actor_id"] == agent.id
    assert event["agent_id"] == agent.id
    assert event["agent_name"]
    assert event["asset_id"] == tenant.get(f"/agents/{agent.id}").json()["asset_id"]
    assert event["tool"] == "read_document"
    assert event["action"] == "read"
    assert event["resource_id"] == document
    assert event["decision_id"] == body["decision_id"]
    assert event["action_request_id"] == body["request_id"]
    assert event["correlation_id"] == body["request_id"]
    assert event["execution_id"] is None
    assert event["occurred_at"] and event["recorded_at"]
    assert version["id"] == body["policy_version_id"]

    source = [a for a in tenant.audit_events("action.decision")
              if a["id"] == event["source_audit_event_id"]]
    assert len(source) == 1
    assert event["source_event_hash"] == source[0]["event_hash"]


def test_allowed_action_records_the_outcome_but_no_denial(tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    body = agent.act("calculate", params=PARAMS).json()

    assert events_of(tenant, "gateway.action_denied") == []
    succeeded = events_of(tenant, "execution.succeeded")
    assert len(succeeded) == 1
    assert succeeded[0]["correlation_id"] == body["request_id"]
    assert succeeded[0]["execution_id"]
    assert succeeded[0]["severity"] == "info"


def test_failed_execution_is_recorded(tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    agent.act("calculate", params={"operator": "divide", "a": 1, "b": 0})
    failed = events_of(tenant, "execution.failed")
    assert len(failed) == 1
    assert failed[0]["reason_code"] == "TOOL_FAILURE"


def test_approval_required_and_rejection_are_recorded(tenant):
    tenant.hold_tool("calculate")
    agent = tenant.agent(tools=["calculate"])
    body = agent.act("calculate", params=PARAMS).json()
    assert len(events_of(tenant, "gateway.approval_required")) == 1

    tenant.post(f"/approvals/{body['approval_id']}/reject", {}, headers=tenant.reviewer)

    rejected = events_of(tenant, "approval.rejected")
    assert len(rejected) == 1
    assert rejected[0]["approval_id"] == body["approval_id"]
    assert rejected[0]["agent_id"] == agent.id
    assert rejected[0]["actor_type"] == "user"


def test_expired_approval_is_recorded(world, tenant):
    tenant.hold_tool("calculate")
    agent = tenant.agent(tools=["calculate"])
    body = agent.act("calculate", params=PARAMS).json()
    reviewer = tenant.reviewer
    later = datetime.now(UTC) + timedelta(days=2)
    world.app.state.container.clock = lambda: later

    tenant.post(f"/approvals/{body['approval_id']}/approve", {}, headers=reviewer)

    expired = events_of(tenant, "approval.expired")
    assert len(expired) == 1
    assert expired[0]["reason_code"] == "APPROVAL_EXPIRED"


@pytest.mark.parametrize(
    "setup, reason",
    [
        ("pending", "APPROVAL_PENDING"),
        ("rejected", "APPROVAL_REJECTED"),
        ("used", "APPROVAL_ALREADY_USED"),
        ("none", "NO_APPROVAL"),
    ],
)
def test_execution_without_a_valid_approval_is_recorded(world, tenant, setup, reason):
    if setup == "none":
        tenant.allow_everything()
        agent = tenant.agent()
        request_id = agent.act("calculate", params=PARAMS).json()["request_id"]
    else:
        tenant.hold_tool("calculate")
        agent = tenant.agent(tools=["calculate"])
        body = agent.act("calculate", params=PARAMS).json()
        request_id = body["request_id"]
        if setup == "rejected":
            tenant.post(f"/approvals/{body['approval_id']}/reject", {}, headers=tenant.reviewer)
        if setup == "used":
            tenant.post(f"/approvals/{body['approval_id']}/approve", {}, headers=tenant.reviewer)
            assert agent.execute(request_id).status_code == 200

    assert agent.execute(request_id).status_code == 409

    refused = events_of(tenant, "gateway.execution_refused")
    assert len(refused) == 1
    assert refused[0]["reason_code"] == reason
    assert refused[0]["agent_id"] == agent.id
    assert refused[0]["correlation_id"] == request_id


def test_policy_and_agent_changes_are_recorded(tenant):
    tenant.allow_everything()
    assert len(events_of(tenant, "policy.activated")) == 1
    assert len(events_of(tenant, "policy.version_created")) == 1

    agent = tenant.agent(tools=["calculate"])
    tenant.post(f"/agents/{agent.id}/status", {"status": "disabled"})

    changed = events_of(tenant, "agent.status_changed")
    assert len(changed) == 1
    assert changed[0]["agent_id"] == agent.id
    assert changed[0]["attributes"] == {"status": "disabled"}
    assert len(events_of(tenant, "grant.changed")) == 1
    assert len(events_of(tenant, "credential.changed")) == 1


def test_administrative_authorization_failure_is_recorded(tenant):
    viewer = tenant.viewer
    me = tenant.get("/auth/me", headers=viewer).json()

    assert tenant.post("/policies", {"name": "x"}, headers=viewer).status_code == 403

    denied = events_of(tenant, "authz.denied")
    assert len(denied) == 1
    assert denied[0]["actor_type"] == "user"
    assert denied[0]["actor_id"] == me["id"]
    assert denied[0]["reason_code"] == "ROLE_NOT_PERMITTED"


def test_authentication_failures_are_recorded_without_secrets(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    parsed = parse_key(agent.key)
    world.client.post(
        "/api/v1/gateway/actions",
        headers=bearer(format_key(parsed.tenant_id, parsed.credential_id, "attempted-secret")),
        json={"idempotency_key": "k", "tool": "calculate", "resource_id": None, "params": PARAMS},
    )
    _ = tenant.admin
    world.client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": tenant.slug,
            "email": f"admin@{tenant.slug}.example.test",
            "password": "attempted-password",
        },
    )

    agent_failed = events_of(tenant, "auth.agent_failed")
    login_failed = events_of(tenant, "auth.login_failed")
    assert len(agent_failed) == 1
    assert len(login_failed) == 1
    assert agent_failed[0]["actor_type"] == "anonymous"
    combined = str(agent_failed) + str(login_failed)
    assert "attempted-secret" not in combined
    assert "attempted-password" not in combined
    assert tenant.slug not in combined


def test_signed_token_for_a_user_absent_from_its_tenant_is_recorded(
    world, tenant, jwt_key_path, urls
):
    other = world.tenant()
    other_user = other.get("/auth/me").json()["id"]
    signer = TokenService(
        Settings(
            _env_file=None,
            environment="test",
            database_url=urls.app,
            jwt_private_key_path=jwt_key_path,
        )
    )
    token = signer.issue(user_id=other_user, tenant_id=tenant.id)

    assert tenant.get("/auth/me", headers=bearer(token)).status_code == 401

    rejected = events_of(tenant, "auth.token_rejected")
    assert len(rejected) == 1
    assert rejected[0]["severity"] == "high"
    assert other_user not in str(rejected[0].get("actor_id"))
    assert events_of(other, "auth.token_rejected") == []


def test_reference_to_an_id_not_visible_is_recorded_without_touching_the_owner(world):
    attacker, victim = world.tenant(), world.tenant()
    victim_agent = victim.agent()
    before = len(events_of(victim))

    assert attacker.get(f"/agents/{victim_agent.id}").status_code == 404

    recorded = events_of(attacker, "access.not_visible")
    assert len(recorded) == 1
    assert recorded[0]["actor_type"] == "user"
    assert recorded[0]["resource_id"] == victim_agent.id
    assert recorded[0]["reason_code"] == "NOT_VISIBLE"
    assert victim_agent.key not in str(recorded[0])
    assert len(events_of(victim)) == before


def test_agent_reference_to_another_tenants_resource_is_flagged(world):
    attacker, victim = world.tenant(), world.tenant()
    attacker.allow_everything()
    secret = victim.document("sensitive", content={"marker": "victim-secret"})
    agent = attacker.agent(tools=["read_document"])

    agent.act("read_document", secret)

    denied = events_of(attacker, "gateway.action_denied")
    assert len(denied) == 1
    assert denied[0]["reason_code"] == "RESOURCE_NOT_FOUND"
    assert denied[0]["attributes"] == {"not_visible_reference": True}
    assert "victim-secret" not in str(denied[0])
    assert "sensitive" not in str(denied[0])


def test_events_contain_no_sensitive_content(world, tenant, attacker_sql):
    tenant.allow_everything()
    document = tenant.document("sensitive", content={"marker": "doc-content-marker"})
    destination = tenant.destination(clearance="sensitive")
    agent = tenant.agent(tools=["read_document", "send_message"], resources=[document, destination])
    agent.act("read_document", document)
    agent.act("send_message", destination, {"body": "message-body-marker"})
    tenant.hold_tool("calculate")
    agent2 = tenant.agent(tools=["calculate"])
    held = agent2.act("calculate", params={"operator": "add", "a": 123456, "b": 654321}).json()
    tenant.post(
        f"/approvals/{held['approval_id']}/reject",
        {"comment": "comment-marker"},
        headers=tenant.reviewer,
    )

    rows = attacker_sql.execute(
        "SELECT to_jsonb(e)::text FROM security_events e WHERE tenant_id = %s", (tenant.id,)
    ).fetchall()
    assert rows
    text_of_rows = " ".join(row[0] for row in rows)
    for marker in ("doc-content-marker", "message-body-marker", "comment-marker", "123456",
                   f"admin@{tenant.slug}"):
        assert marker not in text_of_rows


def test_there_is_no_route_for_submitting_events(tenant):
    body = {"event_type": "gateway.action_denied", "severity": "critical"}
    assert tenant.post("/events", body).status_code == 405
    event_id = events_of(tenant)[0]["id"] if events_of(tenant) else uuid4()
    for method in ("PUT", "PATCH", "DELETE"):
        response = tenant.client.request(
            method, f"/api/v1/events/{event_id}", json=body, headers=tenant.admin
        )
        assert response.status_code == 405


def _record(**overrides):
    values = dict(
        id=uuid4(),
        tenant_id=uuid4(),
        schema_version=1,
        event_type="gateway.action_denied",
        occurred_at=datetime.now(UTC),
        actor_type="agent",
        actor_id=uuid4(),
        severity="medium",
        reason_code="TOOL_NOT_GRANTED",
        source_audit_event_id=uuid4(),
        source_event_hash="a" * 64,
    )
    values.update(overrides)
    return values


def test_a_valid_record_is_accepted():
    SecurityEventRecord(**_record())


@pytest.mark.parametrize(
    "overrides",
    [
        {"event_type": "made.up"},
        {"severity": "catastrophic"},
        {"reason_code": "free text with spaces"},
        {"reason_code": "lowercase"},
        {"actor_type": "martian"},
        {"occurred_at": datetime(2026, 1, 1)},  # naive timestamps are ambiguous
        {"occurred_at": "yesterday"},
        {"source_event_hash": "short"},
        {"schema_version": 0},
        {"tool": "DROP TABLE"},
        {"action": "not an action"},
        {"attributes": {"message_body": "secret"}},
        {"attributes": {"status": {"nested": "object"}}},
        {"attributes": {"status": "x" * 200}},
        {"unexpected_field": "value"},
        {"tenant_id": "not-a-uuid"},
        {"source_audit_event_id": None},
    ],
)
def test_malformed_records_are_rejected(overrides):
    with pytest.raises(ValidationError):
        SecurityEventRecord(**_record(**overrides))


def _audit(db, tenant_id, event_type="auth.login_failed", **kwargs):
    with db.tenant_transaction(tenant_id) as session:
        return append_event(session, tenant_id, event_type=event_type, actor_type="anonymous",
                            **kwargs)


def _raw_event_insert(session, tenant_id, source_id, source_hash="a" * 64):
    session.execute(
        text(
            """
            INSERT INTO security_events
              (id, tenant_id, schema_version, event_type, occurred_at, actor_type, severity,
               reason_code, attributes, source_audit_event_id, source_event_hash)
            VALUES (:id, :tenant, 1, 'auth.login_failed', now(), 'anonymous', 'low',
                    'LOGIN_FAILED', '{}', :source, :hash)
            """
        ),
        {"id": uuid4(), "tenant": tenant_id, "source": source_id, "hash": source_hash},
    )


def test_database_rejects_an_event_with_no_source(db, new_tenant):
    tenant_id = new_tenant()
    with pytest.raises(IntegrityError), db.tenant_transaction(tenant_id) as session:
        _raw_event_insert(session, tenant_id, uuid4())


def test_database_rejects_a_second_event_from_the_same_source(db, new_tenant):
    """The event ID is deterministic, so this needs a different ID to reach the constraint."""
    tenant_id = new_tenant()
    source = _audit(db, tenant_id)
    with pytest.raises(IntegrityError, match="security_events_tenant_id_source_audit_event_id_key"):
        with db.tenant_transaction(tenant_id) as session:
            _raw_event_insert(session, tenant_id, source.id)


def test_database_rejects_an_event_sourced_from_another_tenant(db, new_tenant):
    tenant_a, tenant_b = new_tenant(), new_tenant()
    source = _audit(db, tenant_b)
    with pytest.raises(IntegrityError), db.tenant_transaction(tenant_a) as session:
        _raw_event_insert(session, tenant_a, source.id)


def test_runtime_role_cannot_inject_an_event_into_another_tenant(db, new_tenant):
    tenant_a, tenant_b = new_tenant(), new_tenant()
    source = _audit(db, tenant_b, event_type="test.unmapped")
    with pytest.raises(ProgrammingError, match="row-level security"):
        with db.tenant_transaction(tenant_a) as session:
            _raw_event_insert(session, tenant_b, source.id)


def test_runtime_role_cannot_change_or_delete_events(db, tenant):
    _ = tenant.viewer
    tenant.post("/policies", {"name": "x"}, headers=tenant.viewer)
    for statement in (
        "UPDATE security_events SET severity = 'info'",
        "UPDATE security_events SET reason_code = 'FORGED'",
        "DELETE FROM security_events",
        "TRUNCATE security_events",
    ):
        with pytest.raises(ProgrammingError), db.tenant_transaction(tenant.id) as session:
            session.execute(text(statement))


def test_owner_role_cannot_change_or_delete_events(urls, tenant):
    tenant.post("/policies", {"name": "x"}, headers=tenant.viewer)
    owner = Database(urls.owner, pool_size=1, max_overflow=0)
    try:
        for statement in (
            "UPDATE security_events SET severity = 'info'",
            "DELETE FROM security_events",
        ):
            with pytest.raises(DBAPIError), owner.tenant_transaction(tenant.id) as session:
                session.execute(text(statement))
    finally:
        owner.dispose()


def test_processing_marker_can_change_only_once(db, tenant):
    tenant.post("/policies", {"name": "x"}, headers=tenant.viewer)
    with db.tenant_transaction(tenant.id) as session:
        session.execute(text("UPDATE security_events SET correlation_processed_at = now()"))
    with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
        session.execute(text("UPDATE security_events SET correlation_processed_at = now()"))


def test_duplicate_projection_is_a_no_op(db, new_tenant):
    tenant_id = new_tenant()
    source = _audit(db, tenant_id)
    with db.tenant_transaction(tenant_id) as session:
        audit = session.get(AuditEvent, source.id)
        project_audit_event(session, audit)
        project_audit_event(session, audit)
    with db.tenant_transaction(tenant_id) as session:
        rows = session.execute(
            select(SecurityEvent).where(SecurityEvent.source_audit_event_id == source.id)
        ).scalars().all()
    assert len(rows) == 1


def test_unmapped_audit_events_produce_no_security_event(db, new_tenant):
    tenant_id = new_tenant()
    _audit(db, tenant_id, event_type="asset.created")
    _audit(db, tenant_id, event_type="incident.status_changed")
    _audit(db, tenant_id, event_type="auth.login_succeeded")
    with db.tenant_transaction(tenant_id) as session:
        assert session.execute(select(SecurityEvent)).scalars().all() == []


def test_a_projection_failure_rolls_back_the_audit_event(db, new_tenant, monkeypatch):
    """An audit event and its security event commit together, or not at all."""
    tenant_id = new_tenant()

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic projection fault")

    monkeypatch.setattr(chain, "project_audit_event", fail)
    with pytest.raises(RuntimeError):
        _audit(db, tenant_id)
    monkeypatch.undo()
    with db.tenant_transaction(tenant_id) as session:
        audit = session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "auth.login_failed")
        ).scalars().all()
    assert audit == []


def test_backfill_creates_missing_events_and_is_idempotent(db, new_tenant, monkeypatch):
    tenant_id = new_tenant()
    monkeypatch.setattr(chain, "project_audit_event", lambda session, event: None)
    _audit(db, tenant_id)
    _audit(db, tenant_id)
    _audit(db, tenant_id, event_type="asset.created")
    monkeypatch.undo()

    assert backfill_tenant(db, tenant_id) == 2
    assert backfill_tenant(db, tenant_id) == 0
    with db.tenant_transaction(tenant_id) as session:
        assert len(session.execute(select(SecurityEvent)).scalars().all()) == 2


def test_stored_event_matches_its_reprojection(db, tenant):
    tenant.post("/policies", {"name": "x"}, headers=tenant.viewer)
    with db.tenant_transaction(tenant.id) as session:
        event = session.execute(
            select(SecurityEvent).where(SecurityEvent.event_type == "authz.denied")
        ).scalar_one()
        assert reprojection_matches(session, event) is True


def test_tampered_event_fails_reprojection(db, tenant, attacker_sql):
    tenant.post("/policies", {"name": "x"}, headers=tenant.viewer)
    attacker_sql.execute("ALTER TABLE security_events DISABLE TRIGGER USER")
    try:
        attacker_sql.execute(
            "UPDATE security_events SET severity = 'info', reason_code = 'FORGED' "
            "WHERE tenant_id = %s AND event_type = 'authz.denied'",
            (tenant.id,),
        )
    finally:
        attacker_sql.execute("ALTER TABLE security_events ENABLE TRIGGER USER")
    with db.tenant_transaction(tenant.id) as session:
        event = session.execute(
            select(SecurityEvent).where(SecurityEvent.event_type == "authz.denied")
        ).scalar_one()
        assert reprojection_matches(session, event) is False


def test_altered_source_audit_event_fails_reprojection(db, tenant, attacker_sql):
    """The projection ignores this field, so only the source hash can reveal the change."""
    tenant.post("/policies", {"name": "x"}, headers=tenant.viewer)
    attacker_sql.execute("ALTER TABLE audit_events DISABLE TRIGGER USER")
    try:
        attacker_sql.execute(
            "UPDATE audit_events SET payload = '{\"forged\": true}' "
            "WHERE tenant_id = %s AND event_type = 'authz.denied'",
            (tenant.id,),
        )
    finally:
        attacker_sql.execute("ALTER TABLE audit_events ENABLE TRIGGER USER")
    with db.tenant_transaction(tenant.id) as session:
        event = session.execute(
            select(SecurityEvent).where(SecurityEvent.event_type == "authz.denied")
        ).scalar_one()
        assert reprojection_matches(session, event) is False


def test_tenant_a_cannot_read_tenant_b_events(world):
    a, b = world.tenant(), world.tenant()
    b.post("/policies", {"name": "x"}, headers=b.viewer)
    event = events_of(b, "authz.denied")[0]

    assert a.get(f"/events/{event['id']}").status_code == 404
    assert [item for item in events_of(a) if item["id"] == event["id"]] == []


def test_event_detail_and_filters(tenant):
    tenant.allow_everything()
    agent = tenant.agent()
    document = tenant.document()
    agent.act("read_document", document)
    event = events_of(tenant, "gateway.action_denied")[0]

    assert tenant.get(f"/events/{event['id']}").json()["id"] == event["id"]
    assert tenant.get("/events", severity="medium", agent_id=agent.id).json()["total"] >= 1
    assert tenant.get("/events", agent_id=str(uuid4())).json()["total"] == 0
    assert tenant.get("/events", severity="nonsense").status_code == 422
    assert tenant.get("/events", limit=101).status_code == 422
    assert tenant.get("/events", event_type="not.a.type").status_code == 422


def test_viewer_can_read_events(tenant):
    assert tenant.get("/events", headers=tenant.viewer).status_code == 200


def test_agent_cannot_read_events(tenant):
    agent = tenant.agent()
    assert tenant.client.get("/api/v1/events", headers=agent.headers).status_code == 401


def test_unauthenticated_failure_flood_is_limited_and_counted(world, tenant):
    world.app.state.container.failure_limiter.limit_per_minute = 5
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    parsed = parse_key(agent.key)
    forged = bearer(format_key(parsed.tenant_id, parsed.credential_id, "wrong"))
    action = {"idempotency_key": "k", "tool": "calculate", "resource_id": None, "params": PARAMS}

    responses = [
        world.client.post("/api/v1/gateway/actions", headers=forged, json=action)
        for _ in range(12)
    ]

    assert {response.status_code for response in responses} == {401}
    assert len(events_of(tenant, "auth.agent_failed")) == 5
    assert len(tenant.audit_events("auth.agent_failed")) == 5

    world.app.state.container.failure_limiter.reset()
    world.client.post("/api/v1/gateway/actions", headers=forged, json=action)
    latest = events_of(tenant, "auth.agent_failed")[0]
    assert latest["attributes"] == {"suppressed_since_last": 7}


def test_migration_upgrades_a_populated_0001_database(admin_url, urls):
    """Real upgrade path: data written under 0001 survives, and can be backfilled."""
    name = f"aegis_migration_{uuid4().hex}"
    owner, app = ensure_roles_and_database(
        admin_url,
        database=name,
        owner_password=make_url(urls.owner).password,
        app_password=make_url(urls.app).password,
    )
    try:
        run_migrations(owner, revision="0001")
        tenant_id = uuid4()
        with psycopg.connect(owner.replace("+psycopg", ""), autocommit=False) as connection:
            connection.execute("SELECT set_config('app.tenant_id', %s, true)", (str(tenant_id),))
            connection.execute(
                "INSERT INTO tenants (id, slug, name) VALUES (%s, 'old-tenant', 'Old')",
                (tenant_id,),
            )
            connection.execute(
                "INSERT INTO audit_chain_heads (tenant_id, seq, head_hash) VALUES (%s, 1, %s)",
                (tenant_id, "b" * 64),
            )
            connection.execute(
                """
                INSERT INTO audit_events
                  (id, tenant_id, seq, prev_hash, event_hash, event_type, actor_type,
                   occurred_at, payload)
                VALUES (%s, %s, 1, %s, %s, 'auth.login_failed', 'anonymous', now(), '{}')
                """,
                (uuid4(), tenant_id, "0" * 64, "b" * 64),
            )
            connection.commit()

        run_migrations(owner)

        database = Database(app, pool_size=1, max_overflow=0)
        try:
            assert backfill_tenant(database, tenant_id) == 1
            with database.tenant_transaction(tenant_id) as session:
                event = session.execute(select(SecurityEvent)).scalar_one()
                assert event.event_type == "auth.login_failed"
                assert event.correlation_processed_at is None
        finally:
            database.dispose()
    finally:
        with psycopg.connect(admin_url, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE "{name}" WITH (FORCE)')


def test_provisioning_still_works_after_migration(urls):
    tenant_id = provision_tenant(urls.owner, slug=f"t-{uuid4().hex[:12]}", name="Synthetic")
    create_user(urls.owner, tenant_id, email="a@example.test", password=PASSWORD, role="viewer")
