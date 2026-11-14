"""Scheduled reviews (spec 13): the worker records what the gateway enforces by the clock."""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

import aegis.governance.reviews as reviews
from aegis.api.app import create_app
from aegis.config import Settings
from aegis.governance.reviews import process_due_reviews, process_tenant_reviews
from aegis.governance.worker import GovernanceReviewWorker
from support import (
    ASSETS,
    approve,
    assess,
    reviewers,
    save_profile,
    submitted,
    window,
)

DUE = "/governance/reviews/due"
OVERVIEW = "/governance/overview"
PARAMS = {"operator": "add", "a": 1, "b": 2}


@pytest.fixture
def review_log():
    """Records written by the review worker. The aegis logger does not propagate to the root."""
    records: list[logging.LogRecord] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Collect(level=logging.DEBUG)
    logger = logging.getLogger("aegis.governance.reviews")
    logger.addHandler(handler)
    yield records
    logger.removeHandler(handler)


def approved_agent(tenant, *, valid_days=365, review_days=30, review_at=None, conditions=None):
    """An agent whose asset went through the real review flow, with its own approval window."""
    agent = tenant.agent(tools=["calculate"])
    save_profile(tenant, agent.asset_id)
    assess(tenant, agent.asset_id)
    holder = reviewers(tenant)
    review = submitted(tenant, agent.asset_id)
    dates = window(valid_days, review_days)
    if review_at is not None:
        dates["next_review_at"] = review_at.isoformat()
    response = approve(tenant, review["id"], holder, conditions=conditions, **dates)
    assert response.status_code == 201, response.text
    return agent


def days_ahead(days, seconds=0):
    return datetime.now(UTC) + timedelta(days=days, seconds=seconds)


def state_of(attacker_sql, asset_id):
    row = attacker_sql.execute(
        "SELECT status, version, current_decision_id, hard_block_decision_id, valid_until, "
        "next_review_at FROM asset_governance_state WHERE asset_id = %s", (asset_id,)
    ).fetchone()
    names = ("status", "version", "current_decision_id", "hard_block_decision_id",
             "valid_until", "next_review_at")
    return dict(zip(names, row, strict=True))


def decisions(attacker_sql, asset_id):
    rows = attacker_sql.execute(
        "SELECT d.kind, d.from_status, d.to_status, d.actor_type, d.decided_by, d.reason, "
        "d.review_id, d.assessment_id, d.conditions_hash, d.valid_until, d.next_review_at, "
        "a.actor_type, a.actor_id "
        "FROM governance_decisions d JOIN audit_events a ON a.id = d.audit_event_id "
        "WHERE d.asset_id = %s ORDER BY a.seq", (asset_id,)
    ).fetchall()
    names = ("kind", "from_status", "to_status", "actor_type", "decided_by", "reason",
             "review_id", "assessment_id", "conditions_hash", "valid_until", "next_review_at",
             "audit_actor_type", "audit_actor_id")
    return [dict(zip(names, row, strict=True)) for row in rows]


def reassessments(attacker_sql, asset_id):
    return [d for d in decisions(attacker_sql, asset_id) if d["kind"] == "REQUIRE_REASSESSMENT"]


def db_of(world):
    return world.app.state.container.db


def at(world, moment):
    world.app.state.container.clock = lambda: moment


def calc(agent):
    response = agent.act("calculate", params=PARAMS)
    assert response.status_code == 200, response.text
    return response.json()


def outcome(body):
    return body["outcome"], body["reason_code"]


def check_of(attacker_sql, request_id):
    return attacker_sql.execute(
        "SELECT observed_status, verdict, reason_code FROM governance_gateway_checks "
        "WHERE request_id = %s ORDER BY checked_at DESC LIMIT 1", (request_id,)
    ).fetchone()


def failures_for(records, asset_id):
    return [record for record in records
            if record.levelno >= logging.ERROR and str(asset_id) in record.getMessage()]


# The sweep


def test_due_approval_moves_to_reassessment_required(world, tenant, attacker_sql):
    agent = approved_agent(tenant, review_days=30)
    before = state_of(attacker_sql, agent.asset_id)

    process_due_reviews(db_of(world), clock=lambda: days_ahead(31))

    after = state_of(attacker_sql, agent.asset_id)
    assert after["status"] == "REASSESSMENT_REQUIRED"
    assert after["version"] == before["version"] + 1
    # Only the status moves: the window, the current decision, and the block all stay.
    for column in ("current_decision_id", "hard_block_decision_id", "valid_until",
                   "next_review_at"):
        assert after[column] == before[column]
    (decision,) = reassessments(attacker_sql, agent.asset_id)
    assert (decision["from_status"], decision["to_status"]) == (
        "APPROVED", "REASSESSMENT_REQUIRED")
    assert (decision["actor_type"], decision["decided_by"]) == ("system", None)
    assert (decision["audit_actor_type"], decision["audit_actor_id"]) == ("system", None)
    assert decision["reason"] == "The scheduled review date has passed."
    assert tenant.verify_audit()["valid"] is True


def test_system_decision_has_the_shape_of_a_human_reassessment(world, tenant, attacker_sql):
    swept = approved_agent(tenant, review_days=30)
    by_hand = approved_agent(tenant, review_days=30)
    response = tenant.post(f"{ASSETS}/{by_hand.asset_id}/reassess", {"reason": "By hand."})
    assert response.status_code == 201, response.text

    process_tenant_reviews(db_of(world), tenant.id, clock=lambda: days_ahead(31))

    (system,) = reassessments(attacker_sql, swept.asset_id)
    (human,) = reassessments(attacker_sql, by_hand.asset_id)
    same = ("kind", "from_status", "to_status", "review_id", "assessment_id", "conditions_hash",
            "valid_until", "next_review_at")
    assert {key: system[key] for key in same} == {key: human[key] for key in same}
    assert human["actor_type"] == "user" and system["actor_type"] == "system"
    events = tenant.get("/events", limit=100, event_type="governance.status_changed").json()
    swept_events = [item for item in events["items"] if item["asset_id"] == swept.asset_id
                    and item["reason_code"] == "GOVERNANCE_REQUIRE_REASSESSMENT"]
    assert len(swept_events) == 1


def test_expired_approval_is_recorded_as_expired(world, tenant, attacker_sql):
    agent = approved_agent(tenant, valid_days=10, review_days=10)

    process_tenant_reviews(db_of(world), tenant.id, clock=lambda: days_ahead(11))

    (decision,) = reassessments(attacker_sql, agent.asset_id)
    assert decision["reason"] == "The approval has expired."


def test_conditional_approval_also_moves(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = approved_agent(tenant, review_days=10, conditions={"denied_tools": ["calculate"]})
    before = state_of(attacker_sql, agent.asset_id)
    later = days_ahead(11)
    at(world, later)
    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_CONDITION_DENIED")

    process_tenant_reviews(db_of(world), tenant.id, clock=lambda: later)

    after = state_of(attacker_sql, agent.asset_id)
    (decision,) = reassessments(attacker_sql, agent.asset_id)
    assert decision["from_status"] == "CONDITIONALLY_APPROVED"
    assert after["status"] == "REASSESSMENT_REQUIRED"
    # Conditions live on the current decision, which a reassessment does not repoint.
    assert after["current_decision_id"] == before["current_decision_id"]
    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_CONDITION_DENIED")
    assert world.spy.calls == []


def test_not_yet_due_is_untouched(world, tenant, attacker_sql):
    agent = approved_agent(tenant, review_days=30)
    before = state_of(attacker_sql, agent.asset_id)
    count = len(decisions(attacker_sql, agent.asset_id))

    process_tenant_reviews(db_of(world), tenant.id,
                           clock=lambda: before["next_review_at"] - timedelta(microseconds=1))

    assert state_of(attacker_sql, agent.asset_id) == before
    assert len(decisions(attacker_sql, agent.asset_id)) == count
    # The review date itself is due, as the expiry instant is expired at the gateway.
    process_tenant_reviews(db_of(world), tenant.id, clock=lambda: before["next_review_at"])
    assert state_of(attacker_sql, agent.asset_id)["status"] == "REASSESSMENT_REQUIRED"


def test_only_approved_statuses_are_swept(world, tenant, attacker_sql):
    reassessing = approved_agent(tenant, review_days=10)
    response = tenant.post(f"{ASSETS}/{reassessing.asset_id}/reassess", {"reason": "By hand."})
    assert response.status_code == 201, response.text
    count = len(decisions(attacker_sql, reassessing.asset_id))

    process_tenant_reviews(db_of(world), tenant.id, clock=lambda: days_ahead(400))

    assert len(decisions(attacker_sql, reassessing.asset_id)) == count
    assert state_of(attacker_sql, reassessing.asset_id)["status"] == "REASSESSMENT_REQUIRED"


def test_second_pass_is_idempotent(world, tenant, attacker_sql):
    agent = approved_agent(tenant, review_days=30)
    later = days_ahead(31)

    assert process_tenant_reviews(db_of(world), tenant.id, clock=lambda: later) == 1
    version = state_of(attacker_sql, agent.asset_id)["version"]
    assert process_tenant_reviews(db_of(world), tenant.id, clock=lambda: later) == 0

    assert len(reassessments(attacker_sql, agent.asset_id)) == 1
    assert state_of(attacker_sql, agent.asset_id)["version"] == version


def test_concurrent_passes_produce_one_decision(world, tenant, urls, attacker_sql, review_log):
    """Both passes list the asset, then queue on its locks; the second re-checks and stops."""
    agent = approved_agent(tenant, review_days=30)
    later = days_ahead(31)
    db = db_of(world)
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        with psycopg.connect(urls.superuser, autocommit=True) as observer:
            with attacker_sql.transaction():
                attacker_sql.execute(
                    "SELECT id FROM agents WHERE asset_id = %s FOR UPDATE", (agent.asset_id,))
                passes = [pool.submit(process_tenant_reviews, db, tenant.id, clock=lambda: later)
                          for _ in range(2)]
                # One waits on the agent rows, the other on the per-asset lock behind it.
                waiting = 0
                deadline = time.monotonic() + 20
                while waiting < 2 and time.monotonic() < deadline:
                    waiting = observer.execute(
                        "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                        "AND datname = current_database() AND pid <> pg_backend_pid()"
                    ).fetchone()[0]
                    time.sleep(0.05)
                assert waiting == 2, "both passes should be queued on the asset's locks"
                assert not any(item.done() for item in passes)
        results = sorted(item.result(timeout=60) for item in passes)
    finally:
        pool.shutdown(wait=True)

    assert results == [0, 1]
    assert len(reassessments(attacker_sql, agent.asset_id)) == 1
    assert failures_for(review_log, agent.asset_id) == []
    assert tenant.verify_audit()["valid"] is True


def test_concurrent_passes_over_many_assets(world, tenant, attacker_sql, review_log):
    agents = [approved_agent(tenant, review_days=30) for _ in range(3)]
    later = days_ahead(31)
    db = db_of(world)
    barrier = threading.Barrier(4)

    def run():
        barrier.wait(timeout=30)
        return process_tenant_reviews(db, tenant.id, clock=lambda: later)

    with ThreadPoolExecutor(max_workers=4) as pool:
        total = sum(f.result(timeout=90) for f in [pool.submit(run) for _ in range(4)])

    assert total == 3
    for agent in agents:
        assert len(reassessments(attacker_sql, agent.asset_id)) == 1
        assert failures_for(review_log, agent.asset_id) == []


def test_a_stale_listing_is_rechecked_under_the_lock(world, tenant, attacker_sql, monkeypatch):
    """An asset re-approved after the listing was read must not be moved."""
    agent = approved_agent(tenant, review_days=30)
    before = state_of(attacker_sql, agent.asset_id)
    monkeypatch.setattr(reviews, "due_asset_ids",
                        lambda session, now, limit: [UUID(agent.asset_id)])

    assert process_tenant_reviews(db_of(world), tenant.id, clock=lambda: days_ahead(1)) == 0

    assert state_of(attacker_sql, agent.asset_id) == before
    assert reassessments(attacker_sql, agent.asset_id) == []


def test_worker_never_clears_a_hard_block(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = approved_agent(tenant, review_days=30)
    blocking = state_of(attacker_sql, agent.asset_id)["current_decision_id"]
    # Only a database edit can put a block on an approved asset; the sweep must keep it.
    attacker_sql.execute("SET session_replication_role = replica")
    try:
        attacker_sql.execute(
            "UPDATE asset_governance_state SET hard_block_decision_id = %s WHERE asset_id = %s",
            (blocking, agent.asset_id))
    finally:
        attacker_sql.execute("SET session_replication_role = origin")

    process_tenant_reviews(db_of(world), tenant.id, clock=lambda: days_ahead(31))

    after = state_of(attacker_sql, agent.asset_id)
    assert after["status"] == "REASSESSMENT_REQUIRED"
    assert after["hard_block_decision_id"] == blocking
    assert len(reassessments(attacker_sql, agent.asset_id)) == 1
    assert outcome(calc(agent)) == ("DENY", "GOVERNANCE_BLOCKED")


# The gateway does not depend on the worker


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_gateway_verdict_is_the_same_before_and_after_the_worker_runs(
        world, tenant, attacker_sql, mode):
    tenant.allow_everything()
    agent = approved_agent(tenant, valid_days=1, review_days=1)
    if mode == "enforce":
        tenant.set_enforcement("enforce")
    later = days_ahead(2)
    at(world, later)

    before = calc(agent)
    process_due_reviews(db_of(world), clock=lambda: later)
    after = calc(agent)

    assert state_of(attacker_sql, agent.asset_id)["status"] == "REASSESSMENT_REQUIRED"
    assert outcome(after) == outcome(before)
    first, second = check_of(attacker_sql, before["request_id"]), check_of(
        attacker_sql, after["request_id"])
    assert first[1:] == second[1:]
    assert first[2] == "GOVERNANCE_APPROVAL_EXPIRED"
    # Only the recorded status was brought in line with what the clock already said.
    assert (first[0], second[0]) == ("APPROVED", "REASSESSMENT_REQUIRED")
    expected = ("DENY", "GOVERNANCE_APPROVAL_EXPIRED") if mode == "enforce" else (
        "ALLOW", "ALLOWED_BY_RULE")
    assert outcome(after) == expected


def test_review_date_holds_in_enforce_as_a_human_reassessment_does(world, tenant, attacker_sql):
    """Before expiry, a due review is a reassessment: the same verdict as one made by hand."""
    tenant.allow_everything()
    swept = approved_agent(tenant, valid_days=365, review_days=10)
    by_hand = approved_agent(tenant, valid_days=365, review_days=10)
    tenant.set_enforcement("enforce")
    response = tenant.post(f"{ASSETS}/{by_hand.asset_id}/reassess", {"reason": "By hand."})
    assert response.status_code == 201, response.text
    later = days_ahead(11)
    at(world, later)
    assert outcome(calc(swept)) == ("ALLOW", "ALLOWED_BY_RULE")

    process_tenant_reviews(db_of(world), tenant.id, clock=lambda: later)

    expected = ("REQUIRE_APPROVAL", "GOVERNANCE_REASSESSMENT_REQUIRED")
    assert outcome(calc(swept)) == outcome(calc(by_hand)) == expected


def test_failure_on_one_asset_does_not_stop_others(world, tenant, attacker_sql, monkeypatch,
                                                   review_log):
    failing = approved_agent(tenant, review_days=10)
    others = [approved_agent(tenant, review_days=days) for days in (20, 30)]
    real = reviews.require_reassessment

    def flaky(session, actor_type, user_id, now, asset_id, *, reason):
        if str(asset_id) == failing.asset_id:
            raise RuntimeError("synthetic secret detail")
        return real(session, actor_type, user_id, now, asset_id, reason=reason)

    monkeypatch.setattr(reviews, "require_reassessment", flaky)
    later = days_ahead(31)

    assert process_tenant_reviews(db_of(world), tenant.id, clock=lambda: later) == 2

    assert state_of(attacker_sql, failing.asset_id)["status"] == "APPROVED"
    assert reassessments(attacker_sql, failing.asset_id) == []
    for agent in others:
        assert state_of(attacker_sql, agent.asset_id)["status"] == "REASSESSMENT_REQUIRED"
    (record,) = failures_for(review_log, failing.asset_id)
    assert "synthetic secret detail" not in record.getMessage()
    assert record.exc_info is None
    assert tenant.verify_audit()["valid"] is True

    monkeypatch.setattr(reviews, "require_reassessment", real)
    assert process_tenant_reviews(db_of(world), tenant.id, clock=lambda: later) == 1


def test_worker_failure_leaves_gateway_working(world, tenant, monkeypatch, review_log):
    tenant.allow_everything()
    tenant.set_enforcement("enforce")
    agent = approved_agent(tenant, review_days=30)

    def broken(db, now):
        raise RuntimeError("synthetic secret detail")

    monkeypatch.setattr(reviews, "due_tenants", broken)
    container = world.app.state.container
    worker = GovernanceReviewWorker(container.db, container.clock, 0.05)
    worker.start()
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and len(review_log) < 2:
            time.sleep(0.05)
        assert outcome(calc(agent)) == ("ALLOW", "ALLOWED_BY_RULE")
        assert worker._thread.is_alive()
    finally:
        worker.stop()

    # Retried, not abandoned, and nothing from the exception reached the log.
    assert len(review_log) >= 2
    assert all("synthetic secret detail" not in r.getMessage() for r in review_log)
    assert all(r.exc_info is None for r in review_log)
    assert not worker._thread.is_alive()


def test_the_worker_runs_without_being_asked(urls, jwt_key_path, attacker_sql):
    from aegis.provisioning import provision_tenant
    from support import TenantWorld, ToolSpy

    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=urls.app,
        jwt_private_key_path=jwt_key_path,
        correlation_worker_enabled=False,
        governance_worker_enabled=True,
        governance_review_poll_seconds=0.1,
    )
    app = create_app(settings, tools=ToolSpy().registry())
    with TestClient(app, raise_server_exceptions=False) as client:
        slug = f"t-{uuid4().hex[:16]}"
        tenant_id = provision_tenant(urls.owner, slug=slug, name="Synthetic")
        tenant = TenantWorld(client, urls, tenant_id, slug)
        agent = approved_agent(tenant, review_days=30)
        later = days_ahead(31)
        app.state.container.clock = lambda: later

        deadline = time.monotonic() + 15
        status = None
        while time.monotonic() < deadline and status != "REASSESSMENT_REQUIRED":
            status = state_of(attacker_sql, agent.asset_id)["status"]
            time.sleep(0.1)

    assert status == "REASSESSMENT_REQUIRED"


def test_worker_settings_default_to_enabled_and_a_minute():
    fields = Settings.model_fields
    assert fields["governance_worker_enabled"].default is True
    assert fields["governance_review_poll_seconds"].default == 60.0


# The definer function


def test_definer_function_returns_only_ids(world, tenant, attacker_sql, db):
    (row,) = attacker_sql.execute(
        """
        SELECT p.prosecdef, p.proretset, p.prorettype::regtype::text, p.proargmodes,
               p.proconfig, pg_get_function_identity_arguments(p.oid), r.rolname,
               has_function_privilege('aegis_app', p.oid, 'EXECUTE'),
               coalesce(p.proacl::text[], '{}'),
               (SELECT r2.rolname FROM pg_proc p2 JOIN pg_roles r2 ON r2.oid = p2.proowner
                WHERE p2.proname = 'aegis_tenants_with_pending_events')
        FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
        WHERE p.proname = 'aegis_tenants_with_due_governance_reviews'
        """
    ).fetchall()
    (definer, returns_set, returns, modes, config, arguments, owner, app_may_run, acl,
     pending_owner) = row
    assert (definer, returns_set, returns, modes) == (True, True, "uuid", None)
    assert config == ["search_path=pg_catalog, pg_temp"]
    assert arguments == "p_now timestamp with time zone"
    assert owner == pending_owner and app_may_run is True
    assert acl and not any(entry.startswith("=") for entry in acl), "PUBLIC may not execute it"
    policies = attacker_sql.execute(
        "SELECT policyname, cmd, roles::text[], qual FROM pg_policies "
        "WHERE tablename = 'asset_governance_state' AND policyname <> 'tenant_isolation'"
    ).fetchall()
    assert policies == [("owner_finds_due_reviews", "SELECT", [owner],
                         "(next_review_at IS NOT NULL)")]

    due = approved_agent(tenant, review_days=1)
    quiet = world.tenant()
    approved_agent(quiet, review_days=30)
    tenant_ids = {r[0] for r in attacker_sql.execute("SELECT id FROM tenants").fetchall()}

    with db._sessions() as session, session.begin():
        rows = session.execute(
            text("SELECT * FROM aegis_tenants_with_due_governance_reviews(:now)"),
            {"now": days_ahead(2)},
        ).all()
    assert all(len(r) == 1 and isinstance(r[0], UUID) for r in rows)
    returned = {r[0] for r in rows}
    assert returned <= tenant_ids
    assert tenant.id in returned and quiet.id not in returned
    assert UUID(due.asset_id) not in returned
    # Without a tenant context the runtime role still sees no state rows itself.
    with db._sessions() as session, session.begin():
        assert session.execute(text("SELECT count(*) FROM asset_governance_state")).scalar() == 0


# Listing what is due


def _due_items(tenant, headers, **params):
    response = tenant.get(DUE, headers=headers, **params)
    assert response.status_code == 200, response.text
    return response.json()


def test_reviews_due_lists_upcoming_and_overdue(world, tenant, attacker_sql):
    # The app clock stays real, because moving it would expire the users' tokens; the overdue
    # review is simply set a moment ahead and waited for.
    review_at = days_ahead(0, seconds=3)
    overdue = approved_agent(tenant, review_at=review_at)
    upcoming = approved_agent(tenant, review_days=20)
    distant = approved_agent(tenant, review_days=60)
    suspended = approved_agent(tenant, review_days=5)
    assert tenant.post(f"{ASSETS}/{suspended.asset_id}/suspend",
                       {"reason": "Synthetic stop."}).status_code == 201
    unapproved = tenant.asset()["id"]
    viewer = tenant.viewer
    while datetime.now(UTC) <= review_at:
        time.sleep(0.1)

    page = _due_items(tenant, viewer, window_days=30)
    assert page["total"] == 2 and (page["limit"], page["offset"]) == (50, 0)
    first, second = page["items"]
    assert (first["asset_id"], first["overdue"]) == (overdue.asset_id, True)
    assert (second["asset_id"], second["overdue"]) == (upcoming.asset_id, False)
    assert first["governance_status"] == "APPROVED" and first["expired"] is False
    assert set(first) == {"asset_id", "name", "governance_status", "next_review_at",
                          "valid_until", "overdue", "expired"}
    listed = {item["asset_id"] for item in _due_items(tenant, viewer, window_days=60)["items"]}
    assert listed == {overdue.asset_id, upcoming.asset_id, distant.asset_id}
    assert suspended.asset_id not in listed and unapproved not in listed
    assert [item["asset_id"] for item in _due_items(tenant, viewer, window_days=0)["items"]] == [
        overdue.asset_id]
    paged = _due_items(tenant, viewer, window_days=60, limit=1, offset=1)
    assert paged["total"] == 3 and [i["asset_id"] for i in paged["items"]] == [upcoming.asset_id]
    assert tenant.get(OVERVIEW, headers=viewer).json()["overdue_reviews"] == 1

    assert process_tenant_reviews(db_of(world), tenant.id, clock=lambda: datetime.now(UTC)) == 1

    # The review stays overdue until a new approval sets a new date.
    (item,) = _due_items(tenant, viewer, window_days=0)["items"]
    assert (item["asset_id"], item["governance_status"]) == (
        overdue.asset_id, "REASSESSMENT_REQUIRED")
    assert tenant.get(OVERVIEW, headers=viewer).json()["overdue_reviews"] == 1


def test_reviews_due_validates_the_window_and_refuses_agents(tenant):
    agent = tenant.agent()
    assert tenant.get(DUE, window_days=-1).status_code == 422
    assert tenant.get(DUE, window_days=366).status_code == 422
    assert tenant.get(DUE, limit=0).status_code == 422
    assert tenant.client.get(f"/api/v1{DUE}", headers=agent.headers).status_code == 401
    assert tenant.client.get(f"/api/v1{DUE}").status_code == 401
    assert tenant.get(DUE, headers=tenant.reviewer).status_code == 200


def test_reviews_due_tenant_isolated(world):
    first, second = world.tenant(), world.tenant()
    mine = approved_agent(first, review_days=5)
    theirs = approved_agent(second, review_days=5)

    for tenant, own, other in ((first, mine, theirs), (second, theirs, mine)):
        page = _due_items(tenant, tenant.viewer, window_days=30)
        assert [item["asset_id"] for item in page["items"]] == [own.asset_id]
        assert page["total"] == 1
        assert other.asset_id not in str(page)
