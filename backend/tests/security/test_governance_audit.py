"""Attempts made in the final security audit (Task 21), each a way to break a governance rule."""

import io
import logging
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError

import aegis.governance.gateway_check as gateway_check
from aegis.logging_config import JsonFormatter
from aegis.provisioning import create_user
from support import APPROVALS, PASSWORD, assessed_asset, reviewers, submitted

PARAMS = {"operator": "add", "a": 1, "b": 2}
MARKER = "SYNTHETIC-EVIDENCE-MARKER-7f3a"
# Tables a person or the service may update in place. Every other governance table is history.
MUTABLE = {"governance_settings", "governance_role_grants", "asset_governance_state",
           "governance_reviews"}


def _governance_routes(app):
    for path, operations in app.openapi()["paths"].items():
        if path.startswith("/api/v1/governance"):
            for method in operations:
                yield method.upper(), path


def _with_ids(path):
    url = path
    while "{" in url:
        start, end = url.index("{"), url.index("}")
        url = url[:start] + str(uuid4()) + url[end + 1:]
    return url


def test_every_governance_route_refuses_an_agent(world, tenant):
    agent = tenant.agent()
    routes = list(_governance_routes(world.app))
    assert len(routes) > 40

    for method, path in routes:
        response = tenant.client.request(method, _with_ids(path), headers=agent.headers,
                                         json={} if method == "POST" else None)
        assert response.status_code == 401, f"{method} {path}"
        assert response.json()["error"]["code"] == "UNAUTHENTICATED", f"{method} {path}"


def test_every_governance_history_table_rejects_update_delete_and_truncate(attacker_sql):
    tables = [row[0] for row in attacker_sql.execute(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND c.relkind = 'r' AND (c.relname LIKE 'governance_%%' "
        "OR c.relname LIKE 'risk_%%' OR c.relname LIKE 'asset_profile_%%')"
    ).fetchall()]
    history = sorted(set(tables) - MUTABLE)
    assert len(history) >= 17

    for table in history:
        triggers = attacker_sql.execute(
            "SELECT t.tgtype FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid "
            "WHERE t.tgrelid = %s::regclass AND p.proname = 'aegis_reject_mutation' "
            "AND NOT t.tgisinternal", (table,),
        ).fetchall()
        # tgtype bits: 1 row, 8 delete, 16 update, 32 truncate.
        row_guard = any(t & 1 and t & 8 and t & 16 for (t,) in triggers)
        truncate_guard = any(t & 32 for (t,) in triggers)
        assert row_guard and truncate_guard, table


def test_evidence_content_never_reaches_the_logs(world, tenant):
    """A database refusal must not log the statement's parameters, which hold the evidence."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("aegis")
    logger.addHandler(handler)
    try:
        asset_id = assessed_asset(tenant)
        # PostgreSQL refuses a NUL byte in text, after validation has passed.
        for source, description in (
            ({"source_type": "inline", "content_text": MARKER + "\u0000"}, "Synthetic."),
            ({"source_type": "inline", "content_text": "Synthetic."}, MARKER + "\u0000"),
        ):
            response = tenant.post("/governance/evidence", {
                "asset_id": asset_id, "category": "model_evaluation",
                "description": description, "source": source,
            })
            # Today this is a 500 (REMEDIATION_PLAN risk 23). A future 422 also passes: what
            # matters here is that the write is refused and the value is not logged.
            assert not 200 <= response.status_code < 300
            assert MARKER not in response.text
    finally:
        logger.removeHandler(handler)

    assert MARKER not in stream.getvalue()


def test_latest_review_is_the_latest_by_audit_sequence_not_by_clock(world, tenant):
    """The asset page reads the newest review with limit=1. A clock that steps back must not
    make it show the withdrawn review instead of the open one."""
    holder = reviewers(tenant)
    first = submitted(tenant)
    asset_id = first["asset_id"]
    response = tenant.post(f"{APPROVALS}/{first['id']}/request-information",
                           {"reason": "Please attach the design review."}, headers=holder)
    assert response.status_code == 200, response.text
    earlier = datetime.fromisoformat(first["submitted_at"]) - timedelta(hours=1)
    world.app.state.container.clock = lambda: earlier

    second = submitted(tenant, asset_id, reason="Added the design review.")

    listed = tenant.get(APPROVALS, asset_id=asset_id, limit=1).json()
    assert listed["total"] == 2
    assert [item["id"] for item in listed["items"]] == [second["id"]]
    both = tenant.get(APPROVALS, asset_id=asset_id).json()["items"]
    assert [item["id"] for item in both] == [second["id"], first["id"]]


def _broken_check(*args, **kwargs):
    raise RuntimeError("synthetic governance failure")


@pytest.mark.parametrize(("action", "reason_code"), [
    ("suspend", "GOVERNANCE_BLOCKED"),
    ("revoke", "GOVERNANCE_BLOCKED"),
    ("retire", "GOVERNANCE_RETIRED"),
])
def test_an_evaluation_error_never_lets_a_blocked_asset_through_in_observe(
        world, tenant, monkeypatch, action, reason_code):
    """Spec 11.6: decisions a person made apply in both modes, even when the check fails."""
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    response = tenant.post(f"/governance/assets/{agent.asset_id}/{action}",
                           {"reason": "Synthetic lifecycle change."})
    assert response.status_code == 201, response.text
    monkeypatch.setattr(gateway_check, "check", _broken_check)

    response = agent.act("calculate", params=PARAMS)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["outcome"], body["reason_code"]) == ("DENY", reason_code)
    assert world.spy.calls == []


@pytest.mark.parametrize(("action", "reason_code"), [
    ("suspend", "GOVERNANCE_BLOCKED"),
    ("retire", "GOVERNANCE_RETIRED"),
])
def test_an_evaluation_error_on_a_blocked_asset_keeps_its_reason_in_enforce(
        world, tenant, attacker_sql, monkeypatch, action, reason_code):
    """The fallback names the person's decision in enforce too, and records it in the check row."""
    tenant.allow_everything()
    agent = tenant.governed_agent(tools=["calculate"])
    response = tenant.post(f"/governance/assets/{agent.asset_id}/{action}",
                           {"reason": "Synthetic lifecycle change."})
    assert response.status_code == 201, response.text
    decision_id = response.json()["id"]
    tenant.set_enforcement("enforce")
    monkeypatch.setattr(gateway_check, "check", _broken_check)

    response = agent.act("calculate", params=PARAMS)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["outcome"], body["reason_code"]) == ("DENY", reason_code)
    assert world.spy.calls == []
    row = attacker_sql.execute(
        "SELECT mode, verdict, reason_code, governance_decision_id::text "
        "FROM governance_gateway_checks WHERE request_id = %s", (body["request_id"],),
    ).fetchone()
    assert row == ("enforce", "DENY", reason_code, decision_id)


def test_provisioning_errors_do_not_carry_their_parameters(urls, new_tenant):
    """The owner-role engines hide bound values too: a refused user insert must not put the
    password hash into the exception text that a caller might log."""
    tenant_id = new_tenant()
    email = f"synthetic-{uuid4().hex[:8]}@example.test"
    create_user(urls.owner, tenant_id, email=email, password=PASSWORD, role="viewer")

    with pytest.raises(IntegrityError) as raised:
        create_user(urls.owner, tenant_id, email=email, password=PASSWORD, role="viewer")

    assert "$argon2" not in str(raised.value)
