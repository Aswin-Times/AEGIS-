"""Governance policies: immutable versions, who may change their status, and when they apply."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aegis.governance.engine.policies import evaluate_policies
from aegis.governance.policies import PolicyIntegrityError, applicable_documents
from aegis.governance.profile import AssetProfile

POLICIES = "/governance/policies"
HOUR = timedelta(hours=1)


def stamp(moment: datetime) -> str:
    return moment.isoformat()


def policy_document(**controls):
    return {
        "description": "a synthetic test policy",
        "severity": "medium",
        "applicability": {},
        "controls": controls,
    }


def version_body(document=None, effective_from=None, review_by=None, **controls):
    body = {
        "document": document if document is not None else policy_document(**controls),
        "effective_from": stamp(effective_from or datetime.now(UTC) - HOUR),
    }
    if review_by is not None:
        body["review_by"] = stamp(review_by)
    return body


def create_policy(tenant, name=None, category="general", headers=None):
    return tenant.post(POLICIES, {"name": name if name is not None else f"policy-{uuid4().hex[:8]}",
                                  "category": category}, headers=headers)


def new_policy(tenant, **kwargs) -> dict:
    response = create_policy(tenant, **kwargs)
    assert response.status_code == 201, response.text
    return response.json()


def create_version(tenant, policy_id, headers=None, **kwargs):
    return tenant.post(f"{POLICIES}/{policy_id}/versions", version_body(**kwargs), headers=headers)


def new_version(tenant, policy_id, **kwargs) -> dict:
    response = create_version(tenant, policy_id, **kwargs)
    assert response.status_code == 201, response.text
    return response.json()


def path(policy_id, version_id, action):
    return f"{POLICIES}/{policy_id}/versions/{version_id}/{action}"


def two_reviewers(tenant):
    """The first admin and a second admin, who each hold governance_reviewer."""
    second = tenant.login_as("second-admin", "admin")
    if not getattr(tenant, "reviewers_granted", False):
        tenant.grant_governance("admin", by="second-admin")
        tenant.grant_governance("second-admin", by="admin")
        tenant.reviewers_granted = True
    return second


def approved_version(tenant, policy_id, **kwargs) -> dict:
    """A version created by the first admin and approved by the second."""
    second = two_reviewers(tenant)
    version = new_version(tenant, policy_id, **kwargs)
    response = tenant.post(path(policy_id, version["id"], "approve"), headers=second)
    assert response.status_code == 200, response.text
    return response.json()


def active_version(tenant, policy_id, **kwargs) -> dict:
    version = approved_version(tenant, policy_id, **kwargs)
    response = tenant.post(path(policy_id, version["id"], "activate"))
    assert response.status_code == 200, response.text
    return response.json()


def listing(tenant) -> list[dict]:
    response = tenant.get(POLICIES)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def version_of(tenant, policy_id, version_id) -> dict:
    policy = next(item for item in listing(tenant) if item["id"] == policy_id)
    return next(item for item in policy["versions"] if item["id"] == version_id)


def force(attacker_sql, sql, params=()):
    """Run SQL as a compromised database owner, with the append-only triggers switched off."""
    with attacker_sql.transaction():
        attacker_sql.execute("SET LOCAL session_replication_role = replica")
        attacker_sql.execute(sql, params)


def applicable(db, tenant, now=None):
    with db.tenant_transaction(tenant.id) as session:
        return applicable_documents(session, now or datetime.now(UTC))


# Immutability


def test_policy_version_cannot_be_changed(db, tenant, attacker_sql):
    policy = new_policy(tenant)
    version = new_version(tenant, policy["id"], minimum_approvers=2)
    for sql in (
        "UPDATE governance_policies SET name = 'renamed'",
        "DELETE FROM governance_policies",
        "UPDATE governance_policy_versions SET document_canonical = '{}'",
        "UPDATE governance_policy_versions SET content_hash = repeat('0', 64)",
        "UPDATE governance_policy_versions SET effective_from = now()",
        "DELETE FROM governance_policy_versions",
        "UPDATE governance_policy_events SET actor_id = actor_id",
        "DELETE FROM governance_policy_events",
    ):
        with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
            session.execute(text(sql))
    for table in ("governance_policies", "governance_policy_versions",
                  "governance_policy_events"):
        with pytest.raises(psycopg.Error, match="append-only"):
            attacker_sql.execute(f"TRUNCATE {table} CASCADE")
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute(
            "UPDATE governance_policy_versions SET document_canonical = '{}' WHERE id = %s",
            (version["id"],),
        )
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute("DELETE FROM governance_policy_versions WHERE id = %s",
                             (version["id"],))
    assert version_of(tenant, policy["id"], version["id"])["document"]["controls"] == {
        "minimum_approvers": 2
    }


def test_new_version_leaves_old_version_intact(tenant, attacker_sql):
    policy = new_policy(tenant)
    first = active_version(tenant, policy["id"], minimum_approvers=2)
    before = attacker_sql.execute(
        "SELECT document_canonical, content_hash, effective_from FROM governance_policy_versions "
        "WHERE id = %s", (first["id"],)
    ).fetchone()

    second = new_version(tenant, policy["id"], minimum_approvers=1)
    assert (first["version"], second["version"]) == (1, 2)
    assert second["id"] != first["id"] and second["content_hash"] != first["content_hash"]

    after = attacker_sql.execute(
        "SELECT document_canonical, content_hash, effective_from FROM governance_policy_versions "
        "WHERE id = %s", (first["id"],)
    ).fetchone()
    assert after == before
    old = version_of(tenant, policy["id"], first["id"])
    assert (old["approved"], old["active"]) == (True, True)
    assert old["document"]["controls"] == {"minimum_approvers": 2}
    new = version_of(tenant, policy["id"], second["id"])
    assert (new["approved"], new["active"]) == (False, False)


def test_content_hash_covers_the_policy_number_window_and_document(tenant, attacker_sql):
    from aegis.canonical import canonical_json, sha256_hex

    policy = new_policy(tenant)
    start = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
    version = new_version(tenant, policy["id"], effective_from=start,
                          review_by=start + timedelta(days=30), required_evaluations=["b", "a"])
    canonical = attacker_sql.execute(
        "SELECT document_canonical FROM governance_policy_versions WHERE id = %s",
        (version["id"],),
    ).fetchone()[0]
    assert '"required_evaluations":["a","b"]' in canonical
    assert version["content_hash"] == sha256_hex(canonical_json({
        "policy_id": policy["id"],
        "version": 1,
        "effective_from": "2026-01-02T03:04:05.123456Z",
        "review_by": "2026-02-01T03:04:05.123456Z",
        "document": canonical,
    }))


def test_a_window_in_another_zone_still_matches_after_a_round_trip(db, tenant):
    policy = new_policy(tenant)
    zone = timezone(timedelta(hours=5, minutes=30))
    start = datetime.now(UTC).astimezone(zone) - 2 * HOUR
    version = active_version(tenant, policy["id"], effective_from=start,
                             review_by=start + timedelta(days=1, microseconds=7),
                             minimum_approvers=2)
    (item,) = applicable(db, tenant)
    assert item.version_id == UUID(version["id"])
    assert tenant.get(POLICIES).status_code == 200


# Validation


def test_unknown_document_key_rejected(tenant):
    policy = new_policy(tenant)
    base = policy_document()
    for bad in (
        {**base, "surprise": 1},
        {**base, "controls": {"unknown_control": True}},
        {**base, "controls": {"minimum_approvers": 3}},
        {**base, "controls": {"minimum_approvers": True}},
        {**base, "applicability": {"regions": ["eu"]}},
        {**base, "severity": "urgent"},
        {"severity": "low"},
    ):
        response = create_version(tenant, policy["id"], document=bad)
        assert response.status_code == 422, bad
    assert tenant.post(f"{POLICIES}/{policy['id']}/versions",
                       {**version_body(), "tenant_id": str(tenant.id)}).status_code == 422
    assert tenant.audit_events("governance.policy_version_created") == []
    assert listing(tenant)[0]["versions"] == []


def test_effective_window_is_required_and_must_be_aware_and_ordered(tenant):
    policy = new_policy(tenant)
    url = f"{POLICIES}/{policy['id']}/versions"
    now = datetime.now(UTC)
    good = policy_document()
    assert tenant.post(url, {"document": good}).status_code == 422
    for body in (
        {"document": good, "effective_from": "2026-01-01T00:00:00"},
        {"document": good, "effective_from": stamp(now), "review_by": "2027-01-01T00:00:00"},
        {"document": good, "effective_from": stamp(now), "review_by": stamp(now)},
        {"document": good, "effective_from": stamp(now), "review_by": stamp(now - HOUR)},
        {"document": good, "effective_from": "not a date"},
    ):
        assert tenant.post(url, body).status_code == 422, body
    assert tenant.post(url, {"document": good, "effective_from": stamp(now),
                             "review_by": stamp(now + HOUR)}).status_code == 201


def test_policy_names_are_unique_per_tenant(tenant, world):
    new_policy(tenant, name="Data handling")
    duplicate = create_policy(tenant, name="Data handling")
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "POLICY_NAME_TAKEN"
    assert len(tenant.audit_events("governance.policy_created")) == 1
    assert create_policy(world.tenant(), name="Data handling").status_code == 201
    assert create_policy(tenant, name="").status_code == 422
    assert create_policy(tenant, category="").status_code == 422


def test_versions_are_numbered_per_policy_in_sequence(tenant):
    first, second = new_policy(tenant), new_policy(tenant)
    numbers = [new_version(tenant, first["id"], minimum_approvers=1)["version"] for _ in range(3)]
    assert numbers == [1, 2, 3]
    assert new_version(tenant, second["id"])["version"] == 1
    assert create_version(tenant, uuid4()).status_code == 404


def test_concurrent_versions_get_distinct_numbers(tenant):
    policy = new_policy(tenant)
    headers = tenant.admin
    barrier = threading.Barrier(4)

    def run(number):
        barrier.wait(timeout=30)
        return create_version(tenant, policy["id"], headers=headers,
                              minimum_approvers=1 + number % 2)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [future.result(timeout=60)
                   for future in [pool.submit(run, n) for n in range(4)]]
    assert [r.status_code for r in results] == [201] * 4
    assert sorted(r.json()["version"] for r in results) == [1, 2, 3, 4]
    assert tenant.verify_audit()["valid"] is True


# Approval and activation


def test_approver_must_differ_from_creator(tenant):
    two_reviewers(tenant)  # The creator holds the role too.
    policy = new_policy(tenant)
    version = new_version(tenant, policy["id"])

    refused = tenant.post(path(policy["id"], version["id"], "approve"))
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "SELF_APPROVAL_REFUSED"
    assert tenant.audit_events("governance.policy_version_approved") == []
    assert len(tenant.audit_events("authz.denied")) == 1
    assert version_of(tenant, policy["id"], version["id"])["approved"] is False

    approved = tenant.post(path(policy["id"], version["id"], "approve"),
                           headers=tenant.login_as("second-admin", "admin"))
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["approved"] is True
    assert body["approved_by"] == tenant.user_id("second-admin")
    assert body["created_by"] == tenant.user_id("admin")
    events = tenant.audit_events("governance.policy_version_approved")
    assert len(events) == 1 and events[0]["subject_id"] == version["id"]

    again = tenant.post(path(policy["id"], version["id"], "approve"),
                        headers=tenant.login_as("second-admin", "admin"))
    assert again.status_code == 409 and again.json()["error"]["code"] == "ALREADY_APPROVED"


def test_only_reviewer_holder_can_approve(tenant):
    policy = new_policy(tenant)
    version = new_version(tenant, policy["id"])
    target = path(policy["id"], version["id"], "approve")
    # Neither an admin nor a reviewer is enough without the grant.
    for headers in (tenant.admin, tenant.reviewer, tenant.viewer):
        assert tenant.post(target, headers=headers).status_code == 403
    assert tenant.audit_events("governance.policy_version_approved") == []

    tenant.grant_governance("reviewer")
    approved = tenant.post(target, headers=tenant.reviewer)
    assert approved.status_code == 200
    assert approved.json()["approved_by"] == tenant.user_id("reviewer")


def test_only_an_admin_authors_activates_or_deactivates(tenant):
    two_reviewers(tenant)
    tenant.grant_governance("reviewer")
    policy = new_policy(tenant)
    version = approved_version(tenant, policy["id"])
    for headers in (tenant.reviewer, tenant.viewer):
        assert create_policy(tenant, headers=headers).status_code == 403
        assert create_version(tenant, policy["id"], headers=headers).status_code == 403
        assert tenant.post(path(policy["id"], version["id"], "activate"),
                           headers=headers).status_code == 403
        assert tenant.post(path(policy["id"], version["id"], "deactivate"),
                           headers=headers).status_code == 403
    # Holding the reviewer role does not let someone else's admin work be done by a non-admin.
    assert version_of(tenant, policy["id"], version["id"])["active"] is False
    assert tenant.post(path(policy["id"], version["id"], "activate")).status_code == 200
    assert tenant.post(path(policy["id"], version["id"], "deactivate"),
                       headers=tenant.reviewer).status_code == 403
    assert tenant.post(path(policy["id"], version["id"], "deactivate")).status_code == 200


def test_unapproved_version_cannot_be_activated(tenant):
    policy = new_policy(tenant)
    version = new_version(tenant, policy["id"])
    refused = tenant.post(path(policy["id"], version["id"], "activate"))
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "POLICY_VERSION_NOT_APPROVED"
    assert tenant.audit_events("governance.policy_version_activated") == []
    assert version_of(tenant, policy["id"], version["id"])["active"] is False


def test_activation_state_is_checked_in_both_directions(tenant):
    policy = new_policy(tenant)
    version = approved_version(tenant, policy["id"])
    activate, deactivate = (
        path(policy["id"], version["id"], action) for action in ("activate", "deactivate")
    )
    never_active = tenant.post(deactivate)
    assert never_active.status_code == 409 and never_active.json()["error"]["code"] == "NOT_ACTIVE"
    assert tenant.post(activate).status_code == 200
    twice = tenant.post(activate)
    assert twice.status_code == 409 and twice.json()["error"]["code"] == "ALREADY_ACTIVE"
    assert tenant.post(deactivate).status_code == 200
    assert tenant.post(deactivate).status_code == 409


def test_activation_history_is_append_only_and_audited(db, tenant, attacker_sql):
    policy = new_policy(tenant)
    version = approved_version(tenant, policy["id"])
    steps = ["activate", "deactivate", "activate"]
    for step in steps:
        assert tenant.post(path(policy["id"], version["id"], step)).status_code == 200
    assert version_of(tenant, policy["id"], version["id"])["active"] is True

    events = attacker_sql.execute(
        "SELECT e.event FROM governance_policy_events e JOIN audit_events a "
        "ON a.id = e.audit_event_id WHERE e.policy_version_id = %s ORDER BY a.seq",
        (version["id"],),
    ).fetchall()
    assert [row[0] for row in events] == ["APPROVED", "ACTIVATED", "DEACTIVATED", "ACTIVATED"]
    for event_type, expected in (("activated", 2), ("deactivated", 1), ("approved", 1),
                                 ("created", 1)):
        found = tenant.audit_events(f"governance.policy_version_{event_type}")
        assert len(found) == expected, event_type
        assert all(not isinstance(v, float) for e in found for v in e["payload"].values())
    assert tenant.verify_audit()["valid"] is True

    # The status of a version is the latest event by audit sequence, so a later row is enough to
    # change it and an earlier one never is, whatever the timestamps say.
    force(attacker_sql, "UPDATE governance_policy_events SET created_at = now() "
                        "WHERE event = 'ACTIVATED'")
    assert version_of(tenant, policy["id"], version["id"])["active"] is True
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute("DELETE FROM governance_policy_events")


def test_database_guards_approval_and_activation(db, tenant):
    """Below the service: the creator cannot approve, and an unapproved version cannot activate."""
    policy = new_policy(tenant)
    version = new_version(tenant, policy["id"])
    creator = UUID(tenant.user_id("admin"))

    def insert_event(event, actor):
        with db.tenant_transaction(tenant.id) as session:
            audit = session.execute(text("SELECT id FROM audit_events ORDER BY seq DESC")).first()
            session.execute(
                text(
                    "INSERT INTO governance_policy_events "
                    "(id, tenant_id, policy_version_id, event, actor_id, audit_event_id) "
                    "VALUES (:id, :tenant, :version, :event, :actor, :audit)"
                ),
                {"id": uuid4(), "tenant": tenant.id, "version": version["id"], "event": event,
                 "actor": actor, "audit": audit[0]},
            )

    with pytest.raises(DBAPIError, match="creator"):
        insert_event("APPROVED", creator)
    with pytest.raises(DBAPIError, match="approved"):
        insert_event("ACTIVATED", creator)
    assert version_of(tenant, policy["id"], version["id"])["approved"] is False


# The effective window


def test_version_outside_effective_window_does_not_apply(db, tenant):
    policy = new_policy(tenant)
    now = datetime.now(UTC)
    future = active_version(tenant, policy["id"], effective_from=now + 2 * HOUR,
                            minimum_approvers=2)
    assert applicable(db, tenant, now) == []
    assert applicable(db, tenant, now + HOUR) == []
    documents = applicable(db, tenant, now + 3 * HOUR)
    assert [d.version_id for d in documents] == [UUID(future["id"])]
    # The boundary itself applies: now >= effective_from.
    boundary = datetime.fromisoformat(future["effective_from"])
    assert [d.version_id for d in applicable(db, tenant, boundary)] == [UUID(future["id"])]
    assert applicable(db, tenant, boundary - timedelta(microseconds=1)) == []


def test_only_approved_and_active_versions_apply(db, tenant):
    policy = new_policy(tenant)
    unapproved = new_version(tenant, policy["id"])
    assert applicable(db, tenant) == []
    approved = approved_version(tenant, policy["id"])
    assert applicable(db, tenant) == []
    tenant.post(path(policy["id"], approved["id"], "activate"))
    assert [d.version_id for d in applicable(db, tenant)] == [UUID(approved["id"])]
    tenant.post(path(policy["id"], approved["id"], "deactivate"))
    assert applicable(db, tenant) == []
    assert unapproved["id"] != approved["id"]


def test_applicable_documents_carry_the_document_and_name(db, tenant):
    policy = new_policy(tenant, name="Provider list")
    version = active_version(tenant, policy["id"], permitted_model_providers=["Acme"])
    (item,) = applicable(db, tenant)
    assert (item.version_id, item.policy_id, item.name) == (
        UUID(version["id"]), UUID(policy["id"]), "Provider list"
    )
    assert item.document.controls.permitted_model_providers == ["Acme"]
    assert item.review_overdue is False


def test_a_passed_review_date_still_applies_and_is_visible(db, tenant):
    policy = new_policy(tenant)
    now = datetime.now(UTC)
    active_version(tenant, policy["id"], effective_from=now - 3 * HOUR, review_by=now + HOUR,
                   minimum_approvers=2, permitted_model_providers=["Nobody"])
    (current,) = applicable(db, tenant, now)
    assert current.review_overdue is False
    (overdue,) = applicable(db, tenant, now + 2 * HOUR)
    assert overdue.review_overdue is True

    outcome = evaluate_policies([overdue], AssetProfile(model_provider="Acme"), "HIGH", set())
    assert outcome.minimum_approvers == 2
    assert [f.control for f in outcome.findings] == ["permitted_model_providers", "review_by"]
    assert evaluate_policies([current], AssetProfile(model_provider="Acme"), "HIGH",
                             set()).findings[0].control == "permitted_model_providers"


def test_two_active_versions_both_apply_and_the_stricter_wins(db, tenant):
    first, second = new_policy(tenant), new_policy(tenant)
    active_version(tenant, first["id"], minimum_approvers=1, self_approval="permitted")
    active_version(tenant, second["id"], self_approval="prohibited", minimum_approvers=2)
    outcome = evaluate_policies(applicable(db, tenant), AssetProfile(), None, set())
    assert outcome.minimum_approvers == 2
    assert outcome.self_approval_permitted is False


# Integrity


TAMPERS = [
    "content_hash = repeat('0', 64)",
    # The window and the numbering decide whether a version applies, so they are covered too.
    "effective_from = effective_from + interval '1 day'",
    "effective_from = effective_from - interval '1 microsecond'",
    "review_by = review_by - interval '1 day'",
    "review_by = NULL",
    "version = version + 10",
    "policy_id = (SELECT id FROM governance_policies WHERE id <> policy_id AND tenant_id = "
    "governance_policy_versions.tenant_id LIMIT 1)",
    "document_canonical = replace(document_canonical, '\"minimum_approvers\":1', "
    "'\"minimum_approvers\":2')",
    "document_canonical = '{\"surprise\":1}', content_hash = encode(sha256('{\"surprise\":1}'), "
    "'hex')",
]


@pytest.mark.parametrize("tamper", TAMPERS)
def test_tampered_version_fails_closed(db, tenant, attacker_sql, tamper, world):
    other = world.tenant()
    other_policy = new_policy(other)
    active_version(other, other_policy["id"], minimum_approvers=1)

    policy = new_policy(tenant)
    new_policy(tenant)  # Somewhere else for a version to be moved to.
    healthy = new_version(tenant, policy["id"], required_evaluations=["bias"])
    version = active_version(tenant, policy["id"], minimum_approvers=1,
                             review_by=datetime.now(UTC) + 30 * 24 * HOUR)
    second = tenant.login_as("second-admin", "admin")
    force(attacker_sql, f"UPDATE governance_policy_versions SET {tamper} WHERE id = %s",
          (version["id"],))

    with pytest.raises(PolicyIntegrityError):
        applicable(db, tenant)
    # Never skipped: skipping a policy could silently drop a requirement.
    read = tenant.get(POLICIES)
    assert read.status_code == 503
    assert read.json()["error"]["code"] == "POLICY_INTEGRITY_FAILED"
    for action in ("approve", "activate", "deactivate"):
        response = tenant.post(path(policy["id"], version["id"], action),
                               headers=second if action == "approve" else None)
        if "policy_id" in tamper:  # Under another policy now, so not found under this one.
            assert response.status_code == 404, action
            continue
        assert response.status_code == 503, action
        assert response.json()["error"]["code"] == "POLICY_INTEGRITY_FAILED"
    # A version of the same policy that is intact can still be created.
    assert create_version(tenant, policy["id"]).status_code == 201
    assert healthy["id"] != version["id"]
    # Another tenant is unaffected.
    assert len(applicable(db, other)) == 1
    assert other.get(POLICIES).status_code == 200


def test_tampered_version_that_does_not_apply_does_not_block_the_rest(db, tenant, attacker_sql):
    policy = new_policy(tenant)
    unused = new_version(tenant, policy["id"])
    force(attacker_sql, "UPDATE governance_policy_versions SET content_hash = repeat('0', 64) "
                        "WHERE id = %s", (unused["id"],))
    assert applicable(db, tenant) == []
    # But reading it is refused.
    assert tenant.get(POLICIES).status_code == 503


# Separation from runtime policies


def test_governance_policies_are_separate_from_runtime_policies(db, tenant, attacker_sql):
    runtime = tenant.allow_everything()
    runtime_before = tenant.get("/policies").json()
    active_before = attacker_sql.execute(
        "SELECT active_policy_version_id FROM tenants WHERE id = %s", (tenant.id,)
    ).fetchone()[0]
    counts_before = attacker_sql.execute(
        "SELECT (SELECT count(*) FROM policies), (SELECT count(*) FROM policy_versions)"
    ).fetchone()

    policy = new_policy(tenant, name="Governance only")
    active_version(tenant, policy["id"], minimum_approvers=2)

    assert tenant.get("/policies").json() == runtime_before
    assert str(attacker_sql.execute(
        "SELECT active_policy_version_id FROM tenants WHERE id = %s", (tenant.id,)
    ).fetchone()[0]) == str(active_before) == runtime["id"]
    assert attacker_sql.execute(
        "SELECT (SELECT count(*) FROM policies), (SELECT count(*) FROM policy_versions)"
    ).fetchone() == counts_before
    assert [item["name"] for item in listing(tenant)] == ["Governance only"]
    assert all(item["name"] != "Governance only" for item in runtime_before["items"])


# Access


def test_any_authenticated_user_can_read_policies(tenant):
    new_policy(tenant)
    for role in ("admin", "reviewer", "viewer"):
        assert tenant.get(POLICIES, headers=tenant.login(role)).status_code == 200


def test_agent_principal_cannot_use_policy_routes(tenant):
    agent = tenant.agent()
    for method, route in [
        ("get", POLICIES),
        ("post", POLICIES),
        ("post", f"{POLICIES}/{uuid4()}/versions"),
        ("post", path(uuid4(), uuid4(), "approve")),
        ("post", path(uuid4(), uuid4(), "activate")),
        ("post", path(uuid4(), uuid4(), "deactivate")),
    ]:
        response = getattr(tenant.client, method)(f"/api/v1{route}", headers=agent.headers)
        assert response.status_code == 401, route


def test_unknown_policy_or_version_is_not_found(tenant):
    two_reviewers(tenant)
    second = tenant.login_as("second-admin", "admin")
    policy, other = new_policy(tenant), new_policy(tenant)
    version = new_version(tenant, policy["id"])
    for action, headers in (("approve", second), ("activate", None), ("deactivate", None)):
        assert tenant.post(path(policy["id"], uuid4(), action), headers=headers).status_code == 404
        assert tenant.post(path(uuid4(), version["id"], action), headers=headers).status_code == 404
        # The version exists, but under another policy.
        assert tenant.post(path(other["id"], version["id"], action),
                           headers=headers).status_code == 404
    assert tenant.audit_events("governance.policy_version_approved") == []
