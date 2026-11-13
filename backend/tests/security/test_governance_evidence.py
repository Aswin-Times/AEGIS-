"""Evidence is submitted by an admin and verified by someone else; only verified evidence counts."""

from datetime import UTC, datetime
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aegis.canonical import sha256_hex
from support import (
    activate_policy,
    approve,
    assessed_asset,
    error_code,
    reviewers,
    save_profile,
    submitted,
)

EVIDENCE = "/governance/evidence"
TEXT = "Synthetic model evaluation: the held-out accuracy was recorded."


def inline(content=TEXT, **extra):
    return {"source_type": "inline", "content_text": content, **extra}


def external(content="alpha"):
    return {"source_type": "external_reference", "source_uri": "https://example.test/report",
            "content_sha256": sha256_hex(content)}


def internal(record_type, record_id):
    return {"source_type": "internal_record", "record_type": record_type,
            "record_id": str(record_id)}


def submit_evidence(tenant, asset_id, source=None, category="model_evaluation", headers=None,
                    **extra):
    return tenant.post(EVIDENCE, {"asset_id": asset_id, "category": category,
                                  "description": "Synthetic evidence.",
                                  "source": source or inline(), **extra}, headers=headers)


def evidence_of(tenant, asset_id, source=None, **kwargs) -> dict:
    response = submit_evidence(tenant, asset_id, source, **kwargs)
    assert response.status_code == 201, response.text
    return response.json()


def verify(tenant, evidence_id, headers, outcome="VERIFIED", method="content_recomputed",
           note="Checked by a reviewer.", **extra):
    return tenant.post(f"{EVIDENCE}/{evidence_id}/verify",
                       {"outcome": outcome, "method": method, "note": note, **extra},
                       headers=headers)


def verification_rows(attacker_sql, evidence_id):
    return attacker_sql.execute(
        "SELECT outcome, method FROM governance_evidence_verifications WHERE evidence_id = %s",
        (evidence_id,),
    ).fetchall()


def current(tenant, evidence_id):
    return tenant.get(f"{EVIDENCE}/{evidence_id}").json()["current_verification"]


def assert_nothing_verified(tenant, attacker_sql, evidence_id):
    assert verification_rows(attacker_sql, evidence_id) == []
    assert tenant.audit_events("governance.evidence_verified") == []
    assert current(tenant, evidence_id) == "UNVERIFIED"
    assert tenant.verify_audit()["valid"] is True


def tamper(attacker_sql, table, statement, params):
    """Change a row as a superuser could, with the protective triggers off."""
    attacker_sql.execute(f"ALTER TABLE {table} DISABLE TRIGGER USER")
    try:
        attacker_sql.execute(statement, params)
    finally:
        attacker_sql.execute(f"ALTER TABLE {table} ENABLE TRIGGER USER")


def assessment_id_of(tenant, asset_id):
    return tenant.get(f"/governance/assets/{asset_id}/assessments").json()["items"][0]["id"]


def decision_id_of(tenant, asset_id):
    history = tenant.get(f"/governance/assets/{asset_id}/history").json()["items"]
    return next(item["id"] for item in history if item["type"] == "decision")


def make_incident(world, tenant):
    from aegis.correlation.engine import process_tenant

    tenant.allow_everything()
    agent = tenant.agent()
    for _ in range(3):
        agent.act("run_shell_command")
    container = world.app.state.container
    process_tenant(container.db, tenant.id, clock=container.clock)
    return tenant.get("/incidents", rule_key="repeated_unauthorized_tools").json()["items"][0]


# Who may do what


def test_only_an_admin_submits_evidence(tenant):
    asset = tenant.asset()["id"]
    for headers in (tenant.reviewer, tenant.viewer):
        assert submit_evidence(tenant, asset, headers=headers).status_code == 403
    assert tenant.get(EVIDENCE).json()["total"] == 0
    assert submit_evidence(tenant, asset, headers=tenant.admin).status_code == 201


def test_new_evidence_is_unverified_and_does_not_count(tenant):
    reviewers(tenant)
    asset = assessed_asset(tenant)
    created = evidence_of(tenant, asset)
    assert created["current_verification"] == "UNVERIFIED"
    assert created["latest_verification"] is None
    assert created["content_sha256"] == sha256_hex(TEXT)
    overview = tenant.get("/governance/overview").json()
    assert (overview["evidence_verified"], overview["evidence_total"]) == (0, 1)
    assert tenant.get(EVIDENCE, verification="UNVERIFIED").json()["total"] == 1
    assert tenant.get(EVIDENCE, verification="VERIFIED").json()["total"] == 0

    second = tenant.login_as("second-admin", "admin")
    assert verify(tenant, created["id"], second).status_code == 201
    overview = tenant.get("/governance/overview").json()
    assert (overview["evidence_verified"], overview["evidence_total"]) == (1, 1)


def test_submitter_cannot_verify_own_evidence(tenant, attacker_sql):
    reviewers(tenant)  # the first admin submits, and holds the role
    created = evidence_of(tenant, tenant.asset()["id"])

    refused = verify(tenant, created["id"], tenant.admin)
    assert (refused.status_code, error_code(refused)) == (403, "SELF_VERIFICATION_REFUSED")
    assert verification_rows(attacker_sql, created["id"]) == []
    assert tenant.audit_events("governance.evidence_verified") == []

    # Below the service, the same refusal holds for a direct insert.
    submitter = tenant.user_id("admin")
    event = attacker_sql.execute(
        "SELECT id FROM audit_events WHERE tenant_id = %s ORDER BY seq LIMIT 1", (tenant.id,)
    ).fetchone()[0]
    with pytest.raises(psycopg.Error, match="submitter"):
        attacker_sql.execute(
            "INSERT INTO governance_evidence_verifications (id, tenant_id, evidence_id, outcome, "
            "method, note, verified_by, verified_at, audit_event_id) "
            "VALUES (%s, %s, %s, 'VERIFIED', 'manual_attestation', 'x', %s, now(), %s)",
            (uuid4(), tenant.id, created["id"], submitter, event),
        )
    assert verification_rows(attacker_sql, created["id"]) == []


def test_plain_reviewer_cannot_verify(tenant, attacker_sql):
    reviewers(tenant)
    created = evidence_of(tenant, tenant.asset()["id"])
    # A reviewer role, or a viewer, without the governance grant.
    for headers in (tenant.reviewer, tenant.viewer):
        assert verify(tenant, created["id"], headers).status_code == 403
    assert verification_rows(attacker_sql, created["id"]) == []


# Hashes


def test_inline_hash_is_computed_not_trusted(tenant):
    asset = tenant.asset()["id"]
    forged = submit_evidence(tenant, asset, inline(content_sha256=sha256_hex("something else")))
    assert forged.status_code == 422, forged.text
    assert tenant.get(EVIDENCE).json()["total"] == 0

    created = evidence_of(tenant, asset)
    assert created["content_sha256"] == sha256_hex(TEXT)


def test_inline_verification_recomputes_hash(tenant, attacker_sql):
    second = reviewers(tenant)
    created = evidence_of(tenant, tenant.asset()["id"])
    tamper(attacker_sql, "governance_evidence",
           "UPDATE governance_evidence SET content_text = 'rewritten afterwards' WHERE id = %s",
           (created["id"],))

    refused = verify(tenant, created["id"], second)
    assert (refused.status_code, error_code(refused)) == (409, "HASH_MISMATCH")
    assert_nothing_verified(tenant, attacker_sql, created["id"])

    # The check is free for inline text, so attesting cannot skip it.
    attested = verify(tenant, created["id"], second, method="manual_attestation")
    assert (attested.status_code, error_code(attested)) == (409, "HASH_MISMATCH")
    assert_nothing_verified(tenant, attacker_sql, created["id"])


def test_inline_attestation_of_intact_text_reports_the_recomputed_hash(tenant):
    second = reviewers(tenant)
    created = evidence_of(tenant, tenant.asset()["id"])
    attested = verify(tenant, created["id"], second, method="manual_attestation")
    assert attested.status_code == 201, attested.text
    assert (attested.json()["method"], attested.json()["scope"]) == (
        "manual_attestation", "hash_recomputed")


# 2. the check is anchored to the audit event written at submission


def test_rewriting_text_and_hash_together_is_caught_by_the_submission_event(tenant, attacker_sql):
    second = reviewers(tenant)
    created = evidence_of(tenant, tenant.asset()["id"])
    forged = "rewritten with a matching hash"
    tamper(attacker_sql, "governance_evidence",
           "UPDATE governance_evidence SET content_text = %s, content_sha256 = %s WHERE id = %s",
           (forged, sha256_hex(forged), created["id"]))
    for method in ("content_recomputed", "manual_attestation"):
        refused = verify(tenant, created["id"], second, method=method)
        assert (refused.status_code, error_code(refused)) == (409, "HASH_MISMATCH"), method
    assert_nothing_verified(tenant, attacker_sql, created["id"])


def test_rewriting_the_category_is_caught_by_the_submission_event(tenant, attacker_sql):
    second = reviewers(tenant)
    created = evidence_of(tenant, tenant.asset()["id"], category="monitoring_records")
    tamper(attacker_sql, "governance_evidence",
           "UPDATE governance_evidence SET category = 'model_evaluation' WHERE id = %s",
           (created["id"],))
    refused = verify(tenant, created["id"], second)
    assert (refused.status_code, error_code(refused)) == (409, "HASH_MISMATCH")
    assert_nothing_verified(tenant, attacker_sql, created["id"])
    # A rejection only tightens, so it needs no intact record.
    assert verify(tenant, created["id"], second, outcome="REJECTED").status_code == 201


def test_external_reference_with_content_checks_hash(tenant, attacker_sql):
    second = reviewers(tenant)
    created = evidence_of(tenant, tenant.asset()["id"], external("alpha"))
    assert created["content_text"] is None and created["source_uri"] == "https://example.test/report"

    refused = verify(tenant, created["id"], second, content="beta")
    assert (refused.status_code, error_code(refused)) == (409, "HASH_MISMATCH")
    assert_nothing_verified(tenant, attacker_sql, created["id"])

    checked = verify(tenant, created["id"], second, content="alpha")
    assert checked.status_code == 201, checked.text
    assert (checked.json()["method"], checked.json()["scope"]) == (
        "content_recomputed", "hash_recomputed")


def test_external_reference_without_content_is_manual_attestation_only(tenant, attacker_sql):
    second = reviewers(tenant)
    created = evidence_of(tenant, tenant.asset()["id"], external())

    # Nothing to recompute from, so a recomputation cannot be claimed.
    assert verify(tenant, created["id"], second).status_code == 422
    assert verify(tenant, created["id"], second, method="internal_record_checked"
                  ).status_code == 422
    assert verification_rows(attacker_sql, created["id"]) == []

    attested = verify(tenant, created["id"], second, method="manual_attestation")
    assert attested.status_code == 201, attested.text
    assert (attested.json()["method"], attested.json()["scope"]) == (
        "manual_attestation", "attestation_only")
    detail = tenant.get(f"{EVIDENCE}/{created['id']}").json()
    assert detail["latest_verification"]["scope"] == "attestation_only"
    assert [item["method"] for item in detail["verifications"]] == ["manual_attestation"]

    # Content is for recomputing an external reference only.
    other = evidence_of(tenant, tenant.asset()["id"], external())
    assert verify(tenant, other["id"], second, method="manual_attestation", content="alpha"
                  ).status_code == 422
    inline_item = evidence_of(tenant, tenant.asset()["id"])
    assert verify(tenant, inline_item["id"], second, content=TEXT).status_code == 422


def test_a_rejection_needs_no_passing_check(tenant, attacker_sql):
    second = reviewers(tenant)
    created = evidence_of(tenant, tenant.asset()["id"], external("alpha"))
    rejected = verify(tenant, created["id"], second, outcome="REJECTED", content=None)
    assert rejected.status_code == 201
    assert rejected.json()["scope"] == "judgment_only"
    assert current(tenant, created["id"]) == "REJECTED"
    detail = tenant.get(f"{EVIDENCE}/{created['id']}").json()
    assert detail["latest_verification"]["scope"] == "judgment_only"


# Internal records


def test_internal_record_verification_checks_the_record(tenant, attacker_sql):
    second = reviewers(tenant)
    asset = assessed_asset(tenant)
    review = submitted(tenant, asset)
    assessment = assessment_id_of(tenant, asset)
    decision = decision_id_of(tenant, asset)
    first_event = tenant.audit_events()[0]["id"]
    decision_event = attacker_sql.execute(
        "SELECT audit_event_id FROM governance_decisions WHERE id = %s", (decision,)
    ).fetchone()[0]
    assert review["asset_id"] == asset

    items = {
        kind: evidence_of(tenant, asset, internal(kind, record_id))
        for kind, record_id in (("assessment", assessment), ("decision", decision),
                                ("audit_event", first_event))
    }
    assert items["assessment"]["record_type"] == "assessment"
    assert items["audit_event"]["content_sha256"] is not None

    # Untouched, each record verifies, and the response says what was shown.
    for kind, created in items.items():
        response = verify(tenant, created["id"], second, method="internal_record_checked")
        assert response.status_code == 201, (kind, response.text)
        assert response.json()["scope"] == "record_verified"

    # Tampered, each is refused, and the earlier verification stays as it was.
    later = {
        kind: evidence_of(tenant, asset, internal(kind, record_id))
        for kind, record_id in (("assessment", assessment), ("decision", decision),
                                ("audit_event", first_event))
    }
    tamper(attacker_sql, "audit_events",
           "UPDATE audit_events SET payload = payload || '{\"altered\": \"yes\"}'::jsonb "
           "WHERE id = ANY(%s)", ([str(first_event), str(decision_event)],))
    tamper(attacker_sql, "risk_assessments",
           "UPDATE risk_assessments SET score = score + 1 WHERE id = %s", (assessment,))
    for kind, created in later.items():
        refused = verify(tenant, created["id"], second, method="internal_record_checked")
        assert (refused.status_code, error_code(refused)) == (409, "HASH_MISMATCH"), kind
        assert verification_rows(attacker_sql, created["id"]) == [], kind


def test_decision_evidence_must_name_the_decision_in_its_audit_event(tenant, attacker_sql):
    second = reviewers(tenant)
    asset = assessed_asset(tenant)
    submitted(tenant, asset)
    decision = decision_id_of(tenant, asset)
    created = evidence_of(tenant, asset, internal("decision", decision))
    # Point the decision at another real event, whose own hash is intact.
    other = attacker_sql.execute(
        "SELECT id, event_hash FROM audit_events WHERE tenant_id = %s ORDER BY seq LIMIT 1",
        (tenant.id,),
    ).fetchone()
    tamper(attacker_sql, "governance_evidence",
           "UPDATE governance_evidence SET content_sha256 = %s WHERE id = %s",
           (other[1], created["id"]))
    tamper(attacker_sql, "governance_decisions",
           "UPDATE governance_decisions SET audit_event_id = %s WHERE id = %s",
           (other[0], decision))
    refused = verify(tenant, created["id"], second, method="internal_record_checked")
    assert (refused.status_code, error_code(refused)) == (409, "HASH_MISMATCH")


def test_incident_and_investigation_run_prove_existence_only(world, tenant):
    second = reviewers(tenant)
    asset = tenant.asset()["id"]
    incident = make_incident(world, tenant)
    run = tenant.post(f"/incidents/{incident['id']}/investigation-runs", {},
                      headers=tenant.reviewer)
    assert run.status_code == 201, run.text

    for kind, record_id in (("incident", incident["id"]),
                            ("investigation_run", run.json()["id"])):
        created = evidence_of(tenant, asset, internal(kind, record_id),
                              category="incident_investigation_records")
        assert created["content_sha256"] is None
        response = verify(tenant, created["id"], second, method="internal_record_checked")
        assert response.status_code == 201, response.text
        assert response.json()["scope"] == "existence_only", kind


def test_a_vanished_incident_is_a_hash_mismatch(world, tenant, attacker_sql):
    second = reviewers(tenant)
    incident = make_incident(world, tenant)
    created = evidence_of(tenant, tenant.asset()["id"], internal("incident", incident["id"]),
                          category="incident_investigation_records")
    # Delete it as a superuser, with foreign keys and triggers off.
    attacker_sql.execute("SET session_replication_role = replica")
    try:
        attacker_sql.execute("DELETE FROM incidents WHERE id = %s", (incident["id"],))
    finally:
        attacker_sql.execute("SET session_replication_role = DEFAULT")
    refused = verify(tenant, created["id"], second, method="internal_record_checked")
    assert (refused.status_code, error_code(refused)) == (409, "HASH_MISMATCH")
    assert verification_rows(attacker_sql, created["id"]) == []


def test_internal_record_must_belong_to_this_asset(tenant):
    reviewers(tenant)
    mine, other = assessed_asset(tenant), assessed_asset(tenant)
    for kind, record_id in (("assessment", assessment_id_of(tenant, other)),
                            ("assessment", uuid4()), ("incident", uuid4()),
                            ("audit_event", uuid4()), ("decision", uuid4())):
        assert submit_evidence(tenant, mine, internal(kind, record_id)).status_code == 422, kind


def test_evidence_cannot_reference_another_tenants_record(world, db):
    first, second = world.tenant(), world.tenant()
    reviewers(first)
    mine = assessed_asset(first)
    theirs = second.asset()["id"]
    foreign_assessment = assessment_id_of(first, mine)
    foreign_event = first.audit_events()[0]["id"]

    # Through the service the other tenant finds nothing to point at.
    assert submit_evidence(second, theirs, internal("assessment", foreign_assessment)
                           ).status_code == 422
    assert submit_evidence(second, theirs, internal("audit_event", foreign_event)
                           ).status_code == 422
    assert submit_evidence(second, mine).status_code == 404

    # Below the service, composite foreign keys refuse the same rows.
    insert = (
        "INSERT INTO governance_evidence (id, tenant_id, asset_id, category, description, "
        "source_type, submitted_by, created_at, content_sha256, {column}) "
        "VALUES (:id, :tenant, :asset, 'model_evaluation', 'x', 'internal_record', :user, now(), "
        "repeat('0', 64), :record)"
    )
    for column, record, asset in (("audit_event_id", foreign_event, theirs),
                                  ("assessment_id", foreign_assessment, theirs),
                                  ("audit_event_id", foreign_event, mine)):
        with pytest.raises(DBAPIError), db.tenant_transaction(second.id) as session:
            session.execute(text(insert.format(column=column)),
                            {"id": uuid4(), "tenant": second.id, "asset": asset,
                             "user": second.user_id("admin"), "record": record})
    assert second.get(EVIDENCE).json()["total"] == 0


# Ordering


def test_a_decision_can_name_only_real_evidence(db, tenant):
    reviewers(tenant)
    review = submitted(tenant)
    decision = decision_id_of(tenant, review["asset_id"])
    real = evidence_of(tenant, review["asset_id"])
    insert = text("INSERT INTO governance_decision_evidence (id, tenant_id, decision_id, "
                  "evidence_id) VALUES (:id, :tenant, :decision, :evidence)")
    with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
        session.execute(insert, {"id": uuid4(), "tenant": tenant.id, "decision": decision,
                                 "evidence": uuid4()})
    with db.tenant_transaction(tenant.id) as session:
        session.execute(insert, {"id": uuid4(), "tenant": tenant.id, "decision": decision,
                                 "evidence": real["id"]})


def test_latest_verification_wins_by_audit_sequence(world, tenant):
    second = reviewers(tenant)
    # Every verification below carries the same timestamp, so only the audit sequence orders them.
    moment = datetime.now(UTC)
    world.app.state.container.clock = lambda: moment
    created = evidence_of(tenant, tenant.asset()["id"])

    assert verify(tenant, created["id"], second).status_code == 201
    assert current(tenant, created["id"]) == "VERIFIED"
    assert verify(tenant, created["id"], second, outcome="REJECTED", note="Withdrawn."
                  ).status_code == 201
    assert current(tenant, created["id"]) == "REJECTED"
    assert tenant.get(EVIDENCE, verification="VERIFIED").json()["total"] == 0
    assert tenant.get(EVIDENCE, verification="REJECTED").json()["total"] == 1
    overview = tenant.get("/governance/overview").json()
    assert (overview["evidence_verified"], overview["evidence_total"]) == (0, 1)

    assert verify(tenant, created["id"], second, note="Checked again.").status_code == 201
    detail = tenant.get(f"{EVIDENCE}/{created['id']}").json()
    assert detail["current_verification"] == "VERIFIED"
    assert [item["outcome"] for item in detail["verifications"]] == [
        "VERIFIED", "REJECTED", "VERIFIED"]
    assert len({item["verified_at"] for item in detail["verifications"]}) == 1


def test_evidence_and_verifications_are_append_only(db, tenant, attacker_sql):
    second = reviewers(tenant)
    created = evidence_of(tenant, tenant.asset()["id"])
    assert verify(tenant, created["id"], second).status_code == 201
    attacker_sql.execute(
        "INSERT INTO governance_evidence_controls (id, tenant_id, evidence_id, control_id) "
        "VALUES (%s, %s, %s, %s)", (uuid4(), tenant.id, created["id"], uuid4()))
    tables = ("governance_evidence", "governance_evidence_controls",
              "governance_evidence_verifications")
    for table in tables:
        for sql in (f"UPDATE {table} SET tenant_id = tenant_id", f"DELETE FROM {table}"):
            with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
                session.execute(text(sql))
        with pytest.raises(psycopg.Error, match="append-only"):
            attacker_sql.execute(f"TRUNCATE {table} CASCADE")
        with pytest.raises(psycopg.Error, match="append-only"):
            attacker_sql.execute(f"UPDATE {table} SET tenant_id = tenant_id")


# Visibility


def test_inline_content_hidden_from_viewer(tenant):
    reviewers(tenant)
    created = evidence_of(tenant, tenant.asset()["id"])
    path = f"{EVIDENCE}/{created['id']}"

    seen = tenant.get(path, headers=tenant.viewer)
    assert seen.status_code == 200
    assert seen.json()["content_text"] is None
    assert seen.json()["content_sha256"] == sha256_hex(TEXT)
    assert seen.json()["description"] == "Synthetic evidence."
    listed = tenant.get(EVIDENCE, headers=tenant.viewer).json()["items"]
    assert [item["content_text"] for item in listed] == [None]

    for headers in (tenant.admin, tenant.reviewer):
        assert tenant.get(path, headers=headers).json()["content_text"] == TEXT
        assert tenant.get(EVIDENCE, headers=headers).json()["items"][0]["content_text"] == TEXT


# Asset state


def test_evidence_on_retired_asset_refused(tenant, attacker_sql):
    second = reviewers(tenant)
    asset = tenant.asset()["id"]
    save_profile(tenant, asset)
    earlier = evidence_of(tenant, asset)
    assert tenant.post(f"/governance/assets/{asset}/retire", {"reason": "Decommissioned."}
                       ).status_code == 201

    refused = submit_evidence(tenant, asset)
    assert (refused.status_code, error_code(refused)) == (409, "ASSET_RETIRED")
    refused = verify(tenant, earlier["id"], second)
    assert (refused.status_code, error_code(refused)) == (409, "ASSET_RETIRED")
    assert verification_rows(attacker_sql, earlier["id"]) == []
    # A rejection only tightens, so it is still allowed.
    assert verify(tenant, earlier["id"], second, outcome="REJECTED").status_code == 201
    assert current(tenant, earlier["id"]) == "REJECTED"
    # History stays readable.
    assert tenant.get(f"{EVIDENCE}/{earlier['id']}").status_code == 200
    assert tenant.get(EVIDENCE, asset_id=asset).json()["total"] == 1


def test_evidence_for_an_asset_with_no_governance_state_is_allowed(tenant):
    created = evidence_of(tenant, tenant.asset()["id"])
    assert created["current_verification"] == "UNVERIFIED"


def test_unknown_asset_is_not_found(tenant):
    assert submit_evidence(tenant, str(uuid4())).status_code == 404


# Policies and approvals


def test_policy_finding_clears_only_after_verification(tenant):
    second = reviewers(tenant)
    activate_policy(tenant, required_evidence_categories=["model_evaluation"])

    def evidenced(*outcomes):
        asset = assessed_asset(tenant)
        created = evidence_of(tenant, asset)
        for outcome in outcomes:
            assert verify(tenant, created["id"], second, outcome=outcome).status_code == 201
        return asset

    def findings(asset):
        return [item["control"] for item in submitted(tenant, asset)["findings"]]

    assert findings(evidenced()) == ["required_evidence_categories"]
    assert findings(evidenced("REJECTED")) == ["required_evidence_categories"]
    assert findings(evidenced("VERIFIED", "REJECTED")) == ["required_evidence_categories"]
    assert findings(evidenced("VERIFIED")) == []
    # Evidence of another category does not clear it.
    other = assessed_asset(tenant)
    created = evidence_of(tenant, other, category="monitoring_records")
    assert verify(tenant, created["id"], second).status_code == 201
    assert findings(other) == ["required_evidence_categories"]


def test_approval_references_evidence_of_its_own_asset(tenant, attacker_sql):
    second = reviewers(tenant)
    review = submitted(tenant)
    mine = evidence_of(tenant, review["asset_id"])
    other_asset = evidence_of(tenant, tenant.asset()["id"])

    for bad in ([other_asset["id"]], [str(uuid4())], [mine["id"], other_asset["id"]]):
        refused = approve(tenant, review["id"], second, evidence_ids=bad)
        assert refused.status_code == 422, bad
    assert attacker_sql.execute("SELECT count(*) FROM governance_decision_evidence "
                                "WHERE tenant_id = %s", (tenant.id,)).fetchone()[0] == 0

    approved = approve(tenant, review["id"], second, evidence_ids=[mine["id"], mine["id"]])
    assert approved.status_code == 201, approved.text
    assert approved.json()["evidence_ids"] == [mine["id"]]


def test_control_ids_are_refused_until_controls_exist(tenant):
    asset = tenant.asset()["id"]
    assert submit_evidence(tenant, asset, control_ids=[str(uuid4())]).status_code == 422
    assert submit_evidence(tenant, asset, control_ids=[]).status_code == 201


# Shape


@pytest.mark.parametrize("body", [
    {"category": "not_a_category"},
    {"description": "   "},
    {"source": {"source_type": "inline", "content_text": ""}},
    {"source": {"source_type": "inline", "content_text": "x" * 16_001}},
    {"source": {"source_type": "inline", "content_text": "é" * 8_001}},
    {"source": {"source_type": "external_reference", "source_uri": "ftp://example.test/a",
                "content_sha256": "0" * 64}},
    {"source": {"source_type": "external_reference", "source_uri": "https://example.test/a",
                "content_sha256": "A" * 64}},
    {"source": {"source_type": "external_reference", "source_uri": "https://example.test/a"}},
    {"source": {"source_type": "internal_record", "record_type": "user", "record_id": "x"}},
    {"source": {"source_type": "other"}},
    {"tenant_id": str(uuid4())},
])
def test_malformed_evidence_is_refused(tenant, body):
    asset = tenant.asset()["id"]
    payload = {"asset_id": asset, "category": "model_evaluation", "description": "Synthetic.",
               "source": inline(), **body}
    assert tenant.post(EVIDENCE, payload).status_code == 422
    assert tenant.get(EVIDENCE).json()["total"] == 0


def test_the_largest_inline_content_is_accepted(tenant):
    created = evidence_of(tenant, tenant.asset()["id"], inline("x" * 16_000))
    assert created["content_sha256"] == sha256_hex("x" * 16_000)


def test_listing_filters_by_asset_and_category(tenant):
    reviewers(tenant)
    first, second = tenant.asset()["id"], tenant.asset()["id"]
    evidence_of(tenant, first, category="model_evaluation")
    evidence_of(tenant, first, category="monitoring_records")
    evidence_of(tenant, second, category="model_evaluation")
    assert tenant.get(EVIDENCE).json()["total"] == 3
    assert tenant.get(EVIDENCE, asset_id=first).json()["total"] == 2
    assert tenant.get(EVIDENCE, category="model_evaluation").json()["total"] == 2
    assert tenant.get(EVIDENCE, asset_id=second, category="monitoring_records"
                      ).json()["total"] == 0
    assert tenant.get(EVIDENCE, limit=1, offset=1).json()["total"] == 3
    assert len(tenant.get(EVIDENCE, limit=1, offset=1).json()["items"]) == 1
