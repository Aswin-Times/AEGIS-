"""Framework libraries and control status: a status that claims implementation needs evidence
that someone other than its submitter verified, and no framework view claims certification."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aegis.errors import Forbidden
from aegis.governance.compliance import (
    NO_CERTIFICATION_STATEMENT,
    assess_control,
    ensure_frameworks,
)
from aegis.governance.frameworks.nist_ai_rmf_1_0 import NIST
from aegis.governance.frameworks.nist_ai_rmf_1_0_identifiers import SOURCE_IDENTIFIERS
from aegis.security.principals import UserPrincipal
from support import error_code, reviewers

FRAMEWORKS = "/governance/frameworks"
CONTROLS = "/governance/controls"
EVIDENCE = "/governance/evidence"


def frameworks(tenant, headers=None) -> dict:
    response = tenant.get(FRAMEWORKS, headers=headers)
    assert response.status_code == 200, response.text
    return {item["key"]: item for item in response.json()["items"]}


def controls(tenant, headers=None, **params) -> dict:
    response = tenant.get(CONTROLS, headers=headers, **{"limit": 100, **params})
    assert response.status_code == 200, response.text
    return response.json()


def control(tenant, identifier="MEASURE 2.7") -> dict:
    nist = frameworks(tenant)["nist_ai_rmf"]["id"]
    return next(item for item in controls(tenant, framework_id=nist)["items"]
                if item["identifier"] == identifier)


def control_of(tenant, control_id) -> dict:
    return next(item for item in controls(tenant)["items"] if item["id"] == control_id)


def assess(tenant, control_id, status, headers, note="Reviewed against the evidence.",
           evidence_ids=None):
    body = {"status": status, "note": note}
    if evidence_ids is not None:
        body["evidence_ids"] = evidence_ids
    return tenant.post(f"{CONTROLS}/{control_id}/assess", body, headers=headers)


def linked_evidence(tenant, control_ids, asset_id=None, category="security_evaluation") -> dict:
    """Evidence submitted by the first admin and linked to the given controls. Unverified."""
    response = tenant.post(EVIDENCE, {
        "asset_id": asset_id or tenant.asset()["id"], "category": category,
        "description": "Synthetic security evaluation.",
        "source": {"source_type": "inline", "content_text": f"synthetic {uuid4().hex}"},
        "control_ids": list(control_ids),
    })
    assert response.status_code == 201, response.text
    return response.json()


def verify(tenant, evidence_id, headers, outcome="VERIFIED"):
    response = tenant.post(f"{EVIDENCE}/{evidence_id}/verify",
                           {"outcome": outcome, "method": "content_recomputed",
                            "note": "Checked by a reviewer."}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def assessment_rows(attacker_sql, control_id):
    return attacker_sql.execute(
        "SELECT status FROM governance_control_assessments WHERE control_id = %s", (control_id,)
    ).fetchall()


def assert_nothing_assessed(tenant, attacker_sql, control_id):
    assert assessment_rows(attacker_sql, control_id) == []
    assert tenant.audit_events("governance.control_assessed") == []
    assert control_of(tenant, control_id)["current_status"] == "NOT_ASSESSED"
    assert tenant.verify_audit()["valid"] is True


# Seeding


def test_frameworks_seeded_once_per_tenant(world, attacker_sql):
    first, second = world.tenant(), world.tenant()
    container = world.app.state.container
    barrier = threading.Barrier(8)

    def first_read(_):
        barrier.wait()
        with container.db.tenant_transaction(first.id) as session:
            ensure_frameworks(session, first.id, container.clock())

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(first_read, range(8)))

    def counts(tenant):
        return attacker_sql.execute(
            "SELECT (SELECT count(*) FROM governance_frameworks WHERE tenant_id = %(t)s), "
            "(SELECT count(*) FROM governance_controls WHERE tenant_id = %(t)s)",
            {"t": tenant.id},
        ).fetchone()

    assert counts(first) == (2, len(NIST.controls))
    assert len(first.audit_events("governance.framework_seeded")) == 2
    # Later reads find the library in place and add nothing.
    frameworks(first)
    controls(first)
    assert counts(first) == (2, len(NIST.controls))
    assert len(first.audit_events("governance.framework_seeded")) == 2
    assert first.verify_audit()["valid"] is True

    # Each tenant has its own copy, seeded on its own first read.
    assert counts(second) == (0, 0)
    seen = frameworks(second)
    assert counts(second) == (2, len(NIST.controls))
    assert seen["nist_ai_rmf"]["id"] != frameworks(first)["nist_ai_rmf"]["id"]


def test_a_framework_key_and_version_are_unique_per_tenant(db, tenant):
    frameworks(tenant)
    with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
        session.execute(text(
            "INSERT INTO governance_frameworks (id, tenant_id, key, version, name, "
            "source_document, library_status, created_at) VALUES (:id, :tenant, 'nist_ai_rmf', "
            "'1.0', 'copy', 'copy', 'NOT_LOADED', now())"), {"id": uuid4(), "tenant": tenant.id})


# Status


def test_control_with_no_assessment_is_not_assessed(tenant):
    listed = controls(tenant)
    assert listed["total"] == len(NIST.controls)
    assert {item["current_status"] for item in listed["items"]} == {"NOT_ASSESSED"}
    assert all(item["latest_assessment"] is None for item in listed["items"])
    assert controls(tenant, status="NOT_ASSESSED")["total"] == len(NIST.controls)
    assert controls(tenant, status="IMPLEMENTED")["total"] == 0


def test_implemented_refused_without_verified_evidence(db, tenant, attacker_sql):
    holder = reviewers(tenant)
    target = control(tenant)["id"]
    other = control(tenant, "MEASURE 2.4")["id"]

    def refused(**kwargs):
        response = assess(tenant, target, "IMPLEMENTED", holder, **kwargs)
        assert (response.status_code, error_code(response)) == (409, "EVIDENCE_REQUIRED")

    # No evidence at all.
    refused()
    # Linked but unverified, even when cited.
    pending = linked_evidence(tenant, [target])
    refused()
    refused(evidence_ids=[pending["id"]])
    # Verified, but linked to another control only.
    elsewhere = linked_evidence(tenant, [other])
    verify(tenant, elsewhere["id"], holder)
    refused()
    # Linked and verified, then rejected.
    withdrawn = linked_evidence(tenant, [target])
    verify(tenant, withdrawn["id"], holder)
    verify(tenant, withdrawn["id"], holder, outcome="REJECTED")
    refused()
    assert_nothing_assessed(tenant, attacker_sql, target)

    # Below the service, the same rule refuses a direct insert.
    with pytest.raises(DBAPIError, match="verified evidence"), \
            db.tenant_transaction(tenant.id) as session:
        session.execute(text(
            "INSERT INTO governance_control_assessments (id, tenant_id, control_id, status, note, "
            "assessed_by, assessed_at, audit_event_id) VALUES (:id, :tenant, :control, "
            "'IMPLEMENTED', 'x', :user, now(), (SELECT id FROM audit_events LIMIT 1))"),
            {"id": uuid4(), "tenant": tenant.id, "control": target,
             "user": tenant.user_id("admin")})
    assert assessment_rows(attacker_sql, target) == []


def test_partially_implemented_refused_without_verified_evidence(tenant, attacker_sql):
    holder = reviewers(tenant)
    target = control(tenant)["id"]
    linked_evidence(tenant, [target])
    response = assess(tenant, target, "PARTIALLY_IMPLEMENTED", holder)
    assert (response.status_code, error_code(response)) == (409, "EVIDENCE_REQUIRED")
    assert_nothing_assessed(tenant, attacker_sql, target)

    # Statuses that claim nothing need no evidence.
    for status in ("NOT_IMPLEMENTED", "NOT_APPLICABLE"):
        response = assess(tenant, target, status, holder)
        assert response.status_code == 201, response.text
        assert response.json()["current_status"] == status


def test_implemented_allowed_with_verified_evidence(tenant, attacker_sql):
    holder = reviewers(tenant)
    target = control(tenant)["id"]
    evidence = linked_evidence(tenant, [target])
    verify(tenant, evidence["id"], holder)

    response = assess(tenant, target, "IMPLEMENTED", holder, evidence_ids=[evidence["id"]])
    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["status"], body["current_status"]) == ("IMPLEMENTED", "IMPLEMENTED")
    assert body["evidence_ids"] == [evidence["id"]]
    assert body["assessed_by"] == tenant.user_id("second-admin")

    shown = control_of(tenant, target)
    assert shown["current_status"] == "IMPLEMENTED"
    assert shown["latest_assessment"]["id"] == body["id"]
    assert shown["latest_assessment"]["evidence_ids"] == [evidence["id"]]
    assert (shown["verified_evidence_count"], shown["linked_evidence_count"]) == (1, 1)
    assert assessment_rows(attacker_sql, target) == [("IMPLEMENTED",)]

    event = tenant.audit_events("governance.control_assessed")[0]
    assert event["id"] == body["audit_event_id"]
    assert event["payload"]["status"] == "IMPLEMENTED"
    assert event["payload"]["evidence_ids"] == [evidence["id"]]
    assert tenant.verify_audit()["valid"] is True

    # Partially implemented is allowed on the same footing.
    partial = assess(tenant, target, "PARTIALLY_IMPLEMENTED", holder)
    assert partial.status_code == 201, partial.text


def test_assessment_evidence_must_be_linked_to_the_control(db, tenant, attacker_sql):
    holder = reviewers(tenant)
    target = control(tenant)["id"]
    supporting = linked_evidence(tenant, [target])
    verify(tenant, supporting["id"], holder)
    unlinked = linked_evidence(tenant, [control(tenant, "MEASURE 2.4")["id"]])
    verify(tenant, unlinked["id"], holder)

    for bad in ([unlinked["id"]], [str(uuid4())], [supporting["id"], unlinked["id"]]):
        response = assess(tenant, target, "IMPLEMENTED", holder, evidence_ids=bad)
        assert response.status_code == 422, bad
    assert_nothing_assessed(tenant, attacker_sql, target)

    accepted = assess(tenant, target, "IMPLEMENTED", holder,
                      evidence_ids=[supporting["id"], supporting["id"]])
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["evidence_ids"] == [supporting["id"]]

    # Below the service, a citation of evidence not linked to the control is refused.
    with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
        session.execute(text(
            "INSERT INTO governance_control_assessment_evidence (id, tenant_id, assessment_id, "
            "control_id, evidence_id) VALUES (:id, :tenant, :assessment, :control, :evidence)"),
            {"id": uuid4(), "tenant": tenant.id, "assessment": accepted.json()["id"],
             "control": target, "evidence": unlinked["id"]})


def test_evidence_from_another_tenant_refused(world, db):
    first, second = world.tenant(), world.tenant()
    holder = reviewers(first)
    other_holder = reviewers(second)
    mine = control(first)["id"]
    theirs = control(second)["id"]
    evidence = linked_evidence(first, [mine])
    verify(first, evidence["id"], holder)

    # The other tenant cannot cite this evidence, link to this control, or assess it.
    cited = assess(second, theirs, "NOT_IMPLEMENTED", other_holder, evidence_ids=[evidence["id"]])
    assert cited.status_code == 422
    refused = assess(second, theirs, "IMPLEMENTED", other_holder)
    assert (refused.status_code, error_code(refused)) == (409, "EVIDENCE_REQUIRED")
    assert assess(second, mine, "NOT_IMPLEMENTED", other_holder).status_code == 404
    response = second.post(EVIDENCE, {
        "asset_id": second.asset()["id"], "category": "security_evaluation",
        "description": "Synthetic.", "source": {"source_type": "inline", "content_text": "x"},
        "control_ids": [mine]})
    assert response.status_code == 422
    assert second.audit_events("governance.control_assessed") == []
    assert first.audit_events("governance.control_assessed") == []

    # Below the service, composite foreign keys refuse the same links.
    with pytest.raises(DBAPIError), db.tenant_transaction(first.id) as session:
        session.execute(text(
            "INSERT INTO governance_evidence_controls (id, tenant_id, evidence_id, control_id) "
            "VALUES (:id, :tenant, :evidence, :control)"),
            {"id": uuid4(), "tenant": first.id, "evidence": evidence["id"], "control": theirs})

    # The owning side can still use its evidence.
    assert assess(first, mine, "IMPLEMENTED", holder, evidence_ids=[evidence["id"]]
                  ).status_code == 201


def test_rejected_evidence_no_longer_supports_status(tenant, attacker_sql):
    holder = reviewers(tenant)
    target = control(tenant)["id"]
    evidence = linked_evidence(tenant, [target])
    verify(tenant, evidence["id"], holder)
    assessed = assess(tenant, target, "IMPLEMENTED", holder)
    assert assessed.status_code == 201, assessed.text

    verify(tenant, evidence["id"], holder, outcome="REJECTED")
    shown = control_of(tenant, target)
    assert shown["current_status"] == "EVIDENCE_REQUIRED"
    # The stored assessment is untouched; only what it can claim has changed.
    assert shown["latest_assessment"]["status"] == "IMPLEMENTED"
    assert shown["latest_assessment"]["id"] == assessed.json()["id"]
    assert assessment_rows(attacker_sql, target) == [("IMPLEMENTED",)]
    assert shown["verified_evidence_count"] == 0
    assert controls(tenant, status="EVIDENCE_REQUIRED")["total"] == 1
    assert controls(tenant, status="IMPLEMENTED")["total"] == 0
    counts = frameworks(tenant)["nist_ai_rmf"]["status_counts"]
    assert (counts["EVIDENCE_REQUIRED"], counts["IMPLEMENTED"]) == (1, 0)
    # A new claim is refused until evidence is verified again.
    again = assess(tenant, target, "IMPLEMENTED", holder)
    assert (again.status_code, error_code(again)) == (409, "EVIDENCE_REQUIRED")

    verify(tenant, evidence["id"], holder)
    assert control_of(tenant, target)["current_status"] == "IMPLEMENTED"


def test_latest_assessment_wins_by_audit_sequence(world, tenant):
    holder = reviewers(tenant)
    target = control(tenant)["id"]
    # Every assessment below carries the same timestamp, so only the audit sequence orders them.
    moment = datetime.now(UTC)
    world.app.state.container.clock = lambda: moment
    for status in ("NOT_IMPLEMENTED", "NOT_APPLICABLE", "NOT_IMPLEMENTED"):
        assert assess(tenant, target, status, holder).status_code == 201
    assert control_of(tenant, target)["current_status"] == "NOT_IMPLEMENTED"
    assert assess(tenant, target, "NOT_APPLICABLE", holder).status_code == 201
    assert control_of(tenant, target)["current_status"] == "NOT_APPLICABLE"


def test_control_assessments_are_append_only(db, tenant, attacker_sql):
    holder = reviewers(tenant)
    target = control(tenant)["id"]
    evidence = linked_evidence(tenant, [target])
    verify(tenant, evidence["id"], holder)
    assert assess(tenant, target, "IMPLEMENTED", holder, evidence_ids=[evidence["id"]]
                  ).status_code == 201
    tables = ("governance_frameworks", "governance_controls", "governance_control_assessments",
              "governance_control_assessment_evidence")
    for table in tables:
        for sql in (f"UPDATE {table} SET tenant_id = tenant_id", f"DELETE FROM {table}"):
            with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
                session.execute(text(sql))
        with pytest.raises(psycopg.Error, match="append-only"):
            attacker_sql.execute(f"TRUNCATE {table} CASCADE")
        with pytest.raises(psycopg.Error, match="append-only"):
            attacker_sql.execute(f"UPDATE {table} SET tenant_id = tenant_id")
    assert control_of(tenant, target)["current_status"] == "IMPLEMENTED"


# Who may assess


def test_only_reviewer_holder_can_assess_controls(world, tenant, attacker_sql):
    holder = reviewers(tenant)
    target = control(tenant)["id"]
    plain_admin = tenant.login_as("plain-admin", "admin")
    for headers in (tenant.reviewer, tenant.viewer, plain_admin):
        assert assess(tenant, target, "NOT_IMPLEMENTED", headers).status_code == 403
    assert_nothing_assessed(tenant, attacker_sql, target)

    # The service refuses as well, whatever route reaches it.
    container = world.app.state.container
    viewer = UserPrincipal(id=UUID(tenant.user_id("reviewer")), tenant_id=tenant.id,
                           email="reviewer", role="reviewer")
    with pytest.raises(Forbidden), container.db.tenant_transaction(tenant.id) as session:
        assess_control(session, viewer, container.clock(), target, status="NOT_IMPLEMENTED",
                       note="Not mine to assess.", evidence_ids=[])
    assert_nothing_assessed(tenant, attacker_sql, target)

    assert assess(tenant, target, "NOT_IMPLEMENTED", holder).status_code == 201


def test_agent_principal_cannot_use_compliance_routes(tenant):
    agent = tenant.agent()
    target = control(tenant)["id"]
    for response in (
        tenant.client.get(f"/api/v1{FRAMEWORKS}", headers=agent.headers),
        tenant.client.get(f"/api/v1{CONTROLS}", headers=agent.headers),
        tenant.client.post(f"/api/v1{CONTROLS}/{target}/assess", headers=agent.headers,
                           json={"status": "NOT_IMPLEMENTED", "note": "x"}),
    ):
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHENTICATED"


@pytest.mark.parametrize("body", [
    {"status": "NOT_ASSESSED"},
    {"status": "EVIDENCE_REQUIRED"},
    {"status": "COMPLIANT"},
    {"note": "   "},
    {"note": "x" * 2001},
    {"tenant_id": str(uuid4())},
])
def test_malformed_assessment_is_refused(tenant, attacker_sql, body):
    holder = reviewers(tenant)
    target = control(tenant)["id"]
    payload = {"status": "NOT_IMPLEMENTED", "note": "Reviewed.", **body}
    assert tenant.post(f"{CONTROLS}/{target}/assess", payload, headers=holder).status_code == 422
    assert assessment_rows(attacker_sql, target) == []


def test_unknown_control_is_not_found(tenant):
    holder = reviewers(tenant)
    assert assess(tenant, str(uuid4()), "NOT_IMPLEMENTED", holder).status_code == 404


# What the views say


def test_responses_carry_the_no_certification_statement(tenant):
    holder = reviewers(tenant)
    assert "does not establish certification or compliance" in NO_CERTIFICATION_STATEMENT
    target = control(tenant)["id"]
    responses = [
        tenant.get(FRAMEWORKS, headers=tenant.viewer),
        tenant.get(CONTROLS, headers=tenant.viewer),
        tenant.get(CONTROLS, status="IMPLEMENTED"),  # empty, and still says it
        assess(tenant, target, "NOT_IMPLEMENTED", holder),
    ]
    for response in responses:
        assert response.status_code in (200, 201), response.text
        assert response.json()["statement"] == NO_CERTIFICATION_STATEMENT


def test_iso_reports_not_loaded_with_zero_controls(db, tenant):
    iso = frameworks(tenant)["iso_iec_42001"]
    assert iso["library_status"] == "NOT_LOADED"
    assert (iso["control_count"], iso["source_control_count"]) == (0, None)
    assert "not loaded" in iso["coverage"].lower()
    assert set(iso["status_counts"].values()) == {0}
    assert controls(tenant, framework_id=iso["id"])["total"] == 0

    # Below the service, a control cannot be filed under a library that is not loaded.
    with pytest.raises(DBAPIError, match="not loaded"), \
            db.tenant_transaction(tenant.id) as session:
        session.execute(text(
            "INSERT INTO governance_controls (id, tenant_id, framework_id, position, "
            "control_identifier, name, description, source_reference, required_evidence, "
            "created_at) VALUES (:id, :tenant, :framework, 1, 'A.1', 'x', 'x', 'x', "
            "ARRAY['risk_assessment'], now())"),
            {"id": uuid4(), "tenant": tenant.id, "framework": iso["id"]})
    assert frameworks(tenant)["iso_iec_42001"]["control_count"] == 0


def test_coverage_counts_come_from_stored_rows(tenant, attacker_sql):
    holder = reviewers(tenant)
    nist = frameworks(tenant)["nist_ai_rmf"]
    shipped = len(NIST.controls)
    assert nist["library_status"] == "LOADED_PARTIAL"
    assert (nist["control_count"], nist["source_control_count"]) == (shipped,
                                                                   len(SOURCE_IDENTIFIERS))
    assert nist["coverage"] == (f"{shipped} of {len(SOURCE_IDENTIFIERS)} NIST AI RMF 1.0 "
                                "subcategories are in the library.")
    assert nist["status_counts"]["NOT_ASSESSED"] == shipped

    # Assessing changes the counts.
    target = control(tenant)["id"]
    assert assess(tenant, target, "NOT_APPLICABLE", holder).status_code == 201
    counts = frameworks(tenant)["nist_ai_rmf"]["status_counts"]
    assert (counts["NOT_APPLICABLE"], counts["NOT_ASSESSED"]) == (1, shipped - 1)

    # A row written behind the code's back is counted too: the numbers are read, not assumed.
    attacker_sql.execute(
        "INSERT INTO governance_controls (id, tenant_id, framework_id, position, "
        "control_identifier, name, description, source_reference, required_evidence, "
        "created_at) VALUES (%s, %s, %s, 999, 'GOVERN 2.2', 'x', 'x', 'x', "
        "ARRAY['risk_assessment'], now())", (uuid4(), tenant.id, nist["id"]))
    after = frameworks(tenant)["nist_ai_rmf"]
    assert after["control_count"] == shipped + 1
    assert after["coverage"].startswith(f"{shipped + 1} of {len(SOURCE_IDENTIFIERS)} ")
    assert controls(tenant, framework_id=nist["id"])["total"] == shipped + 1


def test_controls_show_their_source(tenant):
    shown = control(tenant)
    shipped = next(item for item in NIST.controls if item.identifier == "MEASURE 2.7")
    assert (shown["name"], shown["description"], shown["source_reference"]) == (
        shipped.name, shipped.description, shipped.source_reference)
    assert shown["required_evidence"] == list(shipped.required_evidence)
    assert shown["framework_key"] == "nist_ai_rmf"
    listed = controls(tenant, limit=2, offset=1)
    assert (listed["total"], len(listed["items"])) == (len(NIST.controls), 2)
    # Source order, not text order.
    assert [item["identifier"] for item in controls(tenant)["items"]] == [
        item.identifier for item in NIST.controls]


# Evidence links


def test_evidence_links_to_controls_of_this_tenant(tenant, attacker_sql):
    first, second = control(tenant)["id"], control(tenant, "MEASURE 2.4")["id"]
    created = linked_evidence(tenant, [first, second, first])
    assert sorted(created["control_ids"]) == sorted([first, second])
    assert tenant.get(f"{EVIDENCE}/{created['id']}").json()["control_ids"] == created[
        "control_ids"]
    event = tenant.audit_events("governance.evidence_submitted")[-1]
    assert sorted(event["payload"]["control_ids"]) == sorted([first, second])
    assert control_of(tenant, first)["linked_evidence_count"] == 1

    for bad in ([str(uuid4())], [first, str(uuid4())]):
        response = tenant.post(EVIDENCE, {
            "asset_id": tenant.asset()["id"], "category": "security_evaluation",
            "description": "Synthetic.", "source": {"source_type": "inline", "content_text": "x"},
            "control_ids": bad})
        assert response.status_code == 422, bad
    assert attacker_sql.execute(
        "SELECT count(*) FROM governance_evidence WHERE tenant_id = %s", (tenant.id,)
    ).fetchone()[0] == 1
