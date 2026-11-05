"""Reviews, decisions, and submission: what is frozen, what is recorded, and who may act."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from aegis.canonical import sha256_hex
from aegis.db.models import SecurityEvent
from aegis.events.projection import reprojection_matches
from aegis.governance.approvals import _frozen_hash, record_decision
from support import (
    APPROVALS,
    ASSETS,
    PROFILE,
    activate_policy,
    another_holder,
    approve,
    assert_review_untouched,
    assess,
    assessed_asset,
    assign,
    decisions_of,
    detail_status,
    error_code,
    insert_decision,
    reject,
    review_of,
    review_status_of,
    reviewers,
    revoke_governance,
    save_profile,
    submit,
    submitted,
    window,
)


def request_information(tenant, review_id, headers, reason="Please attach the design review."):
    body = {} if reason is None else {"reason": reason}
    return tenant.post(f"{APPROVALS}/{review_id}/request-information", body, headers=headers)


def force(attacker_sql, sql, params=()):
    """Run SQL as a compromised database owner, with the guard triggers switched off."""
    with attacker_sql.transaction():
        attacker_sql.execute("SET LOCAL session_replication_role = replica")
        attacker_sql.execute(sql, params)


def state_of(attacker_sql, asset_id):
    return attacker_sql.execute(
        "SELECT status, version, current_decision_id FROM asset_governance_state "
        "WHERE asset_id = %s",
        (asset_id,),
    ).fetchone()


def status_events(tenant):
    response = tenant.get("/events", event_type="governance.status_changed", limit=100)
    assert response.status_code == 200, response.text
    return response.json()["items"]


# Submission needs a complete assessment of exactly what the asset is now


def test_submit_requires_complete_assessment_of_current_profile(tenant):
    # Never profiled, so there is no state row at all.
    bare = tenant.asset()["id"]
    refused = submit(tenant, bare)
    assert (refused.status_code, error_code(refused)) == (409, "ASSESSMENT_NOT_CURRENT")

    # Profiled but never assessed.
    profiled = tenant.asset()["id"]
    save_profile(tenant, profiled)
    refused = submit(tenant, profiled)
    assert (refused.status_code, error_code(refused)) == (409, "ASSESSMENT_NOT_CURRENT")

    # The newest assessment is incomplete, so it cannot be submitted.
    partial = tenant.asset()["id"]
    save_profile(tenant, partial, {"asset_type": "model", "description": "only this"})
    assert assess(tenant, partial)["status"] == "INCOMPLETE"
    refused = submit(tenant, partial)
    assert (refused.status_code, error_code(refused)) == (409, "ASSESSMENT_NOT_CURRENT")

    assert submit(tenant, str(uuid4())).status_code == 404
    assert tenant.audit_events("governance.decision") == []

    review = submitted(tenant, assessed_asset(tenant))
    assert review["status"] == "OPEN"
    assert len(tenant.audit_events("governance.decision")) == 1


def test_new_profile_after_assessment_blocks_submit(tenant):
    asset_id = assessed_asset(tenant)
    # Only the description changes, so the engine's inputs are identical. The profile is still
    # not the one that was assessed, and policies read it directly.
    save_profile(tenant, asset_id, {**PROFILE, "description": "edited after assessing"})
    refused = submit(tenant, asset_id)
    assert (refused.status_code, error_code(refused)) == (409, "ASSESSMENT_NOT_CURRENT")
    assess(tenant, asset_id)
    assert submit(tenant, asset_id).status_code == 201


def test_grant_change_after_assessment_blocks_submit(tenant):
    agent = tenant.agent(tools=["calculate"])
    asset_id = tenant.get(f"/agents/{agent.id}").json()["asset_id"]
    save_profile(tenant, asset_id)
    assess(tenant, asset_id)
    tenant.created(f"/agents/{agent.id}/tool-grants", {"tool": "send_message"})

    refused = submit(tenant, asset_id)
    assert (refused.status_code, error_code(refused)) == (409, "ASSESSMENT_NOT_CURRENT")
    assess(tenant, asset_id)
    assert submit(tenant, asset_id).status_code == 201


@pytest.mark.parametrize(
    ("status", "code"),
    [
        ("DRAFT", "ASSESSMENT_NOT_CURRENT"),
        ("APPROVED", "INVALID_STATE_TRANSITION"),
        ("CONDITIONALLY_APPROVED", "INVALID_STATE_TRANSITION"),
        ("REJECTED", "INVALID_STATE_TRANSITION"),
        ("SUSPENDED", "INVALID_STATE_TRANSITION"),
        ("RETIRED", "ASSET_RETIRED"),
    ],
)
def test_submit_is_refused_outside_the_two_states_that_allow_it(tenant, attacker_sql, status,
                                                               code):
    asset_id = assessed_asset(tenant)
    force(attacker_sql, "UPDATE asset_governance_state SET status = %s WHERE asset_id = %s",
          (status, asset_id))
    refused = submit(tenant, asset_id)
    assert (refused.status_code, error_code(refused)) == (409, code)
    assert state_of(attacker_sql, asset_id)[0] == status


def test_submit_is_allowed_from_reassessment_required(tenant, attacker_sql):
    asset_id = assessed_asset(tenant)
    force(attacker_sql,
          "UPDATE asset_governance_state SET status = 'REASSESSMENT_REQUIRED' "
          "WHERE asset_id = %s", (asset_id,))
    assess(tenant, asset_id)
    review = submitted(tenant, asset_id)
    assert detail_status(tenant, asset_id) == "UNDER_REVIEW"
    assert decisions_of(attacker_sql, asset_id)[0][:3] == (
        "SUBMIT", "REASSESSMENT_REQUIRED", "UNDER_REVIEW"
    )
    assert review["status"] == "OPEN"


def test_submit_records_review_decision_and_state_together(tenant, attacker_sql):
    asset_id = assessed_asset(tenant)
    assessment_id = tenant.get(f"{ASSETS}/{asset_id}/risk").json()["assessment"]["id"]
    review = submitted(tenant, asset_id, reason="Ready for review.")

    assert review["asset_id"] == asset_id
    assert review["assessment_id"] == assessment_id
    assert review["submitted_by"] == tenant.user_id("admin")
    assert review["assigned_reviewer"] is None and review["closed_at"] is None
    assert detail_status(tenant, asset_id) == "UNDER_REVIEW"
    profile_id = tenant.get(f"{ASSETS}/{asset_id}").json()["profile"]["id"]
    assert review["profile_version_id"] == profile_id

    (decision,) = decisions_of(attacker_sql, asset_id)
    assert decision[:5] == ("SUBMIT", "ASSESSMENT_REQUIRED", "UNDER_REVIEW", UUID(review["id"]),
                            "Ready for review.")
    status, version, current = state_of(attacker_sql, asset_id)
    # A submission holds no authority, so it is not the decision the state row points at.
    assert (status, current) == ("UNDER_REVIEW", None)
    assert tenant.verify_audit()["valid"] is True


def test_asset_type_unset_adds_a_finding(tenant):
    without = {key: value for key, value in PROFILE.items() if key != "asset_type"}
    review = submitted(tenant, assessed_asset(tenant, without))
    (finding,) = [item for item in review["findings"] if item["control"] == "asset_type"]
    assert finding["policy_version_id"] is None and finding["severity"] == "medium"
    assert "asset type" in finding["message"]

    typed = submitted(tenant, assessed_asset(tenant))
    assert typed["findings"] == []


# What is frozen at submission


def test_submit_freezes_required_controls_and_findings(tenant):
    first = activate_policy(tenant, minimum_approvers=2, self_approval="permitted",
                            required_owners=["business"])
    asset_id = assessed_asset(tenant)
    review = submitted(tenant, asset_id)

    frozen = review["required_controls"]
    assert frozen["applicable_version_ids"] == [first]
    assert (frozen["minimum_approvers"], frozen["self_approval_permitted"],
            frozen["owner_approval_permitted"]) == (2, True, False)
    assert review["required_approvers"] == 2
    assert [item["control"] for item in frozen["required_controls"]] == ["required_owners"]
    assert [item["control"] for item in review["findings"]] == ["required_owners"]
    assert review["findings"][0]["policy_version_id"] == first

    # A policy that prohibits self-approval and asks for more arrives mid-review.
    activate_policy(tenant, severity="high", minimum_approvers=2, self_approval="prohibited",
                    required_documentation=["design"])
    later = review_of(tenant, review["id"])
    assert later["required_controls"] == frozen
    assert later["findings"] == review["findings"]
    assert later["required_approvers"] == 2


# One open review per asset


def test_second_open_review_refused(tenant, attacker_sql):
    asset_id = assessed_asset(tenant)
    first = submitted(tenant, asset_id)
    refused = submit(tenant, asset_id)
    assert (refused.status_code, error_code(refused)) == (409, "REVIEW_ALREADY_OPEN")
    assert detail_status(tenant, asset_id) == "UNDER_REVIEW"
    assert len(decisions_of(attacker_sql, asset_id)) == 1

    # The index refuses it too, whatever the service does.
    columns = ("tenant_id, asset_id, assessment_id, profile_version_id, submitted_by, "
               "required_controls_canonical, findings_canonical, required_approvers, "
               "frozen_hash, status, version, submitted_at")
    for status in ("OPEN", "INFO_REQUESTED"):
        with pytest.raises(psycopg.errors.UniqueViolation):
            attacker_sql.execute(
                f"INSERT INTO governance_reviews (id, {columns}) "
                f"SELECT %s, tenant_id, asset_id, assessment_id, profile_version_id, "
                f"submitted_by, required_controls_canonical, findings_canonical, "
                f"required_approvers, frozen_hash, %s, version, submitted_at "
                f"FROM governance_reviews WHERE id = %s",
                (uuid4(), status, first["id"]),
            )


def test_concurrent_submissions_create_one_review(tenant, attacker_sql):
    asset_id = assessed_asset(tenant)
    barrier = threading.Barrier(2)

    def run():
        barrier.wait(timeout=30)
        return submit(tenant, asset_id).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = sorted(future.result(timeout=60) for future in [pool.submit(run),
                                                                pool.submit(run)])
    assert codes == [201, 409]
    count = attacker_sql.execute(
        "SELECT count(*) FROM governance_reviews WHERE asset_id = %s", (asset_id,)
    ).fetchone()[0]
    assert count == 1
    assert len(decisions_of(attacker_sql, asset_id)) == 1
    assert tenant.verify_audit()["valid"] is True


def test_submit_locks_agents_before_state(urls, tenant, attacker_sql):
    """Spec 11.4: agent rows, then state, then the chain head, as assess and suspend do."""
    agent = tenant.agent(tools=["calculate"])
    asset_id = tenant.get(f"/agents/{agent.id}").json()["asset_id"]
    save_profile(tenant, asset_id)
    assess(tenant, asset_id)
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        with psycopg.connect(urls.superuser, autocommit=True) as observer:
            with attacker_sql.transaction():
                attacker_sql.execute(
                    "SELECT id FROM agents WHERE asset_id = %s FOR UPDATE", (asset_id,)
                )
                response = pool.submit(submit, tenant, asset_id)
                waiting = 0
                deadline = time.monotonic() + 15
                while not waiting and time.monotonic() < deadline:
                    waiting = observer.execute(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE wait_event_type = 'Lock' AND query LIKE '%FROM agents%' "
                        "AND pid <> pg_backend_pid()"
                    ).fetchone()[0]
                    time.sleep(0.05)
                assert waiting, "submit did not block on the agent rows"
                with observer.transaction():
                    observer.execute(
                        "SELECT 1 FROM asset_governance_state WHERE asset_id = %s "
                        "FOR UPDATE NOWAIT",
                        (asset_id,),
                    )
                assert not response.done()
        assert response.result(timeout=30).status_code == 201
    finally:
        pool.shutdown(wait=True)


# Assignment and requests for information


def test_assigned_reviewer_must_hold_the_role(tenant, attacker_sql):
    second = reviewers(tenant)
    review = submitted(tenant)
    tenant.login_as("plain-reviewer", "reviewer")
    holder = tenant.user_id("second-admin")

    # A reviewer without the grant, a viewer, and a stranger are all refused.
    for who in (tenant.user_id("plain-reviewer"), tenant.user_id("viewer"), str(uuid4())):
        refused = assign(tenant, review["id"], who, second)
        assert refused.status_code == 422, who
    assert review_of(tenant, review["id"])["assigned_reviewer"] is None
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == ["SUBMIT"]

    done = assign(tenant, review["id"], holder, second)
    assert done.status_code == 200, done.text
    assert done.json()["assigned_reviewer"] == holder
    assert done.json()["version"] == review["version"] + 1
    rows = decisions_of(attacker_sql, review["asset_id"])
    assert [row[0] for row in rows] == ["SUBMIT", "ASSIGN_REVIEWER"]
    assert rows[1][1:4] == ("UNDER_REVIEW", "UNDER_REVIEW", UUID(review["id"]))
    # The decision names who was assigned, in its reason and in its audit payload.
    assert holder in rows[1][4]
    payload = attacker_sql.execute(
        "SELECT a.payload FROM governance_decisions d JOIN audit_events a "
        "ON a.id = d.audit_event_id WHERE d.id = %s", (rows[1][5],)
    ).fetchone()[0]
    assert payload["reviewer_id"] == holder

    # Once the grant is revoked the user can no longer be assigned.
    tenant.grant_governance("plain-reviewer", by="admin")
    people = tenant.get("/governance/people").json()["items"]
    grant_id = next(p["reviewer_grant_id"] for p in people
                    if p["id"] == tenant.user_id("plain-reviewer"))
    assert tenant.post(f"/governance/role-grants/{grant_id}/revoke").status_code == 200
    assert assign(tenant, review["id"], tenant.user_id("plain-reviewer"),
                  second).status_code == 422


def test_assignment_and_information_requests_need_the_governance_role(tenant):
    review = submitted(tenant)
    holder = reviewers(tenant)
    mine = tenant.user_id("second-admin")
    plain = tenant.login_as("plain-admin", "admin")

    for headers in (plain, tenant.viewer, tenant.login("reviewer")):
        assert assign(tenant, review["id"], mine, headers).status_code == 403
        assert request_information(tenant, review["id"], headers).status_code == 403
    for name in ("assign", "request-information"):
        agent = tenant.agent()
        response = tenant.client.post(f"/api/v1{APPROVALS}/{review['id']}/{name}",
                                      json={"reviewer_id": mine, "reason": "x"},
                                      headers=agent.headers)
        assert response.status_code == 401
    assert review_of(tenant, review["id"])["assigned_reviewer"] is None
    assert assign(tenant, review["id"], mine, holder).status_code == 200


def test_only_an_admin_submits(tenant):
    asset_id = assessed_asset(tenant)
    for headers in (tenant.login("reviewer"), tenant.viewer):
        assert submit(tenant, asset_id, headers=headers).status_code == 403
    # The governance role does not confer submission on a non-admin.
    tenant.grant_governance("reviewer")
    assert submit(tenant, asset_id, headers=tenant.login("reviewer")).status_code == 403
    agent = tenant.agent()
    assert tenant.client.post(f"/api/v1{ASSETS}/{asset_id}/submit", json={"reason": "x"},
                              headers=agent.headers).status_code == 401
    assert tenant.audit_events("governance.decision") == []


def test_request_information_keeps_asset_under_review(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    response = request_information(tenant, review["id"], holder)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "INFO_REQUESTED" and body["closed_at"] is None
    assert body["version"] == review["version"] + 1
    assert detail_status(tenant, review["asset_id"]) == "UNDER_REVIEW"
    rows = decisions_of(attacker_sql, review["asset_id"])
    assert [row[0] for row in rows] == ["SUBMIT", "REQUEST_INFORMATION"]
    assert rows[1][1:5] == ("UNDER_REVIEW", "UNDER_REVIEW", UUID(review["id"]),
                            "Please attach the design review.")

    again = request_information(tenant, review["id"], holder)
    assert (again.status_code, error_code(again)) == (409, "INFORMATION_ALREADY_REQUESTED")
    assert len(decisions_of(attacker_sql, review["asset_id"])) == 2


def test_only_the_assigned_reviewer_may_request_information(tenant):
    holder = reviewers(tenant)
    review = submitted(tenant)
    assert assign(tenant, review["id"], tenant.user_id("second-admin"), holder).status_code == 200
    # The submitter holds the role too, but the review is assigned to someone else.
    refused = request_information(tenant, review["id"], tenant.admin)
    assert (refused.status_code, error_code(refused)) == (403, "NOT_ASSIGNED_REVIEWER")
    assert review_of(tenant, review["id"])["status"] == "OPEN"
    assert request_information(tenant, review["id"], holder).status_code == 200


def test_a_closed_review_cannot_be_assigned_or_questioned(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    force(attacker_sql,
          "UPDATE governance_reviews SET status = 'WITHDRAWN', closed_at = now() WHERE id = %s",
          (review["id"],))
    for response in (assign(tenant, review["id"], tenant.user_id("second-admin"), holder),
                     request_information(tenant, review["id"], holder)):
        assert (response.status_code, error_code(response)) == (409, "REVIEW_NOT_OPEN")


def test_decision_requires_reason(tenant, attacker_sql):
    holder = reviewers(tenant)
    asset_id = assessed_asset(tenant)
    for reason in (None, "", "   ", "x" * 2001):
        assert submit(tenant, asset_id, reason=reason).status_code == 422, reason
    assert detail_status(tenant, asset_id) == "ASSESSMENT_REQUIRED"
    review = submitted(tenant, asset_id)
    for reason in (None, "", "\t "):
        assert request_information(tenant, review["id"], holder, reason).status_code == 422
    assert review_of(tenant, review["id"])["status"] == "OPEN"
    assert [row[0] for row in decisions_of(attacker_sql, asset_id)] == ["SUBMIT"]
    # No other input is accepted either.
    assert tenant.post(f"{ASSETS}/{asset_id}/submit",
                       {"reason": "ok", "status": "APPROVED"}).status_code == 422


# Resubmission


def test_resubmission_replaces_an_info_requested_review(tenant, attacker_sql):
    holder = reviewers(tenant)
    first = submitted(tenant)
    asset_id = first["asset_id"]
    reviewer_id = tenant.user_id("second-admin")
    assert assign(tenant, first["id"], reviewer_id, holder).status_code == 200
    assert request_information(tenant, first["id"], holder).status_code == 200
    # A vote cast on the first review, written the way the approval task will write it.
    insert_decision(attacker_sql, tenant.id, asset_id, kind="APPROVAL_VOTE",
                    from_status="UNDER_REVIEW", to_status="UNDER_REVIEW", review_id=first["id"],
                    decided_by=reviewer_id)
    before = len(status_events(tenant))

    response = submit(tenant, asset_id, reason="Added the design review.")
    assert response.status_code == 201, response.text
    second = response.json()
    assert second["id"] != first["id"] and second["status"] == "OPEN"
    assert second["assigned_reviewer"] == reviewer_id
    old = review_of(tenant, first["id"])
    assert old["status"] == "WITHDRAWN" and old["closed_at"] is not None
    assert detail_status(tenant, asset_id) == "UNDER_REVIEW"
    open_count = attacker_sql.execute(
        "SELECT count(*) FROM governance_reviews WHERE asset_id = %s "
        "AND status IN ('OPEN', 'INFO_REQUESTED')", (asset_id,)
    ).fetchone()[0]
    assert open_count == 1

    # The vote row borrows the tenant's first audit event, so leave it out of the ordering.
    rows = [row for row in decisions_of(attacker_sql, asset_id) if row[0] != "APPROVAL_VOTE"]
    assert [row[0] for row in rows] == ["SUBMIT", "ASSIGN_REVIEWER", "REQUEST_INFORMATION",
                                       "SUBMIT"]
    resubmit = rows[-1]
    assert resubmit[:5] == ("SUBMIT", "UNDER_REVIEW", "UNDER_REVIEW", UUID(second["id"]),
                            "Added the design review.")
    assert state_of(attacker_sql, asset_id)[2] is None

    # The earlier vote stays with the earlier review, and the same person can vote again.
    votes = attacker_sql.execute(
        "SELECT review_id FROM governance_decisions WHERE asset_id = %s AND kind = 'APPROVAL_VOTE'",
        (asset_id,),
    ).fetchall()
    assert votes == [(UUID(first["id"]),)]
    insert_decision(attacker_sql, tenant.id, asset_id, kind="APPROVAL_VOTE",
                    from_status="UNDER_REVIEW", to_status="UNDER_REVIEW", review_id=second["id"],
                    decided_by=reviewer_id)
    with pytest.raises(psycopg.errors.UniqueViolation):
        insert_decision(attacker_sql, tenant.id, asset_id, kind="APPROVAL_VOTE",
                        from_status="UNDER_REVIEW", to_status="UNDER_REVIEW",
                        review_id=second["id"], decided_by=reviewer_id)

    # The status did not change, so there is nothing for security monitoring to see.
    assert len(status_events(tenant)) == before == 1
    assert tenant.verify_audit()["valid"] is True


def test_resubmission_recomputes_the_frozen_values(tenant):
    holder = reviewers(tenant)
    first = submitted(tenant)
    assert first["required_approvers"] == 1
    version_id = activate_policy(tenant, minimum_approvers=2, required_owners=["technical"])
    assert request_information(tenant, first["id"], holder).status_code == 200

    second = submitted(tenant, first["asset_id"])
    assert second["required_approvers"] == 2
    assert second["required_controls"]["applicable_version_ids"] == [version_id]
    assert [item["control"] for item in second["findings"]] == ["required_owners"]
    # The withdrawn review keeps what it froze.
    old = review_of(tenant, first["id"])
    assert old["required_approvers"] == 1 and old["findings"] == []


def test_resubmission_needs_a_current_assessment_and_is_atomic(tenant, attacker_sql):
    holder = reviewers(tenant)
    first = submitted(tenant)
    assert request_information(tenant, first["id"], holder).status_code == 200
    save_profile(tenant, first["asset_id"], {**PROFILE, "description": "added detail"})

    refused = submit(tenant, first["asset_id"])
    assert (refused.status_code, error_code(refused)) == (409, "ASSESSMENT_NOT_CURRENT")
    assert review_of(tenant, first["id"])["status"] == "INFO_REQUESTED"
    assert len(decisions_of(attacker_sql, first["asset_id"])) == 2

    assess(tenant, first["asset_id"])
    assert submit(tenant, first["asset_id"]).status_code == 201


# Decisions are append-only, constrained, and tied to the audit chain


def test_decisions_are_append_only(db, tenant, attacker_sql):
    review = submitted(tenant)
    for sql in (
        "UPDATE governance_decisions SET reason = 'changed'",
        "DELETE FROM governance_decisions",
        "UPDATE governance_decision_policy_versions SET tenant_id = tenant_id",
        "DELETE FROM governance_decision_policy_versions",
        "UPDATE governance_decision_evidence SET tenant_id = tenant_id",
        "DELETE FROM governance_decision_evidence",
    ):
        with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
            session.execute(text(sql))
    for table in ("governance_decisions", "governance_decision_policy_versions",
                  "governance_decision_evidence"):
        with pytest.raises(psycopg.Error, match="append-only"):
            attacker_sql.execute(f"TRUNCATE {table} CASCADE")
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute("UPDATE governance_decisions SET reason = 'changed' "
                             "WHERE review_id = %s", (review["id"],))
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute("DELETE FROM governance_decisions WHERE review_id = %s",
                             (review["id"],))


def test_submit_records_the_policy_versions_it_was_judged_against(tenant, attacker_sql):
    version_id = activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    rows = attacker_sql.execute(
        "SELECT j.policy_version_id FROM governance_decision_policy_versions j "
        "JOIN governance_decisions d ON d.id = j.decision_id WHERE d.review_id = %s",
        (review["id"],),
    ).fetchall()
    assert rows == [(UUID(version_id),)]


def _decision_values(attacker_sql, tenant, asset_id=None, review=None, **overrides):
    """A legal APPROVE decision, with overrides, as one INSERT's parameters."""
    asset_id = asset_id or assessed_asset(tenant)
    review = review or submitted(tenant, asset_id)
    base = {
        "id": uuid4(),
        "tenant_id": tenant.id,
        "asset_id": asset_id,
        "review_id": review["id"],
        "kind": "APPROVE",
        "from_status": "UNDER_REVIEW",
        "to_status": "APPROVED",
        "actor_type": "user",
        "decided_by": tenant.user_id("admin"),
        "reason": "Looks fine.",
        "assessment_id": review["assessment_id"],
        "conditions_canonical": None,
        "conditions_hash": None,
        "valid_until": datetime.now(UTC) + timedelta(days=365),
        "next_review_at": datetime.now(UTC) + timedelta(days=180),
        "audit_event_id": attacker_sql.execute(
            "SELECT audit_event_id FROM governance_decisions WHERE review_id = %s",
            (review["id"],),
        ).fetchone()[0],
    }
    base.update(overrides)
    return base


def _insert(attacker_sql, values):
    columns = ", ".join(values)
    marks = ", ".join(["%s"] * len(values))
    attacker_sql.execute(
        f"INSERT INTO governance_decisions ({columns}, decided_at) VALUES ({marks}, now())",
        tuple(values.values()),
    )


def test_decision_constraints_refuse_approval_without_assessment(tenant, attacker_sql):
    legal = _decision_values(attacker_sql, tenant)
    for override in (
        {"assessment_id": None},
        {"valid_until": None},
        {"next_review_at": None},
        {"decided_by": None},
        {"actor_type": "system", "decided_by": None},
        {"reason": ""},
        {"reason": "   "},
        {"kind": "BOGUS"},
        {"from_status": "NOWHERE"},
        {"to_status": "NOWHERE"},
        {"actor_type": "agent"},
        {"kind": "APPROVE_CONDITIONAL", "to_status": "CONDITIONALLY_APPROVED"},
        {"kind": "APPROVE_CONDITIONAL", "to_status": "CONDITIONALLY_APPROVED",
         "conditions_canonical": "[]", "conditions_hash": "0" * 64},
        {"conditions_canonical": '[{"c":1}]'},
        {"conditions_hash": "0" * 64},
        {"conditions_canonical": '[{"c":1}]', "conditions_hash": "not a hash"},
    ):
        with pytest.raises(psycopg.errors.CheckViolation):
            _insert(attacker_sql, {**legal, "id": uuid4(), **override})
    # The control: the legal row, a conditional approval with conditions, and a system
    # reassessment, all go in.
    _insert(attacker_sql, legal)
    tenant.login_as("second-admin", "admin")
    _insert(attacker_sql, {**legal, "id": uuid4(), "kind": "APPROVE_CONDITIONAL",
                           "to_status": "CONDITIONALLY_APPROVED",
                           "decided_by": tenant.user_id("second-admin"),
                           "conditions_canonical": '[{"c":1}]', "conditions_hash": "0" * 64})
    # The same person cannot count twice on one review.
    with pytest.raises(psycopg.errors.UniqueViolation):
        _insert(attacker_sql, {**legal, "id": uuid4(), "kind": "APPROVAL_VOTE",
                               "to_status": "UNDER_REVIEW"})
    _insert(attacker_sql, {**legal, "id": uuid4(), "kind": "REQUIRE_REASSESSMENT",
                           "actor_type": "system", "decided_by": None, "assessment_id": None,
                           "valid_until": None, "next_review_at": None,
                           "from_status": "APPROVED", "to_status": "REASSESSMENT_REQUIRED"})


def test_decision_cannot_name_another_assets_review_or_assessment(tenant, attacker_sql):
    legal = _decision_values(attacker_sql, tenant)
    other = submitted(tenant)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _insert(attacker_sql, {**legal, "id": uuid4(), "review_id": other["id"]})
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _insert(attacker_sql, {**legal, "id": uuid4(), "assessment_id": other["assessment_id"]})
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _insert(attacker_sql, {**legal, "id": uuid4(), "audit_event_id": uuid4()})


def test_decision_links_to_a_real_audit_event(tenant, attacker_sql):
    review = submitted(tenant)
    (decision,) = decisions_of(attacker_sql, review["asset_id"])
    events = [e for e in tenant.audit_events("governance.decision")]
    assert len(events) == 1
    event = events[0]
    assert event["subject_id"] == str(decision[5])
    assert event["actor_id"] == tenant.user_id("admin") and event["actor_type"] == "user"
    assert event["payload"] == {
        "decision_id": str(decision[5]),
        "asset_id": review["asset_id"],
        "kind": "SUBMIT",
        "from_status": "ASSESSMENT_REQUIRED",
        "to_status": "UNDER_REVIEW",
        "assessment_id": review["assessment_id"],
        "frozen_hash": attacker_sql.execute(
            "SELECT frozen_hash FROM governance_reviews WHERE id = %s", (review["id"],)
        ).fetchone()[0],
    }
    stored = attacker_sql.execute(
        "SELECT audit_event_id FROM governance_decisions WHERE id = %s", (decision[5],)
    ).fetchone()[0]
    assert str(stored) == event["id"]


# Hard rules the state row relies on


def test_state_cannot_point_at_another_assets_decision(tenant, attacker_sql):
    first, second = submitted(tenant), submitted(tenant)
    (mine,) = decisions_of(attacker_sql, first["asset_id"])
    for column in ("current_decision_id", "hard_block_decision_id"):
        for target in (uuid4(), decisions_of(attacker_sql, second["asset_id"])[0][5]):
            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                attacker_sql.execute(
                    f"UPDATE asset_governance_state SET {column} = %s, version = version + 1 "
                    "WHERE asset_id = %s",
                    (target, first["asset_id"]),
                )
    attacker_sql.execute(
        "UPDATE asset_governance_state SET hard_block_decision_id = %s, version = version + 1 "
        "WHERE asset_id = %s",
        (mine[5], first["asset_id"]),
    )


def test_review_row_constraints_and_guard(db, tenant, attacker_sql):
    review = submitted(tenant)
    copy = ("INSERT INTO governance_reviews (id, tenant_id, asset_id, assessment_id, "
            "profile_version_id, submitted_by, required_controls_canonical, findings_canonical, "
            "required_approvers, frozen_hash, status, version, submitted_at, closed_at) "
            "SELECT %s, tenant_id, asset_id, assessment_id, profile_version_id, submitted_by, "
            "required_controls_canonical, findings_canonical, %s, frozen_hash, %s, version, "
            "submitted_at, %s FROM governance_reviews WHERE id = %s")
    now = datetime.now(UTC)
    for approvers, status, closed in ((3, "DECIDED", now), (0, "DECIDED", now),
                                      (1, "DONE", now), (1, "DECIDED", None),
                                      (1, "WITHDRAWN", None), (1, "OPEN", now)):
        with pytest.raises(psycopg.errors.CheckViolation):
            attacker_sql.execute(copy, (uuid4(), approvers, status, closed, review["id"]))
    attacker_sql.execute(copy, (uuid4(), 1, "DECIDED", now, review["id"]))  # the control

    # Below the service: closed is final, the version moves one at a time, nothing frozen
    # changes, and nothing is deleted.
    pairs = [
        ("UPDATE governance_reviews SET status = 'OPEN', closed_at = NULL, version = version + 1 "
         "WHERE status = 'DECIDED'", "closed"),
        ("UPDATE governance_reviews SET assigned_reviewer = NULL WHERE id = %(id)s", "version"),
        ("UPDATE governance_reviews SET required_approvers = 2, version = version + 1 "
         "WHERE id = %(id)s", "frozen"),
        ("UPDATE governance_reviews SET submitted_by = assigned_reviewer, version = version + 1 "
         "WHERE id = %(id)s", "frozen"),
        ("DELETE FROM governance_reviews WHERE id = %(id)s", "deleted"),
    ]
    for sql, word in pairs:
        with pytest.raises(psycopg.Error, match=word):
            attacker_sql.execute(sql, {"id": review["id"]})
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute("TRUNCATE governance_reviews CASCADE")
    # The runtime role can change only the four columns it was granted.
    for sql in ("UPDATE governance_reviews SET required_approvers = 2",
                "UPDATE governance_reviews SET frozen_hash = repeat('0', 64)",
                "UPDATE governance_reviews SET required_controls_canonical = '{}'",
                "DELETE FROM governance_reviews"):
        with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
            session.execute(text(sql))


# A tampered review fails closed


@pytest.mark.parametrize(
    "tamper",
    [
        "required_controls_canonical = replace(required_controls_canonical, "
        "'\"self_approval_permitted\":false', '\"self_approval_permitted\":true')",
        "findings_canonical = '[]'",
        "required_approvers = 2",
        "submitted_by = (SELECT id FROM users WHERE tenant_id = governance_reviews.tenant_id "
        "AND email LIKE 'viewer@%%')",
        "frozen_hash = repeat('a', 64)",
    ],
)
def test_review_edited_in_the_database_fails_closed(tenant, attacker_sql, tamper):
    holder = reviewers(tenant)
    without = {key: value for key, value in PROFILE.items() if key != "asset_type"}
    review = submitted(tenant, assessed_asset(tenant, without))  # has a finding
    tenant.login("viewer")
    mine = tenant.user_id("second-admin")
    force(attacker_sql, f"UPDATE governance_reviews SET {tamper} WHERE id = %s", (review["id"],))

    for response in (
        tenant.get(f"{APPROVALS}/{review['id']}"),
        tenant.get(APPROVALS),
        assign(tenant, review["id"], mine, holder),
        request_information(tenant, review["id"], holder),
        tenant.get("/governance/overview"),
    ):
        assert response.status_code == 503, response.text
        assert error_code(response) == "REVIEW_INTEGRITY_FAILED"
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == ["SUBMIT"]


def test_tampered_info_requested_review_is_not_replaced_by_resubmission(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    assert request_information(tenant, review["id"], holder).status_code == 200
    force(attacker_sql, "UPDATE governance_reviews SET findings_canonical = '[{}]' "
                        "WHERE id = %s", (review["id"],))
    refused = submit(tenant, review["asset_id"])
    assert (refused.status_code, error_code(refused)) == (503, "REVIEW_INTEGRITY_FAILED")
    assert len(decisions_of(attacker_sql, review["asset_id"])) == 2


HIGH_RISK = {**PROFILE, "data_categories": ["regulated"], "external_exposure": "public",
             "autonomy_level": "autonomous", "human_oversight": "none", "impact_level": "severe",
             "deployment_environment": "production_external", "third_party_reliance": "unvetted"}
INCOMPLETE = {key: value for key, value in PROFILE.items() if key != "impact_level"}


@pytest.mark.parametrize(
    ("profile", "edit", "code"),
    [
        (HIGH_RISK, "UPDATE risk_assessments SET risk_level = 'LOW' WHERE asset_id = %s",
         "ASSESSMENT_INTEGRITY_FAILED"),
        (INCOMPLETE, "UPDATE risk_assessments SET status = 'COMPLETE', score = 0, "
         "risk_level = 'LOW' WHERE asset_id = %s", "ASSESSMENT_INTEGRITY_FAILED"),
        (PROFILE, "UPDATE asset_profile_versions SET profile_canonical = replace("
         "profile_canonical, '\"asset_type\":\"ai_application\"', "
         "'\"asset_type\":\"model\"') WHERE asset_id = %s", "PROFILE_INTEGRITY_FAILED"),
    ],
    ids=["risk_level_lowered", "incomplete_flipped_to_complete", "profile_asset_type_changed"],
)
def test_submit_fails_closed_on_an_edited_assessment_or_profile(tenant, attacker_sql, profile,
                                                                 edit, code):
    asset_id = assessed_asset(tenant, profile)
    before = state_of(attacker_sql, asset_id)
    force(attacker_sql, edit, (asset_id,))
    refused = submit(tenant, asset_id)
    assert (refused.status_code, error_code(refused)) == (503, code)
    assert decisions_of(attacker_sql, asset_id) == []
    assert state_of(attacker_sql, asset_id) == before
    assert attacker_sql.execute(
        "SELECT count(*) FROM governance_reviews WHERE asset_id = %s", (asset_id,)
    ).fetchone()[0] == 0


def test_submit_decision_carries_the_frozen_hash_in_its_audit_payload(tenant, attacker_sql):
    review = submitted(tenant)
    row = decisions_of(attacker_sql, review["asset_id"])[0]
    payload = attacker_sql.execute(
        "SELECT a.payload FROM governance_decisions d JOIN audit_events a "
        "ON a.id = d.audit_event_id WHERE d.id = %s", (row[5],)
    ).fetchone()[0]
    stored = attacker_sql.execute(
        "SELECT frozen_hash FROM governance_reviews WHERE id = %s", (review["id"],)
    ).fetchone()[0]
    assert payload["frozen_hash"] == stored


@pytest.mark.parametrize("rewrite_audit", [False, True],
                         ids=["hash_only", "hash_and_audit_payload"])
def test_review_with_recomputed_hash_is_refused_for_a_decision(tenant, attacker_sql,
                                                               rewrite_audit):
    holder = reviewers(tenant)
    review = submitted(tenant)
    mine = tenant.user_id("second-admin")
    columns = ("id, tenant_id, asset_id, assessment_id, profile_version_id, submitted_by, "
               "required_controls_canonical, findings_canonical, required_approvers")
    values = attacker_sql.execute(
        f"SELECT {columns} FROM governance_reviews WHERE id = %s", (review["id"],)
    ).fetchone()
    names = [name.strip() for name in columns.split(",")]
    fields = dict(zip(names, values, strict=True))
    controls = fields["required_controls_canonical"]
    assert '"self_approval_permitted":false' in controls
    fields["required_controls_canonical"] = controls.replace(
        '"self_approval_permitted":false', '"self_approval_permitted":true')
    new_hash = _frozen_hash(SimpleNamespace(**fields, frozen_hash=None))
    force(attacker_sql, "UPDATE governance_reviews SET required_controls_canonical = %s, "
          "frozen_hash = %s WHERE id = %s",
          (fields["required_controls_canonical"], new_hash, review["id"]))
    if rewrite_audit:
        force(attacker_sql,
              "UPDATE audit_events SET payload = jsonb_set(payload, '{frozen_hash}', "
              "to_jsonb(%s::text)) WHERE id = (SELECT audit_event_id FROM governance_decisions "
              "WHERE review_id = %s AND kind = 'SUBMIT')", (new_hash, review["id"]))

    for response in (assign(tenant, review["id"], mine, holder),
                     request_information(tenant, review["id"], holder)):
        assert (response.status_code, error_code(response)) == (503, "REVIEW_INTEGRITY_FAILED")
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == ["SUBMIT"]


# Reading


def test_reviews_can_be_listed_filtered_and_read_by_any_user(tenant):
    holder = reviewers(tenant)
    first, second = submitted(tenant), submitted(tenant)
    assert request_information(tenant, second["id"], holder).status_code == 200

    listing = tenant.get(APPROVALS, headers=tenant.viewer).json()
    assert listing["total"] == 2
    assert {item["id"] for item in listing["items"]} == {first["id"], second["id"]}
    only = tenant.get(APPROVALS, status="INFO_REQUESTED").json()
    assert [item["id"] for item in only["items"]] == [second["id"]]
    by_asset = tenant.get(APPROVALS, asset_id=first["asset_id"]).json()
    assert [item["id"] for item in by_asset["items"]] == [first["id"]]
    assert tenant.get(APPROVALS, status="BOGUS").status_code == 422
    assert tenant.get(f"{APPROVALS}/{uuid4()}").status_code == 404
    assert tenant.get(f"{APPROVALS}/{first['id']}", headers=tenant.viewer).status_code == 200
    agent = tenant.agent()
    assert tenant.client.get(f"/api/v1{APPROVALS}", headers=agent.headers).status_code == 401


def test_overview_counts_open_reviews_and_their_findings(tenant):
    holder = reviewers(tenant)
    activate_policy(tenant, required_owners=["business", "technical"])
    base = tenant.get("/governance/overview").json()
    assert (base["awaiting_approval"], base["outstanding_findings"]) == (0, 0)

    first = submitted(tenant)
    submitted(tenant)
    assert len(first["findings"]) == 2
    counted = tenant.get("/governance/overview").json()
    assert (counted["awaiting_approval"], counted["outstanding_findings"]) == (2, 4)

    # Waiting on the submitter is still an open review.
    assert request_information(tenant, first["id"], holder).status_code == 200
    again = tenant.get("/governance/overview").json()
    assert (again["awaiting_approval"], again["outstanding_findings"]) == (2, 4)


# The security event


def test_status_change_projects_security_event_and_reprojection_matches(tenant, db):
    holder = reviewers(tenant)
    review = submitted(tenant)
    (event,) = status_events(tenant)
    assert event["event_type"] == "governance.status_changed"
    assert (event["severity"], event["reason_code"]) == ("info", "GOVERNANCE_SUBMIT")
    assert event["schema_version"] == 1
    assert event["asset_id"] == review["asset_id"] and event["agent_id"] is None
    assert event["actor_type"] == "user" and event["actor_id"] == tenant.user_id("admin")
    assert event["attributes"] == {"status": "UNDER_REVIEW"}

    with db.tenant_transaction(tenant.id) as session:
        stored = session.execute(
            select(SecurityEvent).where(SecurityEvent.event_type == "governance.status_changed")
        ).scalar_one()
        assert reprojection_matches(session, stored) is True

    # Assigning and asking for information leave the status alone, so they project nothing.
    assert assign(tenant, review["id"], tenant.user_id("second-admin"), holder).status_code == 200
    assert request_information(tenant, review["id"], holder).status_code == 200
    assert len(tenant.audit_events("governance.decision")) == 3
    assert len(status_events(tenant)) == 1


@pytest.mark.parametrize(
    ("kind", "to_status", "severity"),
    [
        ("SUSPEND", "SUSPENDED", "medium"),
        ("REVOKE", "SUSPENDED", "medium"),
        ("REJECT", "REJECTED", "medium"),
        ("APPROVE", "APPROVED", "info"),
        ("APPROVE_CONDITIONAL", "CONDITIONALLY_APPROVED", "info"),
        ("RETIRE", "RETIRED", "info"),
        ("REQUIRE_REASSESSMENT", "REASSESSMENT_REQUIRED", "info"),
    ],
)
def test_decision_kinds_project_with_their_severity_and_reason(tenant, db, kind, to_status,
                                                               severity):
    review = submitted(tenant)
    system = kind == "REQUIRE_REASSESSMENT"
    approving = kind.startswith("APPROVE")
    now = datetime.now(UTC)
    with db.tenant_transaction(tenant.id) as session:
        record_decision(
            session,
            asset_id=UUID(review["asset_id"]),
            kind=kind,
            from_status="UNDER_REVIEW",
            to_status=to_status,
            actor_type="system" if system else "user",
            decided_by=None if system else UUID(tenant.user_id("admin")),
            now=now,
            reason="synthetic",
            review_id=UUID(review["id"]),
            assessment_id=UUID(review["assessment_id"]) if approving else None,
            conditions=[{"control": "monitor"}] if kind == "APPROVE_CONDITIONAL" else None,
            valid_until=now + timedelta(days=30) if approving else None,
            next_review_at=now + timedelta(days=10) if approving else None,
        )
    event = next(item for item in status_events(tenant)
                 if item["reason_code"] == f"GOVERNANCE_{kind}")
    assert event["severity"] == severity
    assert event["attributes"] == {"status": to_status}
    assert event["actor_type"] == ("system" if system else "user")
    with db.tenant_transaction(tenant.id) as session:
        for stored in session.execute(select(SecurityEvent)).scalars():
            if stored.event_type == "governance.status_changed":
                assert reprojection_matches(session, stored) is True


def test_record_decision_actor_rules(tenant, db):
    review = submitted(tenant)
    now = datetime.now(UTC)
    common = {"asset_id": UUID(review["asset_id"]), "from_status": "APPROVED",
              "to_status": "REASSESSMENT_REQUIRED", "now": now, "reason": "synthetic"}
    with db.tenant_transaction(tenant.id) as session:
        decision = record_decision(session, kind="REQUIRE_REASSESSMENT", actor_type="system",
                                   decided_by=None, **common)
        assert decision.decided_by is None and decision.actor_type == "system"
    with pytest.raises(ValueError), db.tenant_transaction(tenant.id) as session:
        record_decision(session, kind="SUSPEND", actor_type="user", decided_by=None, **common)
    with pytest.raises(ValueError), db.tenant_transaction(tenant.id) as session:
        record_decision(session, kind="SUSPEND", actor_type="system",
                        decided_by=UUID(tenant.user_id("admin")), **common)
    # A system actor on any other kind is refused by the database.
    with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
        record_decision(session, kind="SUSPEND", actor_type="system", decided_by=None, **common)
    system_events = [event for event in tenant.audit_events("governance.decision")
                     if event["actor_type"] == "system"]
    assert len(system_events) == 1 and system_events[0]["actor_id"] is None
    assert tenant.verify_audit()["valid"] is True


def test_record_decision_stores_conditions_policy_versions_and_evidence(tenant, db, attacker_sql):
    version_id = UUID(activate_policy(tenant))
    review = submitted(tenant)
    evidence_id = uuid4()
    now = datetime.now(UTC)
    conditions = [{"control": "monitoring", "within_days": 30}]
    with db.tenant_transaction(tenant.id) as session:
        decision = record_decision(
            session, asset_id=UUID(review["asset_id"]), kind="APPROVE_CONDITIONAL",
            from_status="UNDER_REVIEW", to_status="CONDITIONALLY_APPROVED", actor_type="user",
            decided_by=UUID(tenant.user_id("second-admin")), now=now,
            reason="Approved with limits.",
            review_id=UUID(review["id"]), assessment_id=UUID(review["assessment_id"]),
            conditions=conditions, valid_until=now + timedelta(days=90),
            next_review_at=now + timedelta(days=30), policy_version_ids=[version_id],
            evidence_ids=[evidence_id],
        )
        decision_id = decision.id
    canonical, stored_hash = attacker_sql.execute(
        "SELECT conditions_canonical, conditions_hash FROM governance_decisions WHERE id = %s",
        (decision_id,),
    ).fetchone()
    assert json.loads(canonical) == conditions
    assert stored_hash == sha256_hex(canonical)
    assert attacker_sql.execute(
        "SELECT policy_version_id FROM governance_decision_policy_versions "
        "WHERE decision_id = %s", (decision_id,)
    ).fetchall() == [(version_id,)]
    assert attacker_sql.execute(
        "SELECT evidence_id FROM governance_decision_evidence WHERE decision_id = %s",
        (decision_id,),
    ).fetchall() == [(evidence_id,)]


# Approving and rejecting


def decision_row(attacker_sql, decision_id):
    return attacker_sql.execute(
        "SELECT kind, from_status, to_status, actor_type, decided_by, decided_at, reason, "
        "assessment_id, conditions_canonical, conditions_hash, valid_until, next_review_at, "
        "audit_event_id, review_id FROM governance_decisions WHERE id = %s", (decision_id,)
    ).fetchone()


def full_state(attacker_sql, asset_id):
    return attacker_sql.execute(
        "SELECT status, version, current_decision_id, hard_block_decision_id, valid_until, "
        "next_review_at FROM asset_governance_state WHERE asset_id = %s", (asset_id,)
    ).fetchone()


def status_reasons(tenant):
    """Reason codes of the status-change events, oldest first (the API lists newest first)."""
    return [item["reason_code"] for item in reversed(status_events(tenant))]


def test_approval_stores_full_decision_record(tenant, attacker_sql):
    holder = reviewers(tenant)
    version_id = activate_policy(tenant)
    review = submitted(tenant)
    response = approve(tenant, review["id"], holder, reason="Meets every control asked for.")
    assert response.status_code == 201, response.text
    body = response.json()
    reviewer_id = tenant.user_id("second-admin")

    assert (body["kind"], body["from_status"], body["to_status"]) == (
        "APPROVE", "UNDER_REVIEW", "APPROVED")
    assert body["decided_by"] == reviewer_id and body["review_id"] == review["id"]
    assert body["assessment_id"] == review["assessment_id"]
    assert body["conditions"] is None and body["conditions_hash"] is None
    assert body["policy_version_ids"] == [version_id] and body["evidence_ids"] == []
    assert (body["review_status"], body["governance_status"]) == ("DECIDED", "APPROVED")

    row = decision_row(attacker_sql, body["id"])
    assert row[:5] == ("APPROVE", "UNDER_REVIEW", "APPROVED", "user", UUID(reviewer_id))
    assert row[5] is not None and row[6] == "Meets every control asked for."
    assert str(row[7]) == review["assessment_id"] and row[8] is None and row[9] is None
    assert row[10] == datetime.fromisoformat(body["valid_until"])
    assert row[11] == datetime.fromisoformat(body["next_review_at"]) and row[11] < row[10]
    assert str(row[13]) == review["id"]
    assert attacker_sql.execute(
        "SELECT policy_version_id FROM governance_decision_policy_versions "
        "WHERE decision_id = %s", (body["id"],)).fetchall() == [(UUID(version_id),)]
    assert attacker_sql.execute(
        "SELECT count(*) FROM governance_decision_evidence WHERE decision_id = %s",
        (body["id"],)).fetchone()[0] == 0

    # The audit event names the decision and the reviewer, and the state row points at it.
    (event,) = [item for item in tenant.audit_events("governance.decision")
                if item["subject_id"] == body["id"]]
    assert str(row[12]) == event["id"] and event["actor_id"] == reviewer_id
    assert event["payload"]["kind"] == "APPROVE" and event["payload"]["to_status"] == "APPROVED"
    status, _, current, blocked, valid_until, next_review = full_state(
        attacker_sql, review["asset_id"])
    assert (status, str(current), blocked) == ("APPROVED", body["id"], None)
    assert (valid_until, next_review) == (row[10], row[11])
    closed = review_of(tenant, review["id"])
    assert closed["status"] == "DECIDED" and closed["closed_at"] is not None
    assert closed["version"] == review["version"] + 1
    assert status_reasons(tenant) == ["GOVERNANCE_SUBMIT", "GOVERNANCE_APPROVE"]
    assert tenant.verify_audit()["valid"] is True


def test_conditional_approval_sets_conditionally_approved(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    conditions = {"denied_tools": ["send_message", "calculate"], "hold_all": False,
                  "max_resource_classification": "internal",
                  "advisory_conditions": ["Review the logs weekly."]}
    response = approve(tenant, review["id"], holder, conditions=conditions)
    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["kind"], body["to_status"], body["governance_status"]) == (
        "APPROVE_CONDITIONAL", "CONDITIONALLY_APPROVED", "CONDITIONALLY_APPROVED")
    # Stored as canonical JSON, normalized, with a hash over exactly that text.
    canonical, stored_hash = decision_row(attacker_sql, body["id"])[8:10]
    stored = json.loads(canonical)
    assert stored["denied_tools"] == ["calculate", "send_message"]
    assert stored["max_resource_classification"] == "internal"
    assert stored["advisory_conditions"] == ["Review the logs weekly."]
    assert canonical == json.dumps(stored, sort_keys=True, separators=(",", ":"))
    assert stored_hash == sha256_hex(canonical) == body["conditions_hash"]
    assert body["conditions"] == stored
    assert full_state(attacker_sql, review["asset_id"])[0] == "CONDITIONALLY_APPROVED"
    counted = tenant.get("/governance/overview").json()
    assert (counted["conditionally_approved"], counted["awaiting_approval"]) == (1, 0)
    assert status_reasons(tenant)[-1] == "GOVERNANCE_APPROVE_CONDITIONAL"


def test_advisory_only_conditions_are_still_conditional(tenant):
    holder = reviewers(tenant)
    review = submitted(tenant)
    response = approve(tenant, review["id"], holder,
                       conditions={"advisory_conditions": ["Report incidents to the owner."]})
    assert response.status_code == 201, response.text
    assert response.json()["kind"] == "APPROVE_CONDITIONAL"


def test_conditional_approval_needs_conditions(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    empty = [{}, {"denied_tools": [], "held_tools": [], "advisory_conditions": []},
             {"hold_all": False}, {"max_resource_classification": None}]
    for conditions in empty:
        refused = approve(tenant, review["id"], holder, conditions=conditions)
        assert refused.status_code == 422, conditions
    for conditions in ({"unknown": 1}, {"hold_all": "yes"}, {"denied_tools": "send_message"},
                       {"advisory_conditions": [""]}, {"advisory_conditions": ["  \t "]}, [],
                       "none"):
        assert approve(tenant, review["id"], holder, conditions=conditions
                       ).status_code == 422, conditions
    assert_review_untouched(tenant, attacker_sql, review)


@pytest.mark.parametrize(
    "conditions",
    [
        {"denied_tools": ["no_such_tool"]},
        {"held_tools": ["no_such_tool"]},
        {"denied_actions": ["no_such_action"]},
        {"denied_tools": ["send_message"], "held_tools": ["send_message"]},
        {"max_resource_classification": "top_secret"},
    ],
    ids=["unknown_denied_tool", "unknown_held_tool", "unknown_action", "denied_and_held",
         "unknown_classification"],
)
def test_condition_with_unknown_tool_rejected(tenant, attacker_sql, conditions):
    holder = reviewers(tenant)
    review = submitted(tenant)
    refused = approve(tenant, review["id"], holder, conditions=conditions)
    assert refused.status_code == 422, refused.text
    assert_review_untouched(tenant, attacker_sql, review)
    # The control: a catalog tool is accepted.
    assert approve(tenant, review["id"], holder, conditions={"held_tools": ["calculate"]}
                   ).status_code == 201


@pytest.mark.parametrize(
    "dates",
    [
        lambda: window(valid_days=-1, review_days=-2),
        lambda: window(valid_days=0, review_days=-1),
        lambda: window(valid_days=30, review_days=31),
        lambda: window(valid_days=30, review_days=-1),
        lambda: window(valid_days=30, review_days=0),
    ],
    ids=["valid_until_past", "valid_until_now", "next_review_after_valid_until",
         "next_review_past", "next_review_now"],
)
def test_bad_dates_rejected_with_no_state_change(tenant, attacker_sql, dates):
    holder = reviewers(tenant)
    review = submitted(tenant)
    refused = approve(tenant, review["id"], holder, **dates())
    assert refused.status_code == 422, refused.text
    assert_review_untouched(tenant, attacker_sql, review)


def test_next_review_may_equal_valid_until(tenant):
    holder = reviewers(tenant)
    review = submitted(tenant)
    when = window(valid_days=30)["valid_until"]
    assert approve(tenant, review["id"], holder, valid_until=when, next_review_at=when
                   ).status_code == 201


@pytest.mark.parametrize("field", ["valid_until", "next_review_at"])
def test_naive_datetime_rejected(tenant, attacker_sql, field):
    holder = reviewers(tenant)
    review = submitted(tenant)
    naive = (datetime.now(UTC) + timedelta(days=30)).replace(tzinfo=None).isoformat()
    refused = approve(tenant, review["id"], holder, **{field: naive})
    assert refused.status_code == 422, refused.text
    for missing in ("valid_until", "next_review_at"):
        body = {"reason": "ok", **window()}
        del body[missing]
        assert tenant.post(f"{APPROVALS}/{review['id']}/approve", body, headers=holder
                           ).status_code == 422
    assert_review_untouched(tenant, attacker_sql, review)


def test_service_refuses_naive_datetimes_itself(db, tenant, attacker_sql):
    from aegis.errors import ValidationFailed
    from aegis.gateway.tools import default_registry
    from aegis.governance.approvals import approve as approve_service
    from aegis.security.principals import UserPrincipal

    reviewers(tenant)
    review = submitted(tenant)
    reviewer = UserPrincipal(UUID(tenant.user_id("second-admin")), tenant.id, "x", "admin")
    now = datetime.now(UTC)
    naive = (now + timedelta(days=30)).replace(tzinfo=None)
    with pytest.raises(ValidationFailed), db.tenant_transaction(tenant.id) as session:
        approve_service(session, default_registry(), reviewer, now, UUID(review["id"]),
                        reason="ok", valid_until=naive, next_review_at=naive)
    assert_review_untouched(tenant, attacker_sql, review)


def test_invalid_lifecycle_transitions_refused(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    assert approve(tenant, review["id"], holder).status_code == 201
    count = len(decisions_of(attacker_sql, review["asset_id"]))
    for response in (approve(tenant, review["id"], holder), reject(tenant, review["id"], holder)):
        assert (response.status_code, error_code(response)) == (409, "INVALID_STATE_TRANSITION")
    assert len(decisions_of(attacker_sql, review["asset_id"])) == count
    assert detail_status(tenant, review["asset_id"]) == "APPROVED"

    # An open review whose asset is not under review cannot be decided either.
    other = submitted(tenant)
    force(attacker_sql, "UPDATE asset_governance_state SET status = 'DRAFT' WHERE asset_id = %s",
          (other["asset_id"],))
    for response in (approve(tenant, other["id"], holder), reject(tenant, other["id"], holder)):
        assert (response.status_code, error_code(response)) == (409, "INVALID_STATE_TRANSITION")
    assert [row[0] for row in decisions_of(attacker_sql, other["asset_id"])] == ["SUBMIT"]

    # Nor can a withdrawn one.
    third = submitted(tenant)
    force(attacker_sql,
          "UPDATE governance_reviews SET status = 'WITHDRAWN', closed_at = now() WHERE id = %s",
          (third["id"],))
    for response in (approve(tenant, third["id"], holder), reject(tenant, third["id"], holder)):
        assert (response.status_code, error_code(response)) == (409, "INVALID_STATE_TRANSITION")
    assert approve(tenant, str(uuid4()), holder).status_code == 404
    assert reject(tenant, str(uuid4()), holder).status_code == 404


def test_decision_requires_a_reason(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    for reason in (None, "", "   ", "x" * 2001):
        body = {"reason": reason} if reason is not None else {}
        assert tenant.post(f"{APPROVALS}/{review['id']}/reject", body, headers=holder
                           ).status_code == 422, reason
        assert approve(tenant, review["id"], holder, reason=reason).status_code == 422, reason
    extra = {"reason": "ok", "status": "REJECTED"}
    assert tenant.post(f"{APPROVALS}/{review['id']}/reject", extra, headers=holder
                       ).status_code == 422
    assert_review_untouched(tenant, attacker_sql, review)


def test_evidence_is_not_accepted_before_the_register_exists(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    refused = approve(tenant, review["id"], holder, evidence_ids=[str(uuid4())])
    assert refused.status_code == 422, refused.text
    assert_review_untouched(tenant, attacker_sql, review)
    assert approve(tenant, review["id"], holder, evidence_ids=[]).status_code == 201


def test_two_approvers_required_when_policy_says_so(tenant, attacker_sql):
    holder = reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    assert review["required_approvers"] == 2

    first = approve(tenant, review["id"], holder, reason="First look is fine.")
    assert first.status_code == 201, first.text
    vote = first.json()
    assert (vote["kind"], vote["from_status"], vote["to_status"]) == (
        "APPROVAL_VOTE", "UNDER_REVIEW", "UNDER_REVIEW")
    assert (vote["review_status"], vote["governance_status"]) == ("OPEN", "UNDER_REVIEW")
    assert vote["valid_until"] is None and vote["next_review_at"] is None
    assert full_state(attacker_sql, review["asset_id"])[2:] == (None, None, None, None)
    assert review_status_of(attacker_sql, review["id"]) == "OPEN"
    assert status_reasons(tenant) == ["GOVERNANCE_SUBMIT"]

    second = approve(tenant, review["id"], third, reason="Second look agrees.")
    assert second.status_code == 201, second.text
    final = second.json()
    assert (final["kind"], final["governance_status"], final["review_status"]) == (
        "APPROVE", "APPROVED", "DECIDED")
    kinds = [row[0] for row in decisions_of(attacker_sql, review["asset_id"])]
    assert kinds == ["SUBMIT", "APPROVAL_VOTE", "APPROVE"]
    state = full_state(attacker_sql, review["asset_id"])
    assert str(state[2]) == final["id"] and state[4] is not None
    assert tenant.verify_audit()["valid"] is True


def test_a_rejection_does_not_wait_for_every_approver(tenant, attacker_sql):
    holder = reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    assert approve(tenant, review["id"], holder).json()["kind"] == "APPROVAL_VOTE"
    rejected = reject(tenant, review["id"], third)
    assert rejected.status_code == 201, rejected.text
    assert detail_status(tenant, review["asset_id"]) == "REJECTED"
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == [
        "SUBMIT", "APPROVAL_VOTE", "REJECT"]


def test_votes_validate_their_conditions_and_dates(tenant, attacker_sql):
    holder = reviewers(tenant)
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    assert approve(tenant, review["id"], holder, conditions={"denied_tools": ["nope"]}
                   ).status_code == 422
    assert approve(tenant, review["id"], holder, **window(valid_days=-1, review_days=-2)
                   ).status_code == 422
    assert_review_untouched(tenant, attacker_sql, review)


def test_final_approval_must_carry_the_conditions_of_the_votes(tenant, attacker_sql):
    holder = reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    vote = approve(tenant, review["id"], holder, conditions={"hold_all": True}).json()
    assert vote["kind"] == "APPROVAL_VOTE" and vote["conditions"]["hold_all"] is True
    assert full_state(attacker_sql, review["asset_id"])[0] == "UNDER_REVIEW"

    # Weaker, different, and added-to conditions are all refused: only the same ones pass.
    for conditions in ({"advisory_conditions": ["noted"]},
                       {"denied_tools": ["send_message"]},
                       {"hold_all": True, "advisory_conditions": ["and also this"]}):
        refused = approve(tenant, review["id"], third, conditions=conditions)
        assert (refused.status_code, error_code(refused)) == (409, "CONDITIONS_MISMATCH"), (
            conditions)
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == [
        "SUBMIT", "APPROVAL_VOTE"]

    # The same conditions, spelled with defaults written out, hash the same.
    final = approve(tenant, review["id"], third,
                    conditions={"hold_all": True, "denied_tools": [], "held_tools": []})
    assert final.status_code == 201, final.text
    body = final.json()
    assert (body["kind"], body["governance_status"]) == (
        "APPROVE_CONDITIONAL", "CONDITIONALLY_APPROVED")
    assert body["conditions_hash"] == vote["conditions_hash"]


def test_final_approver_may_add_conditions_when_the_vote_had_none(tenant):
    holder = reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    vote = approve(tenant, review["id"], holder).json()
    assert vote["kind"] == "APPROVAL_VOTE" and vote["conditions"] is None
    final = approve(tenant, review["id"], third, conditions={"denied_tools": ["send_message"]})
    assert final.status_code == 201, final.text
    body = final.json()
    assert (body["kind"], body["governance_status"]) == (
        "APPROVE_CONDITIONAL", "CONDITIONALLY_APPROVED")
    assert body["conditions"]["denied_tools"] == ["send_message"]


def test_a_second_approver_cannot_silently_drop_the_conditions(tenant, attacker_sql):
    holder = reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    assert approve(tenant, review["id"], holder, conditions={"hold_all": True}
                   ).status_code == 201
    dropped = approve(tenant, review["id"], third)
    assert (dropped.status_code, error_code(dropped)) == (409, "CONDITIONS_MISMATCH")
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == [
        "SUBMIT", "APPROVAL_VOTE"]
    assert detail_status(tenant, review["asset_id"]) == "UNDER_REVIEW"
    # They can still approve with the same conditions.
    assert approve(tenant, review["id"], third, conditions={"hold_all": True}).status_code == 201


def test_same_person_cannot_vote_twice(tenant, attacker_sql):
    holder = reviewers(tenant)
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    assert approve(tenant, review["id"], holder).status_code == 201
    again = approve(tenant, review["id"], holder)
    assert (again.status_code, error_code(again)) == (409, "ALREADY_VOTED")
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == [
        "SUBMIT", "APPROVAL_VOTE"]
    assert detail_status(tenant, review["asset_id"]) == "UNDER_REVIEW"
    # Below the service, the index refuses the same person as a vote or as an approval.
    reviewer_id = tenant.user_id("second-admin")
    with pytest.raises(psycopg.errors.UniqueViolation):
        insert_decision(attacker_sql, tenant.id, review["asset_id"], kind="APPROVAL_VOTE",
                        from_status="UNDER_REVIEW", to_status="UNDER_REVIEW",
                        review_id=review["id"], decided_by=reviewer_id)
    final = _decision_values(attacker_sql, tenant, asset_id=review["asset_id"], review=review,
                             decided_by=reviewer_id)
    with pytest.raises(psycopg.errors.UniqueViolation):
        _insert(attacker_sql, final)


def test_concurrent_approvals_produce_one_outcome(tenant, attacker_sql):
    holder = reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    review = submitted(tenant)
    barrier = threading.Barrier(2)

    def run(action, headers):
        barrier.wait(timeout=30)
        return action(tenant, review["id"], headers)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run, approve, holder), pool.submit(run, reject, third)]
        results = [future.result(timeout=60) for future in futures]
    codes = sorted(response.status_code for response in results)
    assert codes == [201, 409], [response.text for response in results]
    loser = next(response for response in results if response.status_code == 409)
    assert error_code(loser) == "INVALID_STATE_TRANSITION"

    winner = next(response for response in results if response.status_code == 201).json()
    kinds = [row[0] for row in decisions_of(attacker_sql, review["asset_id"])]
    assert kinds == ["SUBMIT", winner["kind"]]
    status, _, current, blocked, _, _ = full_state(attacker_sql, review["asset_id"])
    assert str(current) == winner["id"]
    assert (status, blocked is not None) == (
        ("APPROVED", False) if winner["kind"] == "APPROVE" else ("REJECTED", True))
    assert tenant.verify_audit()["valid"] is True


def test_concurrent_votes_by_one_person_count_once(tenant, attacker_sql):
    holder = reviewers(tenant)
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    barrier = threading.Barrier(2)

    def run():
        barrier.wait(timeout=30)
        return approve(tenant, review["id"], holder).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = sorted(future.result(timeout=60) for future in [pool.submit(run),
                                                                pool.submit(run)])
    assert codes == [201, 409]
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == [
        "SUBMIT", "APPROVAL_VOTE"]


@pytest.mark.parametrize("action", [approve, reject], ids=["approve", "reject"])
def test_decisions_lock_agents_before_state(urls, tenant, attacker_sql, action):
    """Spec 11.4: agent rows, then state, then the review, then the chain head."""
    holder = reviewers(tenant)
    agent = tenant.agent(tools=["calculate"])
    asset_id = tenant.get(f"/agents/{agent.id}").json()["asset_id"]
    save_profile(tenant, asset_id)
    assess(tenant, asset_id)
    review = submitted(tenant, asset_id)
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        with psycopg.connect(urls.superuser, autocommit=True) as observer:
            with attacker_sql.transaction():
                attacker_sql.execute(
                    "SELECT id FROM agents WHERE asset_id = %s FOR UPDATE", (asset_id,)
                )
                response = pool.submit(action, tenant, review["id"], holder)
                waiting = 0
                deadline = time.monotonic() + 15
                while not waiting and time.monotonic() < deadline:
                    waiting = observer.execute(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE wait_event_type = 'Lock' AND query LIKE '%FROM agents%' "
                        "AND pid <> pg_backend_pid()"
                    ).fetchone()[0]
                    time.sleep(0.05)
                assert waiting, "the decision did not block on the agent rows"
                # Neither the state row nor the review has been locked yet.
                with observer.transaction():
                    observer.execute(
                        "SELECT 1 FROM asset_governance_state WHERE asset_id = %s "
                        "FOR UPDATE NOWAIT", (asset_id,))
                    observer.execute(
                        "SELECT 1 FROM governance_reviews WHERE id = %s FOR UPDATE NOWAIT",
                        (review["id"],))
                assert not response.done()
        assert response.result(timeout=30).status_code == 201
    finally:
        pool.shutdown(wait=True)


def test_rejection_sets_hard_block(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    # A prior approval's dates must not survive a rejection.
    force(attacker_sql,
          "UPDATE asset_governance_state SET valid_until = now() + interval '30 days', "
          "next_review_at = now() + interval '10 days' WHERE asset_id = %s",
          (review["asset_id"],))
    response = reject(tenant, review["id"], holder, reason="Unmitigated data exposure.")
    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["kind"], body["from_status"], body["to_status"]) == (
        "REJECT", "UNDER_REVIEW", "REJECTED")
    assert body["valid_until"] is None and body["next_review_at"] is None
    assert body["conditions"] is None and body["decided_by"] == tenant.user_id("second-admin")
    assert (body["review_status"], body["governance_status"]) == ("DECIDED", "REJECTED")

    status, _, current, blocked, valid_until, next_review = full_state(
        attacker_sql, review["asset_id"])
    assert status == "REJECTED"
    assert str(current) == str(blocked) == body["id"]
    assert (valid_until, next_review) == (None, None)
    closed = review_of(tenant, review["id"])
    assert closed["status"] == "DECIDED" and closed["closed_at"] is not None
    row = decision_row(attacker_sql, body["id"])
    assert str(row[7]) == review["assessment_id"] and row[6] == "Unmitigated data exposure."
    event = status_events(tenant)[0]
    assert (event["reason_code"], event["severity"]) == ("GOVERNANCE_REJECT", "medium")
    assert tenant.verify_audit()["valid"] is True


def test_approval_clears_the_hard_block(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    blocker = insert_decision(attacker_sql, tenant.id, review["asset_id"], kind="SUSPEND",
                              from_status="DRAFT", to_status="SUSPENDED")
    force(attacker_sql,
          "UPDATE asset_governance_state SET hard_block_decision_id = %s WHERE asset_id = %s",
          (blocker, review["asset_id"]))
    assert full_state(attacker_sql, review["asset_id"])[3] == blocker
    response = approve(tenant, review["id"], holder)
    assert response.status_code == 201, response.text
    assert full_state(attacker_sql, review["asset_id"])[3] is None


def test_votes_leave_the_hard_block_alone(tenant, attacker_sql):
    holder = reviewers(tenant)
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    blocker = insert_decision(attacker_sql, tenant.id, review["asset_id"], kind="SUSPEND",
                              from_status="DRAFT", to_status="SUSPENDED")
    force(attacker_sql,
          "UPDATE asset_governance_state SET hard_block_decision_id = %s WHERE asset_id = %s",
          (blocker, review["asset_id"]))
    assert approve(tenant, review["id"], holder).json()["kind"] == "APPROVAL_VOTE"
    assert full_state(attacker_sql, review["asset_id"])[3] == blocker


def test_failed_audit_rolls_back_the_decision(tenant, attacker_sql, monkeypatch):
    from aegis.governance import approvals

    holder = reviewers(tenant)
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic audit outage")

    monkeypatch.setattr(approvals, "append_event", fail)
    results = [approve(tenant, review["id"], holder), reject(tenant, review["id"], holder)]
    monkeypatch.undo()

    assert [response.status_code for response in results] == [500, 500]
    assert_review_untouched(tenant, attacker_sql, review)
    # Nothing was left half done, so the same person can still act.
    assert approve(tenant, review["id"], holder).status_code == 201


# A review that does not match the audit chain is refused for a decision


def test_repointed_audit_event_is_refused_by_a_decision(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    other = attacker_sql.execute(
        "SELECT id FROM audit_events WHERE tenant_id = %s ORDER BY seq LIMIT 1", (tenant.id,)
    ).fetchone()[0]
    force(attacker_sql,
          "UPDATE governance_decisions SET audit_event_id = %s WHERE review_id = %s "
          "AND kind = 'SUBMIT'", (other, review["id"]))
    for response in (approve(tenant, review["id"], holder), reject(tenant, review["id"], holder)):
        assert (response.status_code, error_code(response)) == (503, "REVIEW_INTEGRITY_FAILED")
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == ["SUBMIT"]
    assert detail_status(tenant, review["asset_id"]) == "UNDER_REVIEW"


def test_second_submit_row_is_refused_by_a_decision(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    insert_decision(attacker_sql, tenant.id, review["asset_id"], kind="SUBMIT",
                    from_status="ASSESSMENT_REQUIRED", to_status="UNDER_REVIEW",
                    review_id=review["id"])
    for response in (approve(tenant, review["id"], holder), reject(tenant, review["id"], holder)):
        assert (response.status_code, error_code(response)) == (503, "REVIEW_INTEGRITY_FAILED")
    assert detail_status(tenant, review["asset_id"]) == "UNDER_REVIEW"
    assert review_status_of(attacker_sql, review["id"]) == "OPEN"


def test_tampered_profile_risk_factor_fails_submit_as_a_profile_error(tenant, attacker_sql):
    asset_id = assessed_asset(tenant)
    before = state_of(attacker_sql, asset_id)
    force(attacker_sql,
          "UPDATE asset_profile_versions SET profile_canonical = replace(profile_canonical, "
          "'\"impact_level\":\"negligible\"', '\"impact_level\":\"severe\"') "
          "WHERE asset_id = %s", (asset_id,))
    refused = submit(tenant, asset_id)
    assert (refused.status_code, error_code(refused)) == (503, "PROFILE_INTEGRITY_FAILED")
    assert decisions_of(attacker_sql, asset_id) == []
    assert state_of(attacker_sql, asset_id) == before


# A vote counts only while its voter could still decide


def test_vote_of_revoked_holder_does_not_count(tenant, attacker_sql):
    holder = reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    fourth = another_holder(tenant, "fourth-admin")
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    assert approve(tenant, review["id"], holder).json()["kind"] == "APPROVAL_VOTE"
    revoke_governance(tenant, "second-admin")
    # The revoked voter cannot vote again, and the index would stop a second vote anyway.
    assert approve(tenant, review["id"], holder).status_code == 403

    # B's approval is still a vote, because A's no longer counts.
    second = approve(tenant, review["id"], third)
    assert second.status_code == 201, second.text
    assert second.json()["kind"] == "APPROVAL_VOTE"
    assert detail_status(tenant, review["asset_id"]) == "UNDER_REVIEW"
    assert review_status_of(attacker_sql, review["id"]) == "OPEN"
    again = approve(tenant, review["id"], third)
    assert (again.status_code, error_code(again)) == (409, "ALREADY_VOTED")

    # A further eligible person completes it.
    final = approve(tenant, review["id"], fourth)
    assert final.status_code == 201, final.text
    assert (final.json()["kind"], final.json()["governance_status"]) == ("APPROVE", "APPROVED")
    assert [row[0] for row in decisions_of(attacker_sql, review["asset_id"])] == [
        "SUBMIT", "APPROVAL_VOTE", "APPROVAL_VOTE", "APPROVE"]


def test_conditions_of_a_revoked_voter_do_not_bind_the_final_approval(tenant):
    holder = reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    fourth = another_holder(tenant, "fourth-admin")
    activate_policy(tenant, minimum_approvers=2)
    review = submitted(tenant)
    assert approve(tenant, review["id"], holder, conditions={"hold_all": True}
                   ).status_code == 201
    revoke_governance(tenant, "second-admin")
    assert approve(tenant, review["id"], third).json()["kind"] == "APPROVAL_VOTE"
    assert approve(tenant, review["id"], fourth).json()["kind"] == "APPROVE"


# The assessment must still describe the asset


@pytest.mark.parametrize("approvers", [1, 2], ids=["final_approval", "vote"])
def test_grant_added_during_review_blocks_approval(tenant, attacker_sql, approvers):
    holder = reviewers(tenant)
    if approvers == 2:
        activate_policy(tenant, minimum_approvers=2)
    agent = tenant.agent(tools=["calculate"])
    asset_id = tenant.get(f"/agents/{agent.id}").json()["asset_id"]
    save_profile(tenant, asset_id)
    assess(tenant, asset_id)
    review = submitted(tenant, asset_id)
    tenant.created(f"/agents/{agent.id}/tool-grants", {"tool": "send_message"})

    refused = approve(tenant, review["id"], holder)
    assert (refused.status_code, error_code(refused)) == (409, "ASSESSMENT_NOT_CURRENT")
    assert_review_untouched(tenant, attacker_sql, review)

    # The way out: ask for information, assess again, resubmit. The new review can be approved.
    assert request_information(tenant, review["id"], holder).status_code == 200
    assess(tenant, asset_id)
    again = submitted(tenant, asset_id)
    assert again["id"] != review["id"]
    done = approve(tenant, again["id"], holder)
    assert done.status_code == 201, done.text
    assert done.json()["kind"] == ("APPROVE" if approvers == 1 else "APPROVAL_VOTE")


@pytest.mark.parametrize("approvers", [1, 2], ids=["final_approval", "vote"])
def test_profile_saved_during_review_blocks_approval(tenant, attacker_sql, approvers):
    holder = reviewers(tenant)
    if approvers == 2:
        activate_policy(tenant, minimum_approvers=2)
    asset_id = assessed_asset(tenant)
    review = submitted(tenant, asset_id)
    # Only the description changes, so the engine's inputs are identical; the profile still moved.
    save_profile(tenant, asset_id, {**PROFILE, "description": "edited during review"})

    refused = approve(tenant, review["id"], holder)
    assert (refused.status_code, error_code(refused)) == (409, "ASSESSMENT_NOT_CURRENT")
    assert_review_untouched(tenant, attacker_sql, review)

    assert request_information(tenant, review["id"], holder).status_code == 200
    assess(tenant, asset_id)
    again = submitted(tenant, asset_id)
    done = approve(tenant, again["id"], holder)
    assert done.status_code == 201, done.text
    assert done.json()["kind"] == ("APPROVE" if approvers == 1 else "APPROVAL_VOTE")


def test_reject_is_allowed_on_a_review_whose_assessment_is_stale(tenant):
    holder = reviewers(tenant)
    asset_id = assessed_asset(tenant)
    review = submitted(tenant, asset_id)
    save_profile(tenant, asset_id, {**PROFILE, "description": "edited during review"})
    assert approve(tenant, review["id"], holder).status_code == 409
    rejected = reject(tenant, review["id"], holder)
    assert rejected.status_code == 201, rejected.text
    assert detail_status(tenant, asset_id) == "REJECTED"


# While information is outstanding


def test_approve_is_refused_while_information_is_requested_but_reject_is_not(tenant,
                                                                           attacker_sql):
    holder = reviewers(tenant)
    activate_policy(tenant, minimum_approvers=2)
    first, second = submitted(tenant), submitted(tenant)
    for review in (first, second):
        assert request_information(tenant, review["id"], holder).status_code == 200
    refused = approve(tenant, first["id"], holder)
    assert (refused.status_code, error_code(refused)) == (409, "REVIEW_AWAITING_INFORMATION")
    assert [row[0] for row in decisions_of(attacker_sql, first["asset_id"])] == [
        "SUBMIT", "REQUEST_INFORMATION"]
    assert review_status_of(attacker_sql, first["id"]) == "INFO_REQUESTED"

    rejected = reject(tenant, second["id"], holder)
    assert rejected.status_code == 201, rejected.text
    assert detail_status(tenant, second["asset_id"]) == "REJECTED"


# Reassessment keeps the conditions that were approved


def test_resubmission_keeps_the_approved_decision_as_current(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    approved = approve(tenant, review["id"], holder, conditions={"hold_all": True}).json()
    asset_id = review["asset_id"]
    before = full_state(attacker_sql, asset_id)
    assert (before[0], str(before[2])) == ("CONDITIONALLY_APPROVED", approved["id"])

    force(attacker_sql,
          "UPDATE asset_governance_state SET status = 'REASSESSMENT_REQUIRED' "
          "WHERE asset_id = %s", (asset_id,))
    assess(tenant, asset_id)
    resubmitted = submitted(tenant, asset_id)
    assert detail_status(tenant, asset_id) == "UNDER_REVIEW"
    after = full_state(attacker_sql, asset_id)
    assert str(after[2]) == approved["id"]
    assert (after[4], after[5]) == (before[4], before[5])
    assert decisions_of(attacker_sql, asset_id)[-1][3] == UUID(resubmitted["id"])
