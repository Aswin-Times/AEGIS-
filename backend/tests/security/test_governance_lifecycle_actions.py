"""Suspend, revoke, reassess, retire, and the actions that force reassessment on their own."""

import ast
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest

import aegis
from aegis.errors import Conflict
from aegis.governance.approvals import require_reassessment
from support import (
    ASSETS,
    PROFILE,
    approve,
    assess,
    assessed_asset,
    decisions_of,
    detail_status,
    error_code,
    reject,
    reviewers,
    save_profile,
    submit,
    submitted,
)

REASON = {"reason": "Synthetic emergency stop."}


def act(tenant, asset_id, action, headers=None, body=None):
    return tenant.post(f"{ASSETS}/{asset_id}/{action}", REASON if body is None else body,
                       headers=headers)


def state_of(attacker_sql, asset_id):
    return attacker_sql.execute(
        "SELECT status, version, current_decision_id, hard_block_decision_id, valid_until, "
        "next_review_at FROM asset_governance_state WHERE asset_id = %s", (asset_id,)
    ).fetchone()


def approved_asset(tenant, conditions=None):
    """An asset taken through the real review flow to APPROVED (or CONDITIONALLY_APPROVED)."""
    holder = reviewers(tenant)
    review = submitted(tenant)
    response = approve(tenant, review["id"], holder, conditions=conditions)
    assert response.status_code == 201, response.text
    return review["asset_id"], review, response.json()


def agent_of(tenant, asset_id, name=None):
    return tenant.created("/agents", {"asset_id": asset_id, "owner": "synthetic-owner",
                                      "name": name or f"agent-{uuid4().hex[:8]}"})["id"]


def kinds(attacker_sql, asset_id):
    return [row[0] for row in decisions_of(attacker_sql, asset_id)]


# Suspend and revoke


def test_suspend_asset_with_no_state_row(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    assert state_of(attacker_sql, asset_id) is None

    response = act(tenant, asset_id, "suspend")
    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["kind"], body["from_status"], body["to_status"]) == (
        "SUSPEND", "DRAFT", "SUSPENDED")
    assert body["governance_status"] == "SUSPENDED" and body["review_id"] is None
    assert body["decided_by"] == tenant.user_id("admin") and body["actor_type"] == "user"

    status, version, current, blocked, valid_until, next_review = state_of(attacker_sql, asset_id)
    assert (status, version) == ("SUSPENDED", 2)
    assert str(current) == str(blocked) == body["id"]
    assert valid_until is None and next_review is None
    (event,) = [item for item in tenant.audit_events("governance.decision")
                if item["subject_id"] == body["id"]]
    assert event["payload"]["kind"] == "SUSPEND" and event["actor_id"] == body["decided_by"]
    assert tenant.get("/governance/overview").json()["suspended"] == 1
    assert tenant.verify_audit()["valid"] is True


def test_suspended_asset_cannot_return_directly_to_approved(tenant, attacker_sql):
    asset_id, review, _ = approved_asset(tenant)
    assert act(tenant, asset_id, "suspend").status_code == 201

    # Neither the service nor the database lets a suspended asset skip reassessment.
    refused = submit(tenant, asset_id)
    assert (refused.status_code, error_code(refused)) == (409, "INVALID_STATE_TRANSITION")
    holder = reviewers(tenant)
    assert approve(tenant, review["id"], holder).status_code == 409
    with pytest.raises(psycopg.Error, match="invalid governance transition"):
        attacker_sql.execute(
            "UPDATE asset_governance_state SET status = 'APPROVED', version = version + 1 "
            "WHERE asset_id = %s", (asset_id,))
    assert detail_status(tenant, asset_id) == "SUSPENDED"


def test_hard_block_survives_reassessment_and_review(tenant, attacker_sql):
    asset_id, _, _ = approved_asset(tenant)
    suspended = act(tenant, asset_id, "suspend").json()

    def blocked():
        return str(state_of(attacker_sql, asset_id)[3])

    assert blocked() == suspended["id"]
    reassessed = act(tenant, asset_id, "reassess")
    assert reassessed.status_code == 201, reassessed.text
    assert reassessed.json()["governance_status"] == "REASSESSMENT_REQUIRED"
    assert blocked() == suspended["id"]
    assess(tenant, asset_id)
    assert blocked() == suspended["id"]
    review = submit(tenant, asset_id)
    assert review.status_code == 201, review.text
    assert detail_status(tenant, asset_id) == "UNDER_REVIEW"
    assert blocked() == suspended["id"]


def test_approval_clears_hard_block(tenant, attacker_sql):
    asset_id, _, _ = approved_asset(tenant)
    assert act(tenant, asset_id, "suspend").status_code == 201
    assert act(tenant, asset_id, "reassess").status_code == 201
    assess(tenant, asset_id)
    review = submit(tenant, asset_id).json()
    holder = reviewers(tenant)
    decision = approve(tenant, review["id"], holder)
    assert decision.status_code == 201, decision.text
    status, _, current, blocked, valid_until, _ = state_of(attacker_sql, asset_id)
    assert (status, blocked) == ("APPROVED", None)
    assert str(current) == decision.json()["id"] and valid_until is not None
    assert kinds(attacker_sql, asset_id) == [
        "SUBMIT", "APPROVE", "SUSPEND", "REQUIRE_REASSESSMENT", "SUBMIT", "APPROVE"]


def test_suspend_clears_valid_until(tenant, attacker_sql):
    asset_id, _, approval = approved_asset(tenant)
    before = state_of(attacker_sql, asset_id)
    assert before[4] is not None and before[5] is not None

    suspended = act(tenant, asset_id, "suspend").json()
    status, _, current, blocked, valid_until, next_review = state_of(attacker_sql, asset_id)
    assert status == "SUSPENDED" and valid_until is None and next_review is None
    assert str(current) == str(blocked) == suspended["id"] != approval["id"]


def test_revoke_records_revoke_kind_and_suspends(tenant, attacker_sql):
    asset_id, _, _ = approved_asset(tenant)
    response = act(tenant, asset_id, "revoke", body={"reason": "Approval withdrawn."})
    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["kind"], body["to_status"], body["governance_status"]) == (
        "REVOKE", "SUSPENDED", "SUSPENDED")
    assert body["reason"] == "Approval withdrawn."
    status, _, current, blocked, valid_until, _ = state_of(attacker_sql, asset_id)
    assert status == "SUSPENDED" and valid_until is None
    assert str(current) == str(blocked) == body["id"]
    assert kinds(attacker_sql, asset_id)[-1] == "REVOKE"


def test_suspending_a_suspended_asset_is_refused(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    assert act(tenant, asset_id, "suspend").status_code == 201
    before = decisions_of(attacker_sql, asset_id)
    for action in ("suspend", "revoke"):
        refused = act(tenant, asset_id, action)
        assert (refused.status_code, error_code(refused)) == (409, "INVALID_STATE_TRANSITION")
    assert decisions_of(attacker_sql, asset_id) == before
    assert tenant.verify_audit()["valid"] is True


def test_suspend_withdraws_the_open_review(tenant, attacker_sql):
    review = submitted(tenant)
    asset_id = review["asset_id"]
    assert detail_status(tenant, asset_id) == "UNDER_REVIEW"

    suspended = act(tenant, asset_id, "suspend").json()
    row = attacker_sql.execute(
        "SELECT status, closed_at, version FROM governance_reviews WHERE id = %s", (review["id"],)
    ).fetchone()
    assert row[0] == "WITHDRAWN" and row[1] is not None and row[2] == review["version"] + 1
    assert suspended["review_id"] == review["id"]
    # The withdrawn review can no longer be decided.
    holder = reviewers(tenant)
    assert approve(tenant, review["id"], holder).status_code == 409
    assert reject(tenant, review["id"], holder).status_code == 409
    assert detail_status(tenant, asset_id) == "SUSPENDED"


def test_viewer_cannot_suspend(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    for action in ("suspend", "revoke", "reassess", "retire"):
        assert act(tenant, asset_id, action, headers=tenant.viewer).status_code == 403, action
    assert state_of(attacker_sql, asset_id) is None
    assert decisions_of(attacker_sql, asset_id) == []


def test_plain_reviewer_cannot_suspend_without_grant(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    for action in ("suspend", "revoke", "reassess"):
        assert act(tenant, asset_id, action, headers=tenant.reviewer).status_code == 403, action
    assert state_of(attacker_sql, asset_id) is None

    # The grant, not the user role, is what confers it.
    reviewers(tenant)
    tenant.grant_governance("reviewer", by="second-admin")
    assert act(tenant, asset_id, "suspend", headers=tenant.reviewer).status_code == 201
    assert decisions_of(attacker_sql, asset_id)[0][0] == "SUSPEND"


def test_only_an_admin_can_retire(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    reviewers(tenant)
    tenant.grant_governance("reviewer", by="second-admin")
    for headers in (tenant.reviewer, tenant.viewer):
        assert act(tenant, asset_id, "retire", headers=headers).status_code == 403
    assert state_of(attacker_sql, asset_id) is None
    assert act(tenant, asset_id, "retire").status_code == 201


def test_agent_principal_cannot_use_the_lifecycle_routes(tenant, attacker_sql):
    agent = tenant.agent()
    asset_id = tenant.get(f"/agents/{agent.id}").json()["asset_id"]
    for action in ("suspend", "revoke", "reassess", "retire"):
        response = tenant.client.post(f"/api/v1{ASSETS}/{asset_id}/{action}", json=REASON,
                                      headers=agent.headers)
        assert response.status_code == 401, action
    assert state_of(attacker_sql, asset_id) is None


@pytest.mark.parametrize("body", [{}, {"reason": ""}, {"reason": "  "}, {"reason": "x" * 2001},
                                  {"reason": "ok", "extra": 1}, {"reason": 5}])
def test_lifecycle_actions_need_a_reason(tenant, attacker_sql, body):
    asset_id = tenant.asset()["id"]
    for action in ("suspend", "revoke", "reassess", "retire"):
        assert act(tenant, asset_id, action, body=body).status_code == 422, action
    assert state_of(attacker_sql, asset_id) is None


# Reassess


def test_reassess_leaves_the_approval_and_conditions_in_place(tenant, attacker_sql):
    conditions = {"denied_tools": ["send_message"]}
    asset_id, _, approval = approved_asset(tenant, conditions=conditions)
    assert approval["to_status"] == "CONDITIONALLY_APPROVED"
    before = state_of(attacker_sql, asset_id)

    response = act(tenant, asset_id, "reassess")
    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["kind"], body["from_status"], body["to_status"]) == (
        "REQUIRE_REASSESSMENT", "CONDITIONALLY_APPROVED", "REASSESSMENT_REQUIRED")
    assert body["actor_type"] == "user" and body["decided_by"] == tenant.user_id("admin")
    after = state_of(attacker_sql, asset_id)
    assert after[0] == "REASSESSMENT_REQUIRED" and after[1] == before[1] + 1
    # The decision that holds the conditions, and the window, are untouched.
    assert after[2:] == before[2:]
    assert str(after[2]) == approval["id"]


def test_reassess_needs_a_status_that_allows_it(tenant, attacker_sql):
    bare = tenant.asset()["id"]
    refused = act(tenant, bare, "reassess")
    assert (refused.status_code, error_code(refused)) == (409, "INVALID_STATE_TRANSITION")
    assert state_of(attacker_sql, bare) is None

    review = submitted(tenant)
    refused = act(tenant, review["asset_id"], "reassess")
    assert (refused.status_code, error_code(refused)) == (409, "INVALID_STATE_TRANSITION")
    assert detail_status(tenant, review["asset_id"]) == "UNDER_REVIEW"
    assert kinds(attacker_sql, review["asset_id"]) == ["SUBMIT"]


def test_reassess_never_clears_the_hard_block(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    suspended = act(tenant, asset_id, "suspend").json()
    assert act(tenant, asset_id, "reassess").status_code == 201
    status, _, current, blocked, valid_until, _ = state_of(attacker_sql, asset_id)
    assert status == "REASSESSMENT_REQUIRED" and valid_until is None
    assert str(blocked) == str(current) == suspended["id"]


def test_rejection_after_a_real_reassessment_leaves_no_approval_in_force(tenant, attacker_sql):
    """The whole path, with no forcing: approve, reassess, assess, submit, then reject."""
    asset_id, _, approval = approved_asset(tenant)
    assert state_of(attacker_sql, asset_id)[4] is not None
    assert act(tenant, asset_id, "reassess").status_code == 201
    assess(tenant, asset_id)
    review = submit(tenant, asset_id).json()
    rejected = reject(tenant, review["id"], reviewers(tenant))
    assert rejected.status_code == 201, rejected.text

    status, _, current, blocked, valid_until, next_review = state_of(attacker_sql, asset_id)
    assert status == "REJECTED"
    assert valid_until is None and next_review is None
    assert str(current) == str(blocked) == rejected.json()["id"] != approval["id"]


# Retire


def test_retire_closes_the_review_and_clears_the_window(tenant, attacker_sql):
    review = submitted(tenant)
    asset_id = review["asset_id"]
    retired = act(tenant, asset_id, "retire", body={"reason": "Decommissioned."})
    assert retired.status_code == 201, retired.text
    body = retired.json()
    assert (body["kind"], body["from_status"], body["to_status"]) == (
        "RETIRE", "UNDER_REVIEW", "RETIRED")
    assert body["review_id"] == review["id"] and body["governance_status"] == "RETIRED"
    status, _, current, blocked, valid_until, next_review = state_of(attacker_sql, asset_id)
    assert (status, blocked, valid_until, next_review) == ("RETIRED", None, None, None)
    assert str(current) == body["id"]
    assert attacker_sql.execute("SELECT status FROM governance_reviews WHERE id = %s",
                                (review["id"],)).fetchone()[0] == "WITHDRAWN"


def test_retire_clears_an_approval_window(tenant, attacker_sql):
    asset_id, _, _ = approved_asset(tenant)
    assert act(tenant, asset_id, "retire").status_code == 201
    status, _, _, _, valid_until, next_review = state_of(attacker_sql, asset_id)
    assert status == "RETIRED" and valid_until is None and next_review is None


def test_retire_keeps_the_hard_block_of_a_suspended_asset(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    suspended = act(tenant, asset_id, "suspend").json()
    retired = act(tenant, asset_id, "retire").json()
    status, _, current, blocked, _, _ = state_of(attacker_sql, asset_id)
    assert status == "RETIRED"
    assert str(blocked) == suspended["id"] and str(current) == retired["id"]


def test_retire_an_asset_with_no_state_row(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    body = act(tenant, asset_id, "retire").json()
    assert (body["from_status"], body["to_status"]) == ("DRAFT", "RETIRED")
    assert state_of(attacker_sql, asset_id)[0] == "RETIRED"


def test_retired_asset_refuses_new_work(tenant, attacker_sql):
    # Review Focus 5. Evidence is asserted with the evidence register.
    asset_id = assessed_asset(tenant)
    assert act(tenant, asset_id, "retire").status_code == 201
    before = decisions_of(attacker_sql, asset_id)

    attempts = [
        tenant.post(f"{ASSETS}/{asset_id}/profile", {"description": "late"}),
        tenant.post(f"{ASSETS}/{asset_id}/assess"),
        submit(tenant, asset_id),
        act(tenant, asset_id, "suspend"),
        act(tenant, asset_id, "revoke"),
        act(tenant, asset_id, "reassess"),
        act(tenant, asset_id, "retire"),
    ]
    for response in attempts:
        assert (response.status_code, error_code(response)) == (409, "ASSET_RETIRED")
    assert decisions_of(attacker_sql, asset_id) == before
    assert tenant.get(f"{ASSETS}/{asset_id}/history").status_code == 200
    assert tenant.get(f"{ASSETS}/{asset_id}").json()["governance_status"] == "RETIRED"


def test_retired_is_terminal_even_for_an_update_that_leaves_the_status(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    assert act(tenant, asset_id, "retire").status_code == 201
    for assignment in ("updated_at = now()", "valid_until = now()",
                       "current_profile_version_id = NULL"):
        with pytest.raises(psycopg.Error, match="retired"):
            attacker_sql.execute(
                f"UPDATE asset_governance_state SET {assignment}, version = version + 1 "
                "WHERE asset_id = %s", (asset_id,))
    with pytest.raises(psycopg.Error):
        attacker_sql.execute(
            "UPDATE asset_governance_state SET status = 'SUSPENDED', version = version + 1 "
            "WHERE asset_id = %s", (asset_id,))
    assert state_of(attacker_sql, asset_id)[0] == "RETIRED"


# Forced reassessment


def test_new_profile_on_approved_asset_forces_reassessment(tenant, attacker_sql):
    asset_id, _, approval = approved_asset(tenant)
    before = state_of(attacker_sql, asset_id)

    response = tenant.post(f"{ASSETS}/{asset_id}/profile", {"description": "changed"})
    assert response.status_code == 201, response.text
    assert response.json()["governance_status"] == "REASSESSMENT_REQUIRED"
    status, _, current, blocked, valid_until, next_review = state_of(attacker_sql, asset_id)
    assert (status, blocked) == ("REASSESSMENT_REQUIRED", None)
    # The approval's window and decision stay, as a reassessment leaves them.
    assert (str(current), valid_until, next_review) == (approval["id"], before[4], before[5])

    rows = decisions_of(attacker_sql, asset_id)
    assert [row[0] for row in rows][-1] == "REQUIRE_REASSESSMENT"
    assert (rows[-1][1], rows[-1][2], rows[-1][4]) == (
        "APPROVED", "REASSESSMENT_REQUIRED", "Asset profile changed.")
    (event,) = [item for item in tenant.audit_events("governance.decision")
                if item["payload"]["kind"] == "REQUIRE_REASSESSMENT"]
    assert event["actor_type"] == "user" and event["actor_id"] == tenant.user_id("admin")
    assert tenant.verify_audit()["valid"] is True


def test_new_profile_on_conditionally_approved_asset_forces_reassessment(tenant, attacker_sql):
    asset_id, _, approval = approved_asset(tenant, conditions={"denied_tools": ["send_message"]})
    assert tenant.post(f"{ASSETS}/{asset_id}/profile", {"description": "changed"}
                       ).json()["governance_status"] == "REASSESSMENT_REQUIRED"
    # The conditions stay in force through reassessment.
    assert str(state_of(attacker_sql, asset_id)[2]) == approval["id"]


def test_identical_profile_is_a_no_op(tenant, attacker_sql):
    asset_id, _, _ = approved_asset(tenant)
    first = tenant.get(f"{ASSETS}/{asset_id}").json()
    before_state = state_of(attacker_sql, asset_id)
    before_events = len(tenant.audit_events())
    before_versions = attacker_sql.execute(
        "SELECT count(*) FROM asset_profile_versions WHERE asset_id = %s", (asset_id,)
    ).fetchone()[0]

    again = tenant.post(f"{ASSETS}/{asset_id}/profile", PROFILE)
    assert again.status_code == 201, again.text
    assert again.json()["id"] == first["profile"]["id"]
    assert again.json()["version"] == first["profile"]["version"]
    assert again.json()["governance_status"] == "APPROVED"
    assert state_of(attacker_sql, asset_id) == before_state
    assert len(tenant.audit_events()) == before_events
    assert attacker_sql.execute(
        "SELECT count(*) FROM asset_profile_versions WHERE asset_id = %s", (asset_id,)
    ).fetchone()[0] == before_versions


def test_a_changed_profile_after_a_no_op_still_saves(tenant):
    asset_id = tenant.asset()["id"]
    one = save_profile(tenant, asset_id, {"description": "one"})
    assert save_profile(tenant, asset_id, {"description": "one"})["id"] == one["id"]
    two = save_profile(tenant, asset_id, {"description": "two"})
    assert two["version"] == 2
    # Going back to an earlier profile is a change from the current one.
    assert save_profile(tenant, asset_id, {"description": "one"})["version"] == 3


def test_profile_on_an_unapproved_asset_does_not_force_reassessment(tenant, attacker_sql):
    asset_id = assessed_asset(tenant)
    assert detail_status(tenant, asset_id) == "ASSESSMENT_REQUIRED"
    save_profile(tenant, asset_id, {"description": "changed"})
    assert detail_status(tenant, asset_id) == "ASSESSMENT_REQUIRED"
    assert kinds(attacker_sql, asset_id) == []


@pytest.mark.parametrize("kind", ["tool", "resource"])
def test_added_grant_on_approved_asset_forces_reassessment(tenant, attacker_sql, kind):
    asset_id = tenant.asset()["id"]
    agent_id = agent_of(tenant, asset_id)
    save_profile(tenant, asset_id)
    assess(tenant, asset_id)
    holder = reviewers(tenant)
    review = submitted(tenant, asset_id)
    approval = approve(tenant, review["id"], holder).json()
    before = state_of(attacker_sql, asset_id)

    if kind == "tool":
        path, body = f"/agents/{agent_id}/tool-grants", {"tool": "calculate"}
    else:
        path, body = f"/agents/{agent_id}/resource-grants", {"resource_id": tenant.document()}
    assert tenant.post(path, body).status_code == 201

    status, _, current, blocked, valid_until, _ = state_of(attacker_sql, asset_id)
    assert (status, blocked, str(current), valid_until) == (
        "REASSESSMENT_REQUIRED", None, approval["id"], before[4])
    rows = decisions_of(attacker_sql, asset_id)
    assert rows[-1][0] == "REQUIRE_REASSESSMENT"
    assert rows[-1][4] == "A grant was added to an agent of this asset."

    if kind == "tool":
        # The assessment no longer describes the agent, so the old one cannot be resubmitted.
        refused = submit(tenant, asset_id)
        assert (refused.status_code, error_code(refused)) == (409, "ASSESSMENT_NOT_CURRENT")
    # The decision is audited before the grant, in the same transaction.
    events = sorted(tenant.audit_events(), key=lambda item: item["seq"])
    types = [item["event_type"] for item in events]
    last_decision = max(i for i, name in enumerate(types) if name == "governance.decision")
    assert types[last_decision:last_decision + 2] == ["governance.decision", f"grant.{kind}_added"]
    assert tenant.verify_audit()["valid"] is True


def test_removed_grant_does_not_force_reassessment(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    agent_id = agent_of(tenant, asset_id)
    resource_id = tenant.document()
    assert tenant.post(f"/agents/{agent_id}/tool-grants", {"tool": "calculate"}
                       ).status_code == 201
    assert tenant.post(f"/agents/{agent_id}/resource-grants", {"resource_id": resource_id}
                       ).status_code == 201
    save_profile(tenant, asset_id)
    assess(tenant, asset_id)
    holder = reviewers(tenant)
    approve(tenant, submitted(tenant, asset_id)["id"], holder)
    before = state_of(attacker_sql, asset_id)

    assert tenant.client.delete(f"/api/v1/agents/{agent_id}/tool-grants/calculate",
                                headers=tenant.admin).status_code == 204
    assert tenant.client.delete(f"/api/v1/agents/{agent_id}/resource-grants/{resource_id}",
                                headers=tenant.admin).status_code == 204
    assert state_of(attacker_sql, asset_id) == before
    assert kinds(attacker_sql, asset_id) == ["SUBMIT", "APPROVE"]


def test_grant_on_ungoverned_asset_has_no_governance_effect(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    agent_id = agent_of(tenant, asset_id)
    assert tenant.post(f"/agents/{agent_id}/tool-grants", {"tool": "calculate"}
                       ).status_code == 201
    assert tenant.post(f"/agents/{agent_id}/resource-grants", {"resource_id": tenant.document()}
                       ).status_code == 201
    assert state_of(attacker_sql, asset_id) is None
    assert tenant.get(f"{ASSETS}/{asset_id}").json()["governance_status"] is None
    assert decisions_of(attacker_sql, asset_id) == []


@pytest.mark.parametrize("move", ["suspend", "assessed", "reassess"])
def test_grant_on_an_asset_that_is_not_approved_changes_nothing(tenant, attacker_sql, move):
    asset_id = tenant.asset()["id"]
    agent_id = agent_of(tenant, asset_id)
    if move == "suspend":
        act(tenant, asset_id, "suspend")
    elif move == "assessed":
        save_profile(tenant, asset_id)
        assess(tenant, asset_id)
    else:
        act(tenant, asset_id, "suspend")
        act(tenant, asset_id, "reassess")
    before = (state_of(attacker_sql, asset_id), decisions_of(attacker_sql, asset_id))
    assert tenant.post(f"/agents/{agent_id}/tool-grants", {"tool": "calculate"}
                       ).status_code == 201
    assert (state_of(attacker_sql, asset_id), decisions_of(attacker_sql, asset_id)) == before


def test_a_refused_grant_does_not_force_reassessment(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    agent_id = agent_of(tenant, asset_id)
    save_profile(tenant, asset_id)
    assess(tenant, asset_id)
    approve(tenant, submitted(tenant, asset_id)["id"], reviewers(tenant))
    before = state_of(attacker_sql, asset_id)
    assert tenant.post(f"/agents/{agent_id}/tool-grants", {"tool": "not_a_tool"}
                       ).status_code == 422
    assert tenant.post(f"/agents/{agent_id}/resource-grants", {"resource_id": str(uuid4())}
                       ).status_code == 404
    assert state_of(attacker_sql, asset_id) == before


# The service function


def test_require_reassessment_by_the_system_needs_no_user(db, tenant, attacker_sql):
    asset_id, _, _ = approved_asset(tenant)
    with db.tenant_transaction(tenant.id) as session:
        decision = require_reassessment(session, "system", None, datetime.now(UTC),
                                        UUID(asset_id), reason="The review date has passed.")
        decision_id = decision.id
    row = attacker_sql.execute(
        "SELECT kind, actor_type, decided_by, to_status FROM governance_decisions WHERE id = %s",
        (decision_id,)).fetchone()
    assert row == ("REQUIRE_REASSESSMENT", "system", None, "REASSESSMENT_REQUIRED")
    assert state_of(attacker_sql, asset_id)[0] == "REASSESSMENT_REQUIRED"
    (event,) = [item for item in tenant.audit_events("governance.decision")
                if item["subject_id"] == str(decision_id)]
    assert event["actor_type"] == "system" and event["actor_id"] is None
    assert tenant.verify_audit()["valid"] is True


def test_require_reassessment_by_a_user_needs_that_user(db, tenant, attacker_sql):
    asset_id, _, _ = approved_asset(tenant)
    before = state_of(attacker_sql, asset_id)
    with pytest.raises(ValueError), db.tenant_transaction(tenant.id) as session:
        require_reassessment(session, "user", None, datetime.now(UTC), UUID(asset_id),
                             reason="No user named.")
    with pytest.raises(ValueError), db.tenant_transaction(tenant.id) as session:
        require_reassessment(session, "system", UUID(tenant.user_id("admin")),
                             datetime.now(UTC), UUID(asset_id), reason="A system with a user.")
    assert state_of(attacker_sql, asset_id) == before


def test_require_reassessment_refuses_a_status_that_does_not_allow_it(db, tenant):
    asset_id = tenant.asset()["id"]
    with pytest.raises(Conflict) as refused, db.tenant_transaction(tenant.id) as session:
        require_reassessment(session, "system", None, datetime.now(UTC), UUID(asset_id),
                             reason="Nothing to reassess.")
    assert refused.value.code == "INVALID_STATE_TRANSITION"


# History


def test_history_route_shows_every_decision_in_audit_order(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    profile = save_profile(tenant, asset_id)
    assessment = assess(tenant, asset_id)
    holder = reviewers(tenant)
    review = submitted(tenant, asset_id)
    approval = approve(tenant, review["id"], holder).json()
    changed = save_profile(tenant, asset_id, {"description": "changed"})
    suspended = act(tenant, asset_id, "suspend").json()

    response = tenant.get(f"{ASSETS}/{asset_id}/history")
    assert response.status_code == 200, response.text
    page = response.json()
    entries = page["items"]
    assert page["total"] == len(entries) == 7
    assert [(item["type"], item["kind"]) for item in entries] == [
        ("profile_version", None),
        ("assessment", None),
        ("decision", "SUBMIT"),
        ("decision", "APPROVE"),
        ("profile_version", None),
        ("decision", "REQUIRE_REASSESSMENT"),
        ("decision", "SUSPEND"),
    ]

    seqs = [item["seq"] for item in entries]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)

    # Each entry's seq is the audit sequence of the event it names, and that event is the one
    # that records it.
    events = {item["id"]: item for item in tenant.audit_events()}
    for item in entries:
        event = events[item["audit_event_id"]]
        assert event["seq"] == item["seq"]
    by_id = {item["id"]: item for item in entries}
    assert [item["id"] for item in entries][:4] == [
        profile["id"], assessment["id"], entries[2]["id"], approval["id"]]
    assert entries[4]["id"] == changed["id"] and entries[6]["id"] == suspended["id"]

    # References resolve: a decision's assessment and review exist, and its audit event names it.
    for item in entries:
        if item["type"] != "decision":
            continue
        decision = item["decision"]
        assert events[item["audit_event_id"]]["subject_id"] == item["id"]
        if decision["assessment_id"] is not None:
            assert by_id[decision["assessment_id"]]["type"] == "assessment"
        if decision["review_id"] is not None:
            assert tenant.get(f"/governance/approvals/{decision['review_id']}"
                              ).status_code == 200
    assert by_id[assessment["id"]]["assessment"]["input_hash"] == assessment["input_hash"]
    assert by_id[profile["id"]]["profile_version"]["version"] == 1
    assert by_id[changed["id"]]["profile_version"]["version"] == 2

    # The history is paged.
    second = tenant.get(f"{ASSETS}/{asset_id}/history", limit=3, offset=3).json()
    assert second["total"] == len(entries)
    assert [item["id"] for item in second["items"]] == [item["id"] for item in entries[3:6]]
    assert tenant.get(f"{ASSETS}/{asset_id}/history", limit=0).status_code == 422


def test_history_is_readable_by_any_user_and_covers_one_asset(tenant):
    first, second = tenant.asset()["id"], tenant.asset()["id"]
    save_profile(tenant, first)
    act(tenant, second, "suspend")
    for headers in (tenant.viewer, tenant.reviewer):
        page = tenant.get(f"{ASSETS}/{first}/history", headers=headers).json()
        assert [item["type"] for item in page["items"]] == ["profile_version"]
    page = tenant.get(f"{ASSETS}/{second}/history", headers=tenant.viewer).json()
    assert [(item["type"], item["kind"]) for item in page["items"]] == [("decision", "SUSPEND")]
    assert tenant.get(f"{ASSETS}/{uuid4()}/history").status_code == 404
    assert tenant.get(f"{ASSETS}/{tenant.asset()['id']}/history").json()["items"] == []


def test_history_agent_principal_is_refused(tenant):
    agent = tenant.agent()
    asset_id = tenant.get(f"/agents/{agent.id}").json()["asset_id"]
    response = tenant.client.get(f"/api/v1{ASSETS}/{asset_id}/history", headers=agent.headers)
    assert response.status_code == 401


# Concurrency and lock order


def test_concurrent_suspend_and_profile_change_and_grant(tenant, attacker_sql):
    """No deadlock, and the block wins, whichever order the three arrive in."""
    asset_id = tenant.asset()["id"]
    first = agent_of(tenant, asset_id, "one")
    second = agent_of(tenant, asset_id, "two")
    save_profile(tenant, asset_id)
    assess(tenant, asset_id)
    approve(tenant, submitted(tenant, asset_id)["id"], reviewers(tenant))
    barrier = threading.Barrier(4)

    def run(call):
        barrier.wait(timeout=30)
        return call().status_code

    calls = [
        lambda: act(tenant, asset_id, "suspend"),
        lambda: tenant.post(f"{ASSETS}/{asset_id}/profile", {"description": "racing"}),
        lambda: tenant.post(f"/agents/{first}/tool-grants", {"tool": "calculate"}),
        lambda: tenant.post(f"/agents/{second}/tool-grants", {"tool": "calculate"}),
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        codes = [future.result(timeout=90) for future in [pool.submit(run, c) for c in calls]]
    assert codes == [201, 201, 201, 201]
    status, _, current, blocked, valid_until, _ = state_of(attacker_sql, asset_id)
    assert status == "SUSPENDED" and valid_until is None and blocked is not None
    assert current == blocked
    assert kinds(attacker_sql, asset_id).count("SUSPEND") == 1
    assert tenant.verify_audit()["valid"] is True


def test_concurrent_suspends_record_one(tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    barrier = threading.Barrier(2)

    def run():
        barrier.wait(timeout=30)
        return act(tenant, asset_id, "suspend").status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = sorted(f.result(timeout=60) for f in [pool.submit(run), pool.submit(run)])
    assert codes == [201, 409]
    assert kinds(attacker_sql, asset_id) == ["SUSPEND"]
    assert tenant.verify_audit()["valid"] is True


def _blocked_on_agents(urls, attacker_sql, asset_id, start, while_waiting=None):
    """Hold the asset's agent rows, start a request, and prove it waits there with no other lock."""
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        with psycopg.connect(urls.superuser, autocommit=True) as observer:
            with attacker_sql.transaction():
                attacker_sql.execute(
                    "SELECT id FROM agents WHERE asset_id = %s FOR UPDATE", (asset_id,))
                response = pool.submit(start)
                waiting = 0
                deadline = time.monotonic() + 15
                while not waiting and time.monotonic() < deadline:
                    waiting = observer.execute(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE wait_event_type = 'Lock' AND query LIKE '%FROM agents%' "
                        "AND pid <> pg_backend_pid()"
                    ).fetchone()[0]
                    time.sleep(0.05)
                assert waiting, "the request did not block on the agent rows"
                # Agent rows come before the state row, so the state row is still free.
                with observer.transaction():
                    observer.execute(
                        "SELECT 1 FROM asset_governance_state WHERE asset_id = %s "
                        "FOR UPDATE NOWAIT", (asset_id,))
                assert not response.done()
                if while_waiting is not None:
                    while_waiting()
        return response.result(timeout=30)
    finally:
        pool.shutdown(wait=True)


def test_lifecycle_actions_take_agent_rows_before_the_state_row(urls, tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    agent_of(tenant, asset_id)
    save_profile(tenant, asset_id)
    assess(tenant, asset_id)
    approve(tenant, submitted(tenant, asset_id)["id"], reviewers(tenant))

    # Changing the profile changes the status of an approved asset, so it locks the same way.
    changed = _blocked_on_agents(urls, attacker_sql, asset_id, lambda: tenant.post(
        f"{ASSETS}/{asset_id}/profile", {"description": "late change"}))
    assert changed.status_code == 201
    assert detail_status(tenant, asset_id) == "REASSESSMENT_REQUIRED"

    suspended = _blocked_on_agents(urls, attacker_sql, asset_id,
                                   lambda: act(tenant, asset_id, "suspend"))
    assert suspended.status_code == 201

    other = tenant.asset()["id"]
    agent_id = agent_of(tenant, other)
    save_profile(tenant, other)
    assess(tenant, other)
    approve(tenant, submitted(tenant, other)["id"], reviewers(tenant))
    granted = _blocked_on_agents(urls, attacker_sql, other, lambda: tenant.post(
        f"/agents/{agent_id}/tool-grants", {"tool": "calculate"}))
    assert granted.status_code == 201
    assert detail_status(tenant, other) == "REASSESSMENT_REQUIRED"


def test_suspend_with_no_state_row_waits_for_the_agent_rows(urls, tenant, attacker_sql):
    asset_id = tenant.asset()["id"]
    agent_of(tenant, asset_id)

    def nothing_written_yet():
        assert state_of(attacker_sql, asset_id) is None

    response = _blocked_on_agents(urls, attacker_sql, asset_id,
                                  lambda: act(tenant, asset_id, "suspend"), nothing_written_yet)
    assert response.status_code == 201
    assert state_of(attacker_sql, asset_id)[0] == "SUSPENDED"


# Module boundaries


def test_governance_never_imports_the_registry_service():
    """The import runs registry to governance only, so the two can never form a cycle."""
    root = Path(aegis.__file__).parent / "governance"
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or "", *(f"{node.module}.{a.name}" for a in node.names)]
            for name in names:
                assert not name.startswith(("aegis.registry", "aegis.gateway.service")), (
                    path.name, name)


@pytest.mark.parametrize("module", ["aegis.registry.service", "aegis.governance.approvals",
                                    "aegis.governance.assets", "aegis.api.app"])
def test_each_module_imports_first_in_a_fresh_interpreter(module):
    result = subprocess.run([sys.executable, "-c", f"import {module}"],  # noqa: S603
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
