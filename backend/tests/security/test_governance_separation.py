"""Separation of duties: who may decide a review, and who never may."""

from datetime import UTC, datetime
from uuid import UUID

import pytest

from aegis.errors import Forbidden
from aegis.gateway.tools import default_registry
from aegis.governance.approvals import approve as approve_service
from aegis.governance.approvals import reject as reject_service
from aegis.security.principals import UserPrincipal
from support import (
    APPROVALS,
    PROFILE,
    activate_policy,
    another_holder,
    approve,
    assert_review_untouched,
    assessed_asset,
    assign,
    detail_status,
    error_code,
    reject,
    reviewers,
    submitted,
    window,
)


def denied_events(tenant):
    return tenant.audit_events("authz.denied")


def refused_as_self_approval(response):
    return (response.status_code, error_code(response)) == (403, "SELF_APPROVAL_REFUSED")


def test_submitter_cannot_approve_by_default(tenant, attacker_sql):
    reviewers(tenant)
    review = submitted(tenant)  # submitted by the first admin, who holds the role
    assert denied_events(tenant) == []
    for response in (approve(tenant, review["id"], tenant.admin),
                     reject(tenant, review["id"], tenant.admin)):
        assert refused_as_self_approval(response), response.text
    assert_review_untouched(tenant, attacker_sql, review)
    denied = denied_events(tenant)
    assert len(denied) == 2
    assert {event["actor_id"] for event in denied} == {tenant.user_id("admin")}


def test_self_approval_only_with_explicit_policy(tenant):
    holder = reviewers(tenant)
    activate_policy(tenant, self_approval="permitted")
    review = submitted(tenant)
    assert review["required_controls"]["self_approval_permitted"] is True
    # Permitted for the submitter; nobody else is affected.
    assert approve(tenant, review["id"], tenant.admin).status_code == 201
    assert detail_status(tenant, review["asset_id"]) == "APPROVED"
    other = submitted(tenant)
    assert approve(tenant, other["id"], holder).status_code == 201


@pytest.mark.parametrize("order", [("permitted", "prohibited"), ("prohibited", "permitted")])
def test_conflicting_policies_refuse_self_approval(tenant, attacker_sql, order):
    reviewers(tenant)
    for value in order:
        activate_policy(tenant, self_approval=value)
    review = submitted(tenant)
    assert review["required_controls"]["self_approval_permitted"] is False
    assert refused_as_self_approval(approve(tenant, review["id"], tenant.admin))
    assert refused_as_self_approval(reject(tenant, review["id"], tenant.admin))
    assert_review_untouched(tenant, attacker_sql, review)


@pytest.mark.parametrize("owner_field", ["business_owner_id", "technical_owner_id"])
def test_owner_cannot_approve_by_default(tenant, attacker_sql, owner_field):
    holder = reviewers(tenant)
    owned = assessed_asset(tenant, {**PROFILE, owner_field: tenant.user_id("second-admin")})
    review = submitted(tenant, owned)
    for response in (approve(tenant, review["id"], holder), reject(tenant, review["id"], holder)):
        assert refused_as_self_approval(response), response.text
    assert_review_untouched(tenant, attacker_sql, review)
    assert len(denied_events(tenant)) == 2

    # Someone who is neither submitter nor owner can decide it.
    third = another_holder(tenant, "third-admin")
    assert approve(tenant, review["id"], third).status_code == 201


def test_business_owner_cannot_approve_by_default(tenant, attacker_sql):
    holder = reviewers(tenant)
    owned = assessed_asset(tenant, {**PROFILE, "business_owner_id": tenant.user_id("second-admin")})
    review = submitted(tenant, owned)
    assert refused_as_self_approval(approve(tenant, review["id"], holder))
    assert_review_untouched(tenant, attacker_sql, review)


def test_technical_owner_cannot_approve_by_default(tenant, attacker_sql):
    holder = reviewers(tenant)
    owned = assessed_asset(
        tenant, {**PROFILE, "technical_owner_id": tenant.user_id("second-admin")})
    review = submitted(tenant, owned)
    assert refused_as_self_approval(reject(tenant, review["id"], holder))
    assert_review_untouched(tenant, attacker_sql, review)


def test_owner_approval_only_with_explicit_policy(tenant):
    holder = reviewers(tenant)
    activate_policy(tenant, owner_approval="permitted")
    owned = assessed_asset(tenant, {**PROFILE, "business_owner_id": tenant.user_id("second-admin")})
    review = submitted(tenant, owned)
    assert review["required_controls"]["owner_approval_permitted"] is True
    # The owner may decide, but permitting owners does not permit the submitter.
    assert refused_as_self_approval(approve(tenant, review["id"], tenant.admin))
    assert approve(tenant, review["id"], holder).status_code == 201


def test_owner_rules_and_self_rules_are_independent(tenant):
    holder = reviewers(tenant)
    activate_policy(tenant, self_approval="permitted")
    owned = assessed_asset(
        tenant, {**PROFILE, "technical_owner_id": tenant.user_id("second-admin")})
    review = submitted(tenant, owned)
    # Permitting self-approval says nothing about owners.
    assert refused_as_self_approval(approve(tenant, review["id"], holder))
    assert approve(tenant, review["id"], tenant.admin).status_code == 201


def test_existing_reviewer_role_is_not_sufficient(tenant, attacker_sql):
    reviewers(tenant)
    review = submitted(tenant)
    plain = tenant.login("reviewer")
    for response in (approve(tenant, review["id"], plain), reject(tenant, review["id"], plain)):
        assert (response.status_code, error_code(response)) == (403, "FORBIDDEN")
    assert_review_untouched(tenant, attacker_sql, review)
    assert len(denied_events(tenant)) == 2


def test_existing_admin_role_is_not_sufficient(tenant, attacker_sql):
    reviewers(tenant)
    review = submitted(tenant)
    plain = tenant.login_as("plain-admin", "admin")
    for response in (approve(tenant, review["id"], plain), reject(tenant, review["id"], plain)):
        assert (response.status_code, error_code(response)) == (403, "FORBIDDEN")
    assert_review_untouched(tenant, attacker_sql, review)


def test_viewer_cannot_decide(tenant, attacker_sql):
    reviewers(tenant)
    review = submitted(tenant)
    for response in (approve(tenant, review["id"], tenant.viewer),
                     reject(tenant, review["id"], tenant.viewer)):
        assert response.status_code == 403
    assert_review_untouched(tenant, attacker_sql, review)


def test_agents_cannot_decide(tenant, attacker_sql):
    reviewers(tenant)
    review = submitted(tenant)
    agent = tenant.agent()
    for name, body in (("approve", {"reason": "x", **window()}), ("reject", {"reason": "x"})):
        response = tenant.client.post(f"/api/v1{APPROVALS}/{review['id']}/{name}", json=body,
                                      headers=agent.headers)
        assert response.status_code == 401
    assert_review_untouched(tenant, attacker_sql, review)


def test_only_assigned_reviewer_can_decide(tenant, attacker_sql):
    holder = reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    review = submitted(tenant)
    assert assign(tenant, review["id"], tenant.user_id("second-admin"), holder
                  ).status_code == 200
    for response in (approve(tenant, review["id"], third), reject(tenant, review["id"], third),
                     approve(tenant, review["id"], tenant.admin)):
        assert response.status_code == 403
    refused = approve(tenant, review["id"], third)
    assert error_code(refused) == "NOT_ASSIGNED_REVIEWER"
    # The submitter is not the assignee either, so the assignment is reported first.
    assert error_code(approve(tenant, review["id"], tenant.admin)) == "NOT_ASSIGNED_REVIEWER"
    assert_review_untouched(tenant, attacker_sql, review, assigned=True)
    assert approve(tenant, review["id"], holder).status_code == 201


def test_unassigned_review_can_be_decided_by_any_eligible_holder(tenant):
    reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    review = submitted(tenant)
    assert approve(tenant, review["id"], third).status_code == 201


def test_revoked_holder_cannot_decide_open_review(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    assert assign(tenant, review["id"], tenant.user_id("second-admin"), holder
                  ).status_code == 200
    people = tenant.get("/governance/people").json()["items"]
    grant_id = next(p["reviewer_grant_id"] for p in people
                    if p["id"] == tenant.user_id("second-admin"))
    assert tenant.post(f"/governance/role-grants/{grant_id}/revoke").status_code == 200
    for response in (approve(tenant, review["id"], holder), reject(tenant, review["id"], holder)):
        assert (response.status_code, error_code(response)) == (403, "FORBIDDEN")
    assert_review_untouched(tenant, attacker_sql, review, assigned=True)


def test_holder_downgraded_to_viewer_cannot_decide(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    assert assign(tenant, review["id"], tenant.user_id("second-admin"), holder
                  ).status_code == 200
    # The grant is still unrevoked, but the user is no longer an admin or reviewer.
    attacker_sql.execute("UPDATE users SET role = 'viewer' WHERE id = %s",
                         (tenant.user_id("second-admin"),))
    for response in (approve(tenant, review["id"], holder), reject(tenant, review["id"], holder)):
        assert response.status_code == 403, response.text
    assert_review_untouched(tenant, attacker_sql, review, assigned=True)


def test_deactivated_holder_cannot_decide(tenant, attacker_sql):
    holder = reviewers(tenant)
    review = submitted(tenant)
    attacker_sql.execute("UPDATE users SET is_active = false WHERE id = %s",
                         (tenant.user_id("second-admin"),))
    for response in (approve(tenant, review["id"], holder), reject(tenant, review["id"], holder)):
        assert response.status_code in (401, 403), response.text
    assert_review_untouched(tenant, attacker_sql, review)


def test_service_rechecks_authority_itself(db, tenant, attacker_sql):
    """The route dependency is not the only check: the service reads the grant at decision time."""
    reviewers(tenant)
    review = submitted(tenant)
    revoked = UserPrincipal(UUID(tenant.user_id("second-admin")), tenant.id, "x", "admin")
    people = tenant.get("/governance/people").json()["items"]
    grant_id = next(p["reviewer_grant_id"] for p in people if p["id"] == str(revoked.id))
    assert tenant.post(f"/governance/role-grants/{grant_id}/revoke").status_code == 200
    now = datetime.now(UTC)
    window_ = window()
    until = datetime.fromisoformat(window_["valid_until"])
    soon = datetime.fromisoformat(window_["next_review_at"])
    with pytest.raises(Forbidden), db.tenant_transaction(tenant.id) as session:
        approve_service(session, default_registry(), revoked, now, UUID(review["id"]),
                        reason="x", valid_until=until, next_review_at=soon)
    with pytest.raises(Forbidden), db.tenant_transaction(tenant.id) as session:
        reject_service(session, revoked, now, UUID(review["id"]), reason="x")
    assert_review_untouched(tenant, attacker_sql, review)


def test_review_can_be_reassigned_after_assignee_loses_authority(tenant, attacker_sql):
    holder = reviewers(tenant)
    third = another_holder(tenant, "third-admin")
    review = submitted(tenant)
    assert assign(tenant, review["id"], tenant.user_id("second-admin"), holder
                  ).status_code == 200
    people = tenant.get("/governance/people").json()["items"]
    grant_id = next(p["reviewer_grant_id"] for p in people
                    if p["id"] == tenant.user_id("second-admin"))
    assert tenant.post(f"/governance/role-grants/{grant_id}/revoke").status_code == 200

    # Nobody can decide it: the assignee has lost the role, and everyone else is not the assignee.
    assert approve(tenant, review["id"], holder).status_code == 403
    assert approve(tenant, review["id"], third).status_code == 403
    assert_review_untouched(tenant, attacker_sql, review, assigned=True)

    # A remaining holder moves it to someone who can.
    assert assign(tenant, review["id"], tenant.user_id("third-admin"), third).status_code == 200
    assert approve(tenant, review["id"], third).status_code == 201
    assert detail_status(tenant, review["asset_id"]) == "APPROVED"
