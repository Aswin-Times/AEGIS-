"""The governance_reviewer role: who can grant it, who holds it, and what is recorded."""

from uuid import UUID, uuid4

import pytest

from aegis.errors import Forbidden
from aegis.security.principals import UserPrincipal

GRANTS = "/governance/role-grants"


def _grant(tenant, user_id, headers=None):
    return tenant.post(GRANTS, {"user_id": user_id}, headers=headers)


def _holds(db, tenant, user_id: str) -> bool:
    from aegis.governance.roles import holds_reviewer

    with db.tenant_transaction(tenant.id) as session:
        return holds_reviewer(session, UUID(user_id))


def test_admin_cannot_grant_reviewer_role_to_self(tenant):
    response = _grant(tenant, tenant.user_id("admin"))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "SELF_GRANT_REFUSED"
    assert tenant.audit_events("governance.role_granted") == []
    assert len(tenant.audit_events("authz.denied")) == 1


def test_self_grant_is_judged_by_who_acts(tenant):
    """Self-grant is judged by who acts, so a different admin may grant to the first."""
    other = tenant.login_as("admin-two", "admin")
    assert _grant(tenant, tenant.user_id("admin"), headers=other).status_code == 201
    assert _grant(tenant, tenant.user_id("admin-two"), headers=other).status_code == 403


@pytest.mark.parametrize("actor", ["reviewer", "viewer"])
def test_only_admin_can_grant(tenant, actor):
    target = tenant.user_id("reviewer")
    response = _grant(tenant, target, headers=tenant.login(actor))
    assert response.status_code == 403
    assert tenant.audit_events("governance.role_granted") == []


@pytest.mark.parametrize("actor", ["reviewer", "viewer"])
def test_only_admin_can_revoke(tenant, actor):
    grant = tenant.grant_governance("reviewer")
    response = tenant.post(f"{GRANTS}/{grant['id']}/revoke", headers=tenant.login(actor))
    assert response.status_code == 403
    assert tenant.audit_events("governance.role_revoked") == []


def test_grantee_must_be_active_admin_or_reviewer(tenant, attacker_sql):
    response = _grant(tenant, tenant.user_id("viewer"))
    assert response.status_code == 422
    assert tenant.audit_events("governance.role_granted") == []

    # A user who is no longer active cannot be granted it either.
    target = tenant.user_id("reviewer")
    attacker_sql.execute("UPDATE users SET is_active = false WHERE id = %s", (target,))
    assert _grant(tenant, target).status_code == 422


def test_an_unknown_user_is_not_found(tenant):
    assert _grant(tenant, str(uuid4())).status_code == 404


def test_agent_principal_rejected_on_governance_routes(tenant):
    agent = tenant.agent()
    target = tenant.user_id("reviewer")
    grant = tenant.grant_governance("reviewer")
    for response in (
        tenant.client.post(f"/api/v1{GRANTS}", json={"user_id": target}, headers=agent.headers),
        tenant.client.post(f"/api/v1{GRANTS}/{grant['id']}/revoke", headers=agent.headers),
        tenant.client.get("/api/v1/governance/people", headers=agent.headers),
    ):
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_revoked_grant_stops_counting(tenant, db):
    target = tenant.user_id("reviewer")
    assert _holds(db, tenant, target) is False

    grant = tenant.grant_governance("reviewer")
    assert _holds(db, tenant, target) is True

    response = tenant.post(f"{GRANTS}/{grant['id']}/revoke")
    assert response.status_code == 200
    assert response.json()["revoked_at"] is not None
    assert _holds(db, tenant, target) is False


def test_revoking_twice_does_not_record_a_second_event(tenant):
    grant = tenant.grant_governance("reviewer")
    first = tenant.post(f"{GRANTS}/{grant['id']}/revoke").json()
    second = tenant.post(f"{GRANTS}/{grant['id']}/revoke")
    assert second.status_code == 200
    assert second.json()["revoked_at"] == first["revoked_at"]
    assert len(tenant.audit_events("governance.role_revoked")) == 1


def test_a_revoked_role_can_be_granted_again(tenant, db):
    grant = tenant.grant_governance("reviewer")
    tenant.post(f"{GRANTS}/{grant['id']}/revoke")
    again = tenant.grant_governance("reviewer")
    assert again["id"] != grant["id"]
    assert _holds(db, tenant, tenant.user_id("reviewer")) is True


def test_holding_the_role_needs_an_active_user_with_a_qualifying_role(tenant, db, attacker_sql):
    target = tenant.user_id("reviewer")
    tenant.grant_governance("reviewer")
    assert _holds(db, tenant, target) is True

    attacker_sql.execute("UPDATE users SET role = 'viewer' WHERE id = %s", (target,))
    assert _holds(db, tenant, target) is False
    attacker_sql.execute("UPDATE users SET role = 'reviewer' WHERE id = %s", (target,))
    assert _holds(db, tenant, target) is True
    attacker_sql.execute("UPDATE users SET is_active = false WHERE id = %s", (target,))
    assert _holds(db, tenant, target) is False


def test_duplicate_active_grant_conflicts(tenant):
    tenant.grant_governance("reviewer")
    response = _grant(tenant, tenant.user_id("reviewer"))
    assert response.status_code == 409
    assert len(tenant.audit_events("governance.role_granted")) == 1


def test_grant_and_revoke_are_audited(tenant):
    grant = tenant.grant_governance("reviewer")
    tenant.post(f"{GRANTS}/{grant['id']}/revoke")

    granted = tenant.audit_events("governance.role_granted")
    revoked = tenant.audit_events("governance.role_revoked")
    assert len(granted) == 1 and len(revoked) == 1
    assert granted[0]["subject_id"] == grant["id"]
    assert granted[0]["actor_id"] == tenant.user_id("admin")
    assert granted[0]["payload"]["user_id"] == tenant.user_id("reviewer")
    assert granted[0]["payload"]["role"] == "governance_reviewer"
    assert revoked[0]["subject_id"] == grant["id"]
    assert tenant.verify_audit()["valid"] is True


def test_grants_are_tenant_isolated(world):
    first, second = world.tenant(), world.tenant()
    foreign_user = second.user_id("reviewer")
    first.login("admin")

    assert _grant(first, foreign_user).status_code == 404
    assert first.audit_events("governance.role_granted") == []

    foreign_grant = second.grant_governance("reviewer")
    response = first.post(f"{GRANTS}/{foreign_grant['id']}/revoke")
    assert response.status_code == 404
    still_active = second.get("/governance/people").json()["items"]
    assert [p for p in still_active if p["id"] == foreign_user][0]["reviewer_grant_id"] == (
        foreign_grant["id"]
    )


def test_people_lists_only_admins_and_reviewers_with_their_grant(tenant):
    tenant.login("viewer")
    grant = tenant.grant_governance("reviewer")
    response = tenant.get("/governance/people")
    assert response.status_code == 200
    page = response.json()
    by_id = {person["id"]: person for person in page["items"]}
    assert set(by_id) == {tenant.user_id("admin"), tenant.user_id("reviewer")}
    assert by_id[tenant.user_id("reviewer")]["reviewer_grant_id"] == grant["id"]
    assert by_id[tenant.user_id("admin")]["reviewer_grant_id"] is None
    assert set(by_id[tenant.user_id("admin")]) == {"id", "email", "role", "reviewer_grant_id"}
    assert page["total"] == 2


def test_people_is_closed_to_viewers(tenant):
    assert tenant.get("/governance/people", headers=tenant.viewer).status_code == 403


def test_the_database_refuses_a_self_grant(tenant, attacker_sql):
    """The service refuses first; the CHECK constraint is the backstop if it is bypassed."""
    import psycopg

    admin = tenant.user_id("admin")
    with pytest.raises(psycopg.errors.CheckViolation):
        attacker_sql.execute(
            "INSERT INTO governance_role_grants "
            "(id, tenant_id, user_id, role, granted_by, granted_at) "
            "VALUES (%s, %s, %s, 'governance_reviewer', %s, now())",
            (uuid4(), tenant.id, admin, admin),
        )


def test_a_revoked_grant_cannot_be_reinstated(tenant, attacker_sql):
    import psycopg

    grant = tenant.grant_governance("reviewer")
    tenant.post(f"{GRANTS}/{grant['id']}/revoke")
    with pytest.raises(psycopg.errors.CheckViolation):
        attacker_sql.execute(
            "UPDATE governance_role_grants SET revoked_at = NULL, revoked_by = NULL "
            "WHERE id = %s",
            (grant["id"],),
        )


def _principal(tenant, role: str) -> UserPrincipal:
    return UserPrincipal(
        id=UUID(tenant.user_id(role)), tenant_id=tenant.id, email=f"{role}@x.test", role=role
    )


def test_reviewer_dependency_requires_the_role_not_the_user_role(world, tenant):
    from aegis.api.dependencies import require_governance_reviewer

    container = world.app.state.container
    reviewer = _principal(tenant, "reviewer")
    admin = _principal(tenant, "admin")
    with pytest.raises(Forbidden):
        require_governance_reviewer(reviewer, container)
    with pytest.raises(Forbidden):
        require_governance_reviewer(admin, container)

    tenant.grant_governance("reviewer")
    assert require_governance_reviewer(reviewer, container) is reviewer
    with pytest.raises(Forbidden):
        require_governance_reviewer(admin, container)


def test_suspender_dependency_allows_admin_or_holder(world, tenant):
    from aegis.api.dependencies import require_suspender

    container = world.app.state.container
    admin, reviewer = _principal(tenant, "admin"), _principal(tenant, "reviewer")
    viewer = _principal(tenant, "viewer")
    assert require_suspender(admin, container) is admin
    with pytest.raises(Forbidden):
        require_suspender(reviewer, container)

    tenant.grant_governance("reviewer")
    assert require_suspender(reviewer, container) is reviewer
    with pytest.raises(Forbidden):
        require_suspender(viewer, container)
