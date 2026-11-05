"""One tenant cannot see or change another tenant's governance records.

Each task that adds a governance route adds it here. Detail and history routes arrive later.
"""

from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError


def test_cross_tenant_asset_access_is_not_found(world):
    first, second = world.tenant(), world.tenant()
    asset = first.asset()
    path = f"/governance/assets/{asset['id']}/profile"

    assert second.post(path, {"description": "taken over"}).status_code == 404
    assert first.post(path, {"description": "mine"}).status_code == 201

    # The other tenant still finds nothing, and nothing was written on its side.
    assert second.post(path, {}).status_code == 404
    assert second.audit_events("governance.profile_saved") == []
    assert len(first.audit_events("governance.profile_saved")) == 1

    detail = f"/governance/assets/{asset['id']}"
    assert second.get(detail).status_code == 404
    assert first.get(detail).status_code == 200

    # The risk routes: the other tenant finds nothing, and cannot cause an assessment.
    profile = {"impact_level": "minor"}
    assert first.post(path, profile).status_code == 201
    assess, risk, history = (f"{detail}/{name}" for name in ("assess", "risk", "assessments"))
    assert second.post(assess).status_code == 404
    assert second.get(risk).status_code == 404
    assert second.get(history).status_code == 404
    assert second.audit_events("governance.risk_assessed") == []
    assert first.post(assess).status_code == 201
    assert first.get(risk).json()["assessment"]["asset_id"] == asset["id"]
    assert first.get(history).json()["total"] == 1
    assert second.get(history).status_code == 404
    assert second.get("/governance/assets", risk="LOW").json()["total"] == 0
    assert second.get("/governance/overview").json()["by_assessed_risk"]["LOW"] == 0


def test_inventory_and_overview_cover_only_this_tenant(world):
    first, second = world.tenant(), world.tenant()
    mine = first.asset()
    theirs = [
        second.created(
            "/assets",
            {
                "name": f"other-tenant-{number}",
                "owner": "synthetic-owner",
                "risk_classification": "low",
                "intended_use": "automated test fixture",
                "is_synthetic": True,
            },
        )
        for number in range(2)
    ]
    for asset in theirs:
        second.post(f"/governance/assets/{asset['id']}/profile", {})

    listing = first.get("/governance/assets").json()
    assert [item["id"] for item in listing["items"]] == [mine["id"]]
    assert listing["total"] == 1
    assert first.get("/governance/assets", search=theirs[0]["name"]).json()["total"] == 0
    assert first.get("/governance/assets", status="DRAFT").json()["total"] == 0
    assert second.get("/governance/assets").json()["total"] == 2

    assert first.get("/governance/overview").json()["total_assets"] == 1
    assert second.get("/governance/overview").json()["total_assets"] == 2


def _insert_settings(db, tenant_id, mode, row_tenant=None):
    with db.tenant_transaction(tenant_id) as session:
        session.execute(
            text(
                "INSERT INTO governance_settings (id, tenant_id, enforcement_mode) "
                "VALUES (:id, :tenant, :mode)"
            ),
            {"id": uuid4(), "tenant": row_tenant or tenant_id, "mode": mode},
        )


def _visible_modes(db, tenant_id):
    with db.tenant_transaction(tenant_id) as session:
        rows = session.execute(text("SELECT enforcement_mode FROM governance_settings"))
        return rows.scalars().all()


def test_governance_settings_belong_to_one_tenant(world, db):
    first, second = world.tenant(), world.tenant()
    _insert_settings(db, first.id, "enforce")

    assert _visible_modes(db, first.id) == ["enforce"]
    assert _visible_modes(db, second.id) == []
    assert first.get("/governance/overview").json()["enforcement_mode"] == "enforce"
    assert second.get("/governance/overview").json()["enforcement_mode"] == "observe"

    # A tenant cannot write a row for another tenant.
    with pytest.raises(DBAPIError):
        _insert_settings(db, second.id, "enforce", row_tenant=first.id)
    assert _visible_modes(db, second.id) == []


def test_governance_settings_refuse_an_unknown_enforcement_mode(world, db):
    tenant = world.tenant()
    with pytest.raises(DBAPIError, match="enforcement_mode"):
        _insert_settings(db, tenant.id, "monitor")
    assert _visible_modes(db, tenant.id) == []
    assert tenant.get("/governance/overview").json()["enforcement_mode"] == "observe"


def test_methodology_versions_belong_to_one_tenant(world, db):
    first, second = world.tenant(), world.tenant()
    built_in = first.get("/governance/methodologies").json()["items"][0]
    second.get("/governance/methodologies")
    own = second.get("/governance/methodologies").json()["items"]
    assert len(own) == 1 and own[0]["id"] != built_in["id"]

    second.grant_governance("reviewer")
    path = f"/governance/methodologies/{built_in['id']}"
    assert second.post(f"{path}/activate").status_code == 404
    assert second.post(f"{path}/approve", headers=second.login("reviewer")).status_code == 404
    # Nothing changed on either side.
    assert first.audit_events("governance.methodology_activated") == []
    assert second.audit_events("governance.methodology_activated") == []
    assert second.get("/governance/methodologies").json()["items"][0]["active"] is True

    # The tenant's own version cannot be made to point at another tenant's, below the service.
    with pytest.raises(DBAPIError), db.tenant_transaction(second.id) as session:
        session.execute(
            text(
                "INSERT INTO governance_settings "
                "(id, tenant_id, active_methodology_version_id) VALUES (:id, :tenant, :other)"
            ),
            {"id": uuid4(), "tenant": second.id, "other": built_in["id"]},
        )


def test_cross_tenant_policy_access(world, db):
    from datetime import UTC, datetime, timedelta

    from aegis.governance.policies import applicable_documents

    first, second = world.tenant(), world.tenant()
    reviewer = first.login_as("second-admin", "admin")
    first.grant_governance("admin", by="second-admin")
    first.grant_governance("second-admin", by="admin")
    second.grant_governance("reviewer")

    body = {"document": {"description": "synthetic", "severity": "low",
                         "controls": {"minimum_approvers": 2}},
            "effective_from": (datetime.now(UTC) - timedelta(hours=1)).isoformat()}
    policy = first.post("/governance/policies", {"name": "shared name", "category": "x"}).json()
    version = first.post(f"/governance/policies/{policy['id']}/versions", body).json()
    base = f"/governance/policies/{policy['id']}"
    target = f"{base}/versions/{version['id']}"

    # The other tenant sees none of it, and cannot approve, activate, or add to it.
    assert second.get("/governance/policies").json()["items"] == []
    assert second.post(f"{base}/versions", body).status_code == 404
    for action, headers in (("approve", second.login("reviewer")),
                            ("activate", None), ("deactivate", None)):
        assert second.post(f"{target}/{action}", headers=headers).status_code == 404, action
    for event in ("created", "approved", "activated", "deactivated"):
        assert second.audit_events(f"governance.policy_version_{event}") == []

    # Nothing changed on the owning side, which can still use its own routes.
    assert first.post(f"{target}/approve", headers=reviewer).status_code == 200
    assert first.post(f"{target}/activate").status_code == 200
    assert [i["id"] for i in first.get("/governance/policies").json()["items"]] == [policy["id"]]
    with db.tenant_transaction(second.id) as session:
        assert applicable_documents(session, datetime.now(UTC)) == []
    with db.tenant_transaction(first.id) as session:
        assert len(applicable_documents(session, datetime.now(UTC))) == 1

    # The same name is free in the other tenant, and nothing leaks across.
    assert second.post("/governance/policies", {"name": "shared name", "category": "x"}
                       ).status_code == 201
    assert len(first.get("/governance/policies").json()["items"]) == 1

    # Below the service, a version cannot be filed under another tenant's policy.
    with pytest.raises(DBAPIError), db.tenant_transaction(second.id) as session:
        session.execute(
            text(
                "INSERT INTO governance_policy_versions (id, tenant_id, policy_id, version, "
                "document_canonical, content_hash, effective_from, created_by) VALUES "
                "(:id, :tenant, :policy, 1, '{}', repeat('0', 64), now(), :creator)"
            ),
            {"id": uuid4(), "tenant": second.id, "policy": policy["id"],
             "creator": second.user_id("admin")},
        )


def test_cross_tenant_approval_access(world, db):
    first, second = world.tenant(), world.tenant()
    second_admin = first.login_as("second-admin", "admin")
    first.grant_governance("admin", by="second-admin")
    first.grant_governance("second-admin", by="admin")
    second.grant_governance("reviewer")
    outsider = second.user_id("reviewer")

    asset = first.asset()["id"]
    profile = {"asset_type": "ai_application", "data_categories": ["internal"],
               "external_exposure": "none", "autonomy_level": "advisory",
               "declared_tool_access": [], "human_oversight": "in_the_loop",
               "impact_level": "negligible", "deployment_environment": "development",
               "third_party_reliance": "none"}
    assert first.post(f"/governance/assets/{asset}/profile", profile).status_code == 201
    assert first.post(f"/governance/assets/{asset}/assess").status_code == 201

    # The other tenant cannot submit the asset, and nothing is written on either side.
    assert second.post(f"/governance/assets/{asset}/submit", {"reason": "mine now"}
                       ).status_code == 404
    assert second.audit_events("governance.decision") == []
    assert first.audit_events("governance.decision") == []

    review = first.post(f"/governance/assets/{asset}/submit", {"reason": "ready"}).json()
    base = f"/governance/approvals/{review['id']}"
    reviewer = second.login("reviewer")
    assert second.get("/governance/approvals").json() == {
        "items": [], "total": 0, "limit": 50, "offset": 0
    }
    assert second.get(base).status_code == 404
    assert second.get("/governance/approvals", asset_id=asset).json()["total"] == 0
    assert second.post(f"{base}/assign", {"reviewer_id": outsider}, headers=reviewer
                       ).status_code == 404
    assert second.post(f"{base}/request-information", {"reason": "x"}, headers=reviewer
                       ).status_code == 404
    assert second.get("/governance/overview").json()["awaiting_approval"] == 0

    # The owning side is unchanged, and its own reviewer can still act.
    assert first.get(base).json()["status"] == "OPEN"
    assert first.get("/governance/overview").json()["awaiting_approval"] == 1
    mine = first.user_id("second-admin")
    assert first.post(f"{base}/assign", {"reviewer_id": mine}, headers=second_admin
                      ).status_code == 200
    assert len(first.audit_events("governance.decision")) == 2

    # A reviewer from another tenant cannot be assigned, even by id.
    assert first.post(f"{base}/assign", {"reviewer_id": outsider}, headers=second_admin
                      ).status_code == 422

    # Below the service, a decision cannot be filed against another tenant's asset or review.
    with pytest.raises(DBAPIError), db.tenant_transaction(second.id) as session:
        session.execute(
            text(
                "INSERT INTO governance_decisions (id, tenant_id, asset_id, review_id, kind, "
                "from_status, to_status, actor_type, decided_by, decided_at, reason, "
                "audit_event_id) VALUES (:id, :tenant, :asset, :review, 'SUBMIT', 'DRAFT', "
                "'UNDER_REVIEW', 'user', :user, now(), 'x', "
                "(SELECT id FROM audit_events LIMIT 1))"
            ),
            {"id": uuid4(), "tenant": second.id, "asset": asset, "review": review["id"],
             "user": outsider},
        )
