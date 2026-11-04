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
