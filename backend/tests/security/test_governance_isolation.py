"""One tenant cannot see or change another tenant's governance records.

Each task that adds a governance route adds it here. Detail and history routes arrive later.
"""


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
