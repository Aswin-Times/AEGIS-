"""The governance inventory and overview: what a client reads, and where each number comes from."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text

ASSETS = "/governance/assets"
OVERVIEW = "/governance/overview"


def find(items, asset_id):
    return next(item for item in items if item["id"] == asset_id)


def ids(response):
    assert response.status_code == 200, response.text
    return {item["id"] for item in response.json()["items"]}


def profile(tenant, asset_id, body=None):
    response = tenant.post(f"{ASSETS}/{asset_id}/profile", body or {})
    assert response.status_code == 201, response.text
    return response.json()


def make_asset(tenant, name, risk="medium"):
    return tenant.created(
        "/assets",
        {
            "name": name,
            "owner": "synthetic-owner",
            "risk_classification": risk,
            "intended_use": "automated test fixture",
            "is_synthetic": True,
        },
    )


def email_of(tenant, role):
    return f"{role}@{tenant.slug}.example.test"


def move(db, tenant, asset_id, *statuses, **columns):
    """Walk the state row through real transitions as the app role, one version per step."""
    assignments = "".join(f", {name} = :{name}" for name in columns)
    for status in statuses or [None]:
        with db.tenant_transaction(tenant.id) as session:
            session.execute(
                text(
                    "UPDATE asset_governance_state "
                    f"SET status = COALESCE(:status, status), version = version + 1{assignments} "
                    "WHERE asset_id = :asset"
                ),
                {"status": status, "asset": asset_id, **columns},
            )


def test_inventory_lists_ungoverned_assets_with_null_status(tenant):
    asset = tenant.asset()
    item = find(tenant.get(ASSETS).json()["items"], asset["id"])
    assert item["governance_status"] is None and item["assessed_risk"] is None
    assert item["declared_risk"] == "medium"
    assert item["business_owner"] is None and item["technical_owner"] is None


def test_inventory_search_and_filters(db, tenant):
    alpha = make_asset(tenant, "alpha-triage", "high")
    beta = make_asset(tenant, "beta-triage", "low")
    gamma = make_asset(tenant, "gamma-summary", "high")
    admin_id, reviewer_id = tenant.user_id("admin"), tenant.user_id("reviewer")
    profile(tenant, alpha["id"], {"business_owner_id": admin_id})
    profile(tenant, beta["id"], {"technical_owner_id": reviewer_id})
    move(db, tenant, beta["id"], "ASSESSMENT_REQUIRED")

    assert ids(tenant.get(ASSETS, search="triage")) == {alpha["id"], beta["id"]}
    assert ids(tenant.get(ASSETS, search="TRIAGE")) == {alpha["id"], beta["id"]}
    assert ids(tenant.get(ASSETS, search="summary")) == {gamma["id"]}
    assert ids(tenant.get(ASSETS, declared_risk="high")) == {alpha["id"], gamma["id"]}
    assert ids(tenant.get(ASSETS, status="DRAFT")) == {alpha["id"]}
    assert ids(tenant.get(ASSETS, status="ASSESSMENT_REQUIRED")) == {beta["id"]}
    assert ids(tenant.get(ASSETS, owner_id=admin_id)) == {alpha["id"]}
    assert ids(tenant.get(ASSETS, owner_id=reviewer_id)) == {beta["id"]}
    both = tenant.get(
        ASSETS, search="triage", declared_risk="high", status="DRAFT", owner_id=admin_id
    )
    assert ids(both) == {alpha["id"]}
    none = tenant.get(ASSETS, search="triage", declared_risk="low", owner_id=admin_id)
    assert ids(none) == set()

    owned = find(tenant.get(ASSETS, owner_id=admin_id).json()["items"], alpha["id"])
    assert owned["business_owner"] == {"id": admin_id, "email": email_of(tenant, "admin")}

    # The owner filter follows the current profile version, not an older one.
    profile(tenant, alpha["id"], {})
    assert ids(tenant.get(ASSETS, owner_id=admin_id)) == set()


@pytest.mark.parametrize(
    "params",
    [{"status": "REVOKED"}, {"risk": "extreme"}, {"declared_risk": "extreme"},
     {"owner_id": "not-a-uuid"}],
)
def test_inventory_rejects_invalid_filters(tenant, params):
    assert tenant.get(ASSETS, **params).status_code == 422


def test_inventory_search_treats_wildcards_literally(tenant):
    discount = make_asset(tenant, "50%-discount")
    under = make_asset(tenant, "tier_one")
    make_asset(tenant, "tierXone")
    make_asset(tenant, "plain")

    assert ids(tenant.get(ASSETS, search="%")) == {discount["id"]}
    assert ids(tenant.get(ASSETS, search="_")) == {under["id"]}
    assert ids(tenant.get(ASSETS, search="tier_one")) == {under["id"]}
    assert ids(tenant.get(ASSETS, search="50%-")) == {discount["id"]}
    assert ids(tenant.get(ASSETS, search="\\")) == set()
    assert ids(tenant.get(ASSETS, search="x' OR '1'='1")) == set()


def test_inventory_pagination_shape(tenant):
    created = {tenant.asset()["id"] for _ in range(3)}
    first = tenant.get(ASSETS, limit=2, offset=0).json()
    second = tenant.get(ASSETS, limit=2, offset=2).json()
    assert set(first) == {"items", "total", "limit", "offset"}
    assert (first["total"], first["limit"], first["offset"]) == (3, 2, 0)
    assert (second["total"], second["limit"], second["offset"]) == (3, 2, 2)
    assert len(first["items"]) == 2 and len(second["items"]) == 1
    assert {item["id"] for item in first["items"] + second["items"]} == created
    assert tenant.get(ASSETS, limit=0).status_code == 422
    assert tenant.get(ASSETS, offset=-1).status_code == 422


def test_overview_counts_come_from_stored_rows(db, tenant):
    empty = tenant.get(OVERVIEW).json()
    assert empty["total_assets"] == 0 and empty["unassessed"] == 0
    assert empty["enforcement_mode"] == "observe"
    assert tenant.get(OVERVIEW).json() == empty

    first, second, third = (tenant.asset() for _ in range(3))
    counts = tenant.get(OVERVIEW).json()
    assert counts["total_assets"] == 3 and counts["unassessed"] == 3
    assert counts["suspended"] == counts["awaiting_approval"] == 0

    for asset in (first, second, third):
        profile(tenant, asset["id"])
    move(db, tenant, first["id"], "ASSESSMENT_REQUIRED", "UNDER_REVIEW")
    move(db, tenant, second["id"], "SUSPENDED")
    move(db, tenant, third["id"], "ASSESSMENT_REQUIRED", "UNDER_REVIEW", "CONDITIONALLY_APPROVED")
    counts = tenant.get(OVERVIEW).json()
    assert counts["awaiting_approval"] == 1
    assert counts["suspended"] == 1
    assert counts["conditionally_approved"] == 1
    assert counts["overdue_reviews"] == 0

    now = datetime.now(UTC)
    move(db, tenant, third["id"], next_review_at=now + timedelta(days=30))
    assert tenant.get(OVERVIEW).json()["overdue_reviews"] == 0
    move(db, tenant, third["id"], next_review_at=now - timedelta(days=1))
    assert tenant.get(OVERVIEW).json()["overdue_reviews"] == 1
    # Only an approved asset has a review that can be overdue.
    move(db, tenant, third["id"], "SUSPENDED")
    after = tenant.get(OVERVIEW).json()
    assert after["overdue_reviews"] == 0 and after["suspended"] == 2
    assert after["total_assets"] == 3

    # Tables that do not exist yet contribute nothing.
    for field in ("outstanding_findings", "evidence_verified", "evidence_total"):
        assert after[field] == 0


def test_overview_reads_enforcement_mode_from_settings(db, tenant):
    assert tenant.get(OVERVIEW).json()["enforcement_mode"] == "observe"
    with db.tenant_transaction(tenant.id) as session:
        session.execute(
            text(
                "INSERT INTO governance_settings (id, tenant_id, enforcement_mode) "
                "VALUES (:id, :tenant, 'enforce')"
            ),
            {"id": uuid4(), "tenant": tenant.id},
        )
    assert tenant.get(OVERVIEW).json()["enforcement_mode"] == "enforce"


def test_declared_risk_never_reported_as_assessed(tenant):
    asset = make_asset(tenant, "declared-only", "critical")
    profile(tenant, asset["id"], {"impact_level": "severe"})
    item = find(tenant.get(ASSETS).json()["items"], asset["id"])
    assert item["declared_risk"] == "critical" and item["assessed_risk"] is None
    detail = tenant.get(f"{ASSETS}/{asset['id']}").json()
    assert detail["declared_risk"] == "critical" and detail["assessed_risk"] is None
    overview = tenant.get(OVERVIEW).json()
    assert sum(overview["by_assessed_risk"].values()) == 0
    assert overview["unassessed"] == overview["total_assets"] == 1


def test_asset_detail_includes_current_profile_and_owners(tenant):
    asset = make_asset(tenant, "detail-asset")
    ungoverned = tenant.get(f"{ASSETS}/{asset['id']}").json()
    assert ungoverned["governance_status"] is None and ungoverned["profile"] is None

    admin_id = tenant.user_id("admin")
    first = profile(tenant, asset["id"], {"description": "first", "business_owner_id": admin_id})
    profile(tenant, asset["id"], {"description": "second", "technical_owner_id": admin_id})
    detail = tenant.get(f"{ASSETS}/{asset['id']}").json()
    assert detail["governance_status"] == "DRAFT"
    assert detail["profile"]["version"] == 2
    assert detail["profile"]["profile"] == {
        "description": "second", "technical_owner_id": admin_id,
    }
    assert detail["profile"]["id"] != first["id"]
    assert detail["business_owner"] is None
    assert detail["technical_owner"] == {"id": admin_id, "email": email_of(tenant, "admin")}
    assert detail["name"] == "detail-asset" and detail["is_synthetic"] is True
    assert "password_hash" not in str(detail)


def test_unknown_asset_detail_is_not_found(tenant):
    assert tenant.get(f"{ASSETS}/{uuid4()}").status_code == 404


@pytest.mark.parametrize("path", [ASSETS, OVERVIEW])
def test_any_user_can_read_but_agents_and_anonymous_cannot(tenant, path):
    for role in ("viewer", "reviewer", "admin"):
        assert tenant.get(path, headers=tenant.login(role)).status_code == 200
    agent = tenant.agent()
    assert tenant.client.get(f"/api/v1{path}", headers=agent.headers).status_code == 401
    assert tenant.client.get(f"/api/v1{path}").status_code == 401


def test_detail_refuses_agents_and_allows_viewers(tenant):
    asset = tenant.asset()
    path = f"{ASSETS}/{asset['id']}"
    assert tenant.get(path, headers=tenant.login("viewer")).status_code == 200
    agent = tenant.agent()
    assert tenant.client.get(f"/api/v1{path}", headers=agent.headers).status_code == 401

