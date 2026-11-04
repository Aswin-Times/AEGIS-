"""Asset profiles and the governance state row: versions, the trigger, and who may write."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aegis.canonical import sha256_hex
from aegis.errors import Conflict
from aegis.governance.assets import (
    load_state,
    lock_asset_agents,
    require_not_retired,
    touch,
    transition,
)
from aegis.governance.engine.lifecycle import TRANSITIONS, GovernanceStatus
from aegis.governance.profile import AssetProfile, canonical_profile

FULL_PROFILE = {
    "asset_type": "autonomous_agent",
    "description": "Synthetic support agent",
    "business_purpose": "Answer customer questions",
    "intended_use": "Internal support triage",
    "prohibited_use": "Legal advice",
    "responsible_team": "support-platform",
    "model_provider": "synthetic-provider",
    "model_name": "synthetic-model",
    "model_version": "1",
    "deployment_environment": "staging",
    "data_categories": ["internal", "personal"],
    "external_exposure": "internal_users",
    "external_integrations": ["ticketing"],
    "autonomy_level": "supervised",
    "human_oversight": "on_the_loop",
    "declared_tool_access": ["lookup_document"],
    "impact_level": "moderate",
    "third_party_reliance": "vetted",
    "evidence_references": ["design-review-1"],
}


def _profile_path(asset_id: str) -> str:
    return f"/governance/assets/{asset_id}/profile"


def _save(tenant, asset_id, body=None, headers=None):
    return tenant.post(_profile_path(asset_id), {} if body is None else body, headers=headers)


def _state(db, tenant, asset_id):
    with db.tenant_transaction(tenant.id) as session:
        state = load_state(session, UUID(asset_id))
        if state is None:
            return None
        return state.status, state.version, state.current_profile_version_id


def _as_app(db, tenant, sql, **params):
    with db.tenant_transaction(tenant.id) as session:
        session.execute(text(sql), params)


def _move(db, tenant, asset_id, status, extra=""):
    _as_app(
        db,
        tenant,
        f"UPDATE asset_governance_state SET status = :status, version = version + 1 {extra} "
        "WHERE asset_id = :asset",
        status=status,
        asset=asset_id,
    )


def test_first_profile_creates_draft_state(db, tenant):
    asset = tenant.asset()
    response = _save(tenant, asset["id"], FULL_PROFILE)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["version"] == 1
    assert body["governance_status"] == "DRAFT"
    assert body["profile"]["autonomy_level"] == "supervised"
    status, version, current = _state(db, tenant, asset["id"])
    assert (status, version) == ("DRAFT", 1)
    assert str(current) == body["id"]
    assert len(tenant.audit_events("governance.profile_saved")) == 1


def test_profile_versions_increment_and_never_change(db, tenant, attacker_sql):
    asset = tenant.asset()
    first = _save(tenant, asset["id"], {"description": "one"}).json()
    second = _save(tenant, asset["id"], {"description": "two"}).json()
    assert (first["version"], second["version"]) == (1, 2)
    assert first["id"] != second["id"]
    assert first["content_hash"] != second["content_hash"]
    status, version, current = _state(db, tenant, asset["id"])
    assert (status, str(current)) == ("DRAFT", second["id"])
    assert version == 2

    with pytest.raises(DBAPIError):
        _as_app(db, tenant, "UPDATE asset_profile_versions SET profile_canonical = '{}'")
    with pytest.raises(DBAPIError):
        _as_app(db, tenant, "DELETE FROM asset_profile_versions")
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute(
            "UPDATE asset_profile_versions SET profile_canonical = '{}' WHERE id = %s",
            (first["id"],),
        )
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute("TRUNCATE asset_profile_versions CASCADE")


def test_stored_hash_matches_stored_profile(attacker_sql, tenant):
    asset = tenant.asset()
    saved = _save(tenant, asset["id"], FULL_PROFILE).json()
    canonical, stored_hash = attacker_sql.execute(
        "SELECT profile_canonical, content_hash FROM asset_profile_versions WHERE id = %s",
        (saved["id"],),
    ).fetchone()
    assert stored_hash == saved["content_hash"] == sha256_hex(canonical)


def test_owner_must_be_a_user_in_this_tenant(world, attacker_sql):
    first, second = world.tenant(), world.tenant()
    outsider = second.user_id("admin")
    asset = first.asset()

    assert _save(first, asset["id"], {"business_owner_id": outsider}).status_code == 422
    assert _save(first, asset["id"], {"technical_owner_id": outsider}).status_code == 422
    assert first.audit_events("governance.profile_saved") == []

    own = first.user_id("reviewer")
    ok = _save(first, asset["id"], {"business_owner_id": own, "technical_owner_id": own})
    assert ok.status_code == 201

    # Below the service, the composite foreign key refuses it as well.
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        attacker_sql.execute(
            """
            INSERT INTO asset_profile_versions
                (id, tenant_id, asset_id, version, profile_canonical, content_hash,
                 business_owner_id, created_by)
            VALUES (%s, %s, %s, 99, '{}', %s, %s, %s)
            """,
            (uuid4(), first.id, asset["id"], "0" * 64, outsider, own),
        )


def test_partial_profile_can_be_saved(db, tenant):
    asset = tenant.asset()
    for body in ({}, {"description": "only this"}):
        response = _save(tenant, asset["id"], body)
        assert response.status_code == 201, response.text
        assert response.json()["profile"] == body
    assert _state(db, tenant, asset["id"])[0] == "DRAFT"


@pytest.mark.parametrize(
    "body",
    [
        {"surprise": 1},
        {"risk_level": "LOW"},
        {"asset_type": "toaster"},
        {"autonomy_level": 3},
        {"data_categories": ["secret"]},
        {"description": 5},
    ],
)
def test_unknown_or_invalid_profile_field_rejected(db, tenant, body):
    asset = tenant.asset()
    assert _save(tenant, asset["id"], body).status_code == 422
    assert _state(db, tenant, asset["id"]) is None


def test_unknown_asset_is_not_found(tenant):
    assert _save(tenant, str(uuid4()), {}).status_code == 404


def test_trigger_rejects_invalid_transition(db, tenant):
    asset = tenant.asset()
    _save(tenant, asset["id"])
    with pytest.raises(DBAPIError, match="invalid governance transition"):
        _move(db, tenant, asset["id"], "APPROVED")
    assert _state(db, tenant, asset["id"])[0] == "DRAFT"
    _move(db, tenant, asset["id"], "ASSESSMENT_REQUIRED")
    assert _state(db, tenant, asset["id"])[0] == "ASSESSMENT_REQUIRED"


def test_trigger_rejects_a_status_outside_the_nine(db, tenant):
    asset = tenant.asset()
    _save(tenant, asset["id"])
    with pytest.raises(DBAPIError):
        _move(db, tenant, asset["id"], "REVOKED")


def test_trigger_agrees_with_the_transition_table(tenant, attacker_sql):
    """The Python table and the trigger are two copies of one rule, so compare every pair."""
    asset = tenant.asset()
    _save(tenant, asset["id"])
    for old in GovernanceStatus:
        for new in GovernanceStatus:
            if new == old:
                continue  # An update that leaves the status alone is not a transition.
            with pytest.raises(_Rollback), attacker_sql.transaction():
                # Place the row in `old` without running the guard, then try the real move.
                attacker_sql.execute("SET LOCAL session_replication_role = replica")
                attacker_sql.execute(
                    "UPDATE asset_governance_state SET status = %s WHERE asset_id = %s",
                    (old.value, asset["id"]),
                )
                attacker_sql.execute("SET LOCAL session_replication_role = origin")
                try:
                    with attacker_sql.transaction():
                        attacker_sql.execute(
                            "UPDATE asset_governance_state "
                            "SET status = %s, version = version + 1 WHERE asset_id = %s",
                            (new.value, asset["id"]),
                        )
                    allowed = True
                except psycopg.Error:
                    allowed = False
                assert allowed == (new in TRANSITIONS[old]), (old, new)
                raise _Rollback


class _Rollback(Exception):
    """Raised to undo the setup of one pair in the parity test."""


def test_trigger_rejects_hard_block_clear_without_approval(db, tenant, attacker_sql):
    asset = tenant.asset()
    _save(tenant, asset["id"])
    # Set up the blocked state directly. The decisions table does not exist yet.
    attacker_sql.execute(
        "UPDATE asset_governance_state SET hard_block_decision_id = %s, "
        "version = version + 1 WHERE asset_id = %s",
        (uuid4(), asset["id"]),
    )
    clear = "hard_block_decision_id = NULL"
    with pytest.raises(DBAPIError, match="hard block"):
        _as_app(
            db, tenant,
            f"UPDATE asset_governance_state SET {clear}, version = version + 1 "
            "WHERE asset_id = :asset",
            asset=asset["id"],
        )
    # Moving through intermediate states does not lift it either.
    with pytest.raises(DBAPIError, match="hard block"):
        _move(db, tenant, asset["id"], "ASSESSMENT_REQUIRED", f", {clear}")

    _move(db, tenant, asset["id"], "ASSESSMENT_REQUIRED")
    _move(db, tenant, asset["id"], "UNDER_REVIEW")
    with pytest.raises(DBAPIError, match="hard block"):
        _move(db, tenant, asset["id"], "REJECTED", f", {clear}")
    # Only the move into an approved status may lift it.
    _move(db, tenant, asset["id"], "APPROVED", f", {clear}")
    assert _state(db, tenant, asset["id"])[0] == "APPROVED"


def test_trigger_rejects_hard_block_clear_without_a_move_into_approval(db, tenant, attacker_sql):
    asset = tenant.asset()
    _save(tenant, asset["id"])
    _move(db, tenant, asset["id"], "ASSESSMENT_REQUIRED")
    _move(db, tenant, asset["id"], "UNDER_REVIEW")
    _move(db, tenant, asset["id"], "APPROVED")
    attacker_sql.execute(
        "UPDATE asset_governance_state SET hard_block_decision_id = %s, "
        "version = version + 1 WHERE asset_id = %s",
        (uuid4(), asset["id"]),
    )
    # The row is already APPROVED, so a status-unchanged update is not a move into approval.
    for extra in ("", ", status = 'APPROVED'"):
        with pytest.raises(DBAPIError, match="hard block"):
            _as_app(
                db, tenant,
                "UPDATE asset_governance_state SET hard_block_decision_id = NULL, "
                f"version = version + 1 {extra} WHERE asset_id = :asset",
                asset=asset["id"],
            )


def test_trigger_rejects_delete_and_binding_change(db, tenant, attacker_sql):
    asset, other = tenant.asset(), tenant.asset()
    _save(tenant, asset["id"])
    with pytest.raises(DBAPIError):
        _as_app(db, tenant, "DELETE FROM asset_governance_state")
    # The runtime role has no grant on these columns; the trigger holds even without that.
    with pytest.raises(psycopg.Error, match="cannot be deleted"):
        attacker_sql.execute("DELETE FROM asset_governance_state")
    with pytest.raises(psycopg.Error, match="immutable"):
        attacker_sql.execute(
            "UPDATE asset_governance_state SET asset_id = %s, version = version + 1 "
            "WHERE asset_id = %s",
            (other["id"], asset["id"]),
        )
    with pytest.raises(psycopg.Error, match="immutable"):
        attacker_sql.execute(
            "UPDATE asset_governance_state SET tenant_id = %s, version = version + 1 "
            "WHERE asset_id = %s",
            (uuid4(), asset["id"]),
        )
    with pytest.raises(DBAPIError):
        _as_app(db, tenant, "UPDATE asset_governance_state SET asset_id = :other",
                other=other["id"])
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute("TRUNCATE asset_governance_state")


def test_trigger_requires_version_increment(db, tenant):
    asset = tenant.asset()
    _save(tenant, asset["id"])
    for version in ("version", "version + 2", "version - 1"):
        with pytest.raises(DBAPIError, match="version"):
            _as_app(
                db, tenant,
                "UPDATE asset_governance_state SET status = 'ASSESSMENT_REQUIRED', "
                f"version = {version} WHERE asset_id = :asset",
                asset=asset["id"],
            )
    # A status-unchanged update is allowed, and still has to advance the version.
    with pytest.raises(DBAPIError, match="version"):
        _as_app(db, tenant, "UPDATE asset_governance_state SET current_decision_id = :id",
                id=uuid4())
    _as_app(db, tenant, "UPDATE asset_governance_state SET current_decision_id = :id, "
            "version = version + 1", id=uuid4())
    assert _state(db, tenant, asset["id"])[:2] == ("DRAFT", 2)


def test_state_cannot_be_inserted_in_any_other_status(attacker_sql, tenant):
    asset = tenant.asset()
    with pytest.raises(psycopg.Error, match="must start"):
        attacker_sql.execute(
            "INSERT INTO asset_governance_state (tenant_id, asset_id, status, version) "
            "VALUES (%s, %s, 'APPROVED', 1)",
            (tenant.id, asset["id"]),
        )


def test_existing_assets_get_no_state_from_the_migration(db, tenant):
    asset = tenant.asset()
    assert _state(db, tenant, asset["id"]) is None
    _save(tenant, asset["id"])
    assert _state(db, tenant, asset["id"])[0] == "DRAFT"


@pytest.mark.parametrize("actor", ["reviewer", "viewer"])
def test_non_admin_cannot_save_profile(db, tenant, actor):
    asset = tenant.asset()
    response = _save(tenant, asset["id"], {"description": "x"}, headers=tenant.login(actor))
    assert response.status_code == 403
    assert _state(db, tenant, asset["id"]) is None
    assert tenant.audit_events("governance.profile_saved") == []


def test_governance_reviewer_role_does_not_confer_profile_writes(tenant):
    tenant.grant_governance("reviewer")
    asset = tenant.asset()
    assert _save(tenant, asset["id"], {}, headers=tenant.login("reviewer")).status_code == 403


def test_agent_principal_cannot_save_profile(tenant):
    agent = tenant.agent()
    asset = tenant.asset()
    response = tenant.client.post(
        f"/api/v1{_profile_path(asset['id'])}", json={}, headers=agent.headers
    )
    assert response.status_code == 401


def test_retired_asset_refuses_new_profiles(db, tenant):
    asset = tenant.asset()
    _save(tenant, asset["id"])
    _move(db, tenant, asset["id"], "RETIRED")
    response = _save(tenant, asset["id"], {"description": "late"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ASSET_RETIRED"


def test_canonical_profile_is_order_independent_and_omits_unset_fields():
    one = AssetProfile(description="d", data_categories=["personal", "internal", "personal"])
    two = AssetProfile(data_categories=["internal", "personal"], description="d")
    assert canonical_profile(one) == canonical_profile(two)
    assert "business_owner_id" not in canonical_profile(one)
    assert canonical_profile(AssetProfile()) == "{}"


def test_transition_service_checks_table_and_bumps_version(db, tenant):
    asset = tenant.asset()
    _save(tenant, asset["id"])
    now = datetime.now(UTC)
    with db.tenant_transaction(tenant.id) as session:
        state = load_state(session, UUID(asset["id"]))
        with pytest.raises(Conflict) as refused:
            transition(session, state, GovernanceStatus.APPROVED, now)
        assert refused.value.code == "INVALID_STATE_TRANSITION"
        assert (state.status, state.version) == ("DRAFT", 1)

        transition(session, state, GovernanceStatus.ASSESSMENT_REQUIRED, now)
        touch(session, state, now, current_decision_id=uuid4())
        with pytest.raises(ValueError):
            touch(session, state, now, asset_id=uuid4())
    assert _state(db, tenant, asset["id"])[:2] == ("ASSESSMENT_REQUIRED", 3)


def test_require_not_retired_and_lock_agents(db, tenant):
    agent = tenant.agent()
    asset_id = UUID(tenant.get(f"/agents/{agent.id}").json()["asset_id"])
    with db.tenant_transaction(tenant.id) as session:
        lock_asset_agents(session, asset_id)
        require_not_retired(None)
    with pytest.raises(Conflict) as refused:
        require_not_retired(SimpleNamespace(status="RETIRED"))
    assert refused.value.code == "ASSET_RETIRED"
