"""Database-layer isolation. API-level tenant tests are in test_tenant_isolation.py."""

from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from aegis.api.app import UnsafeDatabaseRole, assert_runtime_role_is_restricted
from aegis.audit.chain import append_event
from aegis.db.models import AiAsset, AuditEvent, Tenant
from aegis.db.session import Database


def _insert_asset(session, tenant_id, name="asset"):
    asset = AiAsset(
        id=uuid4(),
        tenant_id=tenant_id,
        name=name,
        owner="synthetic",
        risk_classification="low",
        intended_use="test",
        is_synthetic=True,
    )
    session.add(asset)
    session.flush()
    return asset


def test_every_table_with_tenant_id_has_forced_rls(attacker_sql):
    rows = attacker_sql.execute(
        """
        SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
               (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r'
          AND (c.relname = 'tenants' OR EXISTS (
              SELECT 1 FROM pg_attribute a
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped))
        """
    ).fetchall()
    assert len(rows) >= 17
    unprotected = [row[0] for row in rows if not (row[1] and row[2] and row[3] >= 1)]
    assert unprotected == []


def test_every_non_system_table_is_accounted_for(attacker_sql):
    """A new table without tenant_id must be added here deliberately."""
    rows = attacker_sql.execute(
        """
        SELECT c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname <> 'tenants'
          AND NOT EXISTS (
              SELECT 1 FROM pg_attribute a
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
        """
    ).fetchall()
    assert [row[0] for row in rows] == ["alembic_version"]


def test_runtime_role_privileges(attacker_sql):
    row = attacker_sql.execute(
        """
        SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
        FROM pg_roles WHERE rolname = 'aegis_app'
        """
    ).fetchone()
    assert row == (False, False, False, False)
    owns = attacker_sql.execute(
        """
        SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
        WHERE r.rolname = 'aegis_app'
        """
    ).fetchone()
    assert owns[0] == 0


def test_runtime_role_cannot_run_ddl(db):
    tenant = uuid4()
    with pytest.raises(ProgrammingError), db.tenant_transaction(tenant) as session:
        session.execute(text("CREATE TABLE attacker_table (id int)"))


def test_runtime_role_cannot_disable_rls(db):
    with pytest.raises(ProgrammingError), db.tenant_transaction(uuid4()) as session:
        session.execute(text("ALTER TABLE ai_assets DISABLE ROW LEVEL SECURITY"))


def test_runtime_role_cannot_read_migration_history(db):
    with pytest.raises(ProgrammingError), db.tenant_transaction(uuid4()) as session:
        session.execute(text("SELECT * FROM alembic_version"))


def test_no_context_sees_no_rows(db, new_tenant):
    tenant = new_tenant()
    with db.tenant_transaction(tenant) as session:
        _insert_asset(session, tenant)

    # A raw session, with no set_config call, is what a forgotten context looks like.
    with db._sessions() as session, session.begin():
        assert session.execute(select(AiAsset)).scalars().all() == []
        assert session.execute(select(Tenant)).scalars().all() == []


def test_context_clears_when_the_transaction_ends(urls, new_tenant):
    """A pooled connection must not carry one tenant's context into the next use."""
    tenant = new_tenant()
    single_connection = Database(urls.app, pool_size=1, max_overflow=0)
    try:
        with single_connection.tenant_transaction(tenant) as session:
            _insert_asset(session, tenant)
            backend = session.execute(text("SELECT pg_backend_pid()")).scalar_one()

        with single_connection._sessions() as session, session.begin():
            assert session.execute(text("SELECT pg_backend_pid()")).scalar_one() == backend
            assert session.execute(select(AiAsset)).scalars().all() == []
    finally:
        single_connection.dispose()


def test_tenant_sees_only_its_own_rows(db, new_tenant):
    tenant_a, tenant_b = new_tenant(), new_tenant()
    with db.tenant_transaction(tenant_a) as session:
        asset_a = _insert_asset(session, tenant_a)

    with db.tenant_transaction(tenant_b) as session:
        assert session.get(AiAsset, asset_a.id) is None
        assert session.execute(select(AiAsset)).scalars().all() == []
        assert [row.id for row in session.execute(select(Tenant)).scalars()] == [tenant_b]


def test_cannot_write_a_row_for_another_tenant(db, new_tenant):
    tenant_a, tenant_b = new_tenant(), new_tenant()
    with pytest.raises(ProgrammingError, match="row-level security"):
        with db.tenant_transaction(tenant_a) as session:
            _insert_asset(session, tenant_b)


def test_cannot_update_another_tenants_rows(db, new_tenant):
    tenant_a, tenant_b = new_tenant(), new_tenant()
    with db.tenant_transaction(tenant_a) as session:
        asset = _insert_asset(session, tenant_a)
        agent_id = uuid4()
        session.execute(
            text(
                "INSERT INTO agents (id, tenant_id, asset_id, name, owner, status) "
                "VALUES (:id, :tenant, :asset, 'agent', 'synthetic', 'active')"
            ),
            {"id": agent_id, "tenant": tenant_a, "asset": asset.id},
        )

    with db.tenant_transaction(tenant_b) as session:
        result = session.execute(
            text("UPDATE agents SET status = 'disabled' WHERE id = :id"), {"id": agent_id}
        )
        assert result.rowcount == 0

    with db.tenant_transaction(tenant_a) as session:
        status = session.execute(
            text("SELECT status FROM agents WHERE id = :id"), {"id": agent_id}
        ).scalar_one()
        assert status == "active"


def test_composite_foreign_key_blocks_cross_tenant_reference(db, new_tenant):
    tenant_a, tenant_b = new_tenant(), new_tenant()
    with db.tenant_transaction(tenant_a) as session:
        asset_a = _insert_asset(session, tenant_a)

    with pytest.raises(IntegrityError), db.tenant_transaction(tenant_b) as session:
        session.execute(
            text(
                "INSERT INTO agents (id, tenant_id, asset_id, name, owner, status) "
                "VALUES (:id, :tenant, :asset, 'agent', 'synthetic', 'active')"
            ),
            {"id": uuid4(), "tenant": tenant_b, "asset": asset_a.id},
        )


def test_runtime_role_cannot_create_tenants_or_users(db, new_tenant):
    tenant = new_tenant()
    with pytest.raises(ProgrammingError), db.tenant_transaction(tenant) as session:
        session.execute(
            text("INSERT INTO tenants (id, slug, name) VALUES (:id, 'evil-tenant', 'x')"),
            {"id": tenant},
        )
    with pytest.raises(ProgrammingError), db.tenant_transaction(tenant) as session:
        session.execute(
            text(
                "INSERT INTO users (id, tenant_id, email, password_hash, role) "
                "VALUES (:id, :tenant, 'evil@example.test', 'x', 'admin')"
            ),
            {"id": uuid4(), "tenant": tenant},
        )


def test_resolve_tenant_returns_only_an_id_for_an_exact_slug(db, urls, new_tenant):
    tenant = new_tenant()
    with psycopg.connect(urls.superuser) as connection:
        slug = connection.execute(
            "SELECT slug FROM tenants WHERE id = %s", (tenant,)
        ).fetchone()[0]
    assert db.resolve_tenant(slug) == tenant
    assert db.resolve_tenant(slug.upper()) is None
    assert db.resolve_tenant("%") is None


def test_documented_limitation_arbitrary_sql_can_change_tenant_context(db, new_tenant):
    """Records threat T15: RLS guards against app bugs, not arbitrary SQL as aegis_app."""
    tenant_a, tenant_b = new_tenant(), new_tenant()
    with db.tenant_transaction(tenant_a) as session:
        asset = _insert_asset(session, tenant_a)

    with db.tenant_transaction(tenant_b) as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tenant, true)"), {"tenant": str(tenant_a)}
        )
        assert session.get(AiAsset, asset.id) is not None


def test_audit_table_is_not_writable_by_update(db, new_tenant):
    tenant = new_tenant()
    with pytest.raises(DBAPIError), db.tenant_transaction(tenant) as session:
        session.execute(text("UPDATE audit_events SET event_type = 'forged'"))


def test_audit_append_works_for_runtime_role(db, new_tenant):
    tenant = new_tenant()
    with db.tenant_transaction(tenant) as session:
        event = append_event(session, tenant, event_type="test.event", actor_type="system")
    with db.tenant_transaction(tenant) as session:
        assert session.get(AuditEvent, event.id).seq == 2


@pytest.mark.parametrize("attr", ["superuser", "owner"])
def test_api_refuses_to_start_with_a_privileged_database_role(urls, attr):
    url = getattr(urls, attr).replace("postgresql://", "postgresql+psycopg://")
    database = Database(url, pool_size=1, max_overflow=0)
    try:
        with pytest.raises(UnsafeDatabaseRole):
            assert_runtime_role_is_restricted(database)
    finally:
        database.dispose()


def test_api_starts_with_the_restricted_role(db):
    assert_runtime_role_is_restricted(db)


EXPECTED_TABLE_PRIVILEGES = {
    "tenants": {"SELECT"},
    "users": {"SELECT"},
    "ai_assets": {"SELECT", "INSERT"},
    "agents": {"SELECT", "INSERT"},
    "agent_credentials": {"SELECT", "INSERT"},
    "resources": {"SELECT", "INSERT"},
    "agent_tool_grants": {"SELECT", "INSERT", "DELETE"},
    "agent_resource_grants": {"SELECT", "INSERT", "DELETE"},
    "policies": {"SELECT", "INSERT"},
    "policy_versions": {"SELECT", "INSERT"},
    "action_requests": {"SELECT", "INSERT"},
    "policy_decisions": {"SELECT", "INSERT"},
    "approvals": {"SELECT", "INSERT"},
    "executions": {"SELECT", "INSERT"},
    "simulated_outbox": {"SELECT", "INSERT"},
    "audit_chain_heads": {"SELECT"},
    "audit_events": {"SELECT", "INSERT"},
    "security_events": {"SELECT", "INSERT"},
    "correlation_rule_versions": {"SELECT", "INSERT"},
    "incidents": {"SELECT", "INSERT"},
    "incident_events": {"SELECT", "INSERT"},
    "incident_transitions": {"SELECT", "INSERT"},
    "investigation_runs": {"SELECT", "INSERT"},
    "investigation_findings": {"SELECT", "INSERT"},
    "finding_evidence": {"SELECT", "INSERT"},
    "governance_settings": {"SELECT", "INSERT"},
    "governance_role_grants": {"SELECT", "INSERT"},
    "asset_profile_versions": {"SELECT", "INSERT"},
    "asset_governance_state": {"SELECT", "INSERT"},
    "risk_methodology_versions": {"SELECT", "INSERT"},
    "risk_methodology_events": {"SELECT", "INSERT"},
    "risk_assessments": {"SELECT", "INSERT"},
    "governance_policies": {"SELECT", "INSERT"},
    "governance_policy_versions": {"SELECT", "INSERT"},
    "governance_policy_events": {"SELECT", "INSERT"},
}

EXPECTED_COLUMN_UPDATES = {
    "tenants": {"active_policy_version_id"},
    "agents": {"status"},
    "agent_credentials": {"revoked_at"},
    "approvals": {"status", "decided_by", "decided_at", "comment"},
    "executions": {"status", "result", "finished_at"},
    "audit_chain_heads": {"seq", "head_hash"},
    "security_events": {"correlation_processed_at"},
    "incidents": {
        "status",
        "version",
        "event_count",
        "first_observed_at",
        "last_observed_at",
        "assigned_to",
        "updated_at",
    },
    "investigation_runs": {
        "llm_status",
        "llm_provider",
        "llm_model",
        "llm_rejected_count",
        "llm_finished_at",
    },
    "governance_settings": {"enforcement_mode", "active_methodology_version_id"},
    "governance_role_grants": {"revoked_by", "revoked_at"},
    "asset_governance_state": {
        "status",
        "version",
        "current_profile_version_id",
        "latest_assessment_id",
        "current_decision_id",
        "hard_block_decision_id",
        "valid_until",
        "next_review_at",
        "updated_at",
    },
}


def test_runtime_role_table_privileges_are_exactly_as_documented(attacker_sql):
    """Checked in the catalog, because triggers would otherwise hide an excessive grant."""
    rows = attacker_sql.execute(
        """
        SELECT table_name, privilege_type FROM information_schema.role_table_grants
        WHERE grantee = 'aegis_app' AND table_schema = 'public'
        """
    ).fetchall()
    actual = {}
    for table, privilege in rows:
        actual.setdefault(table, set()).add(privilege)
    assert actual == EXPECTED_TABLE_PRIVILEGES


def test_runtime_role_column_updates_are_exactly_as_documented(attacker_sql):
    rows = attacker_sql.execute(
        """
        SELECT table_name, column_name FROM information_schema.column_privileges
        WHERE grantee = 'aegis_app' AND table_schema = 'public' AND privilege_type = 'UPDATE'
        """
    ).fetchall()
    actual = {}
    for table, column in rows:
        actual.setdefault(table, set()).add(column)
    assert actual == EXPECTED_COLUMN_UPDATES


def test_only_the_id_lookups_are_security_definer(attacker_sql):
    """Each exception to RLS is deliberate, returns IDs only, and is listed here."""
    rows = attacker_sql.execute(
        """
        SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.prosecdef
        """
    ).fetchall()
    assert sorted(row[0] for row in rows) == [
        "aegis_resolve_tenant",
        "aegis_tenants_with_pending_events",
    ]
