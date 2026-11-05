"""Governance foundation: per-tenant settings and the governance_reviewer role grants.

Revision ID: 0005
Revises: 0004
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

STATEMENTS = [
    # No row means observe mode and the built-in methodology. The methodology pointer has no
    # foreign key yet, because the table it points at arrives with the risk engine.
    """
    CREATE TABLE governance_settings (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        enforcement_mode text NOT NULL DEFAULT 'observe'
            CHECK (enforcement_mode IN ('observe', 'enforce')),
        active_methodology_version_id uuid,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id)
    )
    """,
    # The self-grant CHECK backs the service rule: a tenant needs two people before any
    # governance approval can happen.
    """
    CREATE TABLE governance_role_grants (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        user_id uuid NOT NULL,
        role text NOT NULL CHECK (role IN ('governance_reviewer')),
        granted_by uuid NOT NULL,
        granted_at timestamptz NOT NULL DEFAULT now(),
        revoked_by uuid,
        revoked_at timestamptz,
        UNIQUE (tenant_id, id),
        CHECK (granted_by <> user_id),
        CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
        FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, granted_by) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, revoked_by) REFERENCES users (tenant_id, id)
    )
    """,
    """
    CREATE UNIQUE INDEX governance_role_grants_one_active
    ON governance_role_grants (tenant_id, user_id, role) WHERE revoked_at IS NULL
    """,
    "CREATE INDEX governance_role_grants_user_idx ON governance_role_grants (tenant_id, user_id)",
    # A grant can be revoked once. Without this, clearing revoked_at would restore authority
    # with no new grant and no audit event.
    """
    CREATE FUNCTION aegis_role_grant_revoke_once() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
    BEGIN
        IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
            RAISE EXCEPTION 'a role grant can only be revoked, once' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER governance_role_grants_revoke_once BEFORE UPDATE ON governance_role_grants
    FOR EACH ROW EXECUTE FUNCTION aegis_role_grant_revoke_once()
    """,
    """
    CREATE TRIGGER governance_role_grants_reject_delete BEFORE DELETE ON governance_role_grants
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_mutation()
    """,
    """
    CREATE TRIGGER governance_role_grants_reject_truncate BEFORE TRUNCATE ON governance_role_grants
    FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_mutation()
    """,
    *(
        statement
        for table in ("governance_settings", "governance_role_grants")
        for statement in (
            f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
            f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
            f"""
            CREATE POLICY tenant_isolation ON {table}
            USING (tenant_id = aegis_current_tenant())
            WITH CHECK (tenant_id = aegis_current_tenant())
            """,
        )
    ),
    "GRANT SELECT, INSERT ON governance_settings TO aegis_app",
    """
    GRANT UPDATE (enforcement_mode, active_methodology_version_id)
    ON governance_settings TO aegis_app
    """,
    "GRANT SELECT, INSERT ON governance_role_grants TO aegis_app",
    "GRANT UPDATE (revoked_by, revoked_at) ON governance_role_grants TO aegis_app",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("Downgrading would destroy governance records; restore from backup")
