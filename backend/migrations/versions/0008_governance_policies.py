"""Governance policies: named policies, their immutable versions, and status events.

These are separate from the runtime `policies` and `policy_versions`, which stay the rules the
gateway evaluates.

Revision ID: 0008
Revises: 0007
"""

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

TABLES = ("governance_policies", "governance_policy_versions", "governance_policy_events")

STATEMENTS = [
    """
    CREATE TABLE governance_policies (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
        category text NOT NULL CHECK (char_length(category) BETWEEN 1 AND 100),
        created_by uuid NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
    )
    """,
    "CREATE UNIQUE INDEX governance_policies_name ON governance_policies (tenant_id, lower(name))",
    # The document is the whole content of a version. Its approval and activation cannot be
    # stored on this append-only row, so they are events. The hash covers the policy, number,
    # window, and document, and is checked at every load.
    """
    CREATE TABLE governance_policy_versions (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        policy_id uuid NOT NULL,
        version integer NOT NULL CHECK (version >= 1),
        document_canonical text NOT NULL,
        content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
        effective_from timestamptz NOT NULL,
        review_by timestamptz,
        created_by uuid NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, policy_id, version),
        CHECK (review_by IS NULL OR review_by > effective_from),
        FOREIGN KEY (tenant_id, policy_id) REFERENCES governance_policies (tenant_id, id),
        FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
    )
    """,
    """
    CREATE TABLE governance_policy_events (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        policy_version_id uuid NOT NULL,
        event text NOT NULL CHECK (event IN ('APPROVED', 'ACTIVATED', 'DEACTIVATED')),
        actor_id uuid NOT NULL,
        audit_event_id uuid NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        FOREIGN KEY (tenant_id, policy_version_id)
            REFERENCES governance_policy_versions (tenant_id, id),
        FOREIGN KEY (tenant_id, actor_id) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, audit_event_id) REFERENCES audit_events (tenant_id, id)
    )
    """,
    """
    CREATE UNIQUE INDEX governance_policy_events_one_approval
    ON governance_policy_events (tenant_id, policy_version_id) WHERE event = 'APPROVED'
    """,
    """
    CREATE INDEX governance_policy_events_version_idx
    ON governance_policy_events (tenant_id, policy_version_id)
    """,
    # Backs two service rules below the service: the approver is not the creator, and only an
    # approved version is ever activated.
    """
    CREATE FUNCTION aegis_policy_event_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
    BEGIN
        IF NEW.event = 'APPROVED' THEN
            IF NEW.actor_id = (
                SELECT created_by FROM public.governance_policy_versions
                WHERE tenant_id = NEW.tenant_id AND id = NEW.policy_version_id
            ) THEN
                RAISE EXCEPTION 'the approver cannot be the creator of the version'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.event = 'ACTIVATED' THEN
            IF NOT EXISTS (
                SELECT 1 FROM public.governance_policy_events
                WHERE tenant_id = NEW.tenant_id AND policy_version_id = NEW.policy_version_id
                AND event = 'APPROVED'
            ) THEN
                RAISE EXCEPTION 'only an approved version can be activated'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER governance_policy_events_guard BEFORE INSERT ON governance_policy_events
    FOR EACH ROW EXECUTE FUNCTION aegis_policy_event_guard()
    """,
    *(
        statement
        for table in TABLES
        for statement in (
            f"""
            CREATE TRIGGER {table}_reject_row_mutation BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION aegis_reject_mutation()
            """,
            f"""
            CREATE TRIGGER {table}_reject_truncate BEFORE TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_mutation()
            """,
            f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
            f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
            f"""
            CREATE POLICY tenant_isolation ON {table}
            USING (tenant_id = aegis_current_tenant())
            WITH CHECK (tenant_id = aegis_current_tenant())
            """,
            f"GRANT SELECT, INSERT ON {table} TO aegis_app",
        )
    ),
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("Downgrading would destroy governance records; restore from backup")
