"""Governance risk: methodology versions, their approval events, and risk assessments.

Revision ID: 0007
Revises: 0006
"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

TABLES = ("risk_methodology_versions", "risk_methodology_events", "risk_assessments")

STATEMENTS = [
    # Version 1 is the built-in document, seeded per tenant with no creator, and counts as
    # approved. The CHECK keeps that exception to version 1: no later version can skip approval.
    """
    CREATE TABLE risk_methodology_versions (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        version integer NOT NULL CHECK (version >= 1),
        document_canonical text NOT NULL,
        content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
        created_by uuid,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, version),
        CHECK ((version = 1) = (created_by IS NULL)),
        FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
    )
    """,
    # An approval cannot be stored on an append-only version row, so it is an event of its own.
    """
    CREATE TABLE risk_methodology_events (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        version_id uuid NOT NULL,
        event text NOT NULL CHECK (event IN ('APPROVED', 'ACTIVATED')),
        actor_id uuid NOT NULL,
        audit_event_id uuid NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        FOREIGN KEY (tenant_id, version_id) REFERENCES risk_methodology_versions (tenant_id, id),
        FOREIGN KEY (tenant_id, actor_id) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, audit_event_id) REFERENCES audit_events (tenant_id, id)
    )
    """,
    """
    CREATE UNIQUE INDEX risk_methodology_events_one_approval
    ON risk_methodology_events (tenant_id, version_id) WHERE event = 'APPROVED'
    """,
    """
    CREATE INDEX risk_methodology_events_version_idx
    ON risk_methodology_events (tenant_id, version_id)
    """,
    # input_canonical and result_canonical are what the engine was given and returned, so a stored
    # assessment can be recomputed. UNIQUE (tenant_id, asset_id, id) lets the state row point only
    # at an assessment of its own asset.
    """
    CREATE TABLE risk_assessments (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        asset_id uuid NOT NULL,
        profile_version_id uuid NOT NULL,
        methodology_version_id uuid NOT NULL,
        input_canonical text NOT NULL,
        input_hash text NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
        result_canonical text NOT NULL,
        result_hash text NOT NULL CHECK (result_hash ~ '^[0-9a-f]{64}$'),
        status text NOT NULL CONSTRAINT risk_assessments_status_known
            CHECK (status IN ('COMPLETE', 'INCOMPLETE')),
        score integer,
        risk_level text CONSTRAINT risk_assessments_level_known
            CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
        assessed_by uuid NOT NULL,
        audit_event_id uuid NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, asset_id, id),
        CONSTRAINT risk_assessments_level_matches_status
            CHECK ((status = 'COMPLETE') = (risk_level IS NOT NULL)),
        CONSTRAINT risk_assessments_score_matches_status
            CHECK ((status = 'COMPLETE') = (score IS NOT NULL)),
        FOREIGN KEY (tenant_id, asset_id) REFERENCES ai_assets (tenant_id, id),
        FOREIGN KEY (tenant_id, asset_id, profile_version_id)
            REFERENCES asset_profile_versions (tenant_id, asset_id, id),
        FOREIGN KEY (tenant_id, methodology_version_id)
            REFERENCES risk_methodology_versions (tenant_id, id),
        FOREIGN KEY (tenant_id, assessed_by) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, audit_event_id) REFERENCES audit_events (tenant_id, id)
    )
    """,
    "CREATE INDEX risk_assessments_asset_idx ON risk_assessments (tenant_id, asset_id)",
    # The pointers left without a foreign key by 0005 and 0006.
    """
    ALTER TABLE governance_settings
    ADD CONSTRAINT governance_settings_methodology_fkey
    FOREIGN KEY (tenant_id, active_methodology_version_id)
    REFERENCES risk_methodology_versions (tenant_id, id)
    """,
    """
    ALTER TABLE asset_governance_state
    ADD CONSTRAINT asset_governance_state_assessment_fkey
    FOREIGN KEY (tenant_id, asset_id, latest_assessment_id)
    REFERENCES risk_assessments (tenant_id, asset_id, id)
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
