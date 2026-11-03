"""Governance assets: immutable profile versions and the per-asset lifecycle state.

Revision ID: 0006
Revises: 0005
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

STATUSES = (
    "DRAFT",
    "ASSESSMENT_REQUIRED",
    "UNDER_REVIEW",
    "APPROVED",
    "CONDITIONALLY_APPROVED",
    "REJECTED",
    "SUSPENDED",
    "REASSESSMENT_REQUIRED",
    "RETIRED",
)
STATUS_LIST = ", ".join(f"'{status}'" for status in STATUSES)

STATEMENTS = [
    # The owner columns repeat what the canonical profile says, so that a composite key can
    # refuse a user from another tenant. UNIQUE (tenant_id, asset_id, id) lets the state row
    # point only at a version of its own asset.
    """
    CREATE TABLE asset_profile_versions (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        asset_id uuid NOT NULL,
        version integer NOT NULL CHECK (version >= 1),
        profile_canonical text NOT NULL,
        content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
        business_owner_id uuid,
        technical_owner_id uuid,
        created_by uuid NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, asset_id, id),
        UNIQUE (tenant_id, asset_id, version),
        FOREIGN KEY (tenant_id, asset_id) REFERENCES ai_assets (tenant_id, id),
        FOREIGN KEY (tenant_id, business_owner_id) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, technical_owner_id) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
    )
    """,
    # No row means the asset is not governed. The decision and assessment pointers have no
    # foreign keys yet, because their tables arrive in later migrations.
    f"""
    CREATE TABLE asset_governance_state (
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        asset_id uuid NOT NULL,
        status text NOT NULL CHECK (status IN ({STATUS_LIST})),
        version integer NOT NULL CHECK (version >= 1),
        current_profile_version_id uuid,
        latest_assessment_id uuid,
        current_decision_id uuid,
        hard_block_decision_id uuid,
        valid_until timestamptz,
        next_review_at timestamptz,
        updated_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (tenant_id, asset_id),
        FOREIGN KEY (tenant_id, asset_id) REFERENCES ai_assets (tenant_id, id),
        FOREIGN KEY (tenant_id, asset_id, current_profile_version_id)
            REFERENCES asset_profile_versions (tenant_id, asset_id, id)
    )
    """,
    "CREATE INDEX asset_governance_state_status_idx ON asset_governance_state (tenant_id, status)",
    """
    CREATE INDEX asset_governance_state_review_idx
    ON asset_governance_state (tenant_id, next_review_at) WHERE next_review_at IS NOT NULL
    """,
    # The same table as engine/lifecycle.py. A test compares the two for every pair.
    """
    CREATE FUNCTION aegis_governance_state_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
    BEGIN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'governance state cannot be deleted' USING ERRCODE = '42501';
        END IF;
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'DRAFT' OR NEW.version <> 1
               OR NEW.hard_block_decision_id IS NOT NULL THEN
                RAISE EXCEPTION 'governance state must start DRAFT at version 1 with no block'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.tenant_id <> OLD.tenant_id OR NEW.asset_id <> OLD.asset_id THEN
            RAISE EXCEPTION 'governance state tenant and asset are immutable'
                USING ERRCODE = '42501';
        END IF;
        IF NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'governance state version must advance by one'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.status <> OLD.status AND NOT (
            (OLD.status = 'DRAFT'
                AND NEW.status IN ('ASSESSMENT_REQUIRED', 'SUSPENDED', 'RETIRED'))
            OR (OLD.status = 'ASSESSMENT_REQUIRED'
                AND NEW.status IN ('UNDER_REVIEW', 'SUSPENDED', 'RETIRED'))
            OR (OLD.status = 'UNDER_REVIEW' AND NEW.status IN (
                'APPROVED', 'CONDITIONALLY_APPROVED', 'REJECTED', 'SUSPENDED', 'RETIRED'))
            OR (OLD.status IN ('APPROVED', 'CONDITIONALLY_APPROVED')
                AND NEW.status IN ('REASSESSMENT_REQUIRED', 'SUSPENDED', 'RETIRED'))
            OR (OLD.status = 'REJECTED' AND NEW.status IN ('ASSESSMENT_REQUIRED', 'RETIRED'))
            OR (OLD.status = 'SUSPENDED' AND NEW.status IN ('REASSESSMENT_REQUIRED', 'RETIRED'))
            OR (OLD.status = 'REASSESSMENT_REQUIRED'
                AND NEW.status IN ('UNDER_REVIEW', 'SUSPENDED', 'RETIRED'))
        ) THEN
            RAISE EXCEPTION 'invalid governance transition % to %', OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
        -- A human block is lifted only by the update that approves the asset.
        IF OLD.hard_block_decision_id IS NOT NULL AND NEW.hard_block_decision_id IS NULL
           AND NEW.status NOT IN ('APPROVED', 'CONDITIONALLY_APPROVED') THEN
            RAISE EXCEPTION 'the hard block can be cleared only by an approval'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER asset_governance_state_guard
    BEFORE INSERT OR UPDATE OR DELETE ON asset_governance_state
    FOR EACH ROW EXECUTE FUNCTION aegis_governance_state_guard()
    """,
    """
    CREATE TRIGGER asset_governance_state_reject_truncate BEFORE TRUNCATE ON asset_governance_state
    FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_mutation()
    """,
    """
    CREATE TRIGGER asset_profile_versions_reject_row_mutation
    BEFORE UPDATE OR DELETE ON asset_profile_versions
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_mutation()
    """,
    """
    CREATE TRIGGER asset_profile_versions_reject_truncate BEFORE TRUNCATE ON asset_profile_versions
    FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_mutation()
    """,
    *(
        statement
        for table in ("asset_profile_versions", "asset_governance_state")
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
    "GRANT SELECT, INSERT ON asset_profile_versions TO aegis_app",
    "GRANT SELECT, INSERT ON asset_governance_state TO aegis_app",
    """
    GRANT UPDATE (
        status, version, current_profile_version_id, latest_assessment_id, current_decision_id,
        hard_block_decision_id, valid_until, next_review_at, updated_at
    ) ON asset_governance_state TO aegis_app
    """,
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("Downgrading would destroy governance records; restore from backup")
