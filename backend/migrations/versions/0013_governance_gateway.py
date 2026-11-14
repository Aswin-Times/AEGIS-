"""Gateway checks: one append-only row per policy decision, recording the governance verdict.

Revision ID: 0013
Revises: 0012
"""

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

STATUSES = ("DRAFT", "ASSESSMENT_REQUIRED", "UNDER_REVIEW", "APPROVED", "CONDITIONALLY_APPROVED",
            "REJECTED", "SUSPENDED", "REASSESSMENT_REQUIRED", "RETIRED")
STATUS_LIST = ", ".join(f"'{status}'" for status in STATUSES)

STATEMENTS = [
    # One row per policy decision, written in the decision's own transaction. A null observed
    # status means the asset had no governance state. The asset is null only if the check
    # could not tell which asset the agent belongs to.
    f"""
    CREATE TABLE governance_gateway_checks (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        decision_id uuid NOT NULL,
        request_id uuid NOT NULL,
        agent_id uuid NOT NULL,
        asset_id uuid,
        mode text NOT NULL CHECK (mode IN ('observe', 'enforce')),
        observed_status text CHECK (observed_status IN ({STATUS_LIST})),
        verdict text NOT NULL
            CHECK (verdict IN ('PASS', 'RECORDED_DENY', 'RECORDED_HOLD', 'DENY', 'HOLD')),
        reason_code text CHECK (reason_code ~ '^GOVERNANCE_[A-Z_]{{1,52}}$'),
        governance_decision_id uuid,
        checked_at timestamptz NOT NULL,
        CONSTRAINT governance_gateway_checks_reason_matches_verdict
            CHECK ((verdict = 'PASS') = (reason_code IS NULL)),
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, decision_id),
        FOREIGN KEY (tenant_id, decision_id) REFERENCES policy_decisions (tenant_id, id),
        FOREIGN KEY (tenant_id, request_id) REFERENCES action_requests (tenant_id, id),
        FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
        FOREIGN KEY (tenant_id, asset_id) REFERENCES ai_assets (tenant_id, id),
        FOREIGN KEY (tenant_id, governance_decision_id)
            REFERENCES governance_decisions (tenant_id, id)
    )
    """,
    # Preflight counts recent checks per asset.
    "CREATE INDEX governance_gateway_checks_asset_idx ON governance_gateway_checks "
    "(tenant_id, asset_id, checked_at)",
    "CREATE INDEX governance_gateway_checks_request_idx ON governance_gateway_checks "
    "(tenant_id, request_id)",
    """
    CREATE TRIGGER governance_gateway_checks_reject_row_mutation
    BEFORE UPDATE OR DELETE ON governance_gateway_checks
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_mutation()
    """,
    """
    CREATE TRIGGER governance_gateway_checks_reject_truncate
    BEFORE TRUNCATE ON governance_gateway_checks
    FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_mutation()
    """,
    "ALTER TABLE governance_gateway_checks ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE governance_gateway_checks FORCE ROW LEVEL SECURITY",
    """
    CREATE POLICY tenant_isolation ON governance_gateway_checks
    USING (tenant_id = aegis_current_tenant())
    WITH CHECK (tenant_id = aegis_current_tenant())
    """,
    "GRANT SELECT, INSERT ON governance_gateway_checks TO aegis_app",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("Downgrading would destroy governance records; restore from backup")
