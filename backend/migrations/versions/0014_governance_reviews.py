"""Review scheduling: how the review worker finds tenants with a due review, with no tenant context.

Revision ID: 0014
Revises: 0013
"""

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

# The third deliberate SECURITY DEFINER exception (spec 13). It returns tenant IDs only, and the
# owner policy exposes only rows that carry a review date, as aegis_tenants_with_pending_events is
# limited to unprocessed events. A row has a review date only while an approval stands.
STATEMENTS = [
    """
    CREATE POLICY owner_finds_due_reviews ON asset_governance_state FOR SELECT TO aegis_owner
    USING (next_review_at IS NOT NULL)
    """,
    """
    CREATE FUNCTION aegis_tenants_with_due_governance_reviews(p_now timestamptz)
    RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
        SELECT DISTINCT tenant_id FROM public.asset_governance_state
        WHERE status IN ('APPROVED', 'CONDITIONALLY_APPROVED')
          AND next_review_at IS NOT NULL
          AND (next_review_at <= p_now OR valid_until <= p_now)
    $$
    """,
    "REVOKE ALL ON FUNCTION aegis_tenants_with_due_governance_reviews(timestamptz) FROM PUBLIC",
    "GRANT EXECUTE ON FUNCTION aegis_tenants_with_due_governance_reviews(timestamptz) TO aegis_app",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("Downgrading would remove a reviewed exception; restore from backup")
