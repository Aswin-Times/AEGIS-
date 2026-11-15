"""RETIRED is terminal: the state guard now refuses every update of a retired row.

Revision ID: 0010
Revises: 0009
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

STATEMENTS = [
    # The function of 0006 with one check added. Before it, only a change of status was refused
    # for a retired row, so an update that left the status alone still went through.
    """
    CREATE OR REPLACE FUNCTION aegis_governance_state_guard() RETURNS trigger
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
        IF OLD.status = 'RETIRED' THEN
            RAISE EXCEPTION 'a retired asset cannot change' USING ERRCODE = '23514';
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
        -- A human block is lifted only by the update that moves the asset into an approval.
        IF OLD.hard_block_decision_id IS NOT NULL AND NEW.hard_block_decision_id IS NULL
           AND (NEW.status = OLD.status
                OR NEW.status NOT IN ('APPROVED', 'CONDITIONALLY_APPROVED')) THEN
            RAISE EXCEPTION 'the hard block can be cleared only by an approval'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END
    $$
    """,
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("Downgrading would weaken a guard; restore from backup")
