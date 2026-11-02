"""Investigation runs and findings, where a verified claim cannot exist without real evidence.

Revision ID: 0004
Revises: 0003
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

STATEMENTS = [
    """
    CREATE TABLE investigation_runs (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        incident_id uuid NOT NULL,
        started_by uuid,
        engine_version integer NOT NULL CHECK (engine_version >= 1),
        input_fingerprint text NOT NULL CHECK (input_fingerprint ~ '^[0-9a-f]{64}$'),
        llm_status text NOT NULL CHECK (llm_status IN (
            'not_configured', 'pending', 'succeeded', 'timeout', 'failed', 'invalid_output'
        )),
        llm_provider text,
        llm_model text,
        llm_rejected_count integer NOT NULL CHECK (llm_rejected_count >= 0),
        llm_finished_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id),
        FOREIGN KEY (tenant_id, started_by) REFERENCES users (tenant_id, id)
    )
    """,
    """
    CREATE INDEX investigation_runs_incident_idx
    ON investigation_runs (tenant_id, incident_id, created_at DESC)
    """,
    # Only the LLM can write a hypothesis, and the LLM can write nothing else.
    """
    CREATE TABLE investigation_findings (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        run_id uuid NOT NULL,
        kind text NOT NULL CHECK (kind IN (
            'observed_fact', 'rule_result', 'ai_hypothesis', 'evidence_gap', 'recommended_action'
        )),
        source text NOT NULL CHECK (source IN ('deterministic', 'llm')),
        statement text NOT NULL CHECK (length(statement) BETWEEN 1 AND 2000),
        confidence text CHECK (confidence IN ('low', 'medium', 'high')),
        position integer NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        CHECK ((source = 'llm') = (kind = 'ai_hypothesis')),
        FOREIGN KEY (tenant_id, run_id) REFERENCES investigation_runs (tenant_id, id)
    )
    """,
    """
    CREATE INDEX investigation_findings_run_idx
    ON investigation_findings (tenant_id, run_id, position)
    """,
    # One real foreign key per record type, so a reference cannot point at a nonexistent record
    # or at another tenant's.
    """
    CREATE TABLE finding_evidence (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        finding_id uuid NOT NULL,
        security_event_id uuid,
        decision_id uuid,
        approval_id uuid,
        execution_id uuid,
        audit_event_id uuid,
        UNIQUE (tenant_id, id),
        CHECK (num_nonnulls(
            security_event_id, decision_id, approval_id, execution_id, audit_event_id
        ) = 1),
        FOREIGN KEY (tenant_id, finding_id) REFERENCES investigation_findings (tenant_id, id),
        FOREIGN KEY (tenant_id, security_event_id) REFERENCES security_events (tenant_id, id),
        FOREIGN KEY (tenant_id, decision_id) REFERENCES policy_decisions (tenant_id, id),
        FOREIGN KEY (tenant_id, approval_id) REFERENCES approvals (tenant_id, id),
        FOREIGN KEY (tenant_id, execution_id) REFERENCES executions (tenant_id, id),
        FOREIGN KEY (tenant_id, audit_event_id) REFERENCES audit_events (tenant_id, id)
    )
    """,
    "CREATE INDEX finding_evidence_finding_idx ON finding_evidence (tenant_id, finding_id)",
    """
    CREATE FUNCTION aegis_finding_requires_evidence() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
    BEGIN
        IF NEW.kind IN ('observed_fact', 'rule_result', 'ai_hypothesis') AND NOT EXISTS (
            SELECT 1 FROM public.finding_evidence
            WHERE tenant_id = NEW.tenant_id AND finding_id = NEW.id
        ) THEN
            RAISE EXCEPTION 'a % finding requires evidence', NEW.kind USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END
    $$
    """,
    """
    CREATE CONSTRAINT TRIGGER investigation_findings_require_evidence
    AFTER INSERT ON investigation_findings
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION aegis_finding_requires_evidence()
    """,
    *(
        statement
        for table in ("investigation_findings", "finding_evidence")
        for statement in (
            f"""
            CREATE TRIGGER {table}_reject_row_mutation BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION aegis_reject_mutation()
            """,
            f"""
            CREATE TRIGGER {table}_reject_truncate BEFORE TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_mutation()
            """,
        )
    ),
    """
    CREATE TRIGGER investigation_runs_reject_delete BEFORE DELETE ON investigation_runs
    FOR EACH ROW EXECUTE FUNCTION aegis_reject_mutation()
    """,
    """
    CREATE TRIGGER investigation_runs_reject_truncate BEFORE TRUNCATE ON investigation_runs
    FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_mutation()
    """,
    *(
        statement
        for table in ("investigation_runs", "investigation_findings", "finding_evidence")
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
    "GRANT SELECT, INSERT ON investigation_runs TO aegis_app",
    """
    GRANT UPDATE (llm_status, llm_provider, llm_model, llm_rejected_count, llm_finished_at)
    ON investigation_runs TO aegis_app
    """,
    "GRANT SELECT, INSERT ON investigation_findings TO aegis_app",
    "GRANT SELECT, INSERT ON finding_evidence TO aegis_app",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("Downgrading would destroy investigations; restore from backup")
