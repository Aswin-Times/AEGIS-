"""Governance evidence, its links to controls, and independent verification.

Revision ID: 0011
Revises: 0010
"""

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

CATEGORIES = (
    "risk_assessment",
    "security_evaluation",
    "architecture_documentation",
    "data_handling_documentation",
    "human_oversight_documentation",
    "model_evaluation",
    "approval_records",
    "monitoring_records",
    "incident_investigation_records",
    "periodic_review_records",
)
CATEGORY_LIST = ", ".join(f"'{category}'" for category in CATEGORIES)
# Under the 64 KB request limit, with room for the other fields of the request.
MAX_CONTENT_BYTES = 16000
RECORD_COLUMNS = "assessment_id, decision_id, audit_event_id, incident_id, investigation_run_id"

TABLES = ("governance_evidence", "governance_evidence_controls",
          "governance_evidence_verifications")

STATEMENTS = [
    # An internal record is named by exactly one of five composite foreign keys. The assessment and
    # the decision are tied to the evidence's own asset. The hash is the record's own: the result
    # hash of an assessment, or the event hash of a decision's audit event or of an audit event.
    # An incident or an investigation run has none, so verification can prove only that it exists.
    f"""
    CREATE TABLE governance_evidence (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        asset_id uuid NOT NULL,
        category text NOT NULL CONSTRAINT governance_evidence_category_known
            CHECK (category IN ({CATEGORY_LIST})),
        description text NOT NULL CONSTRAINT governance_evidence_description_present
            CHECK (char_length(btrim(description)) BETWEEN 1 AND 2000),
        source_type text NOT NULL CONSTRAINT governance_evidence_source_known
            CHECK (source_type IN ('internal_record', 'inline', 'external_reference')),
        submitted_by uuid NOT NULL,
        created_at timestamptz NOT NULL,
        content_sha256 text CHECK (content_sha256 ~ '^[0-9a-f]{{64}}$'),
        content_text text CHECK (octet_length(content_text) <= {MAX_CONTENT_BYTES}),
        source_uri text CHECK (char_length(source_uri) <= 2048),
        assessment_id uuid,
        decision_id uuid,
        audit_event_id uuid,
        incident_id uuid,
        investigation_run_id uuid,
        CONSTRAINT governance_evidence_source_shape CHECK (
            (source_type = 'inline'
                AND content_text IS NOT NULL AND content_sha256 IS NOT NULL
                AND source_uri IS NULL
                AND num_nonnulls({RECORD_COLUMNS}) = 0)
            OR (source_type = 'external_reference'
                AND source_uri IS NOT NULL AND content_sha256 IS NOT NULL
                AND content_text IS NULL
                AND num_nonnulls({RECORD_COLUMNS}) = 0)
            OR (source_type = 'internal_record'
                AND content_text IS NULL AND source_uri IS NULL
                AND num_nonnulls({RECORD_COLUMNS}) = 1
                AND ((content_sha256 IS NULL)
                     = (incident_id IS NOT NULL OR investigation_run_id IS NOT NULL)))
        ),
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, asset_id, id),
        FOREIGN KEY (tenant_id, asset_id) REFERENCES ai_assets (tenant_id, id),
        FOREIGN KEY (tenant_id, submitted_by) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, asset_id, assessment_id)
            REFERENCES risk_assessments (tenant_id, asset_id, id),
        FOREIGN KEY (tenant_id, asset_id, decision_id)
            REFERENCES governance_decisions (tenant_id, asset_id, id),
        FOREIGN KEY (tenant_id, audit_event_id) REFERENCES audit_events (tenant_id, id),
        FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id),
        FOREIGN KEY (tenant_id, investigation_run_id)
            REFERENCES investigation_runs (tenant_id, id)
    )
    """,
    "CREATE INDEX governance_evidence_asset_idx ON governance_evidence (tenant_id, asset_id)",
    "CREATE INDEX governance_evidence_category_idx ON governance_evidence (tenant_id, category)",
    # The foreign key to governance_controls is added with the control library.
    """
    CREATE TABLE governance_evidence_controls (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        evidence_id uuid NOT NULL,
        control_id uuid NOT NULL,
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, evidence_id, control_id),
        FOREIGN KEY (tenant_id, evidence_id) REFERENCES governance_evidence (tenant_id, id)
    )
    """,
    # "Current" is the latest row by audit sequence, which the audit event named here gives.
    """
    CREATE TABLE governance_evidence_verifications (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        evidence_id uuid NOT NULL,
        outcome text NOT NULL CONSTRAINT governance_evidence_verifications_outcome_known
            CHECK (outcome IN ('VERIFIED', 'REJECTED')),
        method text NOT NULL CONSTRAINT governance_evidence_verifications_method_known
            CHECK (method IN ('internal_record_checked', 'content_recomputed',
                              'manual_attestation')),
        note text NOT NULL CONSTRAINT governance_evidence_verifications_note_present
            CHECK (char_length(btrim(note)) BETWEEN 1 AND 2000),
        verified_by uuid NOT NULL,
        verified_at timestamptz NOT NULL,
        audit_event_id uuid NOT NULL,
        UNIQUE (tenant_id, id),
        FOREIGN KEY (tenant_id, evidence_id) REFERENCES governance_evidence (tenant_id, id),
        FOREIGN KEY (tenant_id, verified_by) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, audit_event_id) REFERENCES audit_events (tenant_id, id)
    )
    """,
    """
    CREATE INDEX governance_evidence_verifications_idx
    ON governance_evidence_verifications (tenant_id, evidence_id)
    """,
    # Whoever submitted evidence cannot verify it, whatever role the database user has.
    """
    CREATE FUNCTION aegis_evidence_verifier_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
    BEGIN
        IF NEW.verified_by = (
            SELECT submitted_by FROM public.governance_evidence
            WHERE tenant_id = NEW.tenant_id AND id = NEW.evidence_id
        ) THEN
            RAISE EXCEPTION 'evidence cannot be verified by its submitter'
                USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER governance_evidence_verifications_verifier_guard
    BEFORE INSERT ON governance_evidence_verifications
    FOR EACH ROW EXECUTE FUNCTION aegis_evidence_verifier_guard()
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
