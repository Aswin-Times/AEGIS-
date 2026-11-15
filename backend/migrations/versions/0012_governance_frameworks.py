"""Framework libraries, their controls, and append-only control assessments.

Revision ID: 0012
Revises: 0011
"""

from alembic import op

revision = "0012"
down_revision = "0011"
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
CATEGORY_ARRAY = "ARRAY[" + ", ".join(f"'{category}'" for category in CATEGORIES) + "]::text[]"

TABLES = ("governance_frameworks", "governance_controls", "governance_control_assessments",
          "governance_control_assessment_evidence")

STATEMENTS = [
    # Libraries are seeded per tenant, once: the key and version are unique within a tenant.
    # A loaded library, whole or partial, must say how many identifiers its source defines, so
    # coverage is always shown against the source.
    """
    CREATE TABLE governance_frameworks (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        key text NOT NULL CHECK (key ~ '^[a-z0-9_]{1,64}$'),
        version text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 32),
        name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
        source_url text CHECK (source_url ~ '^https://\\S+$' AND char_length(source_url) <= 2048),
        source_document text NOT NULL CHECK (char_length(source_document) BETWEEN 1 AND 500),
        library_status text NOT NULL CONSTRAINT governance_frameworks_library_status_known
            CHECK (library_status IN ('NOT_LOADED', 'LOADED_PARTIAL', 'LOADED')),
        source_control_count integer CHECK (source_control_count >= 0),
        created_at timestamptz NOT NULL,
        CONSTRAINT governance_frameworks_loaded_counts_source CHECK (
            library_status = 'NOT_LOADED' OR source_control_count IS NOT NULL
        ),
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, key, version)
    )
    """,
    f"""
    CREATE TABLE governance_controls (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        framework_id uuid NOT NULL,
        position integer NOT NULL CHECK (position >= 1),
        control_identifier text NOT NULL
            CHECK (char_length(control_identifier) BETWEEN 1 AND 64),
        name text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
        description text NOT NULL CHECK (char_length(btrim(description)) BETWEEN 1 AND 2000),
        source_reference text NOT NULL CHECK (char_length(source_reference) BETWEEN 1 AND 500),
        required_evidence text[] NOT NULL CONSTRAINT governance_controls_evidence_known CHECK (
            cardinality(required_evidence) >= 1 AND required_evidence <@ {CATEGORY_ARRAY}
        ),
        policy_id uuid,
        created_at timestamptz NOT NULL,
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, framework_id, control_identifier),
        FOREIGN KEY (tenant_id, framework_id) REFERENCES governance_frameworks (tenant_id, id),
        FOREIGN KEY (tenant_id, policy_id) REFERENCES governance_policies (tenant_id, id)
    )
    """,
    "CREATE INDEX governance_controls_framework_idx ON governance_controls "
    "(tenant_id, framework_id, position)",
    # A library that is not loaded claims no controls, whoever writes the row.
    """
    CREATE FUNCTION aegis_control_library_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
    BEGIN
        IF (
            SELECT library_status FROM public.governance_frameworks
            WHERE tenant_id = NEW.tenant_id AND id = NEW.framework_id
        ) = 'NOT_LOADED' THEN
            RAISE EXCEPTION 'controls cannot be added to a framework whose library is not loaded'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER governance_controls_library_guard
    BEFORE INSERT ON governance_controls
    FOR EACH ROW EXECUTE FUNCTION aegis_control_library_guard()
    """,
    # The link table of 0011 was left without this key until the controls existed.
    """
    ALTER TABLE governance_evidence_controls
    ADD CONSTRAINT governance_evidence_controls_control_fkey
    FOREIGN KEY (tenant_id, control_id) REFERENCES governance_controls (tenant_id, id)
    """,
    "CREATE INDEX governance_evidence_controls_control_idx ON governance_evidence_controls "
    "(tenant_id, control_id)",
    # NOT_ASSESSED and EVIDENCE_REQUIRED are never stored: the first is the absence of a row, the
    # second is what a stored claim reads as once its evidence no longer verifies. "Current" is
    # the latest row by the audit sequence of the audit event named here.
    """
    CREATE TABLE governance_control_assessments (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        control_id uuid NOT NULL,
        status text NOT NULL CONSTRAINT governance_control_assessments_status_known CHECK (
            status IN ('IMPLEMENTED', 'PARTIALLY_IMPLEMENTED', 'NOT_IMPLEMENTED',
                       'NOT_APPLICABLE')
        ),
        note text NOT NULL CHECK (char_length(btrim(note)) BETWEEN 1 AND 2000),
        assessed_by uuid NOT NULL,
        assessed_at timestamptz NOT NULL,
        audit_event_id uuid NOT NULL,
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, control_id, id),
        FOREIGN KEY (tenant_id, control_id) REFERENCES governance_controls (tenant_id, id),
        FOREIGN KEY (tenant_id, assessed_by) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, audit_event_id) REFERENCES audit_events (tenant_id, id)
    )
    """,
    "CREATE INDEX governance_control_assessments_control_idx ON governance_control_assessments "
    "(tenant_id, control_id)",
    # A claim of implementation needs, at the moment it is made, evidence linked to the control
    # whose latest verification by audit sequence is VERIFIED. Reads apply the same rule later.
    """
    CREATE FUNCTION aegis_control_assessment_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
    BEGIN
        IF NEW.status IN ('IMPLEMENTED', 'PARTIALLY_IMPLEMENTED') AND NOT EXISTS (
            SELECT 1 FROM public.governance_evidence_controls link
            WHERE link.tenant_id = NEW.tenant_id AND link.control_id = NEW.control_id
              AND (
                  SELECT verification.outcome
                  FROM public.governance_evidence_verifications verification
                  JOIN public.audit_events event
                    ON event.tenant_id = verification.tenant_id
                   AND event.id = verification.audit_event_id
                  WHERE verification.tenant_id = link.tenant_id
                    AND verification.evidence_id = link.evidence_id
                  ORDER BY event.seq DESC
                  LIMIT 1
              ) = 'VERIFIED'
        ) THEN
            RAISE EXCEPTION 'a status claiming implementation needs verified evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER governance_control_assessments_evidence_guard
    BEFORE INSERT ON governance_control_assessments
    FOR EACH ROW EXECUTE FUNCTION aegis_control_assessment_guard()
    """,
    # Evidence an assessment cites. The second key makes "linked to this control" a database
    # rule: the pair must be a row of governance_evidence_controls.
    """
    CREATE TABLE governance_control_assessment_evidence (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        assessment_id uuid NOT NULL,
        control_id uuid NOT NULL,
        evidence_id uuid NOT NULL,
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, assessment_id, evidence_id),
        FOREIGN KEY (tenant_id, control_id, assessment_id)
            REFERENCES governance_control_assessments (tenant_id, control_id, id),
        FOREIGN KEY (tenant_id, evidence_id, control_id)
            REFERENCES governance_evidence_controls (tenant_id, evidence_id, control_id)
    )
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
