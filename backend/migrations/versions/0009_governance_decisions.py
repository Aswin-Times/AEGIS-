"""Governance reviews and decisions, and the state pointers that wait for them.

Revision ID: 0009
Revises: 0008
"""

from alembic import op

revision = "0009"
down_revision = "0008"
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
KINDS = (
    "SUBMIT",
    "ASSIGN_REVIEWER",
    "REQUEST_INFORMATION",
    "APPROVAL_VOTE",
    "APPROVE",
    "APPROVE_CONDITIONAL",
    "REJECT",
    "SUSPEND",
    "REVOKE",
    "REQUIRE_REASSESSMENT",
    "RETIRE",
)
STATUS_LIST = ", ".join(f"'{status}'" for status in STATUSES)
KIND_LIST = ", ".join(f"'{kind}'" for kind in KINDS)

APPEND_ONLY = (
    "governance_decisions",
    "governance_decision_policy_versions",
    "governance_decision_evidence",
)
TABLES = ("governance_reviews", *APPEND_ONLY)

STATEMENTS = [
    # The frozen columns are what the policy engine asked for at submission. frozen_hash covers
    # them with the review's identity, and is checked wherever the review is read for a decision,
    # because a decision relies on the self-approval flag stored in required_controls_canonical.
    """
    CREATE TABLE governance_reviews (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        asset_id uuid NOT NULL,
        assessment_id uuid NOT NULL,
        profile_version_id uuid NOT NULL,
        submitted_by uuid NOT NULL,
        assigned_reviewer uuid,
        required_controls_canonical text NOT NULL,
        findings_canonical text NOT NULL,
        required_approvers integer NOT NULL
            CONSTRAINT governance_reviews_approvers_known CHECK (required_approvers IN (1, 2)),
        frozen_hash text NOT NULL CHECK (frozen_hash ~ '^[0-9a-f]{64}$'),
        status text NOT NULL CONSTRAINT governance_reviews_status_known
            CHECK (status IN ('OPEN', 'INFO_REQUESTED', 'DECIDED', 'WITHDRAWN')),
        version integer NOT NULL CHECK (version >= 1),
        submitted_at timestamptz NOT NULL,
        closed_at timestamptz,
        CONSTRAINT governance_reviews_closed_matches_status
            CHECK ((status IN ('DECIDED', 'WITHDRAWN')) = (closed_at IS NOT NULL)),
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, asset_id, id),
        FOREIGN KEY (tenant_id, asset_id) REFERENCES ai_assets (tenant_id, id),
        FOREIGN KEY (tenant_id, asset_id, assessment_id)
            REFERENCES risk_assessments (tenant_id, asset_id, id),
        FOREIGN KEY (tenant_id, asset_id, profile_version_id)
            REFERENCES asset_profile_versions (tenant_id, asset_id, id),
        FOREIGN KEY (tenant_id, submitted_by) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, assigned_reviewer) REFERENCES users (tenant_id, id)
    )
    """,
    # The duplicate-submission guard: one open review per asset.
    """
    CREATE UNIQUE INDEX governance_reviews_one_open ON governance_reviews (tenant_id, asset_id)
    WHERE status IN ('OPEN', 'INFO_REQUESTED')
    """,
    "CREATE INDEX governance_reviews_asset_idx ON governance_reviews (tenant_id, asset_id)",
    "CREATE INDEX governance_reviews_status_idx ON governance_reviews (tenant_id, status)",
    # Frozen content never changes, a closed review is final, and the version advances by one.
    """
    CREATE FUNCTION aegis_governance_review_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
    BEGIN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'governance reviews cannot be deleted' USING ERRCODE = '42501';
        END IF;
        IF ROW(NEW.id, NEW.tenant_id, NEW.asset_id, NEW.assessment_id, NEW.profile_version_id,
               NEW.submitted_by, NEW.required_controls_canonical, NEW.findings_canonical,
               NEW.required_approvers, NEW.frozen_hash, NEW.submitted_at)
           IS DISTINCT FROM
           ROW(OLD.id, OLD.tenant_id, OLD.asset_id, OLD.assessment_id, OLD.profile_version_id,
               OLD.submitted_by, OLD.required_controls_canonical, OLD.findings_canonical,
               OLD.required_approvers, OLD.frozen_hash, OLD.submitted_at) THEN
            RAISE EXCEPTION 'the frozen content of a governance review is immutable'
                USING ERRCODE = '42501';
        END IF;
        IF NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'governance review version must advance by one'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.status IN ('DECIDED', 'WITHDRAWN') THEN
            RAISE EXCEPTION 'a closed governance review cannot change' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER governance_reviews_guard BEFORE UPDATE OR DELETE ON governance_reviews
    FOR EACH ROW EXECUTE FUNCTION aegis_governance_review_guard()
    """,
    # Decisions are the record of who did what to an asset. The audit event is written first and
    # named here. UNIQUE (tenant_id, asset_id, id) lets the state row point only at a decision of
    # its own asset.
    f"""
    CREATE TABLE governance_decisions (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        asset_id uuid NOT NULL,
        review_id uuid,
        kind text NOT NULL CONSTRAINT governance_decisions_kind_known
            CHECK (kind IN ({KIND_LIST})),
        from_status text NOT NULL CONSTRAINT governance_decisions_from_known
            CHECK (from_status IN ({STATUS_LIST})),
        to_status text NOT NULL CONSTRAINT governance_decisions_to_known
            CHECK (to_status IN ({STATUS_LIST})),
        actor_type text NOT NULL CHECK (actor_type IN ('user', 'system')),
        decided_by uuid,
        decided_at timestamptz NOT NULL,
        reason text NOT NULL CONSTRAINT governance_decisions_reason_present
            CHECK (char_length(btrim(reason)) BETWEEN 1 AND 2000),
        assessment_id uuid,
        conditions_canonical text,
        conditions_hash text CHECK (conditions_hash ~ '^[0-9a-f]{{64}}$'),
        valid_until timestamptz,
        next_review_at timestamptz,
        audit_event_id uuid NOT NULL,
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, asset_id, id),
        CONSTRAINT governance_decisions_actor_matches
            CHECK ((actor_type = 'user') = (decided_by IS NOT NULL)),
        CONSTRAINT governance_decisions_system_scope
            CHECK (actor_type = 'user' OR kind = 'REQUIRE_REASSESSMENT'),
        CONSTRAINT governance_decisions_approval_complete
            CHECK (kind NOT IN ('APPROVE', 'APPROVE_CONDITIONAL')
                   OR (assessment_id IS NOT NULL AND valid_until IS NOT NULL
                       AND next_review_at IS NOT NULL)),
        CONSTRAINT governance_decisions_conditions_present
            CHECK (kind <> 'APPROVE_CONDITIONAL'
                   OR (conditions_canonical IS NOT NULL
                       AND conditions_canonical NOT IN ('[]', '{{}}', 'null'))),
        CONSTRAINT governance_decisions_conditions_hashed
            CHECK ((conditions_canonical IS NULL) = (conditions_hash IS NULL)),
        FOREIGN KEY (tenant_id, asset_id) REFERENCES ai_assets (tenant_id, id),
        FOREIGN KEY (tenant_id, asset_id, review_id)
            REFERENCES governance_reviews (tenant_id, asset_id, id),
        FOREIGN KEY (tenant_id, asset_id, assessment_id)
            REFERENCES risk_assessments (tenant_id, asset_id, id),
        FOREIGN KEY (tenant_id, decided_by) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, audit_event_id) REFERENCES audit_events (tenant_id, id)
    )
    """,
    "CREATE INDEX governance_decisions_asset_idx ON governance_decisions (tenant_id, asset_id)",
    "CREATE INDEX governance_decisions_review_idx ON governance_decisions (tenant_id, review_id)",
    # One person counts once on a review, whether as a vote or as the approval that closes it.
    """
    CREATE UNIQUE INDEX governance_decisions_one_vote
    ON governance_decisions (tenant_id, review_id, decided_by)
    WHERE kind IN ('APPROVAL_VOTE', 'APPROVE', 'APPROVE_CONDITIONAL')
    """,
    """
    CREATE TABLE governance_decision_policy_versions (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        decision_id uuid NOT NULL,
        policy_version_id uuid NOT NULL,
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, decision_id, policy_version_id),
        FOREIGN KEY (tenant_id, decision_id) REFERENCES governance_decisions (tenant_id, id),
        FOREIGN KEY (tenant_id, policy_version_id)
            REFERENCES governance_policy_versions (tenant_id, id)
    )
    """,
    # The evidence table arrives in a later migration, which adds its foreign key.
    """
    CREATE TABLE governance_decision_evidence (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        decision_id uuid NOT NULL,
        evidence_id uuid NOT NULL,
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, decision_id, evidence_id),
        FOREIGN KEY (tenant_id, decision_id) REFERENCES governance_decisions (tenant_id, id)
    )
    """,
    # The pointers left without a foreign key by 0006. Naming the asset as well as the decision
    # keeps a state row from pointing at another asset's decision.
    """
    ALTER TABLE asset_governance_state
    ADD CONSTRAINT asset_governance_state_decision_fkey
    FOREIGN KEY (tenant_id, asset_id, current_decision_id)
    REFERENCES governance_decisions (tenant_id, asset_id, id)
    """,
    """
    ALTER TABLE asset_governance_state
    ADD CONSTRAINT asset_governance_state_hard_block_fkey
    FOREIGN KEY (tenant_id, asset_id, hard_block_decision_id)
    REFERENCES governance_decisions (tenant_id, asset_id, id)
    """,
    *(
        statement
        for table in APPEND_ONLY
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
    CREATE TRIGGER governance_reviews_reject_truncate BEFORE TRUNCATE ON governance_reviews
    FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_mutation()
    """,
    *(
        statement
        for table in TABLES
        for statement in (
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
    "GRANT UPDATE (assigned_reviewer, status, version, closed_at) ON governance_reviews "
    "TO aegis_app",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("Downgrading would destroy governance records; restore from backup")
