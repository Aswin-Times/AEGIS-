"""Security events: a minimal, append-only projection of the audit chain.

Revision ID: 0002
Revises: 0001
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

STATEMENTS = [
    "ALTER TABLE audit_events ADD CONSTRAINT audit_events_tenant_id_id_key UNIQUE (tenant_id, id)",
    """
    CREATE TABLE security_events (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        schema_version integer NOT NULL CHECK (schema_version >= 1),
        event_type text NOT NULL,
        occurred_at timestamptz NOT NULL,
        recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        actor_type text NOT NULL
            CHECK (actor_type IN ('user', 'agent', 'system', 'anonymous')),
        actor_id uuid,
        asset_id uuid,
        agent_id uuid,
        action_request_id uuid,
        tool text CHECK (tool ~ '^[a-z][a-z0-9_]{0,63}$'),
        action text CHECK (action IN ('read', 'compute', 'transmit')),
        resource_id uuid,
        decision_id uuid,
        approval_id uuid,
        execution_id uuid,
        correlation_id uuid,
        severity text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
        reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
        attributes jsonb NOT NULL DEFAULT '{}'::jsonb
            CHECK (jsonb_typeof(attributes) = 'object'),
        source_audit_event_id uuid NOT NULL,
        source_event_hash text NOT NULL CHECK (source_event_hash ~ '^[0-9a-f]{64}$'),
        correlation_processed_at timestamptz,
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, source_audit_event_id),
        FOREIGN KEY (tenant_id, source_audit_event_id) REFERENCES audit_events (tenant_id, id),
        FOREIGN KEY (tenant_id, asset_id) REFERENCES ai_assets (tenant_id, id),
        FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
        FOREIGN KEY (tenant_id, action_request_id) REFERENCES action_requests (tenant_id, id),
        FOREIGN KEY (tenant_id, decision_id) REFERENCES policy_decisions (tenant_id, id),
        FOREIGN KEY (tenant_id, approval_id) REFERENCES approvals (tenant_id, id),
        FOREIGN KEY (tenant_id, execution_id) REFERENCES executions (tenant_id, id)
    )
    """,
    "CREATE INDEX security_events_recent_idx ON security_events (tenant_id, occurred_at DESC)",
    """
    CREATE INDEX security_events_agent_idx
    ON security_events (tenant_id, agent_id, occurred_at DESC)
    """,
    """
    CREATE INDEX security_events_pending_idx ON security_events (tenant_id, occurred_at, id)
    WHERE correlation_processed_at IS NULL
    """,
    """
    CREATE FUNCTION aegis_security_event_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
    BEGIN
        IF TG_OP <> 'UPDATE' THEN
            RAISE EXCEPTION 'security events are append-only' USING ERRCODE = '42501';
        END IF;
        IF OLD.correlation_processed_at IS NOT NULL
           OR NEW.correlation_processed_at IS NULL
           OR (to_jsonb(NEW) - 'correlation_processed_at')
              <> (to_jsonb(OLD) - 'correlation_processed_at') THEN
            RAISE EXCEPTION 'only the processing marker may change, once'
                USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER security_events_guard BEFORE UPDATE OR DELETE ON security_events
    FOR EACH ROW EXECUTE FUNCTION aegis_security_event_guard()
    """,
    """
    CREATE TRIGGER security_events_reject_truncate BEFORE TRUNCATE ON security_events
    FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_mutation()
    """,
    "ALTER TABLE security_events ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE security_events FORCE ROW LEVEL SECURITY",
    """
    CREATE POLICY tenant_isolation ON security_events
    USING (tenant_id = aegis_current_tenant())
    WITH CHECK (tenant_id = aegis_current_tenant())
    """,
    "GRANT SELECT, INSERT ON security_events TO aegis_app",
    "GRANT UPDATE (correlation_processed_at) ON security_events TO aegis_app",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("Downgrading would destroy security evidence; restore from backup")
