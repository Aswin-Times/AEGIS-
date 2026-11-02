"""Correlation rule versions, incidents, event links, and incident history.

Revision ID: 0003
Revises: 0002
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

TABLES = [
    """
    CREATE TABLE correlation_rule_versions (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        rule_key text NOT NULL CHECK (rule_key ~ '^[a-z][a-z0-9_]{1,63}$'),
        version integer NOT NULL CHECK (version >= 1),
        definition_canonical text NOT NULL,
        content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
        created_by uuid,
        created_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, rule_key, version),
        FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
    )
    """,
    """
    CREATE TABLE incidents (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        rule_version_id uuid NOT NULL,
        rule_key text NOT NULL,
        rule_version integer NOT NULL,
        scope_type text NOT NULL CHECK (scope_type IN ('agent', 'actor', 'tenant')),
        scope_key text NOT NULL,
        agent_id uuid,
        title text NOT NULL,
        severity text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
        status text NOT NULL
            CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'CLOSED')),
        version integer NOT NULL CHECK (version >= 1),
        event_count integer NOT NULL CHECK (event_count >= 0),
        first_observed_at timestamptz NOT NULL,
        last_observed_at timestamptz NOT NULL,
        assigned_to uuid,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, id),
        CHECK (first_observed_at <= last_observed_at),
        FOREIGN KEY (tenant_id, rule_version_id)
            REFERENCES correlation_rule_versions (tenant_id, id),
        FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
        FOREIGN KEY (tenant_id, assigned_to) REFERENCES users (tenant_id, id)
    )
    """,
    """
    CREATE UNIQUE INDEX incidents_one_active ON incidents (tenant_id, rule_key, scope_key)
    WHERE status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING')
    """,
    "CREATE INDEX incidents_queue_idx ON incidents (tenant_id, status, last_observed_at DESC)",
    """
    CREATE TABLE incident_events (
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        incident_id uuid NOT NULL,
        event_id uuid NOT NULL,
        linked_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (tenant_id, incident_id, event_id),
        FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id),
        FOREIGN KEY (tenant_id, event_id) REFERENCES security_events (tenant_id, id)
    )
    """,
    "CREATE INDEX incident_events_event_idx ON incident_events (tenant_id, event_id)",
    """
    CREATE TABLE incident_transitions (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        incident_id uuid NOT NULL,
        from_status text,
        to_status text NOT NULL,
        actor_type text NOT NULL CHECK (actor_type IN ('user', 'system')),
        actor_id uuid,
        reason text,
        occurred_at timestamptz NOT NULL,
        audit_event_id uuid NOT NULL,
        UNIQUE (tenant_id, id),
        FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id),
        FOREIGN KEY (tenant_id, actor_id) REFERENCES users (tenant_id, id),
        FOREIGN KEY (tenant_id, audit_event_id) REFERENCES audit_events (tenant_id, id)
    )
    """,
    """
    CREATE INDEX incident_transitions_incident_idx
    ON incident_transitions (tenant_id, incident_id, occurred_at)
    """,
]

GUARDS = [
    """
    CREATE FUNCTION aegis_incident_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
    AS $$
    BEGIN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'incidents cannot be deleted' USING ERRCODE = '42501';
        END IF;
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'OPEN' OR NEW.version <> 1 THEN
                RAISE EXCEPTION 'an incident must start OPEN at version 1'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
           OR NEW.rule_version_id <> OLD.rule_version_id OR NEW.rule_key <> OLD.rule_key
           OR NEW.rule_version <> OLD.rule_version OR NEW.scope_type <> OLD.scope_type
           OR NEW.scope_key <> OLD.scope_key OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
           OR NEW.title <> OLD.title OR NEW.severity <> OLD.severity
           OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'incident identity and severity are immutable'
                USING ERRCODE = '42501';
        END IF;
        IF NEW.status = OLD.status THEN
            IF NEW.version <> OLD.version THEN
                RAISE EXCEPTION 'version changes only with status' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'version must advance with status' USING ERRCODE = '23514';
        END IF;
        IF NOT (
            (OLD.status = 'OPEN' AND NEW.status IN ('ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED'))
            OR (OLD.status = 'ACKNOWLEDGED' AND NEW.status IN ('INVESTIGATING', 'RESOLVED'))
            OR (OLD.status = 'INVESTIGATING' AND NEW.status = 'RESOLVED')
            OR (OLD.status = 'RESOLVED' AND NEW.status IN ('CLOSED', 'INVESTIGATING'))
        ) THEN
            RAISE EXCEPTION 'invalid incident transition % to %', OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER incidents_guard BEFORE INSERT OR UPDATE OR DELETE ON incidents
    FOR EACH ROW EXECUTE FUNCTION aegis_incident_guard()
    """,
    """
    CREATE TRIGGER incidents_reject_truncate BEFORE TRUNCATE ON incidents
    FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_mutation()
    """,
    *(
        statement
        for table in ("correlation_rule_versions", "incident_events", "incident_transitions")
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
]

ROW_LEVEL_SECURITY = [
    statement
    for table in (
        "correlation_rule_versions",
        "incidents",
        "incident_events",
        "incident_transitions",
    )
    for statement in (
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"""
        CREATE POLICY tenant_isolation ON {table}
        USING (tenant_id = aegis_current_tenant())
        WITH CHECK (tenant_id = aegis_current_tenant())
        """,
    )
]

# The correlation worker must find work without a tenant context. This returns tenant IDs only,
# and the owner policy exposes only unprocessed rows, the same way aegis_resolve_tenant is limited.
PENDING_TENANTS = [
    """
    CREATE POLICY owner_finds_pending ON security_events FOR SELECT TO aegis_owner
    USING (correlation_processed_at IS NULL)
    """,
    """
    CREATE FUNCTION aegis_tenants_with_pending_events() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
        SELECT DISTINCT tenant_id FROM public.security_events
        WHERE correlation_processed_at IS NULL
    $$
    """,
    "REVOKE ALL ON FUNCTION aegis_tenants_with_pending_events() FROM PUBLIC",
    "GRANT EXECUTE ON FUNCTION aegis_tenants_with_pending_events() TO aegis_app",
]

GRANTS = [
    "GRANT SELECT, INSERT ON correlation_rule_versions TO aegis_app",
    "GRANT SELECT, INSERT ON incidents TO aegis_app",
    """
    GRANT UPDATE (status, version, event_count, first_observed_at, last_observed_at,
                  assigned_to, updated_at)
    ON incidents TO aegis_app
    """,
    "GRANT SELECT, INSERT ON incident_events TO aegis_app",
    "GRANT SELECT, INSERT ON incident_transitions TO aegis_app",
]


def upgrade() -> None:
    for group in (TABLES, GUARDS, ROW_LEVEL_SECURITY, PENDING_TENANTS, GRANTS):
        for statement in group:
            op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("Downgrading would destroy incident evidence; restore from backup")
