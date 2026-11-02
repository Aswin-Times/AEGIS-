# AEGIS Database Design

PostgreSQL 16. All identifiers are UUIDs generated in the application. Timestamps are
`timestamptz`.

## Isolation rules, applied to every tenant table

1. A `tenant_id` column that is `NOT NULL`, with `UNIQUE (tenant_id, id)`.
2. Foreign keys to other tenant tables are **composite**: `(tenant_id, x_id)`. A row cannot reference another tenant's row, even if the application is wrong.
3. `ENABLE` and `FORCE ROW LEVEL SECURITY`, with `USING` and `WITH CHECK` on `tenant_id = aegis_current_tenant()`.
4. `aegis_current_tenant()` returns `NULLIF(current_setting('app.tenant_id', true), '')::uuid`, so a missing context matches no rows.

## Entities

```
tenants 1--* users
        1--* ai_assets 1--* agents 1--* agent_credentials
                                  1--* agent_tool_grants
                                  1--* agent_resource_grants *--1 resources
        1--* policies 1--* policy_versions
        1--* action_requests *--1 agents
                 1--* policy_decisions *--1 policy_versions (nullable)
                 1--0..1 approvals
                 1--0..1 executions
        1--* simulated_outbox
        1--1 audit_chain_heads
        1--* audit_events
```

## Milestone 1 tables

| Table | Key columns | Notes |
|-------|-------------|-------|
| `tenants` | `id`, `slug` unique, `name`, `active_policy_id` | RLS: `id = aegis_current_tenant()` |
| `users` | `email` unique per tenant, `password_hash`, `role`, `is_active` | Role is checked by `CHECK` |
| `ai_assets` | `name`, `owner`, `risk_classification`, `intended_use`, `is_synthetic` | |
| `agents` | `asset_id`, `name` unique per tenant, `owner`, `status` | |
| `agent_credentials` | `agent_id`, `secret_hash`, `expires_at`, `revoked_at` | Plaintext is never stored |
| `resources` | `kind`, `name`, `classification`, `clearance`, `content` jsonb, `is_synthetic` | |
| `agent_tool_grants` | `agent_id`, `tool` | PK `(tenant_id, agent_id, tool)` |
| `agent_resource_grants` | `agent_id`, `resource_id` | PK `(tenant_id, agent_id, resource_id)` |
| `policies` | `name` unique per tenant, `active_version_id` | |
| `policy_versions` | `policy_id`, `version`, `document`, `content_hash`, `created_by` | Immutable by trigger |
| `action_requests` | `agent_id`, `idempotency_key`, `tool`, `action`, `resource_id`, `params`, `action_hash`, `status` | `UNIQUE (tenant_id, agent_id, idempotency_key)` |
| `policy_decisions` | `request_id`, `agent_id`, `resource_id`, `tool`, `action`, `policy_version_id`, `policy_version`, `outcome`, `reason_code`, `matched_rule_id`, `evaluated_at`, `evidence` | Append-only |
| `approvals` | `request_id` unique, `decision_id`, `action_hash`, `status`, `expires_at`, `decided_by`, `decided_at`, `comment` | Transition trigger |
| `executions` | `request_id` unique, `status`, `result`, `started_at`, `finished_at` | Unique constraint prevents re-execution |
| `simulated_outbox` | `request_id` unique, `destination_id`, `body`, `attachment_resource_id` | Synthetic sink |
| `audit_chain_heads` | `tenant_id` PK, `seq`, `head_hash` | Row lock serializes appends per tenant |
| `audit_events` | `id`, `seq`, `prev_hash`, `event_hash`, `event_type`, `actor_type`, `actor_id`, `correlation_id`, `subject_type`, `subject_id`, `policy_version_id`, `occurred_at`, `payload` | `UNIQUE (tenant_id, seq)`; append-only |

## Deferred tables (Phase 4)

`security_events`, `incidents`, `incident_events`, `incident_findings`,
`governance_assessments`. `incident_findings` will distinguish `kind` values
(`observed_fact`, `deterministic_finding`, `ai_hypothesis`, `unverified_assumption`,
`recommended_action`). A fact must reference an event through a real foreign key.

`users.role` is a single fixed role. A roles-and-permissions table has no use until
custom roles are a requirement (`DECISIONS.md` D-009).

## Database-level enforcement

| Trigger | Table | Rule |
|---------|-------|------|
| `aegis_reject_mutation` | `audit_events`, `policy_decisions`, `policy_versions` | Rejects `UPDATE` and `DELETE`. A statement-level trigger rejects `TRUNCATE` |
| `aegis_approval_transition` | `approvals` | Allows only: `PENDING -> APPROVED, REJECTED, CANCELLED`, and `APPROVED -> EXECUTED, CANCELLED`. Forbids changing binding columns (`request_id`, `action_hash`, `decision_id`). Forbids `DELETE` |

## Runtime grants (`aegis_app`)

| Access | Tables |
|--------|--------|
| `SELECT, INSERT` only | `audit_events`, `policy_decisions`, `policy_versions`, `action_requests`, `simulated_outbox` |
| `SELECT, INSERT, UPDATE` | `ai_assets`, `agents`, `agent_credentials`, `resources`, `policies`, `approvals`, `executions`, `users`, `audit_chain_heads` |
| `SELECT, INSERT, DELETE` | `agent_tool_grants`, `agent_resource_grants` |
| `SELECT, UPDATE` | `tenants` |
| `EXECUTE` | `aegis_resolve_tenant(text)`, `aegis_current_tenant()` |

`action_requests.status` is derived rather than updated, so that table can stay
insert-only: current state is read from the decision, approval, and execution rows.

## `aegis_resolve_tenant(slug)`

Login and failed-login auditing need a tenant ID before a tenant context exists. This
`SECURITY DEFINER` function, with a fixed `search_path`, returns only the ID for an exact
slug. It is the sole deliberate RLS exception. It allows slug probing; login returns the
same error whether or not the tenant exists, and the function has no HTTP exposure of its
own.

## Audit hash

```
event_hash = SHA-256( canonical_json({ all fields except event_hash, including prev_hash and seq }) )
```

Canonical JSON: sorted keys, no whitespace, UTF-8, UUIDs and ISO-8601 UTC timestamps as
strings. The genesis `prev_hash` is 64 zeros. The row is locked in `audit_chain_heads`
for each append, so the chain is linear per tenant. Throughput is deliberately serialized
per tenant; see the trade-off in `DECISIONS.md` D-006.

Verification walks events by `seq` and checks: contiguous `seq`, `prev_hash` linkage,
recomputed hash, and that the last event matches the head row.

## Credential lifecycle

- **Issue:** the server generates a 256-bit secret, stores its SHA-256, and returns the key once.
- **Rotate:** issue a second credential, move the agent, revoke the first. Multiple active credentials are allowed for this purpose.
- **Revoke:** `revoked_at` is set; checked on every request, so it takes effect immediately.
- **Expiry:** optional `expires_at`.
- **Why SHA-256 and not Argon2:** a 256-bit random secret cannot be brute-forced, and a per-request Argon2 cost would be a denial-of-service lever. Passwords, which are low entropy, use Argon2id.
