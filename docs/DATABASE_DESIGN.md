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
        1--0..1 active policy version
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
| `tenants` | `id`, `slug` unique, `name`, `active_policy_version_id` | RLS: `id = aegis_current_tenant()`. A single pointer, so exactly one version is active per tenant |
| `users` | `email` unique per tenant, `password_hash`, `role`, `is_active` | Role is checked by `CHECK` |
| `ai_assets` | `name`, `owner`, `risk_classification`, `intended_use`, `is_synthetic` | |
| `agents` | `asset_id`, `name` unique per tenant, `owner`, `status` | |
| `agent_credentials` | `agent_id`, `secret_hash`, `expires_at`, `revoked_at` | Plaintext is never stored |
| `resources` | `kind`, `name`, `classification`, `clearance`, `content` jsonb, `is_synthetic` | |
| `agent_tool_grants` | `agent_id`, `tool` | PK `(tenant_id, agent_id, tool)` |
| `agent_resource_grants` | `agent_id`, `resource_id` | PK `(tenant_id, agent_id, resource_id)` |
| `policies` | `name` unique per tenant | |
| `policy_versions` | `policy_id`, `version`, `document_canonical`, `content_hash`, `created_by` | Immutable by trigger. The hash is checked at every load |
| `action_requests` | `agent_id`, `idempotency_key`, `tool`, `action`, `resource_id`, `params_canonical`, `action_hash` | `UNIQUE (tenant_id, agent_id, idempotency_key)`. `resource_id` has no foreign key because it records what was *requested*, which may not exist. Parameters are stored as canonical text so the action hash can be recomputed exactly |
| `policy_decisions` | `request_id`, `agent_id`, `resource_id`, `tool`, `action`, `policy_version_id`, `policy_version`, `outcome`, `reason_code`, `matched_rule_id`, `evaluated_at`, `evidence` | Append-only |
| `approvals` | `request_id` unique, `decision_id`, `action_hash`, `status`, `expires_at`, `decided_by`, `decided_at`, `comment` | Transition trigger |
| `executions` | `request_id` unique, `status`, `result`, `started_at`, `finished_at` | Unique constraint prevents re-execution |
| `simulated_outbox` | `request_id` unique, `destination_id`, `body`, `attachment_resource_id` | Synthetic sink |
| `audit_chain_heads` | `tenant_id` PK, `seq`, `head_hash` | Row lock serializes appends per tenant |
| `audit_events` | `id`, `seq`, `prev_hash`, `event_hash`, `event_type`, `actor_type`, `actor_id`, `correlation_id`, `subject_type`, `subject_id`, `policy_version_id`, `occurred_at`, `payload` | `UNIQUE (tenant_id, seq)`; append-only |

## Phase 2 tables

| Table | Key columns | Notes |
|-------|-------------|-------|
| `security_events` | See `INCIDENT_PIPELINE.md` | `UNIQUE (tenant_id, source_audit_event_id)`. Composite foreign keys to the audit event, agent, decision, approval, and execution. A trigger allows only the processing marker to change, once |
| `correlation_rule_versions` | `rule_key`, `version`, `definition_canonical`, `content_hash`, `created_by` | Immutable. `created_by` is null for built-in defaults |
| `incidents` | `rule_version_id`, `rule_key`, `rule_version`, `scope_key`, `severity`, `status`, `version`, `event_count`, first and last observed | Partial unique index `incidents_one_active`. A trigger enforces transitions and makes identity and severity immutable |
| `incident_events` | `incident_id`, `event_id` | Composite primary key. Append-only |
| `incident_transitions` | `from_status`, `to_status`, actor, `reason`, `occurred_at`, `audit_event_id` | Append-only, with a required audit event |
| `investigation_runs` | `incident_id`, `started_by`, `input_fingerprint`, `llm_status` | Only the LLM status columns can be updated |
| `investigation_findings` | `run_id`, `kind`, `source`, `statement`, `position` | Append-only. `CHECK ((source = 'llm') = (kind = 'ai_hypothesis'))`. A deferred constraint trigger requires evidence for facts, rule results, and hypotheses |
| `finding_evidence` | One nullable foreign key per record type | `CHECK (num_nonnulls(...) = 1)`. All composite, so another tenant's record cannot be referenced |

## Phase 3 tables (governance, migration `0005`)

| Table | Key columns | Notes |
|-------|-------------|-------|
| `governance_settings` | `enforcement_mode` (`observe`, `enforce`), `active_methodology_version_id` | `UNIQUE (tenant_id)`, one row per tenant. No row means `observe` and the built-in methodology. The methodology pointer has no foreign key until the table it references exists |
| `governance_role_grants` | `user_id`, `role`, `granted_by`, `granted_at`, `revoked_by`, `revoked_at` | One role, `governance_reviewer`. A partial unique index allows one unrevoked grant per user and role. `CHECK (granted_by <> user_id)` backs the no-self-grant rule. A trigger allows a grant to be revoked once and never reinstated, and rejects `DELETE` and `TRUNCATE` |

## Phase 3 tables (governance assets, migration `0006`)

| Table | Key columns | Notes |
|-------|-------------|-------|
| `asset_profile_versions` | `asset_id`, `version`, `profile_canonical`, `content_hash`, `business_owner_id`, `technical_owner_id`, `created_by` | Immutable, with `UNIQUE (tenant_id, asset_id, version)`. The owner columns are composite foreign keys to `users`, so another tenant's user cannot be named. Rejects `UPDATE`, `DELETE`, and `TRUNCATE` |
| `asset_governance_state` | Primary key `(tenant_id, asset_id)`. `status`, `version`, `current_profile_version_id`, `latest_assessment_id`, `current_decision_id`, `hard_block_decision_id`, `valid_until`, `next_review_at`, `updated_at` | No row means the asset is not governed, and the migration creates none. The profile pointer is a composite key that must name a version of the same asset. The decision and assessment pointers have no foreign key until their tables exist. `aegis_governance_state_guard` is described below |

## Deferred tables

`governance_assessments`.

`users.role` is a single fixed role. A roles-and-permissions table has no use until
custom roles are a requirement (`DECISIONS.md` D-009).

## Database-level enforcement

| Trigger | Table | Rule |
|---------|-------|------|
| `aegis_reject_mutation` | `audit_events`, `policy_decisions`, `policy_versions` | Rejects `UPDATE` and `DELETE`. A statement-level trigger rejects `TRUNCATE` |
| `aegis_approval_transition` | `approvals` | Allows only: `PENDING -> APPROVED, REJECTED, CANCELLED`, and `APPROVED -> EXECUTED, CANCELLED`. Forbids changing binding columns (`request_id`, `action_hash`, `decision_id`). Forbids `DELETE` |
| `aegis_governance_state_guard` | `asset_governance_state` | Inserts must be `DRAFT` at version 1 with no hard block. Updates must raise `version` by exactly one. A status change must follow the lifecycle table (spec 7.1). `tenant_id` and `asset_id` are immutable. `hard_block_decision_id` can go from set to null only in an update that moves the status into `APPROVED` or `CONDITIONALLY_APPROVED`. A status-unchanged update cannot clear it. Forbids `DELETE`. A status-unchanged update is allowed, and still bumps `version` |

## Runtime grants (`aegis_app`)

| Access | Tables |
|--------|--------|
| `SELECT` only | `users` |
| `SELECT`, `UPDATE (active_policy_version_id)` | `tenants` |
| `SELECT`, `UPDATE (seq, head_hash)` | `audit_chain_heads` |
| `SELECT, INSERT`, `UPDATE (enforcement_mode, active_methodology_version_id)` | `governance_settings` |
| `SELECT, INSERT`, `UPDATE (revoked_by, revoked_at)` | `governance_role_grants` |
| `SELECT, INSERT`, `UPDATE (status, version, current_profile_version_id, latest_assessment_id, current_decision_id, hard_block_decision_id, valid_until, next_review_at, updated_at)` | `asset_governance_state` |
| `SELECT, INSERT` only | `ai_assets`, `resources`, `policies`, `policy_versions`, `action_requests`, `policy_decisions`, `simulated_outbox`, `audit_events`, `correlation_rule_versions`, `incident_events`, `incident_transitions`, `investigation_findings`, `finding_evidence`, `asset_profile_versions` |
| `SELECT, INSERT`, `UPDATE (correlation_processed_at)` | `security_events` |
| `SELECT, INSERT`, `UPDATE (status, version, event_count, first_observed_at, last_observed_at, assigned_to, updated_at)` | `incidents` |
| `SELECT, INSERT`, `UPDATE (llm_status, llm_provider, llm_model, llm_rejected_count, llm_finished_at)` | `investigation_runs` |
| `SELECT, INSERT`, `UPDATE (status)` | `agents` |
| `SELECT, INSERT`, `UPDATE (revoked_at)` | `agent_credentials` |
| `SELECT, INSERT`, `UPDATE (status, decided_by, decided_at, comment)` | `approvals` |
| `SELECT, INSERT`, `UPDATE (status, result, finished_at)` | `executions` |
| `SELECT, INSERT, DELETE` | `agent_tool_grants`, `agent_resource_grants` |
| `EXECUTE` | `aegis_resolve_tenant(text)` |

Updates are column-level, so the runtime role cannot change a request, an approval's binding,
or an agent's owner. A test compares this table with the live catalog. Tenants and users can
only be created by the owner role, through `aegis.provisioning`.

A request's current state is read from its decision, approval, and execution rows, so
`action_requests` can stay insert-only.

## `aegis_tenants_with_pending_events()`

The second and only other `SECURITY DEFINER` function. The correlation worker must find work without a
tenant context, so this returns tenant IDs only. The matching owner policy exposes only unprocessed
rows. A test fails if any other such function appears.

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
