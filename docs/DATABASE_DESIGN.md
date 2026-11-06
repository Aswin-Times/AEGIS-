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
| `governance_settings` | `enforcement_mode` (`observe`, `enforce`), `active_methodology_version_id` | `UNIQUE (tenant_id)`, one row per tenant. No row means `observe` and the built-in methodology. The methodology pointer is a composite foreign key to `risk_methodology_versions`, added in `0007` |
| `governance_role_grants` | `user_id`, `role`, `granted_by`, `granted_at`, `revoked_by`, `revoked_at` | One role, `governance_reviewer`. A partial unique index allows one unrevoked grant per user and role. `CHECK (granted_by <> user_id)` backs the no-self-grant rule. A trigger allows a grant to be revoked once and never reinstated, and rejects `DELETE` and `TRUNCATE` |

## Phase 3 tables (governance assets, migration `0006`)

| Table | Key columns | Notes |
|-------|-------------|-------|
| `asset_profile_versions` | `asset_id`, `version`, `profile_canonical`, `content_hash`, `business_owner_id`, `technical_owner_id`, `created_by` | Immutable, with `UNIQUE (tenant_id, asset_id, version)`. The owner columns are composite foreign keys to `users`, so another tenant's user cannot be named. Rejects `UPDATE`, `DELETE`, and `TRUNCATE` |
| `asset_governance_state` | Primary key `(tenant_id, asset_id)`. `status`, `version`, `current_profile_version_id`, `latest_assessment_id`, `current_decision_id`, `hard_block_decision_id`, `valid_until`, `next_review_at`, `updated_at` | No row means the asset is not governed, and the migration creates none. The profile pointer is a composite key that must name a version of the same asset. The assessment pointer is a composite foreign key `(tenant_id, asset_id, latest_assessment_id)` to `risk_assessments`, added in `0007`, so it can name only an assessment of the same asset. The decision pointers are composite foreign keys `(tenant_id, asset_id, current_decision_id)` and `(tenant_id, asset_id, hard_block_decision_id)` to `governance_decisions`, added in `0009`, so a state row can name only a decision of its own asset. `aegis_governance_state_guard` is described below |

## Phase 3 tables (governance risk, migration `0007`)

| Table | Key columns | Notes |
|-------|-------------|-------|
| `risk_methodology_versions` | `version`, `document_canonical`, `content_hash`, `created_by` | Append-only, with `UNIQUE (tenant_id, version)`. Version 1 is the built-in document, seeded per tenant on first use with a null `created_by`, and counts as approved. `CHECK ((version = 1) = (created_by IS NULL))` keeps that exception to version 1. The hash is checked at every load |
| `risk_methodology_events` | `version_id`, `event` (`APPROVED`, `ACTIVATED`), `actor_id`, `audit_event_id` | Append-only. Approval cannot live on the version row, because that row cannot change. A partial unique index allows one `APPROVED` event per version. Activation also sets `governance_settings.active_methodology_version_id` |
| `risk_assessments` | `asset_id`, `profile_version_id`, `methodology_version_id`, `input_canonical`, `input_hash`, `result_canonical`, `result_hash`, `status`, `score`, `risk_level`, `assessed_by`, `audit_event_id`, `created_at` | Append-only. `(status = 'COMPLETE') = (risk_level IS NOT NULL)` and `(status = 'COMPLETE') = (score IS NOT NULL)`, so missing information can never be stored as a level. `UNIQUE (tenant_id, asset_id, id)` and a composite key to the profile version keep an assessment to one asset. The stored input and result let `GET .../risk` recompute it. "Latest" means the highest audit sequence of `audit_event_id`, never `created_at` |

## Phase 3 tables (governance policies, migration `0008`)

These are separate from the runtime `policies` and `policy_versions`, which stay the rules the gateway evaluates.

| Table | Key columns | Notes |
|-------|-------------|-------|
| `governance_policies` | `name`, `category`, `created_by` | Append-only. A unique index on `(tenant_id, lower(name))` keeps names distinct |
| `governance_policy_versions` | `policy_id`, `version`, `document_canonical`, `content_hash`, `effective_from`, `review_by`, `created_by` | Append-only, with `UNIQUE (tenant_id, policy_id, version)`. `effective_from` is required and `review_by` optional, and `CHECK (review_by IS NULL OR review_by > effective_from)`. `content_hash` covers `policy_id`, `version`, `effective_from`, `review_by` (UTC, fixed-width), and the document, so editing the window or the numbering is detected as well as the document. It is checked at every load, and a mismatch fails closed |
| `governance_policy_events` | `policy_version_id`, `event` (`APPROVED`, `ACTIVATED`, `DEACTIVATED`), `actor_id`, `audit_event_id` | Append-only. A partial unique index allows one `APPROVED` event per version. A version's activation status is its latest `ACTIVATED` or `DEACTIVATED` event by audit sequence, never by `created_at`. `aegis_policy_event_guard` is described below |

Adding a tool or resource grant now takes the per-asset advisory lock and the asset's agent row locks, even for an asset with no governance state, so it can wait on in-flight gateway evaluations.

## Phase 3 tables (governance reviews and decisions, migration `0009`)

| Table | Purpose | Notes |
|-------|---------|-------|
| `governance_reviews` | `asset_id`, `assessment_id`, `profile_version_id`, `submitted_by`, `assigned_reviewer`, `required_controls_canonical`, `findings_canonical`, `required_approvers`, `frozen_hash`, `status` (`OPEN`, `INFO_REQUESTED`, `DECIDED`, `WITHDRAWN`), `version`, `submitted_at`, `closed_at` | A partial unique index on `(tenant_id, asset_id)` where the status is `OPEN` or `INFO_REQUESTED` allows one open review per asset. `required_controls_canonical` holds the whole frozen policy outcome: applicable policy version IDs, required controls, `minimum_approvers`, `self_approval_permitted`, and `owner_approval_permitted`. `required_approvers` copies `minimum_approvers` and is `1` or `2`. `frozen_hash` covers the review's identity and the frozen text and is checked wherever the review is read, failing closed with `503 REVIEW_INTEGRITY_FAILED`. The hash is also written into the audit payload of the review's own `SUBMIT` decision, and a review read to make a decision is compared against that event (whose own hash is recomputed), so recomputing the unkeyed hash after an edit is detected. `closed_at` is set exactly when the status is `DECIDED` or `WITHDRAWN`. Composite keys tie the assessment and profile version to the same asset. `aegis_governance_review_guard` is described below |
| `governance_decisions` | `asset_id`, `review_id`, `kind`, `from_status`, `to_status`, `actor_type` (`user`, `system`), `decided_by`, `decided_at`, `reason`, `assessment_id`, `conditions_canonical`, `conditions_hash`, `valid_until`, `next_review_at`, `audit_event_id` | Append-only. `UNIQUE (tenant_id, asset_id, id)` backs the state row's pointers. Composite keys tie the review and assessment to the same asset, and `audit_event_id` is required and must name a real audit event. Checks: `reason` is non-empty; a user is present exactly when the actor is `user`; the system actor is allowed only for `REQUIRE_REASSESSMENT`; `APPROVE` and `APPROVE_CONDITIONAL` need an assessment, `valid_until`, and `next_review_at`; `APPROVE_CONDITIONAL` needs non-empty conditions; conditions and their hash are both present or both absent. A partial unique index on `(tenant_id, review_id, decided_by)` for `APPROVAL_VOTE`, `APPROVE`, and `APPROVE_CONDITIONAL` keeps one person from counting twice on a review |
| `governance_decision_policy_versions` | `decision_id`, `policy_version_id` | Append-only. The policy versions a decision was made against |
| `governance_decision_evidence` | `decision_id`, `evidence_id` | Append-only. There is no foreign key to `governance_evidence`: the service requires each id to be this tenant's evidence for the decision's asset, and the table is left unconstrained so the tests that write a decision with an arbitrary evidence id keep passing |

## Phase 3 tables (evidence, migration `0011`)

| Table | Purpose | Notes |
|-------|---------|-------|
| `governance_evidence` | `asset_id`, `category` (the ten evidence categories), `description`, `source_type` (`internal_record`, `inline`, `external_reference`), `submitted_by`, `created_at`, `content_sha256`, `content_text`, `source_uri`, and the record columns `assessment_id`, `decision_id`, `audit_event_id`, `incident_id`, `investigation_run_id` | Append-only, with `UNIQUE (tenant_id, id)` and `UNIQUE (tenant_id, asset_id, id)`. One check fixes the shape by source: `inline` has text and a hash and nothing else; `external_reference` has a URI and a declared hash; `internal_record` has exactly one record column, and a hash unless the record is an incident or investigation run, which have none. The assessment and decision columns are composite foreign keys that include `asset_id`, so they can name only a record of the same asset; the other three include only the tenant. `content_text` is capped at 16000 bytes |
| `governance_evidence_controls` | `evidence_id`, `control_id` | Append-only. The foreign key to `governance_controls` is added with the control library |
| `governance_evidence_verifications` | `evidence_id`, `outcome` (`VERIFIED`, `REJECTED`), `method` (`internal_record_checked`, `content_recomputed`, `manual_attestation`), `note`, `verified_by`, `verified_at`, `audit_event_id` | Append-only. A verification's current status is the latest row by the audit sequence of its audit event, never by timestamp. `aegis_evidence_verifier_guard` refuses an insert whose `verified_by` is the evidence's `submitted_by` |

## Deferred tables

The remaining governance tables (compliance and gateway checks) arrive with later migrations.

`users.role` is a single fixed role. A roles-and-permissions table has no use until
custom roles are a requirement (`DECISIONS.md` D-009).

## Database-level enforcement

| Trigger | Table | Rule |
|---------|-------|------|
| `aegis_reject_mutation` | `audit_events`, `policy_decisions`, `policy_versions`, `asset_profile_versions`, `risk_methodology_versions`, `risk_methodology_events`, `risk_assessments`, `governance_policies`, `governance_policy_versions`, `governance_policy_events`, `governance_decisions`, `governance_decision_policy_versions`, `governance_decision_evidence`, `governance_evidence`, `governance_evidence_controls`, `governance_evidence_verifications` | Rejects `UPDATE` and `DELETE`. A statement-level trigger rejects `TRUNCATE` |
| `aegis_approval_transition` | `approvals` | Allows only: `PENDING -> APPROVED, REJECTED, CANCELLED`, and `APPROVED -> EXECUTED, CANCELLED`. Forbids changing binding columns (`request_id`, `action_hash`, `decision_id`). Forbids `DELETE` |
| `aegis_governance_state_guard` | `asset_governance_state` | Inserts must be `DRAFT` at version 1 with no hard block. Updates must raise `version` by exactly one. A status change must follow the lifecycle table (spec 7.1). `tenant_id` and `asset_id` are immutable. `hard_block_decision_id` can go from set to null only in an update that moves the status into `APPROVED` or `CONDITIONALLY_APPROVED`. A status-unchanged update cannot clear it. Forbids `DELETE`. A status-unchanged update is allowed, and still bumps `version`, except on a `RETIRED` row, which refuses every update (replaced by migration `0010`, which changes the function and adds no table) |
| `aegis_governance_review_guard` | `governance_reviews` | The frozen columns (identity, `required_controls_canonical`, `findings_canonical`, `required_approvers`, `frozen_hash`, `submitted_at`) cannot change. `version` must rise by exactly one. A `DECIDED` or `WITHDRAWN` review cannot change. Forbids `DELETE`. A statement-level `aegis_reject_mutation` trigger rejects `TRUNCATE` |
| `aegis_evidence_verifier_guard` | `governance_evidence_verifications` | On insert, `verified_by` cannot be the evidence's `submitted_by` |
| `aegis_policy_event_guard` | `governance_policy_events` | On insert, an `APPROVED` event cannot name the version's creator as actor, and an `ACTIVATED` event needs an existing `APPROVED` event for the version |

## Runtime grants (`aegis_app`)

| Access | Tables |
|--------|--------|
| `SELECT` only | `users` |
| `SELECT`, `UPDATE (active_policy_version_id)` | `tenants` |
| `SELECT`, `UPDATE (seq, head_hash)` | `audit_chain_heads` |
| `SELECT, INSERT`, `UPDATE (enforcement_mode, active_methodology_version_id)` | `governance_settings` |
| `SELECT, INSERT`, `UPDATE (revoked_by, revoked_at)` | `governance_role_grants` |
| `SELECT, INSERT`, `UPDATE (assigned_reviewer, status, version, closed_at)` | `governance_reviews` |
| `SELECT, INSERT`, `UPDATE (status, version, current_profile_version_id, latest_assessment_id, current_decision_id, hard_block_decision_id, valid_until, next_review_at, updated_at)` | `asset_governance_state` |
| `SELECT, INSERT` only | `governance_policies`, `governance_policy_versions`, `governance_policy_events`, `governance_decisions`, `governance_decision_policy_versions`, `governance_decision_evidence`, `governance_evidence`, `governance_evidence_controls`, `governance_evidence_verifications`, `risk_methodology_versions`, `risk_methodology_events`, `risk_assessments`, `ai_assets`, `resources`, `policies`, `policy_versions`, `action_requests`, `policy_decisions`, `simulated_outbox`, `audit_events`, `correlation_rule_versions`, `incident_events`, `incident_transitions`, `investigation_findings`, `finding_evidence`, `asset_profile_versions` |
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
