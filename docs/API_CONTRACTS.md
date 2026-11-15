# AEGIS API Contracts

Base path: `/api/v1`. All bodies are JSON and unknown fields are rejected.

**Authentication schemes**

- **User**: `Authorization: Bearer <JWT>`. The token proves identity only; role and active status are read from the database on each request.
- **Agent**: `Authorization: Bearer aegis_agent.<tenant_id>.<credential_id>.<secret>`.

Tokens of one kind are refused on routes for the other.

## Errors

Every error has this shape. Stack traces and internal details are never returned.

```json
{ "error": { "code": "AGENT_DISABLED", "message": "Human-readable summary", "request_id": "uuid" } }
```

| Status | Meaning | Example codes |
|--------|---------|---------------|
| 401 | Not authenticated | `UNAUTHENTICATED` |
| 403 | Authenticated but not permitted | `FORBIDDEN` |
| 404 | Not found, or belongs to another tenant (indistinguishable) | `NOT_FOUND` |
| 409 | State conflict | `INVALID_STATE_TRANSITION`, `IDEMPOTENCY_CONFLICT`, `APPROVAL_NOT_EXECUTABLE`, `APPROVAL_EXPIRED`, `ALREADY_EXISTS` |
| 411 | Chunked body refused, so that size can be checked up front | `LENGTH_REQUIRED` |
| 413 | Body over 64 KiB | `PAYLOAD_TOO_LARGE` |
| 422 | Validation failure | `VALIDATION_ERROR` |
| 503 | Fail-closed dependency failure | `SERVICE_UNAVAILABLE`, `RULE_INTEGRITY_FAILED`, and the governance integrity codes `METHODOLOGY_INTEGRITY_FAILED`, `POLICY_INTEGRITY_FAILED`, `ASSESSMENT_INTEGRITY_FAILED`, `PROFILE_INTEGRITY_FAILED`, `REVIEW_INTEGRITY_FAILED` |

Governance adds its own 403 and 409 codes, listed with each route under "Governance" below.

A policy **deny is not an HTTP error**. It returns 200 from the gateway with
`outcome: "DENY"`, because the request was handled correctly.

## Pagination

Collections accept `limit` (1 to 100, default 50) and `offset`, and return
`{ "items": [...], "total": n, "limit": n, "offset": n }`.

## Auth

| Method, path | Auth | Body | Result |
|--------------|------|------|--------|
| `POST /auth/login` | None | `tenant_slug`, `email`, `password` | `access_token`, `expires_in`. Any failure is the same 401 |
| `GET /auth/me` | User | | `id`, `tenant_id`, `email`, `role` |

## Assets (user)

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /assets` | Any | Paginated |
| `GET /assets/{asset_id}` | Any | |
| `POST /assets` | admin | `name`, `owner`, `risk_classification` (`low`, `medium`, `high`, `critical`), `intended_use`, `is_synthetic` |

## Agents (user)

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /agents` | Any | Paginated; includes grants |
| `GET /agents/{id}` | Any | |
| `POST /agents` | admin | `asset_id`, `name`, `owner` |
| `POST /agents/{id}/status` | admin | `status`: `active` or `disabled`. Audited |
| `POST /agents/{id}/credentials` | admin | Returns the key **once** |
| `POST /agents/{id}/credentials/{cid}/revoke` | admin | Audited, and effective on the next request |
| `POST /agents/{id}/tool-grants` | admin | `tool` must be in the catalog. Audited |
| `DELETE /agents/{id}/tool-grants/{tool}` | admin | Audited |
| `POST /agents/{id}/resource-grants` | admin | `resource_id`. Audited |
| `DELETE /agents/{id}/resource-grants/{resource_id}` | admin | Audited |

## Resources (user)

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /resources` | Any | Paginated; never includes content |
| `POST /resources` | admin | `kind` (`document`, `customer_record`, `destination`), `name`, `classification` (`public`, `internal`, `sensitive`), `content` (object), `clearance` (destinations only), `is_synthetic` |

## Policies (user)

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /policies` | Any | Includes the active version |
| `POST /policies` | admin | `name` |
| `POST /policies/{id}/versions` | admin | `document`, validated. Creates an immutable version |
| `POST /policies/{id}/activate` | admin | `version_id`. Exactly one active policy per tenant. Audited |

### Policy document

```json
{
  "rules": [
    {
      "id": "hold-outbound",
      "effect": "require_approval",
      "match": { "tools": ["send_message"] },
      "reason_code": "OUTBOUND_REQUIRES_APPROVAL"
    }
  ]
}
```

- `effect`: `allow`, `deny`, or `require_approval`.
- `match` fields are optional and combine with AND: `tools`, `actions`, `resource_classifications`, `resource_kinds`, `attachment_classifications`.
- Precedence: any deny, then any require_approval, then any allow. No match is a deny.
- Maximum 200 rules.

## Gateway (agent)

### `POST /gateway/actions`

```json
{ "idempotency_key": "client-chosen", "tool": "read_document",
  "resource_id": "uuid-or-null", "params": {} }
```

Result (200 in all policy outcomes):

```json
{
  "request_id": "uuid",
  "outcome": "ALLOW | DENY | REQUIRE_APPROVAL",
  "reason_code": "TOOL_NOT_GRANTED",
  "decision_id": "uuid",
  "policy_version_id": "uuid-or-null",
  "approval_id": "uuid-or-null",
  "approval_status": "PENDING | APPROVED | REJECTED | EXECUTED | CANCELLED | null",
  "execution": { "status": "SUCCEEDED | FAILED", "result": {} }
}
```

`execution` is `null` unless the tool was invoked. Resubmitting the same key and content
returns the original result without re-executing. Reusing a key with different content
returns 409 `IDEMPOTENCY_CONFLICT`.

### `GET /gateway/actions/{request_id}`

Agent's own requests only: status, outcome, approval state, execution.

### `POST /gateway/actions/{request_id}/execute`

No body, so parameters cannot be changed. Requires an `APPROVED`, unexpired approval and
a re-evaluation that is not a deny. Otherwise 409, and the action is not executed.

### Tool catalog

| Tool | Action | Resource kind | Params |
|------|--------|---------------|--------|
| `read_document` | `read` | `document` | none |
| `lookup_customer` | `read` | `customer_record` | none |
| `calculate` | `compute` | none | `operator` (`add`, `subtract`, `multiply`, `divide`), `a`, `b` |
| `send_message` | `transmit` | `destination` | `body` (max 2000), `attachment_resource_id` (optional) |

`send_message` writes to a simulated outbox table. Nothing leaves the system.

### Reason codes

`ALLOWED_BY_RULE`, `DENIED_BY_RULE`, `APPROVAL_REQUIRED_BY_RULE` (or a rule's custom code),
`AGENT_DISABLED`, `UNKNOWN_TOOL`, `TOOL_NOT_GRANTED`, `INVALID_PARAMETERS`, `RESOURCE_REQUIRED`,
`RESOURCE_NOT_EXPECTED`, `RESOURCE_NOT_FOUND`, `RESOURCE_KIND_MISMATCH`, `RESOURCE_NOT_GRANTED`,
`ATTACHMENT_NOT_GRANTED`, `DESTINATION_CLEARANCE_INSUFFICIENT`, `NO_ACTIVE_POLICY`,
`POLICY_INVALID`, `NO_MATCHING_RULE`, `POLICY_EVALUATION_ERROR`.

## Approvals (user)

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /approvals` | Any | Filter `status`; includes the exact tool, resource, and params |
| `GET /approvals/{id}` | Any | |
| `POST /approvals/{id}/approve` | reviewer, admin | `comment` optional. 409 unless `PENDING` |
| `POST /approvals/{id}/reject` | reviewer, admin | Same |

## Decisions (user)

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /decisions` | Any | Filter `outcome`, `agent_id`; includes whether a tool executed |
| `GET /decisions/{id}` | Any | Includes linked audit event IDs |

## Audit (user)

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /audit/events` | Any | Paginated, newest first. **No mutating routes exist** |
| `GET /audit/head` | Any | `seq`, `head_hash` |
| `POST /audit/verify` | admin, reviewer | Recomputes the tenant's chain and reports the first failure. Reads only |

## Overview (user)

`GET /overview`: counts derived from stored records. No estimates.

## Security events (user)

Read-only over HTTP: there is deliberately no way to submit one.

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /events` | Any | Filter `event_type`, `severity`, `agent_id`. Includes `incident_ids` |
| `GET /events/{event_id}` | Any | |

## Incidents (user)

There is no route to create an incident. Only correlation can.

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /incidents` | Any | Filter `status`, `severity`, `rule_key`, `asset_id` (incidents whose agent belongs to the asset; a UUID, 422 if malformed; an unknown or another tenant's id returns none) |
| `GET /incidents/{incident_id}` | Any | Includes `transitions` and `rule_definition`, which is `null` if the rule fails its integrity check |
| `GET /incidents/{incident_id}/events` | Any | The source events |
| `GET /incidents/{incident_id}/timeline` | Any | Rebuilt from stored records on each request |
| `POST /incidents/{incident_id}/acknowledge` | reviewer, admin | Body `expected_version`, optional `reason` |
| `POST /incidents/{incident_id}/investigate` | reviewer, admin | Same. Only from `OPEN` or `ACKNOWLEDGED` |
| `POST /incidents/{incident_id}/resolve` | reviewer, admin | `reason` required |
| `POST /incidents/{incident_id}/reopen` | reviewer, admin | `reason` required. Only from `RESOLVED` |
| `POST /incidents/{incident_id}/close` | admin | `reason` required. Only from `RESOLVED`. Final |

Errors: 409 `INCIDENT_VERSION_CONFLICT`, `INVALID_STATE_TRANSITION`, or `ACTIVE_INCIDENT_EXISTS`. 422
when a required reason is missing.

## Investigations (user)

| Method, path | Role | Notes |
|--------------|------|-------|
| `POST /incidents/{incident_id}/investigation-runs` | reviewer, admin | Creates an immutable run. Changes nothing else |
| `GET /incidents/{incident_id}/investigation-runs` | Any | Newest first |
| `GET /incidents/{incident_id}/findings` | Any | Latest run, or `run_id` for an earlier one. `verified` is derived from kind and source |
| `GET /evidence/{evidence_type}/{evidence_id}` | Any | `security_event`, `policy_decision`, `approval`, `execution`, or `audit_event`. Allowlisted fields only: never tool results, parameters, or message bodies |

## Correlation rules (user)

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /correlation-rules` | Any | The newest version of each rule |
| `POST /correlation-rules/{rule_key}/versions` | admin | Body `definition`. Creates a new immutable version. Audited |

`GET /overview` also returns `active_incidents` and `pending_correlation`.

## Governance (user, Phase 3)

All under `/api/v1/governance`, taken from `backend/src/aegis/api/routes_governance.py` and
`schemas_governance.py`. Every route refuses an agent principal with 401 `UNAUTHENTICATED`
(`test_governance_audit.py::test_every_governance_route_refuses_an_agent` sweeps all of them). The
tenant always comes from the principal. Lists are `Page[...]` as above. "Holder" means a user who
holds an unrevoked `governance_reviewer` grant and is still an active `admin` or `reviewer`. Every
write is audited in the same transaction as the write.

### People and role grants

| Method, path | Role | Body | Result |
|--------------|------|------|--------|
| `GET /people` | admin, reviewer | | `Page` of `id`, `email`, `role`, `reviewer_grant_id` (admins and reviewers only, for pickers) |
| `POST /role-grants` | admin | `user_id` | 201 `id`, `user_id`, `role`, `granted_by`, `granted_at`, `revoked_by`, `revoked_at`. 403 `SELF_GRANT_REFUSED`; 409 `ROLE_ALREADY_GRANTED`; 422 if the grantee is not an active admin or reviewer |
| `POST /role-grants/{id}/revoke` | admin | | The grant. Revoking twice records nothing new; a revoked grant cannot be reinstated (grant again instead) |

### Overview and inventory

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /overview` | Any | `total_assets`, `by_assessed_risk`, `unassessed`, `awaiting_approval` (assets `UNDER_REVIEW`), `conditionally_approved`, `suspended`, `overdue_reviews` (review date passed, including `REASSESSMENT_REQUIRED` and `UNDER_REVIEW`), `outstanding_findings` (findings frozen on open reviews), `evidence_verified`, `evidence_total`, `enforcement_mode`. All counted from stored rows |
| `GET /assets` | Any | Filters `search` (max 200, wildcards literal), `risk` (assessed: `LOW`..`CRITICAL`), `declared_risk` (`low`..`critical`), `status`, `owner_id`. Rows: `id`, `name`, `owner` (legacy label), `declared_risk`, `assessed_risk` (null unless the latest assessment is complete), `last_assessed_at`, `governance_status` (null when not governed), `business_owner`, `technical_owner` (`id`, `email`), `is_synthetic`, `valid_until`, `next_review_at`, `created_at` |
| `GET /assets/{id}` | Any | The row above plus `intended_use`, `state_version`, `state_updated_at`, `profile` (current version: `id`, `version`, `profile`, `content_hash`, `created_by`, `created_at`) |
| `POST /assets/{id}/profile` | admin | Body: the asset profile (spec 5; every field optional, unknown keys refused, owners must be users of this tenant). 201 `id`, `asset_id`, `version`, `profile`, `content_hash`, `created_by`, `created_at`, `governance_status`. An identical profile is a no-op. On an approved asset it moves the asset to `REASSESSMENT_REQUIRED`. 409 `ASSET_RETIRED` |
| `GET /assets/{id}/history` | Any | `Page` of `type` (`decision`, `assessment`, `profile_version`), `seq` (audit sequence, the order), `id`, `audit_event_id`, `kind`, and the one matching body |

### Risk

| Method, path | Role | Notes |
|--------------|------|-------|
| `POST /assets/{id}/assess` | admin | No body. 201 assessment (`id`, `asset_id`, `profile_version_id`, `methodology_version_id`, `methodology_version`, `input_hash`, `result_hash`, `status` `COMPLETE` or `INCOMPLETE`, `score`, `risk_level` (both null when incomplete), `assessed_by`, `assessed_at`, `audit_event_id`, `input`, `result`) plus `governance_status`. 409 `PROFILE_REQUIRED`, `ASSET_RETIRED` |
| `GET /assets/{id}/risk` | Any | `assessment` (latest by audit sequence, or null) and `recomputed_matches` (the stored input re-run through the stored methodology) |
| `GET /assets/{id}/assessments` | Any | `Page` of assessment summaries, newest first by audit sequence |
| `GET /methodologies` | Any | `Page` of `id`, `version`, `content_hash`, `created_by`, `created_at`, `approved`, `approved_by`, `approved_at`, `active`, `document` |
| `POST /methodologies` | admin | `document` (all eight factors required). 201 the version |
| `POST /methodologies/{id}/approve` | holder, not the author | 403 `SELF_APPROVAL_REFUSED`; 409 `ALREADY_APPROVED` |
| `POST /methodologies/{id}/activate` | admin | 409 `METHODOLOGY_NOT_APPROVED` |

A stored methodology that fails its hash returns 503 `METHODOLOGY_INTEGRITY_FAILED`; an
assessment that no longer recomputes, when a decision needs it, 503 `ASSESSMENT_INTEGRITY_FAILED`.

### Governance policies

Separate from the runtime `/policies` above.

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /policies` | Any | `Page` of `id`, `name`, `category`, `created_by`, `created_at`, `versions` (each `id`, `policy_id`, `version`, `content_hash`, `effective_from`, `review_by`, `created_by`, `created_at`, `approved`, `approved_by`, `approved_at`, `active`, `document`) |
| `POST /policies` | admin | `name`, `category`. 409 `POLICY_NAME_TAKEN` |
| `POST /policies/{policy_id}/versions` | admin | `document` (closed schema, spec 8), `effective_from` and optional `review_by`, both with a time zone, `review_by` after `effective_from` |
| `POST /policies/{policy_id}/versions/{id}/approve` | holder, not the author | 403 `SELF_APPROVAL_REFUSED`; 409 `ALREADY_APPROVED` |
| `POST /policies/{policy_id}/versions/{id}/activate` | admin | 409 `POLICY_VERSION_NOT_APPROVED`, `ALREADY_ACTIVE`. Activating a new version does not deactivate an older one |
| `POST /policies/{policy_id}/versions/{id}/deactivate` | admin | 409 `NOT_ACTIVE` |

A stored version that fails its hash returns 503 `POLICY_INTEGRITY_FAILED` wherever it would apply.

### Reviews and decisions

| Method, path | Role | Body | Notes |
|--------------|------|------|-------|
| `POST /assets/{id}/submit` | admin | `reason` | 201 review. Needs a complete assessment of the current profile and grants, else 409 `ASSESSMENT_NOT_CURRENT`. 409 `REVIEW_ALREADY_OPEN`, `INVALID_STATE_TRANSITION`, `ASSET_RETIRED`. While the open review is `INFO_REQUESTED`, submitting again withdraws it and opens a new one, keeping the assigned reviewer (ledger ruling R7) |
| `GET /approvals` | Any | | Filters `status` (`OPEN`, `INFO_REQUESTED`, `DECIDED`, `WITHDRAWN`), `asset_id`. Newest first by the audit sequence of each review's `SUBMIT` |
| `GET /approvals/{id}` | Any | | Review: `id`, `asset_id`, `assessment_id`, `profile_version_id`, `submitted_by`, `assigned_reviewer`, `required_approvers`, `status`, `version`, `submitted_at`, `closed_at`, `required_controls` (the frozen policy outcome), `findings` |
| `POST /approvals/{id}/assign` | holder | `reviewer_id` | The assignee must hold the role. 409 `REVIEW_NOT_OPEN` |
| `POST /approvals/{id}/request-information` | holder (the assignee, if any) | `reason` | 403 `NOT_ASSIGNED_REVIEWER`; 409 `INFORMATION_ALREADY_REQUESTED` |
| `POST /approvals/{id}/approve` | holder | `reason`, `valid_until`, `next_review_at` (both with a time zone, `now < next_review_at <= valid_until`), optional `conditions` (makes it conditional), `evidence_ids` (evidence of this asset, max 50) | 201 decision: `id`, `asset_id`, `review_id`, `kind` (`APPROVAL_VOTE`, `APPROVE`, `APPROVE_CONDITIONAL`), `from_status`, `to_status`, `decided_by`, `decided_at`, `reason`, `assessment_id`, `conditions`, `conditions_hash`, `valid_until`, `next_review_at`, `audit_event_id`, `policy_version_ids`, `evidence_ids`, `review_status`, `governance_status`. Short of `required_approvers` it is a vote. 403 `SELF_APPROVAL_REFUSED` (submitter or owner, unless a policy permits), `NOT_ASSIGNED_REVIEWER`; 409 `ASSESSMENT_NOT_CURRENT`, `REVIEW_AWAITING_INFORMATION`, `ALREADY_VOTED`, `CONDITIONS_MISMATCH`, `INVALID_STATE_TRANSITION`; 422 for bad dates, naive datetimes, or a condition naming a tool outside the catalog |
| `POST /approvals/{id}/reject` | holder | `reason` | 201 decision. Sets the hard block. Allowed while information is requested |

`conditions` is a closed object: `denied_tools`, `held_tools`, `denied_actions`, `hold_all`,
`max_resource_classification` (`public`, `internal`, `sensitive`), and `advisory_conditions` (up to
20 texts, shown to people and not enforced). A review whose frozen values fail their hash, or no
longer match their `SUBMIT` audit event, returns 503 `REVIEW_INTEGRITY_FAILED`; a profile that
fails its hash, 503 `PROFILE_INTEGRITY_FAILED`.

### Lifecycle actions

| Method, path | Role | Body | Notes |
|--------------|------|------|-------|
| `POST /assets/{id}/suspend` | admin or holder | `reason` | 201 decision (as above, with `actor_type`, nullable `decided_by` and `review_id`) plus `governance_status`. Works on an asset with no governance state. Sets the hard block, clears `valid_until`, withdraws an open review |
| `POST /assets/{id}/revoke` | admin or holder | `reason` | The same change, recorded as `REVOKE` |
| `POST /assets/{id}/reassess` | admin or holder | `reason` | `REQUIRE_REASSESSMENT` from an approved status. Keeps the approval window and conditions; never clears the hard block |
| `POST /assets/{id}/retire` | admin | `reason` | Terminal. Withdraws an open review and clears the window |

409 `INVALID_STATE_TRANSITION` or `ASSET_RETIRED` when the status does not allow the action.

### Evidence

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /evidence` | Any | Filters `asset_id`, `category`, `verification` (`UNVERIFIED`, `VERIFIED`, `REJECTED`). Rows: `id`, `asset_id`, `category`, `description`, `source_type`, `submitted_by`, `created_at`, `content_sha256`, `source_uri`, `record_type`, `record_id`, `content_text` (null for viewers), `control_ids`, `current_verification`, `latest_verification` |
| `POST /evidence` | admin | `asset_id`, `category` (one of ten), `description` (max 2000), `source` (one of: `internal_record` with `record_type` `assessment`, `decision`, `audit_event`, `incident`, `investigation_run` and `record_id`; `inline` with `content_text` up to 16000 bytes, hash computed by the server; `external_reference` with an `http(s)` `source_uri` and declared `content_sha256`), `control_ids` (max 50). 201 evidence, `UNVERIFIED`. 409 `ASSET_RETIRED` |
| `GET /evidence/{id}` | Any | The row plus `verifications`, oldest first by audit sequence |
| `POST /evidence/{id}/verify` | holder, not the submitter | `outcome` (`VERIFIED`, `REJECTED`), `method` (`internal_record_checked`, `content_recomputed`, `manual_attestation`), `note`, optional `content` (for an external reference). 201 `id`, `evidence_id`, `outcome`, `method`, `note`, `verified_by`, `verified_at`, `audit_event_id`, `scope` (`hash_recomputed`, `record_verified`, `existence_only`, `attestation_only`, `judgment_only`). 403 `SELF_VERIFICATION_REFUSED`; 409 `HASH_MISMATCH` |

### Frameworks and controls

Every response carries `statement`, the sentence that a mapping does not establish certification
or compliance.

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /frameworks` | Any | Seeds the tenant's library on first read. Items: `id`, `key`, `version`, `name`, `source_url`, `source_document`, `library_status` (`NOT_LOADED`, `LOADED_PARTIAL`, `LOADED`), `control_count`, `source_control_count`, `coverage`, `status_counts` |
| `GET /controls` | Any | Filters `framework_id`, `status`. Items: `id`, `framework_id`, `framework_key`, `identifier`, `name`, `description`, `source_reference`, `required_evidence`, `current_status`, `latest_assessment`, `verified_evidence_count`, `linked_evidence_count` |
| `POST /controls/{id}/assess` | holder | `status`, `note`, `evidence_ids` (linked to this control). `IMPLEMENTED` and `PARTIALLY_IMPLEMENTED` need verified linked evidence, else 409 `EVIDENCE_REQUIRED`. A concurrent rejection that the database trigger catches returns 409 `ALREADY_EXISTS` instead (REMEDIATION_PLAN risk 25) |

### Reviews due and enforcement

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /reviews/due` | Any | `window_days` (0 to 365, default 30). Items: `asset_id`, `name`, `governance_status`, `next_review_at`, `valid_until`, `overdue`, `expired` |
| `GET /enforcement` | Any | `enforcement_mode` |
| `POST /enforcement` | admin | `mode` (`observe`, `enforce`), `reason`. 409 `ENFORCEMENT_MODE_UNCHANGED` when the mode is already set |
| `GET /enforcement/preflight` | Any | `enforcement_mode`, `since`, `assets_checked`, `would_deny`, `would_hold`, `items` (`asset_id`, `name`, `governance_status`, `verdict` `DENY` or `HOLD`, `reason_code`, `recent_actions`, `recent_not_passed`). Not paged |

### Governance reason codes at the gateway

A governance verdict changes a gateway decision only by tightening it, and keeps a policy or
hard-check deny's own code. Codes: `GOVERNANCE_RETIRED`, `GOVERNANCE_BLOCKED`,
`GOVERNANCE_INTEGRITY_FAILED`, `GOVERNANCE_APPROVAL_EXPIRED`, `GOVERNANCE_NOT_APPROVED`,
`GOVERNANCE_CONDITION_DENIED`, `GOVERNANCE_REASSESSMENT_REQUIRED`, `GOVERNANCE_CONDITION_HOLD`,
`GOVERNANCE_EVALUATION_ERROR`. In `observe`, codes for rows 4, 5 and 7 of spec 11.2, and an
evaluation error on an asset that is not retired or blocked, are recorded in
`governance_gateway_checks` and do not change the outcome.

## Deferred routes

`/tenants` does not exist yet and is not mocked.
