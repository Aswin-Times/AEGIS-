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
| 503 | Fail-closed dependency failure | `SERVICE_UNAVAILABLE`, `RULE_INTEGRITY_FAILED` |

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

## Deferred routes

`/governance` and `/tenants` do not exist yet and are not mocked.
