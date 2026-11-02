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
| 409 | State conflict | `INVALID_STATE_TRANSITION`, `IDEMPOTENCY_CONFLICT`, `APPROVAL_NOT_EXECUTABLE`, `ALREADY_EXISTS` |
| 422 | Validation failure | `VALIDATION_ERROR` |
| 503 | Fail-closed dependency failure | `SERVICE_UNAVAILABLE` |

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
| `POST /assets` | admin | `name`, `owner`, `risk_classification` (`low`, `medium`, `high`, `critical`), `intended_use`, `is_synthetic` |

## Agents (user)

| Method, path | Role | Notes |
|--------------|------|-------|
| `GET /agents` | Any | Paginated; includes grants |
| `GET /agents/{id}` | Any | |
| `POST /agents` | admin | `asset_id`, `name`, `owner` |
| `POST /agents/{id}/status` | admin | `status`: `active` or `disabled`. Audited |
| `POST /agents/{id}/credentials` | admin | Returns the key **once** |
| `POST /agents/{id}/credentials/{cid}/revoke` | admin | Audited |
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
- `match` fields are optional and combine with AND: `tools`, `actions`, `resource_classifications`, `resource_kinds`.
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
`RESOURCE_NOT_FOUND`, `RESOURCE_KIND_MISMATCH`, `RESOURCE_NOT_GRANTED`,
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

## Deferred routes (Phase 4)

`/events`, `/incidents`, `/governance`, `/tenants`. They do not exist yet and are not
mocked.
