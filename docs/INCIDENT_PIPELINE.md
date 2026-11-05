# Security Events, Correlation, and Investigation

How AEGIS turns individual enforcement decisions into incidents with verifiable evidence.
Decisions behind this design are in `DECISIONS.md` (D-019 onward).

```
gateway / approvals / auth / control plane
        |  same transaction
        v
  audit_events (hash chain: the source of truth)
        |  same transaction: projection
        v
  security_events (normalized, minimal, append-only)
        |  after commit: correlation worker, one event per transaction
        v
  incidents + incident_events + incident_transitions
        |  on request, by a reviewer
        v
  investigation_runs + investigation_findings + finding_evidence
        |  optional, after the deterministic findings are committed
        v
  LLM adapter -> ai_hypothesis findings only, each reference verified
```

Correlation and investigation run **after** the enforcement decision is committed, and nothing
in this pipeline can authorize, deny, or execute a protected action. A correlation failure leaves
a visible backlog. It does not block enforcement.

## Security events

### Source of truth

`audit_events` remains the source of truth. A security event is a **projection** of exactly one
audit event, written in the same transaction, with
`UNIQUE (tenant_id, source_audit_event_id)`. So:

- An event cannot exist without a real, chained audit event (foreign key).
- A duplicate delivery of the same source is a no-op.
- A committed security-relevant audit event always has its security event, unless it predates the
  migration, which `scripts/backfill_events.py` repairs idempotently.
- Reprojecting the audit event must reproduce the stored row. A mismatch means the event was
  altered, and investigations report that instead of relying on it.

There is **no API for submitting events**. Every event originates in trusted backend code.

### Fields

| Field | Notes |
|-------|-------|
| `id`, `tenant_id` | Stable ID and owner |
| `schema_version` | Version of the projection that wrote the row |
| `event_type` | Closed set, below |
| `occurred_at` | When it happened (UTC, from the source audit event) |
| `recorded_at` | When the row was written (database clock). Never used for correlation windows |
| `actor_type`, `actor_id` | Copied from the audit event |
| `asset_id`, `agent_id` | Resolved server-side. Composite foreign keys |
| `action_request_id`, `tool`, `action`, `resource_id` | `resource_id` is what was *requested*, so it has no foreign key |
| `decision_id`, `approval_id`, `execution_id` | Composite foreign keys |
| `correlation_id` | The action request, where there is one |
| `severity` | `info`, `low`, `medium`, `high`, `critical`. Assigned by fixed mapping |
| `reason_code` | Machine-readable, restricted format |
| `attributes` | Allowlisted keys and scalar values only |
| `source_audit_event_id`, `source_event_hash` | Evidence and integrity link to the chain |
| `correlation_processed_at` | The only mutable column |

### What is deliberately never copied

Action parameters, message bodies, tool results, resource content, approval comments, passwords,
secrets, and email addresses. Agent-controlled strings are limited to the tool name, which the
gateway has already restricted to `^[a-z][a-z0-9_]{0,63}$`. Everything else is an ID, a
classification, or a server-assigned code.

### Event types

| Event type | Source audit event | Severity |
|------------|--------------------|----------|
| `gateway.action_denied` | `action.decision` with `DENY` | By reason: `high` for an unknown tool, a clearance failure, or an invalid policy; `low` for bad parameters or no active policy; otherwise `medium` |
| `gateway.approval_required` | `action.decision` with `REQUIRE_APPROVAL` | `info` |
| `gateway.execution_refused` | `approval.execution_refused` (new) | `medium` |
| `approval.approved` / `approval.rejected` | same | `info` / `low` |
| `approval.expired` | `approval.cancelled` with reason `APPROVAL_EXPIRED` | `low` |
| `approval.invalidated` | other `approval.cancelled` | `medium`, `high` for a hash mismatch |
| `execution.succeeded` / `execution.failed` | same | `info` / `low` |
| `auth.agent_failed`, `auth.login_failed` | same | `low` |
| `auth.token_rejected` | new: a correctly signed token naming a user absent from its tenant | `high` |
| `authz.denied` | new: role check failed | `medium` |
| `access.not_visible` | new: an authenticated caller asked for an ID it cannot see | `medium` |
| `policy.version_created`, `policy.activated` | same | `medium` |
| `agent.status_changed` | same | `medium` |
| `grant.changed` | `grant.*` | `medium` |
| `credential.changed` | `credential.*` | `low` |
| `correlation.rule_changed` | new | `medium` |
| `governance.status_changed` | `governance.decision` whose `from_status` differs from `to_status`. The reason code is the decision kind prefixed with `GOVERNANCE_`, and `attributes.status` is the new status | `medium` for `SUSPEND`, `REVOKE`, and `REJECT`; otherwise `info` |

`incident.*` and `investigation.*` audit events are **not** projected, so an incident can never
feed correlation and cause a loop.

### Limiting unauthenticated writes

A failed authentication writes an audit event and takes the tenant's chain lock, and anyone who
knows a tenant ID can trigger it. Since those events now also drive incidents, this directly
affects the pipeline. Failure *recording* is limited per tenant and kind in each process
(`failure_events_per_minute`). Suppressed failures are counted on the next recorded event
(`attributes.suppressed_since_last`), so the count stays visible. The caller's response is
unchanged. This protects the pipeline, and it is **not** login rate limiting: attempts are still
processed. It is also per process.

`auth.token_rejected` is rare by design: it means a token with a valid AEGIS signature named a user who
is not in that token's tenant. A tampered tenant segment on an agent key is recorded as
`auth.agent_failed` in the tenant it names, so it also counts toward `authentication_failures`.

## Correlation

### Rules

A rule is a typed, validated, versioned document:

```json
{
  "enabled": true,
  "title": "Repeated unauthorized tool attempts",
  "severity": "high",
  "threshold": 3,
  "window_seconds": 300,
  "scope": "agent",
  "match": {"event_types": ["gateway.action_denied"], "reason_codes": ["TOOL_NOT_GRANTED", "UNKNOWN_TOOL"]}
}
```

Versions live in `correlation_rule_versions`, are immutable, and carry a content hash. Defaults come
from code and are written for a tenant as version 1 on first use. An administrator changes a threshold
or window by creating a new version, and that is audited. Each incident records the exact version that
created it.

If a stored rule fails its hash or validation, correlation for that tenant **stops and stays
visibly behind** (`pending_correlation` on the overview), rather than silently losing detection.

### Built-in rules

| Key | Scenario | Default |
|-----|----------|---------|
| `repeated_unauthorized_tools` | A: denied tool requests from one agent | 3 in 5 min, `high` |
| `repeated_transfer_denials` | B: denied outbound transfers from one agent | 2 in 15 min, `high` |
| `permission_probing` | C: attempts outside registered permissions, against at least 3 distinct tool and resource combinations | 5 in 1 h, `medium` |
| `approval_bypass_attempts` | D: executing without a valid approval | 3 in 1 h, `high` |
| `not_visible_references` | E: repeated references to IDs not visible in this tenant, from one actor | 3 in 15 min, `high` |
| `authentication_failures` | Failed authentication against this tenant | 10 in 5 min, `medium` |

**What these rules do not claim.** Rule B does not mean data was exposed: a denied transfer did not
run. Rule C detects probing, not a change against a behavioral baseline, because no baseline is
modeled. Rule E cannot confirm a cross-tenant attempt: a missing ID looks identical to one held by
another tenant, by design. AEGIS does not check, because answering would tell the attempting tenant
that the ID exists elsewhere. The victim tenant is not informed either.

### Processing

A worker in the API process polls every `correlation_poll_seconds`, and it can also be run directly.
It finds tenants with pending events through `aegis_tenants_with_pending_events()`, which returns IDs
only. Then, for each pending event, ordered by `occurred_at` and `id`, in its own transaction:

1. Lock the event row (`FOR UPDATE SKIP LOCKED`).
2. Lock the tenant's audit chain head. Correlation is therefore serial per tenant.
3. For each enabled rule the event matches:
   - If an active incident exists for the rule and scope, link the event, unless it is older than
     one window before the incident's first event.
   - Otherwise, load matching events within one window either side that are not linked to an incident of this rule,
     and look for a qualifying window. If one exists, create the incident and link that window's events.
4. Mark the event processed.

### Guarantees

| Requirement | Mechanism |
|-------------|-----------|
| Duplicate delivery | Unique source audit event. `incident_events` primary key. Processed marker |
| Duplicate incidents | Partial unique index on `(tenant_id, rule_key, scope_key)` while active |
| Concurrent processing | Skip-locked rows, chain lock, and the index as the final guard, with retry |
| Out-of-order events | Windows use `occurred_at`, and the search covers one window either side |
| Cross-tenant correlation | Runs under one tenant's RLS context. Composite foreign keys |
| Traceability | `rule_version_id`, `rule_version`, and links to source events |
| Reprocessing after resolution | An event already linked to an incident of this rule never counts again |

**Out-of-order limit.** An event more than one window older than an active incident's first event is
processed but not linked. Rules look at `occurred_at`, not arrival, so a late event can still form an
incident with neighbors within the window.

**Known evasion.** Thresholds are not secret, and an attacker staying below them raises no incident.

### Lock order

Writers that touch both take the **chain head before the incident row**. Correlation and state
transitions do this to avoid deadlock.

## Incident lifecycle

```
OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED -> CLOSED
  |          |                               |
  |          +--> RESOLVED                   +--> INVESTIGATING (reopen)
  +--> INVESTIGATING
  +--> RESOLVED
```

| Rule | Mechanism |
|------|-----------|
| Allowed transitions | `aegis.incidents.state`, and independently a database trigger |
| Who | `reviewer` and `admin`. Only `admin` can close |
| Reason | Required to resolve, close, and reopen |
| No silent overwrite | Each request sends `expected_version`. A mismatch is 409 |
| History | `incident_transitions`: actor, from, to, time, reason, audit event. Append-only |
| Severity | Set by the rule at creation. The runtime role has no update grant on it, so nothing can change it |
| One active incident | Reopening when a new active incident exists is 409 |

## Investigation

`POST /incidents/{id}/investigation-runs` assembles evidence and writes a new, immutable run. Findings
are separated by `kind`:

| Kind | Source | Evidence |
|------|--------|----------|
| `observed_fact` | Deterministic, from stored records | Required, enforced by a deferred constraint trigger at commit |
| `rule_result` | Deterministic, from the rule version | Required, enforced the same way |
| `evidence_gap` | Deterministic: what the records cannot show | Optional |
| `recommended_action` | Deterministic template. Never executed | Optional |
| `ai_hypothesis` | Only the LLM. A check constraint ties `source = llm` to this kind | Required, each reference verified |

`finding_evidence` has one foreign key per record type and a check that exactly one is set, so a
reference to a nonexistent or other-tenant record cannot be stored. A second, application-level check
requires evidence to belong to the incident.

Before a stored event backs a fact, it is verified: the source audit event's hash is recomputed, and
reprojection must match the row. An event that fails becomes an `evidence_gap`, not a fact.

Runs over the same evidence produce the same deterministic statements. `input_fingerprint` records
what was examined.

## LLM layer

Optional, off by default, and the system is complete without it. When configured:

- It runs **after** the deterministic findings are committed, outside any transaction.
- The prompt holds minimized evidence only: types, reason codes, severities, timestamps, and tool
  names. Never parameters, bodies, results, names, or emails. It is framed as untrusted data.
- Output must fit a strict schema. Each hypothesis must cite evidence from the set it was given.
  Unsupported hypotheses are rejected and counted.
- Timeout, provider failure, or invalid output sets `llm_status`, and leaves the deterministic results intact.
- Output is stored only as `ai_hypothesis`. The LLM module cannot reach the transition, policy,
  grant, or execution code, which a static test enforces.
