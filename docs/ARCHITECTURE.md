# AEGIS Architecture

A **modular monolith**: one FastAPI process, one PostgreSQL database, one Next.js
dashboard. Module boundaries are Python packages. Nothing here needs a second
deployable yet (see `DECISIONS.md` D-001).

```
 Agent (API key)                 Human (browser)
      |                                |
      |                         Next.js dashboard (server-side session cookie)
      |                                | Bearer JWT
      v                                v
 +--------------------------------------------------------------+
 | FastAPI                                                      |
 |                                                              |
 |  auth -> resolves a Principal (agent or user + tenant)       |
 |                                                              |
 |  /gateway  ---> Gateway service                              |
 |                  1 authenticate        (done by auth)        |
 |                  2 validate request    (strict schemas)      |
 |                  3 load facts          (RLS-scoped queries)  |
 |                  4 policy engine       (pure function)       |
 |                  4b governance check   (pure; only tightens) |
 |                  5 persist decision + audit, same txn        |
 |                  6 claim execution     (unique constraint)   |
 |                  7 tool executor       (only call site)      |
 |                  8 persist outcome + audit                   |
 |                                                              |
 |  /approvals -> state machine, row locks, action-hash binding |
 |  /registry, /policies, /audit, /events: control plane        |
 |  /governance -> profiles, risk, policies, reviews, evidence, |
 |                 frameworks, enforcement mode                 |
 +--------------------------------------------------------------+
      |  background workers: correlate events into incidents; sweep due governance reviews
      | connects as aegis_app (NOSUPERUSER, NOBYPASSRLS)
      v
 PostgreSQL: RLS on every tenant table, composite tenant FKs,
             append-only triggers, approval transition trigger
```

## Components and boundaries

| Module | Responsibility | Must not |
|--------|----------------|----------|
| `aegis.security` | Password hashing, JWT issue/verify, agent key parsing, RBAC | Read tenant data without tenant context |
| `aegis.db` | Engine, models, the tenant transaction helper | Offer a session without tenant context for tenant tables |
| `aegis.policy` | Rule schema and **pure** `evaluate(facts, policy)` | Perform I/O, read the clock, or call an LLM |
| `aegis.gateway` | Orchestrates the protected flow; owns the tool executor | Execute without a persisted allow or consumed approval |
| `aegis.approvals` | State machine, reviewer actions | Execute tools |
| `aegis.audit` | Append, canonicalize, hash, verify | Expose update or delete |
| `aegis.registry` | Assets, agents, credentials, grants | Let an agent principal call it |
| `aegis.events` | Project audit events into minimal security events | Accept events from outside the backend, or copy parameters and results |
| `aegis.correlation` | Versioned rules and the worker that creates incidents | Reach enforcement code, or be required for an action to proceed |
| `aegis.incidents` | The state machine and authorized transitions | Be reachable by agents or by the LLM layer |
| `aegis.investigation` | Timelines, evidence checks, deterministic findings | Change an incident, or store an uncited fact |
| `aegis.llm` | Turn text into text through a provider | Touch the database or any service |
| `aegis.governance.engine` | Pure risk, policy, lifecycle, and enforcement logic | Perform I/O, read the clock, or call an LLM |
| `aegis.governance` | Profiles, assessments, governance policies, reviews and decisions, evidence, frameworks, the gateway facts loader, and the review worker | Import `aegis.registry.service` or `aegis.gateway.service`; loosen a gateway outcome |
| `aegis.api` | HTTP, schemas, error mapping | Contain policy logic |

## Trust boundaries

Summarized here, specified in `SECURITY_BOUNDARIES.md`.

1. **Agent to gateway**: agents are untrusted and may be prompt-injected at any moment.
2. **Browser to API**: users are authenticated, and their role is read from the database, not from the token.
3. **API to database**: the runtime role is limited by RLS and grants; the migration role is separate.
4. **Gateway to tool**: a tool runs only through the executor, after a recorded authorization.
5. **LLM to anything** (future): output is data; it has no path into enforcement.

## Enforcement flow

### Synchronous allow

```
txn 1: load facts -> evaluate -> insert request, decision, audit -> if ALLOW, insert execution(STARTED) + audit -> COMMIT
txn 2: run tool in a savepoint -> update execution(SUCCEEDED|FAILED) + audit -> COMMIT
```

The synthetic tools only touch PostgreSQL, so running them inside txn 2 makes their effect
atomic with the recorded outcome. A tool with external effects could not be atomic this way
and would run between the two transactions.

Evidence of intent is durable *before* the side effect. A crash between the two
transactions leaves `STARTED` forever: execution is **at-most-once** by design, and a
stale `STARTED` is visible rather than silently retried.

### Deny

Transaction 1 only. No execution row is created and the tool executor is not called.
Absence of an execution row for a request is itself evidence.

### Approval required

```
txn 1: decision REQUIRE_APPROVAL + approval(PENDING, action_hash) + audit
reviewer -> txn: SELECT approval FOR UPDATE -> PENDING -> APPROVED|REJECTED + audit
agent POST /gateway/actions/{id}/execute ->
  txn: lock approval -> must be APPROVED and unexpired -> recompute action hash ->
       RE-EVALUATE policy against current state -> APPROVED -> EXECUTED + execution(STARTED) + audit
  txn: run tool in a savepoint, record outcome
```

Re-evaluation at execution closes the time-of-check/time-of-use gap: disabling the
agent or removing a grant after approval cancels the action.

### Governance (Phase 3)

```
txn 1 (as above): ... evaluate policy -> governance facts read in the same txn
     -> verdict = check(facts, action) -> outcome = combine(policy, verdict)
     -> insert decision + governance_gateway_checks row + audit -> ...
```

The check runs after the policy evaluation, and again at re-evaluation in an approved execution.
It can turn an allow into a hold or a deny, and a hold into a deny, and nothing else. A hard-check
or policy deny keeps its own reason code. The order of its rows, and what `observe` records instead
of enforcing, is spec 11.2 (`docs/superpowers/specs/2026-11-03-governance-engine-design.md`).

Lifecycle changes (suspend, revoke, reject, approve, submit, assess, profile save, grant changes) lock the
asset's agent rows `FOR NO KEY UPDATE` in ID order, then the state row, then the chain head. The
gateway's share lock on the agent row conflicts with that, so a suspension either precedes an
evaluation entirely or follows it (`DECISIONS.md` D-030).

The review worker follows the correlation worker: a polling thread, one asset per transaction,
finding tenants through `aegis_tenants_with_due_governance_reviews`. Expiry does not depend on it,
because the gateway compares `valid_until` with its own clock.

## Failure behavior

| Failure | Behavior |
|---------|----------|
| Policy document fails validation | Deny, `POLICY_INVALID` |
| No active policy | Deny, `NO_ACTIVE_POLICY` |
| Unexpected error in the engine | Deny, `POLICY_EVALUATION_ERROR` |
| Audit or decision write fails | Transaction rolls back, tool does not run, HTTP 503 |
| Database unavailable | HTTP 503, tool does not run |
| Tool raises | `execution=FAILED`, audited; the error detail is not returned to the caller |
| Outcome write fails after the tool ran | Execution remains `STARTED`; logged; visible as unresolved |
| Tenant context missing | RLS returns zero rows, writes are rejected |
| Governance check raises | `enforce`: deny, `GOVERNANCE_EVALUATION_ERROR`. `observe`: recorded; a retired or hard-blocked asset is still denied |
| Governance record fails its hash | Conditions: deny in both modes. Policies, methodologies, profiles, assessments, reviews: 503 |
| Review worker fails | Logged and retried; the gateway is unaffected |
| API started with a superuser, `BYPASSRLS`, or table-owning role | The process refuses to start |

## Tenant isolation

Three independent layers:

1. **Application**: every tenant query runs inside `tenant_transaction(tenant_id)`, which issues `set_config('app.tenant_id', ..., true)`.
2. **RLS**: `ENABLE` and `FORCE` on every tenant table; the runtime role has `NOBYPASSRLS`.
3. **Schema**: composite foreign keys such as `(tenant_id, agent_id)` make a cross-tenant reference unrepresentable even if a query is wrong.

The tenant comes from the verified principal. Client-supplied tenant identifiers are
never accepted on tenant-scoped endpoints.

## Technology

| Concern | Choice |
|---------|--------|
| API | Python 3.12, FastAPI, Pydantic v2 strict models |
| Persistence | SQLAlchemy 2 (sync) + psycopg 3, Alembic |
| Database | PostgreSQL 16 |
| Frontend | Next.js (App Router), TypeScript, Tailwind CSS, lucide icons |
| Tests | pytest against real PostgreSQL; hypothesis for engine properties; Playwright end to end |
| Local dev | Docker Compose, or embedded PostgreSQL when Docker is absent |

Redis Streams, OpenTelemetry export, and OPA are deferred until a requirement needs them
(`DECISIONS.md`). Decisions stay synchronous at the execution boundary regardless. The pipeline
from events to investigations is described in `INCIDENT_PIPELINE.md`.
