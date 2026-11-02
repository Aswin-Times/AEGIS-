# AEGIS Security Boundaries

Each boundary lists what crosses it, what enforces it, and what it does **not** protect.

## B1. Agent to gateway

- **Trust:** none. Assume the agent is compromised.
- **Crosses:** a bearer key and a JSON action request.
- **Enforced by:** key verification under tenant RLS; strict schemas; the policy engine.
- **Agent controls:** tool name, resource ID, parameters, idempotency key.
- **Agent never controls:** its identity, tenant, action type (derived from the tool), data classification (read from the resource), approval status.
- **Does not protect:** anything the agent can reach without the gateway; misuse within granted scope.

## B2. Browser to API

- **Trust:** authenticated, role-limited.
- **Crosses:** a bearer JWT, held server-side by the Next.js app in an `HttpOnly` cookie.
- **Enforced by:** signature, `exp`, `iss`, `aud`, and a database lookup of the user's status and role on each request.
- **Does not protect:** a stolen session within its 15-minute lifetime, if the user stays active.

## B3. API to database

- **Crosses:** SQL as `aegis_app`.
- **Enforced by:** grants, RLS with `FORCE`, append-only triggers, the approval transition trigger, composite foreign keys.
- **Does not protect:** against arbitrary SQL under `aegis_app`, which could set `app.tenant_id` freely. RLS is a strong guard against application bugs, not against SQL execution.

### Database roles

| Role | Attributes | Purpose | Tenant tables | Append-only tables |
|------|-----------|---------|---------------|--------------------|
| superuser | `SUPERUSER` | Bootstrap only: creates roles and the database. Never used by the application | Bypasses RLS | Bypasses RLS; triggers can be disabled |
| `aegis_owner` | `LOGIN`, no `SUPERUSER`, no `BYPASSRLS` | Runs Alembic | Owns tables; RLS `FORCE` applies | Triggers apply |
| `aegis_app` | `LOGIN`, no `SUPERUSER`, no `BYPASSRLS`, no `CREATE` | Application runtime | Per-table grants | `SELECT`, `INSERT` only |

## B4. Gateway to tool

- **Crosses:** validated, stored parameters.
- **Enforced by:** a single call site (`ToolExecutor.run`), which requires an `ExecutionClaim` object that only the gateway's claim functions create after writing the execution row.
- **Does not protect:** against other Python code in the same process, which could call a tool function directly. Python offers no real in-process isolation. A static test checks that only the executor calls tool handlers.

## B5. Tool to resource

- **Crosses:** tenant-scoped database reads, and writes to the simulated outbox.
- **Enforced by:** tools receive only the current tenant session and their validated parameters.
- **Does not protect:** nothing external is reachable in the MVP. Tools are synthetic: there is no shell, no file system access, and no outbound network access.

## B6. LLM to platform (future)

- **Rule:** LLM output is data. It may populate hypotheses and draft documents only.
- **Enforced today by:** no LLM client exists, and a static test forbids importing one into `aegis.policy` or `aegis.gateway`.

## Enforcement points and fail-closed behavior

| Enforcement point | On failure |
|-------------------|------------|
| Agent key verification | 401 with a generic message; failure audited when the tenant is resolvable |
| JWT verification | 401 |
| Role check | 403 |
| Request schema | 422 before any database access or tool call |
| Policy load or validation | Deny with a reason code |
| Policy evaluation | Deny with `POLICY_EVALUATION_ERROR` |
| Decision or audit persistence | Rollback, 503, no execution |
| Execution claim conflict | 409, no execution |
| Approval state check | 409, no execution |
| Action hash mismatch | Approval cancelled, no execution |

## Limitations of the audit mechanism

**The hash chain detects, and does not prevent.**

| Attacker | Result |
|----------|--------|
| API user, any role | Cannot modify. No endpoint exists |
| `aegis_app` database role | Cannot update or delete. Can insert false new events, or append to the chain head out of band |
| `aegis_owner` | Blocked by triggers until the owner drops them. Then can rewrite everything, including the chain |
| Superuser | Can rewrite everything, including all hashes and the head, **and verification will pass** |

The chain has value against partial tampering, accidental corruption, and any attacker
who lacks full database control. It is not a defense against a full database compromise
until heads are anchored outside the database's trust domain. `GET /api/v1/audit/head`
exposes the head so external anchoring can be added without a schema change.

Events prove what AEGIS *recorded*, not that it is true of the outside world. A
`SUCCEEDED` execution means the synthetic tool returned without error.
