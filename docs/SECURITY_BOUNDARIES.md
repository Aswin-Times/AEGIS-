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

## B7. Governance to gateway (Phase 3)

- **Crosses:** governance facts read inside the gateway's own transaction: the mode, the asset's
  state row, the hard block, the current decision's conditions, `valid_until`, and the gateway's
  clock.
- **Enforced by:** a pure check (`governance/engine/enforcement.py`) whose verdict can only tighten
  the policy outcome, never loosen it, and never replaces a deny's reason code. Lifecycle changes
  lock the asset's agent rows `FOR NO KEY UPDATE` before the state row, which serializes them
  against in-flight evaluations.
- **Governance never controls:** whether a tool exists, is granted, or matches its resource; those
  hard checks and the runtime policy run first.
- **Does not protect:** anything outside the gateway; individual agents (status is per asset);
  unapproved assets while the tenant is in `observe`; and an asset whose profile states false
  facts, since assessments trust declared inputs except tool access.

## Governance limits

These are the spec's known limits (section 17) and those found while building it. `THREAT_MODEL.md`
lists them with their threats.

- `observe`, the default, enforces only decisions a person made (retired, hard block, conditions).
  Expired and unapproved assets are recorded, not stopped, until an admin switches to `enforce`.
- Assessments trust the declared profile; only tool access is observed. Default weights are
  judgment, not calibration.
- Governance is asset-level. All agents of an asset share its status.
- Two admins can grant each other `governance_reviewer` and collude. A stolen admin session can grant
  it to another account. Both are audited, not prevented.
- Someone with database control can forge governance records as they can any other. Some read
  paths (counted votes, review status, evidence verifications) trust stored rows without
  re-checking their audit events.
- External documents over 16,000 bytes can only be attested, not hash-checked.
- A verification by a reviewer whose grant is later revoked still counts.
- An expired but unprocessed approval is handled by the gateway's own clock; the review worker only
  aligns the status. A passed review date also forces reassessment.
- Most policy controls are shown to the reviewer, not enforced; `reassessment_interval_days` does
  not bound approval dates.
- The NIST AI RMF library is partial (19 of 72 subcategories) and ISO/IEC 42001 is not loaded. A
  framework mapping is not a certification.
- A mode switch is not serialized against in-flight evaluations.
- The dashboard cannot suspend, revoke, retire, request reassessment, or add evidence; those are
  API-only.

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
| Governance check raises | `enforce`: deny, `GOVERNANCE_EVALUATION_ERROR`. `observe`: recorded and not blocking, except a retired or hard-blocked asset, which is still denied |
| Governance check hits a database error | Rollback, 503, no execution, in both modes |
| Stored conditions fail their hash or no longer parse | Deny, `GOVERNANCE_INTEGRITY_FAILED`, in both modes |
| Stored governance policy, methodology, profile, assessment, or review fails its integrity check | 503 with the matching `*_INTEGRITY_FAILED` code |

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
