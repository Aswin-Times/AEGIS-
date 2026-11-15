# AEGIS Test Strategy

## Principles

- Security tests **attempt the violation**. A passing happy path proves nothing about security.
- Tests run against **real PostgreSQL**, connected as the real `aegis_app` role, because RLS, grants, triggers, and row locks are the subject under test. SQLite or mocks would make them meaningless, and a superuser connection would bypass RLS and pass falsely.
- Tool execution is observed by a **spy** registered in the tool registry, so "the tool never ran" is measured rather than assumed.
- All fixtures are synthetic. Tests never run against a production database. The harness creates a throwaway database and drops it.

## Database for tests

| Environment | Source |
|-------------|--------|
| No Docker (default) | The `pgserver` dev dependency runs PostgreSQL 16 from a temporary directory |
| Docker or CI | Set `AEGIS_TEST_ADMIN_URL` to a superuser connection |

The harness creates `aegis_owner` and `aegis_app`, creates a fresh database, runs the
real Alembic migrations as `aegis_owner`, and connects the application as `aegis_app`.
The migrations are therefore tested too.

A separate superuser connection exists **only** in tests that simulate an attacker with
database control (for example, tampering with an audit row to confirm that verification
catches it).

## Layout

```
backend/tests/
  unit/       Pure logic: policy engine, canonicalization, approval state machine
  security/   Attempted violations against the API and database
  api/        Contract tests: registry, pagination, error shapes
```

## Required coverage

| Spec area | Test file |
|-----------|-----------|
| Authorization | `security/test_authz.py`, `security/test_gateway.py` |
| Authentication | `security/test_authn.py` |
| Tenant isolation | `security/test_tenant_isolation.py` |
| Policy enforcement | `security/test_policy_enforcement.py`, `unit/test_policy_engine.py` |
| Policy versions | `security/test_policy_versions.py` |
| Approval safety | `security/test_approval_safety.py` |
| Audit integrity | `security/test_audit_integrity.py` |
| Database privileges and catalog | `security/test_tenant_isolation_db.py` |
| Dashboard, full stack | `frontend/e2e/dashboard.spec.ts` |
| Security events | `security/test_security_events.py` |
| Correlation | `security/test_correlation.py`, `unit/test_correlation_rules.py` |
| Incident lifecycle | `security/test_incident_lifecycle.py` |
| Investigation integrity | `security/test_investigation.py` |
| LLM layer | `security/test_llm_investigation.py`, `unit/test_llm_prompt_shape.py`. Fake providers and a mock transport only |
| Governance roles and separation of duties | `security/test_governance_roles.py`, `security/test_governance_separation.py` |
| Governance profiles, state, and lifecycle | `security/test_governance_assets.py`, `security/test_governance_lifecycle_actions.py`, `unit/test_governance_lifecycle.py` |
| Risk assessment and methodologies | `security/test_governance_assessments.py`, `unit/test_governance_risk.py` (with hypothesis) |
| Governance policies | `security/test_governance_policies.py`, `unit/test_governance_policy_engine.py` |
| Reviews, decisions, and approvals | `security/test_governance_approvals.py` |
| Evidence and verification | `security/test_governance_evidence.py` |
| Frameworks and control status | `security/test_governance_compliance.py`, `unit/test_governance_frameworks.py` |
| Gateway enforcement of governance | `security/test_governance_gateway.py`, `unit/test_governance_enforcement.py`, `unit/test_governance_conditions.py` |
| Review scheduling | `security/test_governance_reviews.py` |
| Governance tenant isolation | `security/test_governance_isolation.py` |
| Governance API contracts | `api/test_governance_contracts.py` |
| Final security audit attempts | `security/test_governance_audit.py` |
| Full governance workflow | `security/test_governance_workflow.py`, `frontend/e2e/governance-workflow.spec.ts` |
| Governance Center, full stack | `frontend/e2e/governance*.spec.ts` |

Phase 3 did not modify existing tests apart from the permitted additions: `EXPECTED_*` entries and the
third function name in `test_tenant_isolation_db.py`, new helpers in `tests/support.py`
(`AgentHandle` gained an `asset_id` field; no existing helper changed behavior), one setting in
`tests/conftest.py` (`governance_worker_enabled=False`), and two new tests appended to
`security/test_correlation.py` for the new `asset_id` filter on `/incidents`, with no existing
assertion touched. In the frontend, one locator in `e2e/dashboard.spec.ts` was pinned to an exact
match after the decision page began showing governance evidence (ledger ruling, Task 16).

## The governance workflow proof

`security/test_governance_workflow.py::test_complete_governance_workflow` follows spec section 1
through the public API, one block per step: register an agent, assign two owners, assess it,
verify evidence, submit it, review it and approve it with conditions, switch to `enforce` and have
the gateway run the allowed tool and deny the one the condition names (with a real agent key and
the tool spy), suspend it and see `GOVERNANCE_BLOCKED`, approve a second asset for a day and see
`GOVERNANCE_APPROVAL_EXPIRED` once the test moves the clock past expiry, and read the full history
in audit order. The people are distinct: an admin submits and adds evidence, a reviewer granted
`governance_reviewer` by that admin verifies and decides, and two other users own the asset. The
database is read only to check that what the API returned refers to rows that exist and agree.

`frontend/e2e/governance-workflow.spec.ts` repeats the workflow in a browser, in a synthetic tenant of
its own. Owners, purpose, assessment, submission, review, and the decision are made on the pages;
the gateway is called with the agent's real key; the history is read on the page. Registering the
agent, adding evidence, and suspending go through the API, because the dashboard has no control for
them.

## Proving the tests can fail

`backend/scripts/mutation_check.py` copies the backend to a temporary directory, removes one
security control at a time (a role check, a grant, a trigger, a re-evaluation), and requires a
test to fail. A control whose removal goes unnoticed is reported as `SURVIVED`. Its first run
found four such gaps, and its run over the Phase 2 controls found eight more. All twelve were weak tests or
redundant locks rather than missing enforcement, and each led to a stronger test. Run it after changing an
enforcement path.

Phase 3 added a mutation for each new enforcement control, including the two controls added by the
Task 21 audit. A `STALE` result means a mutation's target text no longer exists, so the check
proves nothing for it; it is treated as a failure, like `SURVIVED`.

## The Task 21 regression run (2026-11-15)

| Check | Result |
|-------|--------|
| Backend, `pytest -q -rs` | 1352 passed, 0 failed, 0 skipped (18 min 49 s) |
| `ruff check src tests scripts migrations` | Clean |
| `scripts/mutation_check.py`, all mutations in one pass | 157 of 157 caught; 0 `SURVIVED`, 0 `STALE` |
| Frontend `npm run lint`, `npm run typecheck`, `npm run build` | All clean |
| Frontend `npm run test:e2e`, Microsoft Edge, against the dev stack | 68 passed, 0 failed, 0 skipped |

## What is not covered

- **Expiry and the review worker in the browser.** The browser cannot move the server's clock, so
  expiry and the worker's moves are proven in backend tests, and the browser workflow reaches them
  only through the API.
- **Evidence submission, suspend, revoke, retire, reassess in the browser.** The dashboard has no
  controls for them; browser tests call the API for those steps.
- **Docker Compose** has never been run.
- **A real LLM provider** has never been called; only fakes and a mock transport.
- **Load and soak.** No load test, and the review worker has never run for long periods.
- **An external penetration test** has not been done. The security reviews and the Task 21 audit
  were internal.
- **One browser engine.** Browser tests run on Microsoft Edge only.
- **No frontend unit tests.** Page logic such as paging helpers is reached only through end-to-end
  tests.
- **Production readiness** has not been assessed.

## Static guards

Tests that read the source and fail on a structural regression:

- Every table with a `tenant_id` column has RLS enabled and forced (checked against the live catalog).
- Only the executor invokes tool handlers.
- `aegis.policy` and `aegis.gateway` import no LLM clients.
- `aegis.policy.engine` imports no I/O or clock modules.
- No route accepts a `tenant_id` input.
- Exactly three `SECURITY DEFINER` functions exist, by name.
- `aegis.governance.engine` imports no I/O, clock, or LLM module, and governance modules import no
  LLM client and never import `aegis.registry.service` or `aegis.gateway.service`.
- Every governance history table has the row and truncate `aegis_reject_mutation` triggers, and every
  governance route refuses an agent principal (`test_governance_audit.py`).

## Frontend

- `npm run typecheck`, `npm run lint`, `npm run build`.
- `npm run test:e2e`: Playwright, in a real browser, against the running stack. An actual agent key drives the gateway, and the test then checks what the dashboard shows. It uses the installed Microsoft Edge by default; set `AEGIS_E2E_CHANNEL=""` to use Playwright's Chromium.
- No frontend unit tests yet. The components hold little logic, so end-to-end coverage came first.

## Reporting

Each milestone reports executed, passed, failed, and skipped counts from an actual run,
along with properties verified and unverified. Skipped tests are never reported as
passing.
