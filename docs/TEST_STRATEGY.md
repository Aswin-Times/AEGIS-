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
| Investigation integrity | **Not yet: the feature does not exist (Phase 4)** |

## Proving the tests can fail

`backend/scripts/mutation_check.py` copies the backend to a temporary directory, removes one
security control at a time (a role check, a grant, a trigger, a re-evaluation), and requires a
test to fail. A control whose removal goes unnoticed is reported as `SURVIVED`. Its first run
found four such gaps, which led to new tests. Run it after changing an enforcement path.

## Static guards

Tests that read the source and fail on a structural regression:

- Every table with a `tenant_id` column has RLS enabled and forced (checked against the live catalog).
- Only the executor invokes tool handlers.
- `aegis.policy` and `aegis.gateway` import no LLM clients.
- `aegis.policy.engine` imports no I/O or clock modules.
- No route accepts a `tenant_id` input.

## Frontend

- `npm run typecheck`, `npm run lint`, `npm run build`.
- `npm run test:e2e`: Playwright, in a real browser, against the running stack. An actual agent key drives the gateway, and the test then checks what the dashboard shows. It uses the installed Microsoft Edge by default; set `AEGIS_E2E_CHANNEL=""` to use Playwright's Chromium.
- No frontend unit tests yet. The components hold little logic, so end-to-end coverage came first.

## Reporting

Each milestone reports executed, passed, failed, and skipped counts from an actual run,
along with properties verified and unverified. Skipped tests are never reported as
passing.
