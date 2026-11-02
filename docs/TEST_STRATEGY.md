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
| Investigation integrity | **Not yet: the feature does not exist (Phase 4)** |

## Static guards

Tests that read the source and fail on a structural regression:

- Every table with a `tenant_id` column has RLS enabled and forced (checked against the live catalog).
- Only the executor invokes tool handlers.
- `aegis.policy` and `aegis.gateway` import no LLM clients.
- `aegis.policy.engine` imports no I/O or clock modules.
- No route accepts a `tenant_id` input.

## Frontend

- `npm run typecheck`, `npm run lint`, `npm run build`.
- Manual browser verification against a live backend for milestone 1. Automated end-to-end tests are deferred and listed as a gap.

## Reporting

Each milestone reports executed, passed, failed, and skipped counts from an actual run,
along with properties verified and unverified. Skipped tests are never reported as
passing.
