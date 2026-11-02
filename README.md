# AEGIS

**AI Security, Governance & Control Platform.** *Trust your AI. Verify its actions. Govern its behavior.*

AEGIS is an enforcement point between AI agents and the resources they use. An agent submits a
structured action, a deterministic policy engine allows, denies, or holds it for human approval,
and every decision goes into a tamper-evident audit log before anything runs.

AEGIS protects only operations routed through its gateway. An agent holding its own credentials
to a resource can bypass it. See [docs/SECURITY_BOUNDARIES.md](docs/SECURITY_BOUNDARIES.md).

## Status: milestone 1

| Capability | State |
|------------|-------|
| AI asset and agent registry (API) | Built |
| Deterministic policy engine | Built |
| Controlled gateway with synthetic tools | Built |
| Human approval workflow | Built |
| Audit log with hash chain and verification | Built |
| Dashboard (real API data) | Built, read-focused; registration is API-only |
| Security event correlation and incidents | **Not built** |
| Governance engine | **Not built** |
| OIDC, rate limiting, external audit anchoring | **Not built** |

Known gaps are listed in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Do not treat this as
production-ready.

## Run it locally

You need Python 3.12 and Node 20 or later. Docker is not required: development uses an embedded
PostgreSQL 16 from the `pgserver` package.

```bash
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python scripts/dev_stack.py
```

On macOS or Linux, use `.venv/bin/python`. This starts the API at `http://127.0.0.1:8000`. The
first run seeds a clearly synthetic demo organization through the real API, and writes its
generated login to `backend/.dev/demo-credentials.json`.

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:3000` and sign in with those credentials. Delete `backend/.dev` to start
over.

### Docker Compose

```bash
docker compose -f infra/docker-compose.yml up --build
```

> Compose has **not been run**: the machine this was built on has no Docker.

## Run the tests

```bash
cd backend
.venv/Scripts/python -m pytest
```

Tests start their own temporary PostgreSQL, or use `AEGIS_TEST_ADMIN_URL` if it is set. They run
the real migrations and connect as the restricted runtime role.

```bash
cd backend
.venv/Scripts/python scripts/mutation_check.py
```

This removes each security control in a temporary copy, and requires a test to catch it.

```bash
cd frontend
npm run lint
npm run typecheck
npm run build
```

With the stack running:

```bash
cd frontend
npm run test:e2e
```

Browser tests use the installed Microsoft Edge. To use Playwright's Chromium, run
`npx playwright install chromium` and set `AEGIS_E2E_CHANNEL=""`.

## Documentation

| Document | Covers |
|----------|--------|
| [PRODUCT_SPEC](docs/PRODUCT_SPEC.md) | Scope, roles, and non-goals |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Components, enforcement flow, failure behavior |
| [THREAT_MODEL](docs/THREAT_MODEL.md) | 20 threats, residual risk, and known gaps |
| [SECURITY_BOUNDARIES](docs/SECURITY_BOUNDARIES.md) | Trust boundaries and audit limitations |
| [API_CONTRACTS](docs/API_CONTRACTS.md) | Endpoints, schemas, and errors |
| [DATABASE_DESIGN](docs/DATABASE_DESIGN.md) | Schema, RLS, grants, and triggers |
| [TEST_STRATEGY](docs/TEST_STRATEGY.md) | What is tested and how |
| [DECISIONS](docs/DECISIONS.md) | Architectural decisions and trade-offs |
