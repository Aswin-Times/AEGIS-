# AEGIS

**AI Security, Governance & Control Platform.** *Trust your AI. Verify its actions. Govern its behavior.*

AI agents now hold real credentials: database passwords, API keys, access to customer records. Having
technical access to a resource does not mean every use of it is allowed, yet in most deployments nothing
sits between "the agent decided to" and "it happened". AEGIS is that missing control point, plus the
records needed to prove afterwards what did and did not happen.

> **Status: a working prototype, not a production product.** It has not been security-audited, and parts
> of it have never run against real external services. The [Status](#status) section says exactly what is
> built and what is not. Please read [Scope and honest limits](#scope-and-honest-limits) before relying
> on anything here.

## What AEGIS does

An agent never touches a resource directly. It sends AEGIS a **structured action request** (for example,
"read document 42" or "send this record to that address"). AEGIS then:

1. **Authenticates** the agent and works out which organization (tenant) it belongs to.
2. **Evaluates the request** with a deterministic policy engine: plain rules, no AI model involved. The
   result is *allow*, *deny*, or *hold for human approval*.
3. **Records the decision** in a tamper-evident audit log *before* anything runs.
4. **Runs the action** only if it was allowed, or a human approved that exact action, once.
5. **Records the outcome**, and turns suspicious patterns into incidents that people can investigate.

Around that enforcement core, AEGIS also provides the governance a security or compliance team asks for:
an inventory of every AI system, who owns it, how risky it is, who approved it, and what evidence backs
that approval.

### The seven questions it is built to answer

| # | Question | Answered by |
|---|----------|-------------|
| 1 | What AI applications and agents exist? | Asset and agent registry |
| 2 | What can each agent access? | Tool and resource grants |
| 3 | What actions are agents attempting? | Action requests and decisions |
| 4 | Are those actions authorized? | Deterministic policy engine |
| 5 | Can unsafe actions be stopped before they run? | Security gateway |
| 6 | Can activity be investigated with verifiable evidence? | Audit chain, incidents, investigations |
| 7 | Can governance be demonstrated? | Policy versions, approvals, risk assessments, evidence |

## How it works

```
  AI agent (API key)                    Person (browser)
        |                                      |
        |                          Next.js dashboard
        v                                      v
 +-------------------------------------------------------------+
 | FastAPI backend                                             |
 |                                                             |
 |  Security Gateway:  validate -> load facts -> policy engine |
 |                     -> record decision -> run tool -> record|
 |  Approvals:         a human approves ONE exact action, once |
 |  Control plane:     registry, policies, audit, incidents,   |
 |                     governance                              |
 +-------------------------------------------------------------+
        |   connects as a restricted database role
        v
   PostgreSQL: row-level security on every tenant table,
               append-only audit tables, hash-chained log
```

The design choices that matter most:

- **Deterministic enforcement.** Allow/deny decisions come from a pure function over recorded facts. No
  model, clock, or network call can influence them, so the same request always gets the same answer.
- **Evidence before effect.** The decision is written to the audit log before the tool runs. A crash
  leaves a record of intent, never a silent action.
- **Tamper-evident audit.** Every tenant has a hash-chained audit log. Editing or deleting history is
  rejected by the database and detected by verification.
- **Tenant isolation in the database.** Row-level security and composite foreign keys are enforced by
  PostgreSQL itself, and the application connects as a role that cannot bypass them.
- **Humans stay in charge.** An approval is bound to one exact action and can be used once. Reviewers
  cannot approve their own submissions by default.
- **AI is advisory only.** An optional language model can suggest hypotheses during an investigation.
  Its output is stored as clearly labeled text, cites evidence, and has no path into enforcement.

## Status

AEGIS is built in phases. The foundation (Phases 1 and 2) is on `main`. Phase 3 is under active
development on the `phase-3-governance` branch.

### Phases 1 and 2: on `main`

| Capability | State |
|------------|-------|
| AI asset and agent registry (API) | Built |
| Deterministic policy engine | Built |
| Controlled gateway with synthetic tools | Built |
| Human approval workflow | Built |
| Audit log with hash chain and verification | Built |
| Security events projected from the audit chain | Built |
| Deterministic incident correlation with versioned rules | Built |
| Incident lifecycle with recorded, audited transitions | Built |
| Evidence-backed investigations | Built |
| Optional LLM hypotheses | Built, **never run against a real provider** |
| Dashboard (real API data) | Built; registering assets is API-only |

### Phase 3, the Governance Engine: in progress on `phase-3-governance`

The design is in
[docs/superpowers/specs/2026-11-03-governance-engine-design.md](docs/superpowers/specs/2026-11-03-governance-engine-design.md)
and the build plan in
[docs/superpowers/plans/2026-11-03-governance-engine.md](docs/superpowers/plans/2026-11-03-governance-engine.md).
Every piece is built test-first and reviewed before it is committed.

| Piece | What it does | State |
|-------|--------------|-------|
| Governance roles and asset lifecycle | Governed state per AI asset, with enforced transitions and a hard block | Built |
| Governance profile and inventory | Purpose, owner, data categories, tool access, reviewed over time | Built |
| Deterministic risk engine | Integer scoring from recorded facts, versioned methodology, no AI scoring; missing information yields "incomplete", never "low" | Built |
| Versioned governance policies | Policy changes create new versions; nothing is edited silently | Built |
| Approval lifecycle | Submit, review, approve or reject, conditions, suspension, retirement, forced reassessment, separation of duties | Built |
| Evidence and verification | Evidence counts only after someone other than the submitter verifies it | Final fixes under review |
| NIST AI RMF and ISO/IEC 42001 mappings | NIST: only a partial subset of subcategories; ISO: not loaded, with no controls | Not built |
| Gateway enforcement | The gateway enforces governance status, in observe or enforce mode | Not built |
| Scheduled review worker | Flags overdue governance reviews | Not built |
| Governance Center (dashboard) | Next.js screens for all of the above | Not built |

The compliance mappings will be labeled partial or not loaded, because shipping an incomplete control
library under a full framework's name would be a false claim. AEGIS supports governance evidence; it does
not certify anyone as compliant with anything.

### Not built anywhere yet

OIDC single sign-on, login rate limiting, and external anchoring of the audit log (periodically
publishing its hash chain outside the database). Known risks and the order to address them are in
[docs/REMEDIATION_PLAN.md](docs/REMEDIATION_PLAN.md).

## Scope and honest limits

- **AEGIS protects only what goes through its gateway.** An agent holding its own database password or API
  key can bypass it, and AEGIS cannot detect that. Real credentials must sit behind the gateway, not with
  the agent. See [docs/SECURITY_BOUNDARIES.md](docs/SECURITY_BOUNDARIES.md).
- **Tools are synthetic.** The gateway runs demonstration tools that touch only the AEGIS database. There
  is no shell access and no general network access.
- **Demo data is synthetic.** The seeded organization is fake and labeled as such. Dashboard figures come
  from stored data, never hardcoded numbers.
- **The audit log is tamper-evident, not tamper-proof.** Someone with full database control can rewrite
  history and recompute the chain; external anchoring (above) is how that would be closed.
- **Docker Compose has not been run**, because the machine this was developed on has no Docker.
- **Do not treat this as production-ready.**

## Run it locally

You need Python 3.12 and Node 20 or later. Docker is not required: development uses an embedded
PostgreSQL 16 from the `pgserver` package.

```bash
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python scripts/dev_stack.py
```

On macOS or Linux, use `.venv/bin/python`. This starts the API at `http://127.0.0.1:8000`. The first run
seeds a clearly synthetic demo organization through the real API and writes its generated login to
`backend/.dev/demo-credentials.json`. Each start also applies migrations, backfills security events for
older audit records, and runs a background worker that correlates events into incidents.

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:3000` and sign in with those credentials. Delete `backend/.dev` to start over.

### Docker Compose

```bash
docker compose -f infra/docker-compose.yml up --build
```

### Optional: AI hypotheses

Investigations are complete without this. To add a model's hypotheses, install the extra and set three
variables. Doing so sends minimized evidence to the provider.

```bash
.venv/Scripts/python -m pip install -e ".[llm]"
```

| Variable | Value |
|----------|-------|
| `AEGIS_LLM_PROVIDER` | `anthropic` (default `none`) |
| `AEGIS_LLM_API_KEY` | Your API key |
| `AEGIS_LLM_MODEL` | Optional. Default `claude-opus-5-5` |

## Run the tests

```bash
cd backend
.venv/Scripts/python -m pytest
```

The suite has more than a thousand tests. They start their own temporary PostgreSQL, or use
`AEGIS_TEST_ADMIN_URL` if it is set, run the real migrations, and connect as the restricted runtime role,
so isolation and append-only rules are tested against the real database, not mocks.

```bash
cd backend
.venv/Scripts/python scripts/mutation_check.py
```

This removes each security control in a temporary copy of the code and requires at least one test to fail.
A control that no test notices is reported as uncaught.

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

## Repository layout

| Path | Contents |
|------|----------|
| `backend/src/aegis/` | The FastAPI application, one package per module (gateway, policy, approvals, audit, registry, incidents, governance, and so on) |
| `backend/migrations/` | Hand-written Alembic SQL migrations |
| `backend/tests/` | Unit, API, and security tests, including database isolation tests |
| `backend/scripts/` | Local dev stack and the mutation check |
| `frontend/` | The Next.js dashboard |
| `infra/` | Docker Compose configuration |
| `docs/` | Specification, architecture, threat model, and design records |

## Documentation

| Document | Covers |
|----------|--------|
| [PRODUCT_SPEC](docs/PRODUCT_SPEC.md) | Scope, roles, and non-goals |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Components, enforcement flow, failure behavior |
| [THREAT_MODEL](docs/THREAT_MODEL.md) | Threats, residual risk, and known gaps |
| [SECURITY_BOUNDARIES](docs/SECURITY_BOUNDARIES.md) | Trust boundaries and audit limitations |
| [API_CONTRACTS](docs/API_CONTRACTS.md) | Endpoints, schemas, and errors |
| [DATABASE_DESIGN](docs/DATABASE_DESIGN.md) | Schema, RLS, grants, and triggers |
| [TEST_STRATEGY](docs/TEST_STRATEGY.md) | What is tested and how |
| [DECISIONS](docs/DECISIONS.md) | Architectural decisions and trade-offs |
| [INCIDENT_PIPELINE](docs/INCIDENT_PIPELINE.md) | Events, correlation, lifecycle, and investigation |
| [REMEDIATION_PLAN](docs/REMEDIATION_PLAN.md) | Known risks and the proposed order to address them |
| [Governance engine design](docs/superpowers/specs/2026-11-03-governance-engine-design.md) | The Phase 3 specification |
| [Governance engine plan](docs/superpowers/plans/2026-11-03-governance-engine.md) | The Phase 3 build plan |
