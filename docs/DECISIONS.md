# AEGIS Decision Log

## D-001: Modular monolith
**Decision:** One API process, one database. **Why:** Nothing yet needs independent
scaling, and synchronous enforcement is simpler and safer in one transaction domain.
**Cost:** The gateway cannot scale separately from the control plane. Package boundaries
keep a later split possible.

## D-002: Own deterministic policy engine, not OPA
**Decision:** A small Python rule engine that is a pure function. **Why:** The required
rules are few, and a pure function in the same process cannot time out or be unreachable.
OPA would add a dependency without adding enforcement today. **Revisit:** When customers
need to author complex policy, or policy must be shared with other systems.

## D-003: Sync SQLAlchemy and psycopg 3, sync FastAPI handlers
**Decision:** Threadpool handlers, no asyncio database access. **Why:** Transactions,
row locks, and `SET LOCAL` are easier to get right and to test with plain sync code; the
`set_config` context cannot leak across `await` points. **Cost:** Throughput per process
is bounded by the thread pool. Acceptable for a low-rate control point.

## D-004: Fixed hard checks before configurable rules
**Decision:** Agent status, tool grant, resource grant, kind match, and destination
clearance are enforced in code before policy rules, and rules cannot override them.
**Why:** A permissive policy document must not be able to disable tenant-level invariants.
Rules can only further restrict what grants already permit. **Cost:** Less flexible, by
intent.

## D-005: Default deny with deny-overrides precedence
**Decision:** Any deny, then any require_approval, then any allow; no match is a deny.
**Why:** The result does not depend on rule order, which makes policies reviewable and
evaluation reproducible.

## D-006: Per-tenant linear audit chain, locked on append
**Decision:** A head row is locked within the transaction that appends. **Why:** The
simplest correct linear chain, and evidence commits atomically with the decision. **Cost:**
Decisions in a tenant serialize on the head row until commit. Acceptable for the MVP; the
known path out is batching into a Merkle tree. A hash chain does not stop a privileged
attacker (see `SECURITY_BOUNDARIES.md`).

## D-007: Evidence before effect; at-most-once execution
**Decision:** The execution row commits before the tool runs. A crash leaves `STARTED`,
and nothing retries it. **Why:** For sensitive operations, losing an action is safer than
repeating one, and an unrecorded effect is the worst outcome. **Cost:** Operators must
resolve stale `STARTED` records by hand.

## D-008: Local login with EdDSA JWTs; OIDC behind the same verifier later
**Decision:** Argon2id password login that issues 15-minute Ed25519-signed JWTs with `iss`,
`aud`, `sub`, `exp`, `jti`. Roles are read from the database on each request. **Why:** No
identity provider exists in this environment, and the milestone needs real authentication
rather than a mock. The token shape matches OIDC, so an IdP verifier can replace the local
issuer. **Cost:** No refresh tokens, so re-login every 15 minutes. No rate limiting yet.

## D-009: Fixed roles, not a permissions table
**Decision:** `admin`, `reviewer`, `viewer` as a checked column. **Why:** A permissions
table without custom roles adds surface and no capability. **Revisit:** When custom roles
are required.

## D-010: Agent keys embed the tenant ID
**Decision:** `aegis_agent.<tenant>.<credential>.<secret>`. **Why:** The tenant can be set
before any credential lookup, so authentication needs no RLS bypass. An altered tenant
segment finds no credential under RLS. **Cost:** The key reveals the tenant ID, which is
not a secret.

## D-011: Embedded PostgreSQL for no-Docker development and tests
**Decision:** `pgserver` (a dev-only dependency that ships PostgreSQL 16 binaries) when
Docker is unavailable, alongside a Compose file. **Why:** The development machine has no
Docker, and tests must use real PostgreSQL. **Cost:** A third-party binary source in the dev
toolchain. It is never used in deployment. The Compose file has not been run on this
machine.

## D-012: Destinations are registered resources
**Decision:** `send_message` takes a resource ID, never a URL or address. **Why:** An
allowlist of IDs cannot be bypassed with URL tricks. **Cost:** Every destination must be
registered first.

## D-013: Executing an approved action is an agent call, with no body
**Decision:** After approval, the agent calls `POST /gateway/actions/{id}/execute`, with no
parameters. **Why:** The approver's session never runs tools, the agent receives its own
result, and the absence of a body rules out parameter changes. Parameters are read from
the stored request and the hash is recomputed.

## D-014: No four-eyes rule between agent owner and approver yet
**Decision:** Any reviewer or admin in the tenant may approve. **Why:** `owner` is a free-text
label in the MVP, not a user reference, so the rule could not be enforced honestly.
**Revisit:** When owners become user references.

## D-015: Development on `main` for the initial build
**Decision:** The repository starts empty, and the project owner asked for work to be pushed
after each step, so milestone commits go directly to `main`. **Revisit:** Move to pull requests
once CI is running on GitHub.

## D-016: Column-level update grants for the runtime role
**Decision:** The runtime role may update only named columns. **Why:** The approval trigger
protects binding columns, but a grant that never existed cannot be misused, and a test can
compare the grants against the live catalog. **Cost:** A migration is needed whenever a new
column must become updatable.

## D-017: Unbuilt views are absent, not stubbed
**Decision:** The dashboard has no Incidents or Governance pages until those features exist.
**Why:** An empty page would imply a capability the system does not have. Security Events
currently shows policy decisions, the only event source that exists.

## D-018: Playwright with the installed browser
**Decision:** End-to-end tests use `channel: msedge` locally. **Why:** It needs no browser
download, and it works without a visible window. **Cost:** Results come from one browser engine.
