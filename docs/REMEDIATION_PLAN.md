# Remediation Plan for Known Security Risks

Phase 2 did **not** solve these risks, apart from the partial mitigations stated below. Each entry
says where it stands and what closing it would take. They are ordered by how directly they can hurt
a real deployment.

## Risk register

| # | Risk | Status after Phase 2 | Severity |
|---|------|----------------------|----------|
| 1 | Sensitive text in a message to an approved destination is not blocked | **Open.** A test records it. Investigations now state the gap | High |
| 2 | Password guessing has no rate limit | **Open** for login attempts. Failure *recording* is now limited, which protects the audit chain only | High |
| 3 | Arbitrary SQL under the runtime role can switch tenant | **Open.** A test records it | High |
| 4 | Someone with full database control can rewrite the whole audit chain | **Open.** A test records it. Investigations now state the gap | High |
| 5 | Any reviewer can approve any action, and one admin can activate a policy | **Open** | Medium |
| 6 | Tool results, including sensitive content, are retained in `executions.result` | **Open.** Events, timelines, and evidence never expose them | Medium |
| 7 | A crash can leave an execution in `STARTED` | **Open.** Investigations now report it as "no recorded outcome" instead of guessing | Medium |
| 8 | Docker Compose has never been run | **Open.** CI has now run and passed on GitHub | Low |
| 9 | Correlation thresholds are public, so an attacker can stay just below them | **New, accepted for now** | Medium |
| 10 | Anyone who knows a tenant ID can trigger authentication failure events and one incident | **New, limited.** At most one active incident per scope, and recording is limited per process | Medium |
| 11 | The real LLM provider has never been called | **New.** Tested only against a mock transport | Low |
| 12 | No dashboard content security policy | **Open** | Low |
| 13 | Action parameters, including message bodies, are kept indefinitely in `action_requests` and `simulated_outbox`. No data has a retention or deletion path | **Open.** Found in the Phase 2 audit | Medium |
| 14 | Any role, including read-only viewers, can read full action parameters through the approval queue | **Open.** Found in the Phase 2 audit | Medium |
| 15 | One admin can disable a correlation rule. It is audited, but nothing alerts, and the dashboard has no view of rules | **Open** | Medium |
| 16 | `not_visible_references` also fires on honest mistakes, such as stale links, at `high` severity. The browser tests triggered it | **Open.** Investigations state it cannot confirm a cross-tenant attempt | Medium |
| 17 | Evidence and timelines verify each event per request, and neither has been load tested | **Open** | Low |
| 18 | `pytest` 8.4.2 has a published advisory (PYSEC-2026-1845, fixed in 9.0.3). It is a development dependency and is not deployed | **Open** | Low |

## Proposed order of work

### Step 1: Login and authentication throttling (risks 2, 10)

Add per-account and per-source limits in a shared store, since the current limiter is per process.
Rejected attempts return 429 before password hashing runs. Add a test that a flood is throttled across
two API processes.

### Step 2: Sensitive data flow control (risk 1)

Track, per agent session, whether sensitive data was read through the gateway. Hold any later outbound
message for approval. This needs a session concept, which does not exist yet, so design it first. It
will not catch every path, so it should be described as reducing the risk rather than removing it.

### Step 3: Anchor the audit chain externally (risk 4)

Publish chain heads on a schedule to storage the database administrator cannot write, such as object
lock storage. Verification then compares against the anchored head. This narrows the undetected
rewrite to the time since the last anchor. The API already exposes `GET /audit/head` for this.

### Step 4: Separation of duties (risk 5)

Make agent owners real user references, then refuse approval by the agent's owner. Require a second
admin to activate a policy version or a correlation rule change, and show rule versions in the dashboard
(risk 15).

### Step 5: Database hardening (risk 3)

Reduce what a stolen runtime credential can do. Sign the tenant context in a way the database verifies,
or run per-tenant roles. This has real cost and complexity, so it needs its own design. Also restrict
network access to the database at deployment.

### Step 6: Execution records (risks 6, 7)

Store only a digest of each tool result and make retries return a status rather than content, or
encrypt results with a retention limit. Apply the same to stored action parameters, and define a retention
policy for all of this data. Limit parameter visibility to reviewers (risks 13, 14). Add an operator
workflow to review and resolve executions stuck in `STARTED`.

### Step 7: Delivery checks (risks 8, 11, 12, 16, 17, 18)

Run Compose on a machine with Docker and add it to CI. Run the Claude provider once against the real API
with synthetic evidence. Add a nonce-based content security policy. Tune the `not_visible_references`
severity using real data, load test investigations, and upgrade `pytest`.

## What Phase 2 changed for these risks

- Failure recording is limited, and suppressed failures are still counted (risks 2, 10). This was
  prioritized because unauthenticated writes directly affect the new pipeline.
- Investigations state risks 1, 4, and 7 as evidence gaps whenever they apply, so a reviewer is not led
  to assume otherwise.
- No new path exposes tool results or message bodies (risk 6).
