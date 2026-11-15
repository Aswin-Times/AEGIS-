# Remediation Plan for Known Security Risks

Phase 2 did **not** solve these risks, apart from the partial mitigations stated below. Phase 3 (the
Governance Engine) added risks 19 to 31, from its final security audit (Task 21) and its build. Each entry
says where it stands and what closing it would take. They are ordered by how directly they can hurt
a real deployment.

## Risk register

| # | Risk | Status after Phase 2 | Severity |
|---|------|----------------------|----------|
| 1 | Sensitive text in a message to an approved destination is not blocked | **Open.** A test records it. Investigations now state the gap | High |
| 2 | Password guessing has no rate limit | **Open** for login attempts. Failure *recording* is now limited, which protects the audit chain only | High |
| 3 | Arbitrary SQL under the runtime role can switch tenant | **Open.** A test records it | High |
| 4 | Someone with full database control can rewrite the whole audit chain | **Open.** A test records it. Investigations now state the gap | High |
| 5 | Any reviewer can approve any action, and one admin can activate a policy | **Partly addressed in Phase 3** for governance only: asset owners are user references, and governance approvals refuse the submitter and owners unless a policy permits it. Runtime action approvals and runtime policy activation are unchanged | Medium |
| 6 | Tool results, including sensitive content, are retained in `executions.result` | **Open.** Events, timelines, and evidence never expose them | Medium |
| 7 | A crash can leave an execution in `STARTED` | **Open.** Investigations now report it as "no recorded outcome" instead of guessing | Medium |
| 8 | Docker Compose has never been run | **Open.** CI has now run and passed on GitHub. Still unrun after Phase 3 | Low |
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
| 19 | Governance policy controls other than `minimum_approvers`, `self_approval`, `owner_approval` and the finding-producing fields are descriptive. In particular `reassessment_interval_days` does not bound an approval's `next_review_at` or `valid_until` (`approvals.py` `_require_dates`), and `required_evaluations`, `required_documentation` and `incident_reporting` produce no finding (`engine/policies.py` `_findings`) | **Open.** Found in the Task 21 audit. Frozen on the review and shown to the reviewer | Medium |
| 20 | The dashboard has no controls for adding evidence, suspending, revoking, retiring, or requesting reassessment (spec 7.4, 14). The emergency stop is API-only | **Open.** Carried from Task 20 | Medium |
| 21 | Findings are frozen at submission, so evidence rejected later does not add a finding to an open review, and an approval may cite evidence whatever its current verification status | **Accepted for now.** The approval page shows each item's current status | Low |
| 22 | Governance rows are not anchored to their audit events on read. Only two reads compare a row with its own audit event: a review's frozen values are compared with its `SUBMIT` decision's audit payload when a decision is made (`approvals.py` `verify_review_anchored`), and an evidence row is compared with its `evidence_submitted` event when it is verified. Other rows are checked at most against a hash stored in the same row, which someone who can write the row can recompute: policy and methodology versions, review `frozen_hash`, decision `conditions_hash` (the gateway reads conditions from the decision row alone), and profile hashes at submission and decision. Nothing compares decision rows, counted votes, review status and withdrawals, evidence verifications, control assessments, or policy and methodology events with their audit events; `run_assessment` reads the current profile without checking its hash; and the `content_hash`, `input_hash`, and `result_hash` values written into audit payloads are never read back. Someone with database control can therefore change these rows undetected (T11, T15) | **Open** | Medium |
| 23 | The 500 handler logs exception messages. Database parameters are now hidden (fixed in Task 21), but an exception raised in a service whose message echoes a value would still be logged. A NUL byte in text gives 500 rather than 422 | **Partly fixed** | Low |
| 24 | `_is_seeded` compares control counts, so once a seeded framework gains controls every compliance read takes the per-tenant advisory lock | **Open.** Performance only | Low |
| 25 | A concurrent evidence rejection caught by the control-assessment trigger returns 409 `ALREADY_EXISTS` instead of `EVIDENCE_REQUIRED` | **Open.** Fails closed with a misleading code | Low |
| 26 | Unpaged reads: the preflight lists every asset; the risk page reads methodologies and history with `limit=100`; the control detail page loads every control, evidence item and asset | **Open** | Low |
| 27 | Review worker: more than 500 persistently failing assets can hide later due ones, and `stop()` waits 10 seconds, which a long pass can outlast. Expiry does not depend on the worker | **Open** | Low |
| 28 | The dashboard's `submittedValues` copies every submitted form field back into client state after a refusal. Harmless today; a future sensitive field would be echoed to the browser that sent it | **Open** | Low |
| 29 | The NIST AI RMF library is partial (19 of 72 subcategories) and ISO/IEC 42001 is not loaded. ISO can reach existing tenants only through a new seeding migration | **Accepted.** Stated in the product | Low |
| 30 | Two admins can grant each other `governance_reviewer` and collude; a stolen admin session can grant it to another account | **Accepted.** Audited, not prevented | Medium |
| 31 | A governance hold at the re-evaluation of an action a person already approved does not block it, but the re-evaluation decision is recorded as `REQUIRE_APPROVAL` beside a `SUCCEEDED` execution, which reads oddly in the audit record | **Open.** Audit-record clarity only; enforcement is as designed (spec 11.2) | Low |

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

### Step 8: Governance follow-ups (risks 19 to 28, and 31)

In this order. First, add dashboard controls for suspend, revoke, reassess, retire, and adding
evidence, so the emergency stop does not need the API (risk 20). Second, decide with the product
owner whether `reassessment_interval_days` should refuse an approval whose dates exceed it, and
make the other descriptive controls produce findings (risk 19). Third, compare decisions, votes, review
status, verifications, and control assessments with their audit events on read, and use the hash
anchors already written (risk 22). Then the Low items (21, 23 to 28, 31).

## What the Phase 3 audit fixed (Task 21)

- Database errors were logged with their bound parameters, so a refused insert could write inline
  evidence text to the logs. Fixed with `hide_parameters=True`
  (`test_governance_audit.py::test_evidence_content_never_reaches_the_logs`).
- In `observe`, an exception in the governance check let a retired or hard-blocked asset act. Rows
  1 and 2 are now read from the state row alone
  (`test_an_evaluation_error_never_lets_a_blocked_asset_through_in_observe`).
- Reviews were listed by `submitted_at`, so the asset page could show a withdrawn review as the
  latest if the clock stepped back. They are now ordered by the audit sequence of their `SUBMIT`
  (`test_latest_review_is_the_latest_by_audit_sequence_not_by_clock`).

## What Phase 2 changed for these risks

- Failure recording is limited, and suppressed failures are still counted (risks 2, 10). This was
  prioritized because unauthenticated writes directly affect the new pipeline.
- Investigations state risks 1, 4, and 7 as evidence gaps whenever they apply, so a reviewer is not led
  to assume otherwise.
- No new path exposes tool results or message bodies (risk 6).
