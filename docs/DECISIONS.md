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

## D-019: Security events are projected from the audit chain
**Decision:** One security event per relevant audit event, in the same transaction. **Why:** One source
of truth, atomic evidence, and a way to verify a stored event by reprojecting it. **Cost:** Changing a
mapping requires a new schema version, or older events would fail verification.

## D-020: Correlation runs after commit, in an in-process worker
**Decision:** A polling thread, not Redis Streams and not inside the gateway transaction. **Why:**
Enforcement must not depend on detection, and a database table already gives durable, retryable work
with no new infrastructure. **Cost:** Detection lags by a poll interval, and it runs per API process, so
several processes rely on row locks and the unique index to cooperate.

## D-021: One event per correlation transaction, holding the chain lock
**Decision:** Each event gets its own transaction, and takes the chain head first. **Why:** Simple
reasoning about retries, serial correlation per tenant, and a single lock order with incident changes
to prevent deadlock. **Cost:** Correlation contends with gateway decisions for the same tenant. Acceptable
for the MVP, and measured only by the concurrency tests, not under load.

## D-022: Failure recording is limited, and the count is kept
**Decision:** After the limit, failed authentications are counted and not individually recorded. **Why:**
An unauthenticated attacker could otherwise write without limit to a tamper-evident log that also drives
incidents. **Cost:** Individual records are lost past the limit, and the limit is per process.

## D-023: AEGIS does not check whether a missing ID exists elsewhere
**Decision:** A reference to an invisible ID is recorded in the attempting tenant only. **Why:** Checking
across tenants would need a privileged query, and acting on the answer would reveal that the ID exists.
**Cost:** Scenario E can show a suspicious pattern, never a confirmed cross-tenant attempt, and the owning
tenant is not told.

## D-024: Evidence through a single allowlisted route
**Decision:** `GET /evidence/{type}/{id}` returns named fields only. **Why:** Every reference in a finding
needs one place to lead, and a new column must not appear by default. **Cost:** A new evidence type needs
a route entry.

## D-025: The Claude provider uses the official SDK, as an optional extra
**Decision:** `anthropic` is installed only with the `llm` extra and imported only by one module, using
`claude-opus-5-5` with `fallbacks: "default"`. **Why:** The SDK handles retries and errors, nothing else in
AEGIS should depend on a provider, and a server-side fallback means a classifier decline can still produce
hypotheses. **Cost:** The fallback may answer from another model, recorded only as a success under the
configured model. Tested against a mock transport, not the real API.

## Phase 3: the Governance Engine

The design is `docs/superpowers/specs/2026-11-03-governance-engine-design.md`. The decisions below
are the ones a later reader is most likely to question. Every deviation ruled during the build is
listed in full after them.

## D-026: Governance authority is a grant, apart from the fixed roles (revisits D-009)
**Decision:** `governance_role_grants` holds one role, `governance_reviewer`, granted by an admin to
an active `admin` or `reviewer`, never to oneself (service check and `CHECK (granted_by <> user_id)`).
Holding it means an unrevoked grant **and** a still-qualifying user role, checked again under the
review lock at the moment of a decision. **Why:** D-009 kept fixed roles because a permissions
table added surface with no capability. Governance needs exactly one extra authority that must be
separable from administering the tenant; a grant table with one role adds that without custom
roles. **Cost:** A tenant needs two people before any governance approval. Two admins can still
grant each other the role and collude, and a stolen admin session can grant it to another account
it controls; both are audited, not prevented.

## D-027: Owners are user references on the asset profile (resolves D-014 for governance)
**Decision:** `business_owner_id` and `technical_owner_id` on each profile version are composite
foreign keys to the tenant's users. The submitter and both owners are refused as deciders unless an
applicable policy explicitly permits it and none prohibits it. **Why:** D-014 could not enforce a
four-eyes rule while the owner was a free-text label. **Cost:** Runtime action approvals
(`/approvals`) are unchanged: any reviewer or admin may still approve a held action, and the legacy
`owner` text field remains (REMEDIATION_PLAN risk 5).

## D-028: Every tenant starts in `observe`
**Decision:** No settings row means `observe`. In `observe`, rows 4, 5 and 7 of spec 11.2 (expired,
not approved, reassessment required) are recorded in `governance_gateway_checks` and do not change
the outcome; decisions a person made (retired, hard block, condition deny or hold) apply in both
modes. An admin switches to `enforce` after reading the preflight, and the switch is audited and
reversible. **Why:** Turning governance on must not cause an outage for existing assets, which had
no governance record. **Cost:** Until a tenant switches, an unapproved asset is not stopped.

## D-029: The hard block
**Decision:** `hard_block_decision_id` is set by suspend, revoke, and reject, and the state trigger
lets it be cleared only in the update that moves the asset into `APPROVED` or
`CONDITIONALLY_APPROVED`. The gateway checks it before the status, and also treats `SUSPENDED` or
`REJECTED` without a block as blocked. Since this audit, a failed check in `observe` still denies a
retired or blocked asset. **Why:** Without it, the lifecycle path back through
`REASSESSMENT_REQUIRED` or `UNDER_REVIEW` would quietly lift a person's block in `observe`.
**Cost:** A blocked asset stays denied until a new approval, even if the problem was fixed sooner.

## D-030: Agent-row locks, `FOR NO KEY UPDATE`
**Decision:** Suspend, revoke, reject, approve, submit, assess, profile save, and grant changes lock every
agent row of the asset in ID order, then the state row, then the chain head (spec 11.4). The agent
rows are locked `FOR NO KEY UPDATE`, not `FOR UPDATE`. **Why:** The lock on agent rows serializes a
lifecycle change against in-flight gateway evaluations, which hold a share lock on the agent row,
even for an asset with no state row. `FOR UPDATE` deadlocked in a real-thread test: suspend held
the agent rows waiting for the chain head, while a finishing execution held the chain head and its
security-event insert needed a key share lock on the same agent row for its foreign key check.
`FOR NO KEY UPDATE` still conflicts with the gateway's share lock and does not conflict with a
foreign key's key share lock (ruled in Task 14 after the reviewer checked PostgreSQL's conflict
table; `test_suspend_does_not_deadlock_with_a_finishing_execution` fails without it). **Cost:** A
grant change waits for in-flight evaluations of that asset's agents.

## D-031: A third `SECURITY DEFINER` function
**Decision:** `aegis_tenants_with_due_governance_reviews(p_now)` returns tenant IDs only, with a
fixed `search_path`, `EXECUTE` revoked from `PUBLIC` and granted to `aegis_app`, and an owner policy
limited to rows with a `next_review_at`. **Why:** The review worker must find tenants with due
reviews without a tenant context, as the correlation worker does. **Cost:** One more deliberate RLS
exception. `test_only_the_id_lookups_are_security_definer` lists exactly three functions, and this
audit counted three in the migrations (`0001`, `0003`, `0014`).

## D-032: Framework libraries are seeded per tenant
**Decision:** Framework and control rows are tenant rows, seeded on first read under a per-tenant
advisory lock, once per framework row. **Why:** Only `alembic_version` may lack a tenant, so a
global catalog would break the isolation rule. **Cost:** Seeding happens once per framework row, so
a framework added later (for example ISO/IEC 42001 controls) reaches existing tenants only through
a new migration.

## D-033: The NIST AI RMF library is partial
**Decision:** The NIST AI RMF 1.0 library ships 19 controls, stored as `LOADED_PARTIAL` with
`source_control_count` 72, and every identifier is checked against a list taken from NIST AI 100-1.
**Why:** Only identifiers verified against the source may ship (invariant 9), and a partial library
under the framework's name must say it is partial. **Cost:** Coverage is 19 of 72 subcategories.
AEGIS does not claim compliance with NIST AI RMF.

## D-034: ISO/IEC 42001 is not loaded
**Decision:** The ISO/IEC 42001:2023 framework row exists with `library_status = NOT_LOADED` and no
controls, and a trigger refuses controls under a `NOT_LOADED` library. **Why:** The Annex A
identifiers could not be verified against an authoritative copy. **Cost:** No ISO mapping exists.
Loading it needs a licensed copy, AEGIS-written descriptions, and a new seeding migration for
existing tenants. AEGIS does not claim compliance with ISO/IEC 42001.

## D-035: Database errors are logged without their parameters
**Decision:** The runtime engine, and the owner-role engines in `aegis.provisioning`, are created with `hide_parameters=True`. **Why:** Found in the Task 21
audit: a NUL byte in inline evidence made PostgreSQL refuse the insert after validation, and the
500 handler logged the SQLAlchemy error, whose text included every bound value, so the evidence
text reached the logs. **Cost:** Database errors in the logs no longer show the values, which makes
some debugging slower.

## Governance build rulings, in order

Each deviation from the spec or plan that the controller ruled during the build, as recorded in
the build ledger (which is not committed). "Preflight" rulings were made before Task 1 from a scan
of the plan; "R7" and similar labels refer to that scan. Each ends with the controller's estimate
of the cost if the ruling is wrong.

1. **Preflight.** R1 Task 3's isolation test covers the profile route only; Task 4 adds detail, Task 6 risk, Task 8 approvals, Task 10 history — a test cannot target a route that does not exist — cost if wrong: none, routes are all covered by Task 10.
2. **Preflight.** R2 The state trigger allows status-unchanged updates with version+1 (for latest_assessment_id and similar); transition rules apply only when status changes; `assets.py` gets `touch(session, state, now, **columns)` — spec 7.1 requires version bump but not a status change on every update — cost if wrong: small trigger edit.
3. **Preflight.** R3 Each owning task wires its overview field: outstanding_findings and awaiting_approval (8), conditionally_approved, suspended (10), evidence (11), overdue_reviews (15), enforcement_mode (14) — plan leaves it implicit — cost if wrong: a zero until Task 20 catches it.
4. **Preflight.** R4 Assessment is allowed in every state but RETIRED. From DRAFT and REJECTED it moves to ASSESSMENT_REQUIRED; elsewhere status is unchanged. Submit is allowed only from ASSESSMENT_REQUIRED and REASSESSMENT_REQUIRED (and resubmission per R7). Hard block is untouched — spec 7.1 lists the transition but no owner — cost if wrong: small service change.
5. **Preflight.** R5 `required_controls_canonical` holds the whole frozen PolicyOutcome including applicable_version_ids, self_approval_permitted, owner_approval_permitted — spec 7.4 freezes the requirements at submission — cost if wrong: one key moves to a column.
6. **Preflight.** R6 Review status CHECK is OPEN, INFO_REQUESTED, DECIDED, WITHDRAWN; suspend/revoke/retire close an open review as WITHDRAWN — spec names only open states — cost if wrong: rename.
7. **Preflight.** R7 `POST /assets/{id}/submit` while the review is INFO_REQUESTED withdraws that review and opens a new one, recomputing frozen controls, keeping the assigned reviewer and asset status UNDER_REVIEW, recording a SUBMIT decision. Prior votes do not carry over. The current assessment must still be current. Test in Task 8 — review.assessment_id is deliberately not updatable, and this keeps it so — cost if wrong: an approver re-votes.
8. **Preflight.** R8 build_record uses `fields.pop("asset_id", None)` falling back to the agent's asset. Existing mappings never pass asset_id, so older events reproject identically — required to link status events to assets — cost if wrong: minimal.
9. **Preflight.** R9 conditions.py imports ToolRegistry under TYPE_CHECKING only, so engine/enforcement.py stays free of I/O imports — cost if wrong: none.
10. **Preflight.** R10 Add `TenantWorld.login_as(name, role)` for extra users — no cost.
11. **Preflight.** R11 Governance modules never import aegis.registry.service or aegis.gateway.service; only gateway.tools — prevents import cycles — cost if wrong: none.
12. **Preflight.** R12 `/assets/{id}/reassess` uses SuspenderDep (admin or role holder); it never clears the hard block — it tightens or keeps enforcement, like suspend — cost if wrong: one dependency swap.
13. **Preflight.** R13 Source identifiers live in a Python module `nist_ai_rmf_1_0_identifiers.py` as a tuple, not `.txt` — must ship in non-editable installs — cost if wrong: none.
14. **Preflight.** R14 library_status allows NOT_LOADED, LOADED_PARTIAL, LOADED — honesty rule; already disclosed to the user — cost if wrong: rename.
15. **Preflight.** R15 Pages catch ApiError 403 around `api()` and render PermissionDenied; error.tsx stays generic — production error boundaries get digests only — cost if wrong: small refactor.
16. **Process.** Commit trailers name the model that actually wrote the commit (subagents follow their own harness attribution), not always Opus — accurate attribution — cost if wrong: trailer rewrite before merge.
17. **Task 4.** In Task 6 `risk` filters assessed risk and a new `declared_risk` filter handles the declared value; assessed vocabulary uppercase, declared lowercase as stored, UI labels both — spec 4 forbids declared as a fallback — cost if wrong: query parameter rename.
18. **Task 5.** A tenant-authored methodology must include all eight factors, enforced in create_methodology_version in Task 6 — otherwise omitting a factor would hide missing information, breaking invariant 7 — cost if wrong: tenants cannot drop a factor (weight 0 still allowed).
19. **Task 6.** `risk_methodology_events` replaces the spec's `approved_by` column on risk_methodology_versions — an append-only row cannot gain an approver after insert, and this mirrors governance_policy_events — cost if wrong: one table to fold back.
20. **Task 6.** Tool level for an asset with agents but no grants is 0 with source grants; no agents uses declared_tool_access; absent is missing — spec section 5 — cost if wrong: small mapping change.
21. **Task 6.** Editing Phase 3 test setups when a later task adds a foreign key is allowed, so long as assertions are unchanged; "unmodified" protects the baseline 588 only — those setups targeted a placeholder column — cost if wrong: none, assertions unchanged.
22. **Task 6.** review saw 5091ef8. Important (edited Phase 3 test setups for the FK): Ruling: waived; the controller's dispatch required that FK and assertions are unchanged; applies again when decision FKs arrive in Task 8.
23. **Task 6.** Lock-order item confirmed as a real gap and enters the fix loop: run_assessment locks state then agents, but spec 11.4 orders agents, state, chain head, and suspend will follow the spec, so the two can deadlock. save_profile also moves to the locked loader.
24. **Task 6.** Read level filtered to the tool's own resource_kind stands (read_document with a sensitive customer-record grant is 2) — the gateway enforces kind, so that grant is unreachable through that tool — cost if wrong: under-scores one factor until a matching tool is granted, which re-scores it.
25. **Task 6.** last_assessed_at is the latest assessment even if INCOMPLETE — shows when assessment last ran beside a null risk — cost if wrong: label change.
26. **Task 7.** Activating a new version does not deactivate the old; both apply, most restrictive wins, until an admin deactivates one — a replacement can never silently loosen a requirement, which fails safe — cost if wrong: extra click, and a loosened policy needs an explicit deactivation.
27. **Task 7.** Applicability treats unknown facts as non-matching, and submission requires a COMPLETE assessment so missing facts cannot hide a requirement; asset_type is not a risk factor, so Task 8 adds a finding when asset_type is unset — cost if wrong: an extra finding.
28. **Task 7.** review saw c829f70; 1 Important (effective window outside the hash), fix round 1 dispatched. Ruling: review_overdue on VersionedDocument and the event-guard trigger stand — both sound — cost if wrong: small refactor.
29. **Task 8.** awaiting_approval counts UNDER_REVIEW assets, not review rows — equal whenever reviews come from submit, and it keeps the Task 4 contract test unchanged — cost if wrong: count differs only for state written outside the service.
30. **Task 8.** review saw d1ad904; 3 Important; fix round 1 dispatched. Ruling: Ruling 10 amended: frozen_hash added to the SUBMIT audit payload and compared on decision reads; reviewer_id added to the ASSIGN_REVIEWER payload — anchors the self-approval flag in the audit chain, leaving T11 as the only remaining limit — cost if wrong: two payload keys.
    *Note:* "Ruling 10" here is the tenth ruling the controller made during Task 8's review (on what
    the audit chain anchors), not preflight ruling R10 (`TenantWorld.login_as`, item 10 above).
31. **Task 8.** One tampered review 503s the whole tenant's review list and overview — fail closed, consistent with policy and methodology behavior — cost if wrong: an operator loses those views until the row is addressed.
32. **Task 9.** While a review is INFO_REQUESTED, reject is allowed and approve is refused with 409 REVIEW_AWAITING_INFORMATION — an approver should not approve past their own open question, but must be able to end a stalled review — cost if wrong: one extra resubmit.
33. **Task 9.** denied_actions validated against catalog actions, and owner columns checked against the canonical profile — both fail safe — cost if wrong: small.
34. **Task 9.** Final approval's conditions_hash must equal an earlier vote's conditions if it carried any; final may add when the vote had none — a last approver cannot silently undo the first's restrictions — cost if wrong: approvers must agree exactly, resolved by rejecting and resubmitting.
35. **Task 9.** Only votes whose voter still holds authority at the final vote count — Review Focus 1 — cost if wrong: an extra approver after a revocation.
36. **Task 9.** approve (vote and final) requires the assessment to still describe the asset, else ASSESSMENT_NOT_CURRENT, reject allowed — closes the window between submit and decision — cost if wrong: a resubmit after benign edits.
37. **Task 9.** current_decision_id only moves on decisions establishing authority or a block, so conditions survive reassessment per spec 11.2 — cost if wrong: history lookups use the decisions table, which they do anyway.
38. **Task 9.** Conditions of every vote on the review bind every later approval, even if the voter no longer counts — revocation cannot be used to shed restrictions, and the way out is request-information plus resubmit — cost if wrong: a reviewer removed for cause forces a resubmit.
39. **Task 11.** Inline VERIFIED always recomputes the hash whatever the method — spec 9, the check is free — cost if wrong: none.
40. **Task 11.** verify_evidence anchors row fields to the evidence_submitted audit event (hash valid, payload equals row) — matches the review frozen_hash anchor — cost if wrong: one extra query per verification.
41. **Task 11.** governance_decision_evidence gets the composite evidence FK; the one Phase 3 approvals test setup uses real evidence, assertions unchanged (Task 6 FK ruling) — cost if wrong: none.
42. **Task 11.** A verification by a later-revoked reviewer still counts — finished act like a decision; remedy is a REJECTED by another reviewer — cost if wrong: a revoked reviewer's verification needs an explicit rejection.
43. **Task 11.** REJECTED allowed on RETIRED assets, VERIFIED refused; REJECTED without a check records scope judgment_only — rejection only tightens, and no check is claimed that did not run — cost if wrong: small.
44. **Task 12.** the changed setup of test_evidence_and_verifications_are_append_only (random control id became a real control) is covered by the Task 6 FK ruling; assertions unchanged — cost if wrong: none.
45. **Task 12.** seeding is once per framework row; ISO can only be loaded for existing tenants by a new migration, and spec 10 and 17 must say so (Task 21) — cost if wrong: a later release needs a seeding migration.
46. **Task 13.** A recorded (observe-only) row never shadows a person-decision row — spec 11.6 says rows 1, 2, 6, 8 apply in both modes; row 6/8 are evaluated even after a recorded row 4/5/7 matched, and win if they deny or hold — cost if wrong: observe mode applies a person's condition earlier than table order.
47. **Task 13.** GovernanceFacts rejects naive datetimes; Task 14 passes aware ones — cost if wrong: none.
48. **Task 14.** Ruling (provisional, reviewer to verify): lock_asset_agents uses FOR NO KEY UPDATE instead of FOR UPDATE — the real-thread test found a deadlock (suspend holds agent rows FOR UPDATE waiting for chain head; finishing execution holds chain head and its security-event insert needs a KEY SHARE on the agent row); NO KEY UPDATE still conflicts with the gateway's share lock and does not conflict with FK KEY SHARE; spec 11.4 wording to align in Task 21 — cost if wrong: deadlock returns or serialization weakens.
49. **Task 14.** dangling current_decision_id counts as conditions not intact (denies in both modes) rather than GOVERNANCE_EVALUATION_ERROR, since observe would skip a person's conditions — cost if wrong: reason code differs.
50. **Task 14.** FOR NO KEY UPDATE on lock_asset_agents ratified (reviewer verified PostgreSQL conflict rules, serialization against the gateway share lock, no caller relied on FOR UPDATE, deterministic test fails without it); Task 21 updates spec 11.4 text and spec 12 (409 ENFORCEMENT_MODE_UNCHANGED) — cost if wrong: deadlock risk returns.
51. **Task 15.** a passed next_review_at makes an asset due, as spec 13 (the definer policy is limited to rows with next_review_at); a worker move on review date may change a PASS to a HOLD, exactly as a human /reassess does; "worker must not change a verdict" applies to expiry only, which the gateway computes itself — cost if wrong: drop the next_review_at half in is_due, the listing and the definer function.
52. **Task 15.** overdue_reviews counts REASSESSMENT_REQUIRED and UNDER_REVIEW as well as approved statuses, so the worker cannot zero the count; stays overdue until a new approval sets the next date — cost if wrong: count definition.
53. **Task 16.** dashboard.spec.ts:119 may be edited (exact-match locator, separate commit) — Task 14 put the policy reason code in decision evidence, so the page's JSON dump repeats it; the page is correct to show governance evidence, and the change pins the assertion to the field — cost if wrong: none.
54. **Task 16.** "Not assessed" (never assessed) versus "Incomplete" (assessment exists with no level) stands — matches the backend's latest-assessment-by-sequence semantics — cost if wrong: label change.
55. **Task 17.** policies on the asset page are the versions frozen on the latest review, labeled as frozen; mappings are controls linked from the asset's evidence — no per-asset routes exist — cost if wrong: add routes later.
56. **Task 18.** policy creation stays API-only in the UI — a policy document is a closed schema of about 13 control fields, a partial form would imply it captures all of them — cost if wrong: a form later.
57. **Task 18.** tests run in a dedicated synthetic tenant (provision_governance_tenant.py), one tenant persists per run; acceptable since tenants cannot be deleted — cost if wrong: tenant clutter in a dev database.
58. **Task 19.** the seed runs on every start only if it is truly idempotent and never fatal after the first run; a person's rejection is never overwritten — cost if wrong: demo data drifts across restarts.
59. **Task 19.** the new e2e file governance-compliance.spec.ts stays separate from governance.spec.ts (synthetic tenants, Task 18 precedent).
60. **Task 20.** the browser workflow test lives in a new file governance-workflow.spec.ts (governance.spec.ts is 600 lines) — cost if wrong: none.
61. **Task 20.** the admin-only Submission section on the asset page is kept (backend route is AdminDep, spec 7.5, spec 14 needs a submit control in the dashboard) — cost if wrong: move it.
62. **Task 20.** the ConfirmAction form-reset bug (Tasks 18-19 code) is fixed in this round, not deferred, because a corrected resubmission could record the opposite verification outcome — cost if wrong: none.
63. **Task 21.** the two tests appended to tests/security/test_correlation.py in Task 17 (a761aa6) are additions only; no existing assertion changed, so they are within the permitted ways (moving the incident asset_id contract test there) — cost if wrong: move them.

**Note on an existing test helper edited outside the permitted list.** `frontend/e2e/helpers.ts`
existed before Phase 3 and was changed in it (commits bc4f2c5, 385723a, 9bf7f81). `newRestrictedAgent`
now finds the seeded demo asset by name, paging through `/assets`, instead of taking the first item:
the governance seed adds assets, so the demo asset is no longer on the first page. `adminHeaders`
became an alias of the new `headersFor("admin")`. No assertion changed. This was not ruled during the
build; it is recorded here so the record of edits to existing tests is complete, beside the Task 16
ruling on `dashboard.spec.ts` (item 53) and the Task 21 ruling above.
