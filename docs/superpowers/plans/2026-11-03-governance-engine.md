# Governance Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Governance Engine so an asset's assessed risk, policies, approval, and evidence end in a decision the Security Gateway enforces, with every decision traceable.

**Architecture:** A new `aegis.governance` package inside the modular monolith. Pure deterministic logic lives in `governance/engine/`, and services follow the registry pattern: each write runs in the caller's tenant transaction and appends audit evidence there. The gateway calls a pure check inside its existing transaction, and governance can only tighten its result.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2 strict models, SQLAlchemy 2 (sync), psycopg 3, Alembic SQL migrations, PostgreSQL 16, pytest, hypothesis, Next.js App Router, TypeScript, Tailwind, lucide, Playwright.

**Spec:** `docs/superpowers/specs/2026-11-03-governance-engine-design.md`. Read it first. This plan argues from it and does not repeat its tables.

## Global Constraints

- All routes under `/api/v1/governance`; tenant comes only from the principal; agent principals are rejected on every governance route.
- Every new table: `tenant_id NOT NULL`, `UNIQUE (tenant_id, id)`, composite tenant foreign keys, `ENABLE` and `FORCE ROW LEVEL SECURITY`, policy `tenant_isolation` using `aegis_current_tenant()`.
- Migrations are hand-written SQL statement lists in the style of `0004_investigations.py`; `downgrade()` raises `NotImplementedError`.
- Each new table's grants are added to `EXPECTED_*` in `tests/security/test_tenant_isolation_db.py` and to `docs/DATABASE_DESIGN.md` in the same task.
- Append-only tables use the `aegis_reject_mutation` row and truncate triggers.
- `governance/engine/` imports no I/O, clock, or LLM module. Audit payloads contain no floats; scores are integers.
- "Latest" rows are ordered by audit sequence (join `AuditEvent.seq`), never by timestamp.
- Existing tests pass **unmodified**, apart from additions to the two catalog tests (`EXPECTED_*`, `test_only_the_id_lookups_are_security_definer`). The harness files `tests/support.py` and `tests/conftest.py` may gain helpers and settings, without changing what existing helpers do. Never weaken an assertion. If an existing test fails, stop and report it.
- No fake metrics, no hardcoded data in the UI, no decorative emoji, lucide icons only. Synthetic data labeled synthetic.
- Every commit ends with: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Commit on `phase-3-governance`. Do not push.

**Commands** (run from `backend/`):

- Focused: `.venv/Scripts/python -m pytest <path> -q`
- Full: `.venv/Scripts/python -m pytest -q`
- Lint: `.venv/Scripts/python -m ruff check src tests scripts migrations`

## Review Focus

Failure modes the spec implies but does not spell out. Each has a test in the owning task.

1. **A person loses authority mid-review.** A holder whose grant was revoked, or whose role fell to `viewer`, must not be able to decide an open review, and the review must be reassignable. (Task 9)
2. **Grants change between assessment and submission.** The assessment no longer describes the agent, so submission must refuse with `ASSESSMENT_NOT_CURRENT`, even though the profile did not change. (Task 8)
3. **An idempotent retry after suspension.** Replaying a key returns the stored result and must not run the tool again or create a second check. (Task 14)
4. **Nonsensical approval dates and conditions.** `valid_until` in the past, `next_review_at` after `valid_until`, naive datetimes, or a condition naming a tool outside the catalog must be rejected with 422 and leave no state change. (Task 9)
5. **Work on a retired asset.** New profiles, assessments, submissions, and evidence must be refused with `ASSET_RETIRED`, while its history stays readable. (Task 10)

---

## Milestone 1: Baseline

### Task 1: Record the baseline

**Files:** none changed.

- [ ] **Step 1: Run the suite and lint on `main`'s code**

Run the Full and Lint commands. Expected: all pass. Record passed, failed, and skipped counts. If anything fails, stop and report it: later milestones cannot be judged against a failing baseline.

- [ ] **Step 2: Run the mutation check**

Run: `.venv/Scripts/python scripts/mutation_check.py`. Expected: exit 0 with no `SURVIVED`. Record the mutation count.

---

## Milestone 2: Roles, profiles, state, inventory

### Task 2: Governance roles and settings

**Files:**
- Create: `migrations/versions/0005_governance_foundation.py`, `src/aegis/governance/__init__.py`, `src/aegis/governance/roles.py`, `src/aegis/api/routes_governance.py`, `src/aegis/api/schemas_governance.py`
- Modify: `src/aegis/db/models.py`, `src/aegis/api/app.py`, `src/aegis/api/dependencies.py`, `tests/security/test_tenant_isolation_db.py`, `docs/DATABASE_DESIGN.md`
- Test: `tests/security/test_governance_roles.py`

**Interfaces:**
- Produces, in `roles.py`:
  - `GOVERNANCE_REVIEWER = "governance_reviewer"`
  - `grant_role(session, actor: UserPrincipal, now, *, user_id: UUID) -> GovernanceRoleGrant`
  - `revoke_grant(session, actor, now, grant_id: UUID) -> GovernanceRoleGrant`
  - `holds_reviewer(session, user_id: UUID) -> bool` (an unrevoked grant **and** the user is active with role `admin` or `reviewer`)
- Produces, in `dependencies.py`: `GovernanceReviewerDep`, which raises `Forbidden` unless `holds_reviewer`, and `SuspenderDep` (admin or holder).
- Produces: migration creating `governance_settings`, `governance_role_grants`.

- [ ] **Step 1: Write the failing tests** in `test_governance_roles.py`

```python
def test_admin_cannot_grant_reviewer_role_to_self(tenant):
    # POST /governance/role-grants with the admin's own id -> 403, code SELF_GRANT_REFUSED; no audit "governance.role_granted"
def test_only_admin_can_grant(tenant):  # reviewer and viewer -> 403
def test_grantee_must_be_active_admin_or_reviewer(tenant):  # viewer grantee -> 422
def test_agent_principal_rejected_on_governance_routes(tenant):  # agent key -> 401
def test_revoked_grant_stops_counting(tenant, db):  # holds_reviewer False after revoke
def test_duplicate_active_grant_conflicts(tenant):  # 409
def test_grant_and_revoke_are_audited(tenant):  # event types governance.role_granted, governance.role_revoked; chain verifies
def test_grants_are_tenant_isolated(world):  # other tenant's user_id -> 404
```

Add a helper to `tests/support.py`: `TenantWorld.grant_governance(role: str, by: str = "admin")` and `TenantWorld.user_id(role: str) -> str`, reading the id from `/auth/me`.

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/security/test_governance_roles.py -q`. Expected: FAIL (404 on the routes).

- [ ] **Step 3: Implement the migration, models, service, and routes**

A partial unique index on `(tenant_id, user_id, role) WHERE revoked_at IS NULL` enforces one active grant. A `CHECK (granted_by <> user_id)` backs the self-grant rule in the database. Grants per spec section 4. Routes: `POST /governance/role-grants`, `POST /governance/role-grants/{id}/revoke`, `GET /governance/people`. Register the router in `app.py` with prefix `/api/v1`.

- [ ] **Step 4: Run focused tests and catalog tests**

Run: `.venv/Scripts/python -m pytest tests/security/test_governance_roles.py tests/security/test_tenant_isolation_db.py -q`. Expected: PASS.

- [ ] **Step 5: Commit** `feat(governance): add governance roles and tenant settings`

### Task 3: Lifecycle, profiles, and state

**Files:**
- Create: `migrations/versions/0006_governance_assets.py`, `src/aegis/governance/engine/__init__.py`, `src/aegis/governance/engine/lifecycle.py`, `src/aegis/governance/profile.py`, `src/aegis/governance/assets.py`
- Modify: `src/aegis/db/models.py`, `src/aegis/api/routes_governance.py`, `src/aegis/api/schemas_governance.py`, catalog tests, `docs/DATABASE_DESIGN.md`
- Test: `tests/unit/test_governance_lifecycle.py`, `tests/security/test_governance_assets.py`, `tests/security/test_governance_isolation.py`

**Interfaces:**
- Produces, in `engine/lifecycle.py`: `class GovernanceStatus(StrEnum)` with the nine states; `TRANSITIONS: dict[GovernanceStatus, frozenset[GovernanceStatus]]` exactly as in spec 7.1; `can_transition(old: str, new: str) -> bool`.
- Produces, in `profile.py`: `class AssetProfile(BaseModel)` (strict, `extra="forbid"`, all fields optional, enums as in spec sections 5 and 6); `canonical_profile(profile) -> str`.
- Produces, in `assets.py`:
  - `save_profile(session, user, now, asset_id, profile: AssetProfile) -> AssetProfileVersion`
  - `load_state(session, asset_id) -> AssetGovernanceState | None`
  - `lock_asset_agents(session, asset_id) -> None` (`SELECT ... FOR UPDATE` on agent rows, `ORDER BY id`)
  - `transition(session, state, target: GovernanceStatus, now, **columns) -> None` (checks `can_transition`, raises `Conflict(code="INVALID_STATE_TRANSITION")`, bumps `version`)
  - `require_not_retired(state) -> None` (raises `Conflict(code="ASSET_RETIRED")`)

- [ ] **Step 1: Write the failing unit tests** in `test_governance_lifecycle.py`

```python
def test_transition_table_matches_spec():
    assert TRANSITIONS[SUSPENDED] == {REASSESSMENT_REQUIRED, RETIRED}
    assert TRANSITIONS[RETIRED] == frozenset()
    assert APPROVED not in TRANSITIONS[SUSPENDED]
@hypothesis.given(st.sampled_from(GovernanceStatus), st.sampled_from(GovernanceStatus))
def test_can_transition_only_for_table_entries(old, new): ...
```

- [ ] **Step 2: Write the failing security tests**

`test_governance_assets.py`:

```python
def test_first_profile_creates_draft_state(tenant)
def test_profile_versions_increment_and_never_change(tenant, attacker_sql)  # UPDATE as aegis_app rejected
def test_owner_must_be_a_user_in_this_tenant(world)  # other tenant's user -> 422/404, and the FK refuses it directly
def test_partial_profile_can_be_saved(tenant)
def test_unknown_profile_field_rejected(tenant)  # 422
def test_trigger_rejects_invalid_transition(db, tenant)  # direct UPDATE DRAFT -> APPROVED as aegis_app raises
def test_trigger_rejects_hard_block_clear_without_approval(db, tenant)
def test_trigger_rejects_delete_and_binding_change(db, tenant)
def test_trigger_requires_version_increment(db, tenant)
def test_existing_assets_get_no_state_from_the_migration(tenant)  # asset created, state is None until first profile
def test_non_admin_cannot_save_profile(tenant)  # reviewer, viewer -> 403
```

`test_governance_isolation.py`: `test_cross_tenant_asset_access_is_not_found(world)` covering profile, detail, and history routes; add new routes here in later tasks.

- [ ] **Step 3: Run to verify they fail.** Expected: import errors or 404s.

- [ ] **Step 4: Implement** the migration (`asset_profile_versions`, `asset_governance_state`, trigger `aegis_governance_state_guard`), `lifecycle.py`, `profile.py`, `assets.py`, and `POST /governance/assets/{id}/profile`.

The trigger must: allow only the transitions in spec 7.1; forbid `DELETE`; keep `tenant_id` and `asset_id` immutable; require `NEW.version = OLD.version + 1`; and allow `hard_block_decision_id` to go from non-null to null only when `NEW.status IN ('APPROVED', 'CONDITIONALLY_APPROVED')`. Foreign keys to decisions and assessments are added by the migrations that create those tables. Saving a profile on an approved or conditionally approved asset is wired in Task 10.

- [ ] **Step 5: Run the three test files and the catalog tests.** Expected: PASS.

- [ ] **Step 6: Commit** `feat(governance): add asset profiles and lifecycle state`

### Task 4: Inventory API

**Files:**
- Create: `src/aegis/governance/inventory.py`
- Modify: `src/aegis/api/routes_governance.py`, `src/aegis/api/schemas_governance.py`
- Test: `tests/api/test_governance_contracts.py`

**Interfaces:**
- Produces: `list_inventory(session, *, search, risk, status, owner_id, limit, offset) -> tuple[list[InventoryRow], int]`; `asset_detail(session, asset_id) -> AssetDetailView`; `overview(session, now) -> OverviewView`. An asset with no state row reports `governance_status: null`. `declared_risk` is `ai_assets.risk_classification`, and `assessed_risk` is null until Task 6.
- Routes: `GET /governance/assets`, `GET /governance/assets/{id}`, `GET /governance/overview`.

- [ ] **Step 1: Write the failing tests**

```python
def test_inventory_lists_ungoverned_assets_with_null_status(tenant):
    asset = tenant.asset()
    item = find(tenant.get("/governance/assets").json()["items"], asset["id"])
    assert item["governance_status"] is None and item["assessed_risk"] is None
    assert item["declared_risk"] == "medium"
def test_inventory_search_and_filters(tenant)
def test_inventory_pagination_shape(tenant)  # items, total, limit, offset
def test_overview_counts_come_from_stored_rows(tenant)  # counts change only when rows change
def test_declared_risk_never_reported_as_assessed(tenant)
```

- [ ] **Step 2: Run to verify they fail.** Expected: 404.

- [ ] **Step 3: Implement** `inventory.py` and the routes. Overview fields: `total_assets`, `by_assessed_risk`, `unassessed`, `awaiting_approval`, `conditionally_approved`, `suspended`, `overdue_reviews`, `outstanding_findings`, `evidence_verified`, `evidence_total`, `enforcement_mode`. Fields whose tables do not exist yet return 0 and are wired in the owning task.

- [ ] **Step 4: Run tests, then the Full suite and Lint.** Expected: PASS, with baseline tests unmodified.

- [ ] **Step 5: Commit** `feat(governance): add asset inventory and overview API`

---

## Milestone 3: Risk

### Task 5: Pure risk engine

**Files:**
- Create: `src/aegis/governance/engine/risk.py`, `src/aegis/governance/methodology.py`
- Test: `tests/unit/test_governance_risk.py`

**Interfaces:**
- Produces, in `engine/risk.py`:
  - `class RiskInputs(BaseModel)`: strict; `data_categories`, `external_exposure`, `autonomy_level`, `tool_access_level: int | None`, `tool_access_source: Literal["grants", "declared"] | None`, `human_oversight`, `impact_level`, `deployment_environment`, `third_party_reliance`.
  - `class Methodology(BaseModel)`: `factors`, `thresholds`, `floors`, `mitigations`, `provenance_note`.
  - `class FactorResult`, `class RiskResult(BaseModel)`: `status: Literal["COMPLETE", "INCOMPLETE"]`, `score: int | None`, `risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None`, `factors`, `floor_applied`, `missing: list[str]`, `mitigations: list[str]`.
  - `assess(inputs: RiskInputs, methodology: Methodology) -> RiskResult`
- Produces, in `methodology.py`: `BUILT_IN_METHODOLOGY: Methodology`, with exactly the weights, level maps, thresholds, and floors of spec section 6, and a `provenance_note` saying the values are engineering judgment, not from any standard.

- [ ] **Step 1: Write the failing tests**

```python
def full_inputs(**over) -> RiskInputs: ...  # all at level 0 unless overridden

def test_weights_sum_to_100(): assert sum(f.weight for f in BUILT_IN_METHODOLOGY.factors) == 100
def test_threshold_boundaries():  # score 99 LOW, 100 MEDIUM, 199 MEDIUM, 200 HIGH, 299 HIGH, 300 CRITICAL
def test_all_factors_at_max_scores_400_critical()
def test_highest_data_category_wins()  # ["public", "regulated"] -> level 4
def test_autonomy_with_sensitive_data_floors_at_high()  # autonomy bounded + personal, low elsewhere -> HIGH, floor_applied set
def test_autonomous_no_oversight_transmit_is_critical()
def test_any_missing_factor_is_incomplete_with_null_level()
    # for each factor removed: status INCOMPLETE, risk_level None, score None, factor named in missing
def test_empty_data_categories_counts_as_missing()
def test_each_factor_explains_itself()  # non-empty explanation, level, weight, contribution
def test_mitigations_come_from_the_document()
@given(inputs_strategy()) def test_same_inputs_same_result(inputs): assert assess(inputs, M) == assess(inputs, M)
@given(inputs_strategy()) def test_complete_iff_level_present(inputs)
@given(...) def test_raising_a_factor_never_lowers_the_score(...)
def test_result_contains_no_floats()
def test_engine_imports_no_clock_or_io()  # same static check as aegis.policy.engine
```

- [ ] **Step 2: Run to verify they fail.** Expected: import error.

- [ ] **Step 3: Implement `assess` and the methodology.** Integer arithmetic only. Floors raise the level and never lower it; the score stays the arithmetic sum.

- [ ] **Step 4: Run the tests.** Expected: PASS.

- [ ] **Step 5: Commit** `feat(governance): add deterministic risk engine`

### Task 6: Assessments and methodology versions

**Files:**
- Create: `migrations/versions/0007_governance_risk.py`, `src/aegis/governance/risk.py`
- Modify: `src/aegis/db/models.py`, routes, schemas, `src/aegis/governance/inventory.py`, catalog tests, `docs/DATABASE_DESIGN.md`
- Test: `tests/security/test_governance_assessments.py`

**Interfaces:**
- Consumes: `assess`, `BUILT_IN_METHODOLOGY`, `lock_asset_agents`, `transition`.
- Produces, in `risk.py`:
  - `build_inputs(session, registry: ToolRegistry, asset_id, profile: AssetProfile) -> RiskInputs` (tool level from real grants and resource classifications when the asset has agents)
  - `active_methodology(session, tenant_id, now) -> RiskMethodologyVersion` (seeds built-in as version 1 with `created_by` null, in the `_ensure_defaults` style)
  - `parse_methodology(version) -> Methodology` (raises `MethodologyIntegrityError` on hash mismatch)
  - `run_assessment(session, registry, user, now, asset_id) -> RiskAssessment`
  - `current_input_hash(session, registry, asset_id) -> str` (used by submit in Task 8)
  - `create_methodology_version`, `approve_methodology_version`, `activate_methodology_version`
- Routes: `POST /assets/{id}/assess`, `GET /assets/{id}/risk`, `GET /assets/{id}/assessments`, `GET /methodologies`, `POST /methodologies`, `POST /methodologies/{id}/approve`, `POST /methodologies/{id}/activate`.

- [ ] **Step 1: Write the failing tests**

```python
def test_assessment_without_profile_is_refused(tenant)  # 409 PROFILE_REQUIRED
def test_incomplete_profile_gives_incomplete_assessment_never_low(tenant)
def test_database_rejects_complete_without_level(db, tenant)  # the check constraint, directly
def test_tool_access_comes_from_grants_not_declaration(tenant)
    # profile declares no tool access; agent holds a transmit tool -> factor level 4, source "grants"
def test_assets_without_agents_use_declared_tool_access(tenant)
def test_reassessing_unchanged_inputs_gives_identical_result_hash(tenant)
def test_new_methodology_version_does_not_change_old_assessments(tenant)
def test_get_risk_recomputes_and_reports_match(tenant)  # recomputed_matches True
def test_tampered_assessment_reports_mismatch(tenant, attacker_sql)  # recomputed_matches False
def test_tampered_methodology_hash_fails_closed(tenant, attacker_sql)  # 503 METHODOLOGY_INTEGRITY_FAILED
def test_methodology_approver_must_differ_from_creator(tenant)  # 403
def test_first_assessment_moves_draft_to_assessment_required(tenant)
def test_assessment_is_audited_and_chain_verifies(tenant)
def test_assessment_is_append_only(db, tenant)
def test_viewer_cannot_assess(tenant)  # 403
```

Add the risk routes to `test_cross_tenant_asset_access_is_not_found`.

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** the migration, service, and routes. `input_hash` and result are hashes of canonical JSON. Register `MethodologyIntegrityError` as a 503 handler in `app.py`, in the `RuleIntegrityError` style. Update `inventory.py` to report `assessed_risk` and the assessment date.

- [ ] **Step 4: Run tests, the catalog tests, then Full and Lint.** Expected: PASS.

- [ ] **Step 5: Commit** `feat(governance): record versioned risk assessments`

---

## Milestone 4: Governance policies

### Task 7: Policy documents, engine, and service

**Files:**
- Create: `migrations/versions/0008_governance_policies.py`, `src/aegis/governance/policy_schema.py`, `src/aegis/governance/engine/policies.py`, `src/aegis/governance/policies.py`
- Modify: models, routes, schemas, catalog tests, `docs/DATABASE_DESIGN.md`
- Test: `tests/unit/test_governance_policy_engine.py`, `tests/security/test_governance_policies.py`

**Interfaces:**
- Produces, in `policy_schema.py`: `class GovernancePolicyDocument(BaseModel)` with `description`, `severity`, `applicability`, and `controls` (closed, `extra="forbid"`, per spec section 8). `self_approval` and `owner_approval` are `Literal["permitted", "prohibited"] | None`; `minimum_approvers` is `Literal[1, 2] | None`.
- Produces, in `engine/policies.py`:
  - `applies(document, profile: AssetProfile, risk_level: str | None) -> bool`
  - `evaluate_policies(documents: list[VersionedDocument], profile, risk_level, verified_evidence_categories: set[str]) -> PolicyOutcome`
  - `PolicyOutcome`: `applicable_version_ids`, `required_controls`, `findings`, `minimum_approvers: int`, `self_approval_permitted: bool`, `owner_approval_permitted: bool`
- Produces, in `policies.py`: `create_policy`, `create_version`, `approve_version`, `activate_version`, `deactivate_version`, `list_policies`, `applicable_documents(session, now) -> list[VersionedDocument]` (approved, active, inside the effective window, hash checked).

- [ ] **Step 1: Write the failing unit tests**

```python
def test_self_approval_default_is_refused():  # no policies -> self_approval_permitted False
def test_explicit_permission_allows_self_approval()
def test_conflict_takes_most_restrictive()  # permitted + prohibited -> False
def test_minimum_approvers_highest_wins_default_one()
def test_applicability_is_anded()
def test_missing_risk_level_does_not_match_a_risk_condition()
def test_unpermitted_provider_produces_a_finding()
def test_missing_owner_produces_a_finding()
def test_missing_verified_evidence_category_produces_a_finding()
def test_findings_never_decide()  # PolicyOutcome has no approve/deny field
```

- [ ] **Step 2: Write the failing security tests**

```python
def test_policy_version_cannot_be_changed(db, tenant)  # UPDATE, DELETE as aegis_app rejected
def test_new_version_leaves_old_version_intact(tenant)
def test_unknown_document_key_rejected(tenant)  # 422
def test_approver_must_differ_from_creator(tenant)  # 403
def test_only_reviewer_holder_can_approve(tenant)  # plain reviewer without the grant -> 403
def test_unapproved_version_cannot_be_activated(tenant)  # 409
def test_version_outside_effective_window_does_not_apply(tenant)
def test_tampered_version_fails_closed(tenant, attacker_sql)
def test_activation_history_is_append_only_and_audited(tenant)
def test_governance_policies_are_separate_from_runtime_policies(tenant)  # /policies unaffected, tenant active version unchanged
def test_cross_tenant_policy_access(world)
```

- [ ] **Step 3: Run to verify they fail.**

- [ ] **Step 4: Implement.** Routes per spec section 12.

- [ ] **Step 5: Run tests, catalog tests, Full, and Lint.** Expected: PASS.

- [ ] **Step 6: Commit** `feat(governance): add versioned governance policies`

---

## Milestone 5: Approval lifecycle

### Task 8: Reviews, decisions, and submission

**Files:**
- Create: `migrations/versions/0009_governance_decisions.py`, `src/aegis/governance/approvals.py`
- Modify: models, routes, schemas, `src/aegis/events/schema.py`, `src/aegis/events/projection.py`, catalog tests, `docs/DATABASE_DESIGN.md`
- Test: `tests/security/test_governance_approvals.py`

**Interfaces:**
- Consumes: `transition`, `current_input_hash`, `evaluate_policies`, `applicable_documents`.
- Produces, in `approvals.py`:
  - `record_decision(session, *, asset_id, kind, from_status, to_status, actor_type, decided_by, now, reason, review_id=None, assessment_id=None, conditions=None, valid_until=None, next_review_at=None, policy_version_ids=(), evidence_ids=()) -> GovernanceDecision` (appends the audit event first, stores `audit_event_id`)
  - `submit(session, registry, user, now, asset_id, *, reason) -> GovernanceReview`
  - `assign_reviewer(session, user, now, review_id, reviewer_id) -> GovernanceReview`
  - `request_information(session, user, now, review_id, *, reason) -> GovernanceReview`
  - `list_reviews`, `get_review`
- Audit event type `governance.decision`, payload: `decision_id`, `asset_id`, `kind`, `from_status`, `to_status`, `assessment_id`.
- Security event: new `EventType` value `governance.status_changed`, `_BUILDERS["governance.decision"]`, projected only when `from_status != to_status`. Severity: `medium` for `SUSPEND`, `REVOKE`, and `REJECT`; `info` otherwise. Reason code is the kind prefixed with `GOVERNANCE_`. `SCHEMA_VERSION` stays 1.

- [ ] **Step 1: Write the failing tests**

```python
def test_submit_requires_complete_assessment_of_current_profile(tenant)  # incomplete -> 409 ASSESSMENT_NOT_CURRENT
def test_new_profile_after_assessment_blocks_submit(tenant)  # 409 ASSESSMENT_NOT_CURRENT
def test_grant_change_after_assessment_blocks_submit(tenant)
    # Review Focus 2: add a tool grant after assessing; submit -> 409 ASSESSMENT_NOT_CURRENT
def test_submit_freezes_required_controls_and_findings(tenant)
    # activate a new policy mid-review; review's frozen controls unchanged
def test_second_open_review_refused(tenant)  # 409; the partial unique index also refuses a direct insert
def test_concurrent_submissions_create_one_review(tenant)  # real threads
def test_assigned_reviewer_must_hold_the_role(tenant)  # 422
def test_request_information_keeps_asset_under_review(tenant)
def test_decision_requires_reason(tenant)  # 422
def test_decisions_are_append_only(db, tenant)
def test_decision_constraints_refuse_approval_without_assessment(db, tenant)  # direct insert raises
def test_decision_links_to_a_real_audit_event(tenant)
def test_status_change_projects_security_event_and_reprojection_matches(tenant, db)
```

Add the approval routes to the isolation test.

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** the migration (including the partial unique index on open reviews, the vote index from spec 7.4, the state foreign keys deferred from Task 3), and the service.

Submission compares `current_input_hash` to the latest assessment's `input_hash`. A mismatch is `ASSESSMENT_NOT_CURRENT`.

- [ ] **Step 4: Run tests, catalog tests, and `tests/security/test_security_events.py`.** Expected: PASS.

- [ ] **Step 5: Commit** `feat(governance): add reviews, decisions, and submission`

### Task 9: Approve, reject, and separation of duties

**Files:**
- Create: `src/aegis/governance/conditions.py`
- Modify: `src/aegis/governance/approvals.py`, routes, schemas
- Test: `tests/security/test_governance_approvals.py`, `tests/security/test_governance_separation.py`

**Interfaces:**
- Produces, in `conditions.py`: `class Conditions(BaseModel)` (strict; `denied_tools`, `held_tools`, `denied_actions`, `hold_all: bool`, `max_resource_classification`, `advisory_conditions: list[str]`); `validate_against_catalog(conditions, registry) -> None` (`ValidationFailed`); `is_enforceable(conditions) -> bool`.
- Produces, in `approvals.py`: `approve(session, registry, user, now, review_id, *, reason, valid_until, next_review_at, conditions=None, evidence_ids=()) -> GovernanceDecision`; `reject(session, user, now, review_id, *, reason) -> GovernanceDecision`.

Rules for `approve` and `reject`, checked in this order under a row lock on the review and on state:

1. Caller holds `governance_reviewer`, else `Forbidden`.
2. If assigned, caller is the assignee, else `Forbidden` with code `NOT_ASSIGNED_REVIEWER`.
3. Self and owner rules from the frozen `PolicyOutcome`, else `Forbidden` with code `SELF_APPROVAL_REFUSED`.
4. Review is open, else `Conflict` with `INVALID_STATE_TRANSITION`.
5. `valid_until > now`, `now < next_review_at <= valid_until`, aware datetimes, conditions valid against the catalog.

The final required approval clears `hard_block_decision_id`, sets `valid_until`, `next_review_at`, `current_decision_id`, and closes the review. `reject` sets `hard_block_decision_id`, clears `valid_until`, and closes the review. An `approve` carrying only `advisory_conditions` is still conditional.

- [ ] **Step 1: Write the failing tests** in `test_governance_separation.py`

```python
def test_submitter_cannot_approve_by_default(tenant)  # 403 SELF_APPROVAL_REFUSED; state unchanged; authz.denied audited
def test_self_approval_only_with_explicit_policy(tenant)
def test_conflicting_policies_refuse_self_approval(tenant)
def test_business_owner_cannot_approve_by_default(tenant)
def test_technical_owner_cannot_approve_by_default(tenant)
def test_existing_reviewer_role_is_not_sufficient(tenant)  # plain reviewer -> 403
def test_existing_admin_role_is_not_sufficient(tenant)  # admin without the grant -> 403
def test_only_assigned_reviewer_can_decide(tenant)
def test_revoked_holder_cannot_decide_open_review(tenant)  # Review Focus 1
def test_holder_downgraded_to_viewer_cannot_decide(tenant, urls)  # Review Focus 1
def test_review_can_be_reassigned_after_assignee_loses_authority(tenant)  # Review Focus 1
def test_viewer_cannot_decide(tenant)
```

- [ ] **Step 2: Add failing tests** to `test_governance_approvals.py`

```python
def test_approval_stores_full_decision_record(tenant)
    # decider, timestamp, reason, assessment, policy versions, evidence, conditions, dates
def test_conditional_approval_sets_conditionally_approved(tenant)
def test_conditional_approval_needs_conditions(tenant)  # 422
def test_invalid_lifecycle_transitions_refused(tenant)  # approve a closed review; approve when DRAFT -> 409
def test_two_approvers_required_when_policy_says_so(tenant)
    # first vote: status stays UNDER_REVIEW; second distinct: APPROVED
def test_same_person_cannot_vote_twice(tenant)  # 409, and direct insert refused
def test_concurrent_approvals_produce_one_outcome(tenant)  # real threads: approve vs reject
def test_past_valid_until_rejected_with_no_state_change(tenant)  # Review Focus 4
def test_next_review_after_valid_until_rejected(tenant)  # Review Focus 4
def test_naive_datetime_rejected(tenant)  # Review Focus 4
def test_condition_with_unknown_tool_rejected(tenant)  # Review Focus 4
def test_rejection_sets_hard_block(tenant)
def test_failed_audit_rolls_back_the_decision(tenant, monkeypatch)
```

- [ ] **Step 3: Run to verify they fail.**

- [ ] **Step 4: Implement `conditions.py`, `approve`, `reject`, and the routes.**

- [ ] **Step 5: Run tests, then Full and Lint.** Expected: PASS.

- [ ] **Step 6: Commit** `feat(governance): enforce separation of duties on approvals`

### Task 10: Suspend, revoke, reassess, retire, and automatic reassessment

**Files:**
- Modify: `src/aegis/governance/approvals.py`, `src/aegis/governance/assets.py`, `src/aegis/governance/risk.py`, `src/aegis/registry/service.py`, routes, schemas
- Test: `tests/security/test_governance_lifecycle_actions.py`

**Interfaces:**
- Produces: `suspend(session, user, now, asset_id, *, reason, kind="SUSPEND"|"REVOKE") -> GovernanceDecision`; `require_reassessment(session, actor_type, user_id, now, asset_id, *, reason) -> GovernanceDecision`; `retire(session, user, now, asset_id, *, reason) -> GovernanceDecision`; `mark_grant_changed(session, user, now, agent_id) -> None`.
- `suspend` calls `lock_asset_agents` first, inserts a `DRAFT` row if none exists, and then transitions. It closes any open review, sets the hard block, and clears `valid_until`.
- `registry.add_tool_grant` and `add_resource_grant` call `mark_grant_changed` before `_audit`. It does nothing unless the asset is approved or conditionally approved. Removing a grant does not call it.
- `save_profile` on an approved or conditionally approved asset calls `require_reassessment`.

- [ ] **Step 1: Write the failing tests**

```python
def test_suspend_asset_with_no_state_row(tenant)  # SUSPENDED, hard block set
def test_suspended_asset_cannot_return_directly_to_approved(tenant)
def test_hard_block_survives_reassessment_and_review(tenant)
    # suspend -> reassess -> assess -> submit: hard_block still set until approved
def test_approval_clears_hard_block(tenant)
def test_suspend_clears_valid_until(tenant)
def test_revoke_records_revoke_kind_and_suspends(tenant)
def test_viewer_cannot_suspend(tenant)
def test_plain_reviewer_cannot_suspend_without_grant(tenant)
def test_new_profile_on_approved_asset_forces_reassessment(tenant)
def test_added_grant_on_approved_asset_forces_reassessment(tenant)
def test_removed_grant_does_not_force_reassessment(tenant)
def test_grant_on_ungoverned_asset_has_no_governance_effect(tenant)  # state stays None
def test_retired_asset_refuses_new_work(tenant)
    # Review Focus 5: profile, assess, submit, evidence -> 409 ASSET_RETIRED; GET history still 200
def test_history_route_shows_every_decision_in_audit_order(tenant)
```

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** the functions, routes (`suspend`, `revoke`, `reassess`, `retire`, `history`), and registry hook. The evidence half of Review Focus 5 is asserted in Task 11.

- [ ] **Step 4: Run tests, then Full and Lint.** Existing registry and gateway tests must be untouched and passing.

- [ ] **Step 5: Run `.venv/Scripts/python scripts/mutation_check.py`.** Expected: no `SURVIVED`.

- [ ] **Step 6: Commit** `feat(governance): add suspension, retirement, and forced reassessment`

---

## Milestone 6: Evidence and frameworks

### Task 11: Evidence and verification

**Files:**
- Create: `migrations/versions/0010_governance_evidence.py`, `src/aegis/governance/evidence.py`
- Modify: models, routes, schemas, `src/aegis/governance/inventory.py`, `src/aegis/governance/approvals.py` (evidence references on decisions), catalog tests, `docs/DATABASE_DESIGN.md`
- Test: `tests/security/test_governance_evidence.py`

**Interfaces:**
- Produces, in `evidence.py`: `submit_evidence(session, user, now, *, asset_id, category, description, source: EvidenceSource, control_ids=()) -> GovernanceEvidence`; `verify_evidence(session, user, now, evidence_id, *, outcome, method, note, content: str | None = None) -> GovernanceEvidenceVerification`; `current_verification(session, evidence_id) -> str` (`UNVERIFIED`, `VERIFIED`, `REJECTED`); `verified_categories(session, asset_id) -> set[str]`.
- `EvidenceSource` is a discriminated union per spec section 9. Task 7's `evaluate_policies` receives `verified_categories`; wire the real call into `submit` here.

- [ ] **Step 1: Write the failing tests**

```python
def test_cross_tenant_evidence_access_is_not_found(world)
def test_evidence_cannot_reference_another_tenants_record(world)  # composite FK
def test_new_evidence_is_unverified_and_does_not_count(tenant)
def test_submitter_cannot_verify_own_evidence(tenant)  # 403; the trigger refuses a direct insert too
def test_plain_reviewer_cannot_verify(tenant)  # 403
def test_inline_hash_is_computed_not_trusted(tenant)  # a client-supplied hash field -> 422
def test_inline_verification_recomputes_hash(tenant, attacker_sql)  # tampered content -> outcome refused 409 HASH_MISMATCH
def test_external_reference_with_content_checks_hash(tenant)  # wrong content -> 409 HASH_MISMATCH
def test_external_reference_without_content_is_manual_attestation_only(tenant)
    # method content_recomputed without content -> 422; manual_attestation allowed and reported as such
def test_internal_record_verification_checks_the_record(tenant, attacker_sql)  # tampered audit event -> refused
def test_latest_verification_wins_by_audit_sequence(tenant)  # verified then rejected -> REJECTED, same timestamp via frozen clock
def test_evidence_and_verifications_are_append_only(db, tenant)
def test_inline_content_hidden_from_viewer(tenant)  # viewer gets metadata, no content_text
def test_evidence_on_retired_asset_refused(tenant)  # Review Focus 5
def test_policy_finding_clears_only_after_verification(tenant)
```

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement.** Internal record verification uses `compute_event_hash` for audit events and existing content hashes where a record has one; an assessment is checked by recomputing it. The `control_ids` foreign key to `governance_controls` is added in Task 12.

- [ ] **Step 4: Run tests, catalog tests, Full, and Lint.** Expected: PASS.

- [ ] **Step 5: Commit** `feat(governance): add evidence with independent verification`

### Task 12: Framework library and control assessments

**Files:**
- Create: `migrations/versions/0011_governance_frameworks.py`, `src/aegis/governance/frameworks/__init__.py`, `src/aegis/governance/frameworks/nist_ai_rmf_1_0.py`, `src/aegis/governance/frameworks/iso_iec_42001_2023.py`, `src/aegis/governance/frameworks/nist_ai_rmf_1_0_identifiers.txt`, `src/aegis/governance/compliance.py`
- Modify: models, routes, schemas, catalog tests, `docs/DATABASE_DESIGN.md`
- Test: `tests/security/test_governance_compliance.py`, `tests/unit/test_governance_frameworks.py`

**Interfaces:**
- Produces: `FrameworkDefinition(key, version, source_url, source_document, library_status, controls)`; `ControlDefinition(identifier, name, description, source_reference, required_evidence)`; `FRAMEWORKS: list[FrameworkDefinition]`; `ensure_frameworks(session, tenant_id, now)`; `list_frameworks`, `list_controls(session, *, framework_id, status, limit, offset)`; `assess_control(session, user, now, control_id, *, status, note, evidence_ids) -> GovernanceControlAssessment`.

- [ ] **Step 1: Extract the source identifiers**

Download NIST AI 100-1 from `https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf` into a new empty directory under the scratchpad. Extract the text with `pypdf`, installed in a throwaway venv and not in the project. Write every subcategory identifier found in the Core tables (form `GOVERN 1.1`), one per line, to `nist_ai_rmf_1_0_identifiers.txt`, with a header comment naming the document and retrieval date. Read the extracted pages and confirm the list by eye. If extraction fails, stop and report it; do not write the list from memory.

- [ ] **Step 2: Write the failing unit tests**

```python
def test_every_shipped_nist_identifier_is_in_the_source_list()
def test_nist_controls_have_source_references()
def test_iso_library_is_empty_and_not_loaded():
    assert ISO.controls == [] and ISO.library_status == "NOT_LOADED"
def test_shipped_descriptions_are_not_empty()
```

- [ ] **Step 3: Write the failing security tests**

```python
def test_frameworks_seeded_once_per_tenant(world)  # concurrent reads, no duplicates
def test_control_with_no_assessment_is_not_assessed(tenant)
def test_implemented_refused_without_verified_evidence(tenant)  # 409 EVIDENCE_REQUIRED, including with unverified evidence
def test_partially_implemented_refused_without_verified_evidence(tenant)
def test_implemented_allowed_with_verified_evidence(tenant)
def test_evidence_from_another_tenant_refused(world)
def test_rejected_evidence_no_longer_supports_status(tenant)  # current status reports EVIDENCE_REQUIRED
def test_control_assessments_are_append_only(db, tenant)
def test_responses_carry_the_no_certification_statement(tenant)
def test_iso_reports_not_loaded_with_zero_controls(tenant)
def test_coverage_counts_come_from_stored_rows(tenant)  # includes "N of M NIST subcategories in the library"
def test_only_reviewer_holder_can_assess_controls(tenant)
```

- [ ] **Step 4: Run to verify they fail.**

- [ ] **Step 5: Implement.** Ship a NIST subset limited to subcategories that an AEGIS capability actually relates to: governance roles and responsibilities, risk tolerance, AI inventory, third-party risk, human oversight, evaluation, incident response, and monitoring. For each, read the source text; write the description in your own words; record the page. Do not claim the whole framework is loaded: `library_status` is `LOADED_PARTIAL` for NIST, and the API reports shipped count against the source list count. The column's check allows `NOT_LOADED`, `LOADED_PARTIAL`, and `LOADED`. Spec section 10 names only `NOT_LOADED`; these two are additions so a partial library cannot read as complete. Link each control's `required_evidence` to the spec's evidence categories.

- [ ] **Step 6: Run tests, catalog tests, Full, and Lint.** Expected: PASS.

- [ ] **Step 7: Commit** `feat(governance): add verified framework library and control status`

---

## Milestone 7: Gateway enforcement

### Task 13: Pure enforcement engine

**Files:**
- Create: `src/aegis/governance/engine/enforcement.py`
- Test: `tests/unit/test_governance_enforcement.py`

**Interfaces:**
- Produces:
  - `class Verdict(StrEnum)`: `PASS`, `RECORDED_DENY`, `RECORDED_HOLD`, `DENY`, `HOLD`
  - `@dataclass(frozen=True) class GovernanceFacts`: `mode`, `status: str | None`, `hard_blocked: bool`, `conditions: Conditions | None`, `conditions_intact: bool`, `valid_until: datetime | None`, `now: datetime`
  - `@dataclass(frozen=True) class ActionContext`: `tool`, `action`, `resource_classification`
  - `@dataclass(frozen=True) class GovernanceCheck`: `verdict`, `reason_code: str | None`
  - `check(facts: GovernanceFacts, action: ActionContext) -> GovernanceCheck`
  - `combine(evaluation: Evaluation, result: GovernanceCheck) -> Evaluation`
- `now` is a field, so the module reads no clock.

- [ ] **Step 1: Write the failing tests**, one parametrized case per row of spec section 11.2 in both modes:

```python
@pytest.mark.parametrize("mode,facts,expected", ROWS)
def test_table_row(mode, facts, expected)

def test_retired_beats_everything()
def test_hard_block_beats_a_valid_approval()
def test_expiry_precedes_reassessment_regardless_of_status()
def test_condition_deny_precedes_reassessment_hold()
def test_under_review_with_approval_in_force_holds_in_enforce()
def test_under_review_with_no_approval_denies_in_enforce()
def test_exactly_at_valid_until_is_expired()
def test_integrity_failure_denies_in_observe()
def test_max_resource_classification_denies_above_limit()
def test_advisory_only_conditions_do_not_restrict()

def test_combine_never_loosens():  # for all Outcome x Verdict
def test_combine_keeps_policy_deny_reason()
def test_combine_recorded_verdicts_change_nothing()
def test_combine_hold_turns_allow_into_require_approval()
def test_combine_deny_overrides_require_approval()

@given(facts_strategy(), action_strategy())
def test_check_is_pure_and_total(facts, action)  # no exception, same result twice

def test_engine_imports_no_clock_or_io()
```

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement.** Apply the rows in table order. `check` raises nothing for any valid `GovernanceFacts`.

- [ ] **Step 4: Run tests.** Expected: PASS.

- [ ] **Step 5: Commit** `feat(governance): add pure gateway enforcement check`

### Task 14: Gateway integration, enforcement mode, and preflight

**Files:**
- Create: `migrations/versions/0012_governance_gateway.py`, `src/aegis/governance/gateway_check.py`, `src/aegis/governance/enforcement_mode.py`
- Modify: `src/aegis/gateway/service.py`, `src/aegis/events/projection.py`, models, routes, schemas, `src/aegis/governance/inventory.py`, catalog tests, `docs/DATABASE_DESIGN.md`
- Test: `tests/security/test_governance_gateway.py`

**Interfaces:**
- Produces, in `gateway_check.py`:
  - `load_facts(session, agent_id: UUID, now) -> tuple[GovernanceFacts, UUID | None]` (returns the asset id)
  - `safe_check(session, agent_id, action: ActionContext, now) -> GatewayOutcome`, wrapping failures per spec 11.2: `enforce` deny, `observe` recorded, reason `GOVERNANCE_EVALUATION_ERROR`
  - `record_check(session, decision: PolicyDecision, outcome: GatewayOutcome, now) -> None`
- Produces, in `enforcement_mode.py`: `get_mode(session) -> str`; `set_mode(session, user, now, *, mode, reason) -> GovernanceSettings`; `preflight(session, now) -> PreflightView`.
- Changes to `gateway/service.py`, in `_decide_and_execute` and in the re-evaluation in `_execute_approved`:
  - after `_safe_evaluate`, call `safe_check` and `combine`;
  - pass the governance outcome to `_record_decision`, which adds `governance` to `evidence` and the audit payload and calls `record_check`.
  - `ActionFacts` and `aegis.policy.engine` do **not** change.
- `_decision` in `projection.py` is unchanged: `observe` passes are `ALLOW`, so they stay unprojected. Add `GOVERNANCE_BLOCKED`, `GOVERNANCE_INTEGRITY_FAILED`, and `GOVERNANCE_EVALUATION_ERROR` to `_HIGH_DENIALS`.

- [ ] **Step 1: Write the failing tests**

Add helpers to `tests/support.py`: `TenantWorld.governed_agent(tools, resources, approve=True, conditions=None, valid_days=30) -> AgentHandle` (full flow through the API with distinct submitter and reviewer), and `TenantWorld.set_enforcement(mode)`.

```python
# Compatibility
def test_default_mode_leaves_ungoverned_agent_behavior_unchanged(tenant, world)
    # allowed, tool ran, reason unchanged; a check row says GOVERNANCE_NOT_APPROVED / RECORDED_DENY
def test_observe_pass_creates_no_security_event(tenant)
def test_migration_does_not_authorize_existing_assets(tenant)  # enforce -> denied, tool never ran
def test_new_tables_add_no_chain_events_per_action(tenant)  # event count per action unchanged

# Missing, expired, suspended, revoked
def test_missing_status_enforce_denies(tenant, world)
def test_expired_approval_enforce_denies_observe_records(tenant, world)  # via a moved clock
def test_exact_expiry_instant_is_expired(tenant, world)
def test_suspended_denies_in_both_modes_and_tool_never_runs(tenant, world)
def test_revoked_denies_in_both_modes(tenant, world)
def test_rejected_denies_in_both_modes(tenant, world)
def test_retired_denies_in_both_modes(tenant, world)
def test_suspended_stays_denied_through_reassessment_in_observe(tenant, world)
def test_reassessment_required_holds_in_enforce(tenant, world)
def test_under_review_with_approval_in_force_holds(tenant, world)
def test_approved_passes_in_enforce(tenant, world)

# Conditions
def test_condition_denied_tool_denies_in_both_modes(tenant, world)
def test_condition_held_tool_creates_action_approval(tenant, world)
def test_condition_deny_survives_reassessment(tenant, world)

# Only tightens
def test_policy_deny_keeps_reason_on_suspended_asset(tenant, world)
def test_hard_check_deny_keeps_reason_on_approved_asset(tenant, world)
def test_approved_governance_does_not_loosen_runtime_policy(tenant, world)

# Time of check
def test_suspend_after_action_approval_cancels_it(tenant, world)
def test_hold_at_reevaluation_does_not_block_human_approved_action(tenant, world)
def test_concurrent_suspend_and_action_on_stateless_asset(tenant, world)  # real threads
    # either action completed before suspension committed, or was denied; never allowed after commit
def test_replay_after_suspension_returns_stored_result(tenant, world)  # Review Focus 3: tool ran once, one check row

# Failure
def test_check_failure_denies_in_enforce(tenant, world, monkeypatch)
def test_check_failure_does_not_block_in_observe(tenant, world, monkeypatch)
def test_tampered_conditions_deny_in_both_modes(tenant, world, attacker_sql)

# Traceability
def test_check_links_decision_and_governance_decision(tenant)
def test_gov_deny_appears_as_security_event_with_reason(tenant)
def test_gov_deny_feeds_correlation(tenant, db)
def test_checks_are_append_only(db, tenant)

# Mode
def test_only_admin_can_change_mode(tenant)
def test_mode_change_is_audited_and_reversible(tenant)
def test_preflight_lists_what_would_be_blocked(tenant)  # counts match real rows; changes nothing
def test_agent_cannot_reach_mode_or_preflight(tenant)
```

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** the migration, `gateway_check.py`, `enforcement_mode.py`, gateway changes, and routes. Add `test_governance_modules_do_not_import_llm_clients` to `test_governance_gateway.py`, using the same static check as the existing guard, which stays untouched. Update the overview's `enforcement_mode`.

- [ ] **Step 4: Run tests, then all of `tests/security/test_gateway.py`, `test_approval_safety.py`, `test_policy_enforcement.py`, unmodified.** Expected: PASS.

- [ ] **Step 5: Add mutations** to `scripts/mutation_check.py`: check result ignored; `combine` can loosen; hard block ignored; expiry ignored; suspend without agent locks; self-approval check removed; hard-block trigger clause removed; evidence-verification self-check removed; `EVIDENCE_REQUIRED` check removed; incomplete assessment given a level.

- [ ] **Step 6: Run `.venv/Scripts/python scripts/mutation_check.py governance` and fix any `SURVIVED` by strengthening a test.** Expected: no `SURVIVED`.

- [ ] **Step 7: Run Full and Lint, then commit** `feat(gateway): enforce governance status at runtime`

### Task 15: Review worker

**Files:**
- Create: `migrations/versions/0013_governance_reviews.py`, `src/aegis/governance/reviews.py`, `src/aegis/governance/worker.py`
- Modify: `src/aegis/config.py`, `src/aegis/api/app.py`, `tests/conftest.py` (add `governance_worker_enabled=False`), `tests/security/test_tenant_isolation_db.py` (add the function name), routes, schemas, `docs/DATABASE_DESIGN.md`
- Test: `tests/security/test_governance_reviews.py`

**Interfaces:**
- Produces: `process_due_reviews(db, *, clock) -> int`; `list_due(session, now, *, window_days, limit, offset)`; `class GovernanceReviewWorker(db, clock, poll_seconds)`, same shape as `CorrelationWorker`; settings `governance_worker_enabled: bool = True`, `governance_review_poll_seconds: float = 60.0`.

- [ ] **Step 1: Write the failing tests**

```python
def test_due_approval_moves_to_reassessment_required(tenant, world)  # system decision recorded, actor_type "system"
def test_conditional_approval_also_moves(tenant, world)
def test_not_yet_due_is_untouched(tenant, world)
def test_second_pass_is_idempotent(tenant, world)  # no second decision
def test_concurrent_passes_produce_one_decision(tenant, world)  # real threads
def test_gateway_verdict_is_the_same_before_and_after_the_worker_runs(tenant, world)  # expired asset, enforce
def test_failure_on_one_asset_does_not_stop_others(tenant, world, monkeypatch)
def test_worker_failure_leaves_gateway_working(tenant, world, monkeypatch)
def test_definer_function_returns_only_ids(attacker_sql)
def test_reviews_due_lists_upcoming_and_overdue(tenant, world)
def test_reviews_due_tenant_isolated(world)
```

Add `"aegis_tenants_with_due_governance_reviews"` to the sorted list in `test_only_the_id_lookups_are_security_definer`. This is the only change to that test.

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** the migration (function and owner policy per spec section 13), `reviews.py`, `worker.py`, and the app lifespan wiring. Each asset gets its own transaction.

- [ ] **Step 4: Run tests, Full, and Lint.** Expected: PASS.

- [ ] **Step 5: Commit** `feat(governance): schedule periodic reviews`

---

## Milestone 8: Governance Center

### Task 16: Navigation, shared states, overview, inventory

**Files:**
- Create: `frontend/src/app/(app)/governance/layout.tsx`, `governance/page.tsx`, `governance/assets/page.tsx`, `governance/loading.tsx`, `governance/error.tsx`, `frontend/src/components/governance-nav.tsx`, `frontend/src/components/permission-denied.tsx`, `frontend/src/lib/governance-types.ts`
- Modify: `frontend/src/components/sidebar.tsx`, `frontend/src/components/ui.tsx`
- Test: `frontend/e2e/governance.spec.ts`

**Interfaces:**
- Produces: `<PermissionDenied />`, rendered by `governance/error.tsx` when the error is an `ApiError` with status 403 (the error boundary receives digest-only errors in production, so pages catch `ApiError` with status 403 around `api()` and render the component directly); governance status entries in `StatusBadge` for the nine states; `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `COMPLETE`, `INCOMPLETE`, `VERIFIED`, `UNVERIFIED`, and the six control statuses; `<NotGovernedBadge />`; `<RiskLabel kind="declared"|"assessed" value=... />`.

- [ ] **Step 1: Write the failing e2e tests**

```ts
test("overview shows counts from the API and the enforcement mode", ...)  // compare to GET /governance/overview
test("overview empty state on a tenant with no assets", ...)
test("inventory shows a new asset as not governed, with declared risk labeled declared", ...)
test("inventory search and filters narrow the list", ...)
```

- [ ] **Step 2: Run to verify they fail.** With the stack running: `cd frontend && npx playwright test e2e/governance.spec.ts`. Expected: FAIL.

- [ ] **Step 3: Implement.** Add one "Governance" sidebar item (Lucide `Landmark`), and sub-navigation in the layout. Reuse `Panel`, `Table`, `Cell`, `EmptyState`, `Pagination`, `FilterLinks`.

- [ ] **Step 4: Run e2e plus `npm run lint`, `npm run typecheck`, `npm run build`.** Expected: PASS.

- [ ] **Step 5: Commit** `feat(frontend): add Governance Center overview and inventory`

### Task 17: Asset details and risk

**Files:**
- Create: `governance/assets/[id]/page.tsx`, `governance/assets/[id]/actions.ts`, `governance/assets/[id]/profile-form.tsx`, `governance/assets/[id]/risk/page.tsx`
- Test: `frontend/e2e/governance.spec.ts`

- [ ] **Step 1: Write the failing e2e tests**

```ts
test("admin saves a profile with owners picked from real users", ...)
test("incomplete assessment shows what is missing and no risk level", ...)
test("complete assessment shows every factor, score, floor, and mitigations", ...)
test("risk page states the weights are engineering judgment", ...)
test("asset page shows policies, history, evidence, mappings, and related incidents", ...)
test("viewer sees no edit controls and a direct mutation is refused", ...)
```

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement.** Related incidents come from existing `/incidents` filtered by the asset's agents. Add a query parameter to the backend only if no filter exists, with a contract test.

- [ ] **Step 4: Run e2e, lint, typecheck, build.** Expected: PASS.

- [ ] **Step 5: Commit** `feat(frontend): add asset governance and risk views`

### Task 18: Approval Center and policies

**Files:**
- Create: `governance/approvals/page.tsx`, `governance/approvals/[id]/page.tsx`, `governance/approvals/[id]/actions.ts`, `governance/approvals/[id]/decision-form.tsx`, `governance/policies/page.tsx`, `governance/policies/actions.ts`
- Test: `frontend/e2e/governance.spec.ts`

- [ ] **Step 1: Write the failing e2e tests**

```ts
test("pending submission shows assessment, frozen controls, findings, and evidence with method", ...)
test("reviewer approves with dates, and history shows the decision", ...)
test("conditional approval requires conditions, and labels advisory ones not enforced", ...)
test("reject and request information record a reason", ...)
test("submitter sees the self-approval refusal message", ...)
test("user without the governance role sees permission denied", ...)
test("policy library shows versions, status, applicability, approver", ...)
test("author cannot approve their own policy version", ...)
```

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement,** using `confirm-action.tsx` for irreversible decisions.

- [ ] **Step 4: Run e2e, lint, typecheck, build.** Expected: PASS.

- [ ] **Step 5: Commit** `feat(frontend): add approval center and policy library`

### Task 19: Compliance, evidence, reviews, enforcement, demo data

**Files:**
- Create: `governance/compliance/page.tsx`, `governance/compliance/actions.ts`, `governance/reviews/page.tsx`, `governance/enforcement/page.tsx`, `governance/enforcement/actions.ts`
- Modify: `backend/scripts/seed_demo.py`, `frontend/src/components/governance-nav.tsx`
- Test: `frontend/e2e/governance.spec.ts`

- [ ] **Step 1: Write the failing e2e tests**

```ts
test("compliance always shows the no-certification statement", ...)
test("ISO shows library not loaded with zero controls", ...)
test("NIST shows shipped count against the source count", ...)
test("evidence shows verification method, and unverified evidence does not count toward coverage", ...)
test("review center shows upcoming, overdue, and reassessment requests", ...)
test("enforcement page lists the preflight, and the change requires confirmation", ...)
test("empty, and error states render on compliance and reviews", ...)
test("all governance views have no horizontal page scroll at phone width", ...)
```

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement,** and extend `seed_demo.py` through the real API with assets at several lifecycle states, labeled synthetic. The seed must create a second user for the reviewer role, so it respects the no-self-grant rule.

- [ ] **Step 4: Run e2e, lint, typecheck, build; delete `backend/.dev` and re-run the stack to confirm a fresh seed works.** Expected: PASS.

- [ ] **Step 5: Commit** `feat(frontend): add compliance, review, and enforcement views`

---

## Milestone 9: Proof, audit, documentation

### Task 20: End-to-end workflow

**Files:**
- Test: `backend/tests/security/test_governance_workflow.py`, `frontend/e2e/governance.spec.ts`

- [ ] **Step 1: Write the workflow test** through the public API, with one assertion block per step of the definition of done:

```python
def test_complete_governance_workflow(tenant, world):
    # 1 register agent  2 assign owners  3 purpose and permitted use
    # 4 complete assessment; recompute matches
    # 5 required controls frozen on submit  6 submit
    # 7 reviewer reads assessment and verified evidence
    # 8 conditional approval  9 decision row + audit event; chain verifies
    # 10 enforce mode: allowed tool runs (spy), denied tool does not
    # 11 suspend -> denied; second asset expires -> denied (moved clock)
    # 12 history returns every decision in audit order with references that resolve
```

- [ ] **Step 2: Add an e2e test** that drives steps 2 to 8 in the browser, with an actual agent key for step 10, and reads the history in the dashboard for step 12.

- [ ] **Step 3: Run both.** Expected: PASS. A failure here is a real gap: fix the owning code, not the test.

- [ ] **Step 4: Commit** `test(governance): prove the complete workflow end to end`

### Task 21: Security audit, regression, documentation

**Files:**
- Modify: `README.md`, `docs/ARCHITECTURE.md`, `docs/DATABASE_DESIGN.md`, `docs/API_CONTRACTS.md`, `docs/THREAT_MODEL.md`, `docs/DECISIONS.md`, `docs/TEST_STRATEGY.md`, `docs/REMEDIATION_PLAN.md`, `docs/PRODUCT_SPEC.md`

- [ ] **Step 1: Audit by attempting each violation not yet covered.** Walk the threats listed in spec section 16 against the running code. Add a test for each gap found, and record any finding that is not fixed in `REMEDIATION_PLAN.md` with a severity. Also check by hand: no route logs request bodies containing evidence content; no new `SECURITY DEFINER` beyond the one named; `git diff main -- backend/tests` touches existing test files only in the permitted ways.

- [ ] **Step 2: Run the complete regression**

Run Full and Lint, `.venv/Scripts/python scripts/mutation_check.py`, then in `frontend/` run `npm run lint`, `npm run typecheck`, `npm run build`, and `npm run test:e2e`. Expected: all pass, no `SURVIVED`. Record real counts, including skipped.

- [ ] **Step 3: Update the documents.** New threats with named tests and honest status. Decisions: governance roles apart from fixed roles (revisits D-009), owner references (resolves D-014), observe by default, hard block, agent-row locks, third definer function, per-tenant library, partial NIST library, ISO not loaded. Status table in the README: built with what remains unproven, Compose still unrun. Spec section 17's limits appear in `SECURITY_BOUNDARIES` or `THREAT_MODEL`. Make no production-readiness claim.

- [ ] **Step 4: Commit** `docs: document the governance engine and its limits`

- [ ] **Step 5: Report** exactly what changed, test counts from the run, and what remains unverified.
