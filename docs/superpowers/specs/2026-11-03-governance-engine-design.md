# Governance Engine: Design

**Status:** Built on `phase-3-governance`. **Phase:** 3. **Date:** 2026-11-03.

> **Aligned with the code in Task 21 (2026-11-15).** These sections were changed to say what was
> built and ruled, so the spec no longer differs from the code: 4 (`risk_methodology_events`
> instead of an `approved_by` column; `frozen_hash`), 7.1 (which states allow assessment), 7.4
> (review statuses, `frozen_hash` in the `SUBMIT` payload, resubmission, approval while information
> is requested), 10 (library statuses, the partial NIST library, how ISO could be loaded), 11.2
> (an evaluation error on a blocked asset in `observe`), 11.4 (`FOR NO KEY UPDATE`), 12
> (`409 ENFORCEMENT_MODE_UNCHANGED`), 13 (the review date as a trigger), and 17
> (limits found while building). Every deviation ruled during the build is listed in
> `docs/DECISIONS.md` under "Governance build rulings".

## 1. Goal

Make AI governance decisions affect runtime enforcement. An asset's owners, purpose, risk,
policies, approval, and evidence must end in a decision the Security Gateway can act on, and every
decision must be explainable and traceable to stored records.

This spec does not claim compliance or certification. A framework mapping records what the stored
evidence supports and nothing more.

### Success

This workflow runs end to end: register an agent, assign owners, assess it, submit it,
review it, approve it, have the gateway act on that decision, suspend or expire it and see the
enforcement response, and read the full history in the dashboard.

### Differences from the mission brief

| Brief | This design | Why |
|-------|-------------|-----|
| `/api/governance/*` | `/api/v1/governance/*` | All routes use `/api/v1` |
| `backend/governance/` with its own `models/`, `schemas/`, `repositories/` | `src/aegis/governance/`, models in `db/models.py`, routes in `api/` | Matches the repository. There is no repository layer |
| Material Symbols | lucide icons | The brief allows it, and the dashboard already uses lucide |
| Nine lifecycle states, no "revoked" | Revocation is a decision kind that leads to `SUSPENDED` | Keeps the brief's state list while still recording revocation |

## 2. Invariants

These are the rules the implementation and tests exist to protect.

1. **Governance only tightens.** It can turn an allow into a hold or a deny, and a hold into a deny.
   It never turns a deny into anything else, and existing reason codes do not change.
2. **Absence is not approval.** An asset with no governance record is never treated as approved.
3. **The gateway stays authoritative.** No other path reaches the tool executor.
4. **A human block can be lifted only by a human approval.** See section 7.2.
5. **History is append-only.** Profiles, assessments, policy versions, decisions, evidence,
   verifications, and gateway checks cannot be changed by the runtime role.
6. **Risk is deterministic.** The same inputs and methodology version give the same result. No LLM
   takes part.
7. **Missing information is never low risk.** It yields `INCOMPLETE` with a null risk level.
8. **Evidence existing does not satisfy a control.** Only a verification by someone other than the
   submitter counts.
9. **Controls come from verified sources.** No identifier is added unless it was checked against
   the authoritative document.

## 3. Module layout

```
src/aegis/governance/
  engine/
    risk.py          Pure: inputs + methodology -> result
    policies.py      Pure: profile + risk + evidence + policy versions -> required controls, findings
    lifecycle.py     Pure: the state machine
    enforcement.py   Pure: governance facts -> verdict; combines verdict with the policy evaluation
  methodology.py     The built-in risk methodology document
  frameworks/        Reviewed control libraries, one module per framework version
  assets.py          AssetGovernanceService
  risk.py            RiskAssessmentService
  policies.py        GovernancePolicyService
  approvals.py       GovernanceApprovalService
  evidence.py        EvidenceManagementService
  compliance.py      ComplianceMappingService
  reviews.py         GovernanceReviewService
  gateway_check.py   Loads governance facts inside the gateway transaction
  worker.py          Periodic review sweep
api/routes_governance.py, api/schemas_governance.py
```

`engine/` follows the same rule as `aegis.policy.engine`: no I/O, no clock, no LLM. Static guards
extend to it. Services follow the registry pattern: each write runs in the caller's tenant
transaction and appends its audit event there.

## 4. Data model (migrations `0005` onward)

Every table has `tenant_id`, `UNIQUE (tenant_id, id)`, composite tenant foreign keys, and `ENABLE`
plus `FORCE` row-level security. A global control catalog would violate the rule that only
`alembic_version` has no tenant, so libraries are seeded per tenant on first use, as correlation
rules are.

| Table | Purpose | Runtime grants |
|-------|---------|----------------|
| `governance_settings` | One row per tenant: `enforcement_mode`, `active_methodology_version_id`. No row means `observe` and the built-in methodology | `SELECT, INSERT`, `UPDATE` on those columns |
| `governance_role_grants` | `user_id`, `role`, `granted_by`, `granted_at`, `revoked_by`, `revoked_at` | `SELECT, INSERT`, `UPDATE (revoked_by, revoked_at)` |
| `asset_profile_versions` | `asset_id`, `version`, `profile_canonical`, `content_hash`, `business_owner_id`, `technical_owner_id`, `created_by` | `SELECT, INSERT` |
| `asset_governance_state` | Primary key `(tenant_id, asset_id)`. `status`, `version`, `current_profile_version_id`, `latest_assessment_id`, `current_decision_id`, `hard_block_decision_id`, `valid_until`, `next_review_at`, `updated_at` | `SELECT, INSERT`, `UPDATE` on those columns |
| `risk_methodology_versions` | `version`, `document_canonical`, `content_hash`, `created_by` | `SELECT, INSERT` |
| `risk_methodology_events` | `version_id`, `event` (`APPROVED`, `ACTIVATED`), `actor_id`, `audit_event_id`. Replaces an `approved_by` column: an append-only row cannot gain an approver after insert | `SELECT, INSERT` |
| `risk_assessments` | `asset_id`, `profile_version_id`, `methodology_version_id`, `input_canonical`, `input_hash`, `result_canonical`, `status`, `score`, `risk_level`, `assessed_by`, `audit_event_id` | `SELECT, INSERT` |
| `governance_policies` | `name`, `category` | `SELECT, INSERT` |
| `governance_policy_versions` | `policy_id`, `version`, `document_canonical`, `content_hash`, `effective_from`, `review_by`, `created_by` | `SELECT, INSERT` |
| `governance_policy_events` | `policy_version_id`, `event` (`APPROVED`, `ACTIVATED`, `DEACTIVATED`), `actor_id`, `audit_event_id` | `SELECT, INSERT` |
| `governance_reviews` | `asset_id`, `assessment_id`, `profile_version_id`, `submitted_by`, `assigned_reviewer`, `required_controls_canonical`, `findings_canonical`, `required_approvers`, `frozen_hash`, `status`, `version`, `submitted_at`, `closed_at` | `SELECT, INSERT`, `UPDATE (assigned_reviewer, status, version, closed_at)` |
| `governance_decisions` | Section 7.3 | `SELECT, INSERT` |
| `governance_decision_policy_versions` | Decision to policy version | `SELECT, INSERT` |
| `governance_decision_evidence` | Decision to evidence | `SELECT, INSERT` |
| `governance_evidence` | Section 9 | `SELECT, INSERT` |
| `governance_evidence_controls` | Evidence to control | `SELECT, INSERT` |
| `governance_evidence_verifications` | `evidence_id`, `outcome`, `method`, `note`, `verified_by`, `audit_event_id` | `SELECT, INSERT` |
| `governance_frameworks` | `key`, `version`, `source_url`, `source_document`, `library_status` | `SELECT, INSERT` |
| `governance_controls` | `framework_id`, `control_identifier`, `name`, `description`, `source_reference`, `required_evidence`, `policy_id` | `SELECT, INSERT` |
| `governance_control_assessments` | `control_id`, `status`, `note`, `assessed_by`, `audit_event_id` | `SELECT, INSERT` |
| `governance_control_assessment_evidence` | The evidence a control assessment cites, which must be linked to the same control | `SELECT, INSERT` |
| `governance_gateway_checks` | `decision_id`, `request_id`, `agent_id`, `asset_id`, `mode`, `observed_status`, `verdict`, `reason_code`, `governance_decision_id`, `checked_at` | `SELECT, INSERT` |

Append-only tables get the `aegis_reject_mutation` row and truncate triggers. The grants test and
`DATABASE_DESIGN.md` are updated with this table.

`ai_assets` and `agents` do not change. `risk_classification` stays as the registrant's declared
value, is labeled "declared" in governance views, and is never used as an assessment result or a
fallback. `owner` stays as the legacy label. The governance owners are the user references on the
profile, which is what makes separation of duties enforceable (D-014).

**Current-version pointers.** "Current" verification status, policy status, and control status are
read from the latest row by audit sequence, not by timestamp, because timestamps can tie.

## 5. Asset profile

A strict Pydantic model, stored as canonical JSON, one immutable version per change. Fields:
`asset_type` (`ai_application`, `autonomous_agent`, `model`, `model_provider`, `ai_enabled_service`),
`description`, `business_purpose`, `intended_use`, `prohibited_use`, `business_owner_id`,
`technical_owner_id`, `responsible_team`, `model_provider`, `model_name`, `model_version`,
`deployment_environment`, `data_categories`, `external_exposure`, `external_integrations`,
`autonomy_level`, `human_oversight`, `declared_tool_access`, `impact_level`, `third_party_reliance`,
and `evidence_references`.

All fields are optional at the schema level, so a partial profile can be saved and the risk engine
can name what is missing.

Tools and permissions are **not** taken from the profile for assets with agents. The assessment
reads the actual grants of the asset's agents. `declared_tool_access` is used only when an asset has
no agents, and that source is recorded in the assessment input.

**Registry hook.** Adding a tool or resource grant to an agent whose asset is approved or
conditionally approved moves the asset to `REASSESSMENT_REQUIRED` in the same transaction, because
the assessment no longer describes what the agent can do. Removing a grant does not. Assets with no
governance state are unaffected, so existing registry behavior is unchanged for them.

## 6. Risk engine

`assess(inputs, methodology) -> RiskResult` is pure. Scores are integers, because the audit chain
rejects floats.

### Built-in methodology, version 1

Each factor yields a level from 0 to 4. `score = sum(weight x level)`, with a maximum of 400.

| Factor | Weight | Input | Levels |
|--------|--------|-------|--------|
| Data sensitivity | 20 | `data_categories`, highest wins | `public` 0, `internal` 1, `personal` 3, `confidential` 3, `regulated` 4 |
| External exposure | 10 | `external_exposure` | `none` 0, `internal_users` 1, `partners` 2, `public` 4 |
| Agent autonomy | 20 | `autonomy_level` | `advisory` 0, `human_approved` 1, `supervised` 2, `bounded` 3, `autonomous` 4 |
| Tool access | 15 | Actual grants, highest wins | No tools 0, compute 1, read of public or internal resources 2, read of sensitive resources 3, any transmit tool 4 |
| Human oversight | 15 | `human_oversight` | `in_the_loop` 0, `on_the_loop` 2, `after_the_fact` 3, `none` 4 |
| Business and user impact | 10 | `impact_level` | `negligible` 0, `minor` 1, `moderate` 2, `major` 3, `severe` 4 |
| Deployment environment | 5 | `deployment_environment` | `development` 0, `test` 1, `staging` 2, `production_internal` 3, `production_external` 4 |
| Third-party reliance | 5 | `third_party_reliance` | `none` 0, `vetted` 1, `partially_vetted` 2, `unvetted` 4 |

Thresholds: below 100 `LOW`, below 200 `MEDIUM`, below 300 `HIGH`, otherwise `CRITICAL`.

Floors, because an average can hide one dangerous combination:

- Autonomy level 3 or higher with data sensitivity level 3 or higher: at least `HIGH`.
- `autonomous` with oversight `none` and any transmit tool: `CRITICAL`.

These weights and thresholds are **engineering judgment, not values taken from any standard**. The
methodology document and the dashboard say so.

### Result

- Per-factor level, weight, contribution, the input it used, and a plain explanation.
- Which floor applied, if any.
- `missing`: required inputs that were absent. Any missing factor makes the status `INCOMPLETE`,
  with null `score` and `risk_level`. A check constraint enforces
  `(status = 'COMPLETE') = (risk_level IS NOT NULL)`.
- `mitigations`: recommendations from the methodology document, keyed by factor and level.

### Versioning and configuration

A methodology is a canonical JSON document with a content hash, checked at every load. Weights,
level maps, thresholds, floors, and mitigation text all live in the document. A tenant may author a
new version; a different person holding `governance_reviewer` must approve it before it can become
active. Existing assessments keep the version they used.

`GET .../risk` can recompute a stored assessment from its stored input and report whether it still
matches, so determinism can be checked on real records rather than only in tests.

## 7. Lifecycle and approval

### 7.1 State machine

```
DRAFT ------------------> ASSESSMENT_REQUIRED, SUSPENDED, RETIRED
ASSESSMENT_REQUIRED ----> UNDER_REVIEW, SUSPENDED, RETIRED
UNDER_REVIEW -----------> APPROVED, CONDITIONALLY_APPROVED, REJECTED, SUSPENDED, RETIRED
APPROVED ---------------> REASSESSMENT_REQUIRED, SUSPENDED, RETIRED
CONDITIONALLY_APPROVED -> REASSESSMENT_REQUIRED, SUSPENDED, RETIRED
REJECTED ---------------> ASSESSMENT_REQUIRED, RETIRED
SUSPENDED --------------> REASSESSMENT_REQUIRED, RETIRED
REASSESSMENT_REQUIRED --> UNDER_REVIEW, SUSPENDED, RETIRED
RETIRED: terminal
```

Enforced twice, as approvals are: in `engine/lifecycle.py` and by a database trigger, which also
makes the asset and tenant columns immutable, requires `version` to increase by one, and forbids
`DELETE`. All transitions run under `SELECT ... FOR UPDATE` with optimistic version checks where a
client supplies a version.

Saving the first profile inserts the state row as `DRAFT`. Assessment is allowed in every state but
`RETIRED`; from `DRAFT` or `REJECTED` it moves the asset to `ASSESSMENT_REQUIRED`, and elsewhere it
leaves the status and the hard block unchanged. So the first assessment moves it to
`ASSESSMENT_REQUIRED`, meaning a complete assessment of the current profile is needed before
submission. Submission requires exactly that, and otherwise fails with `ASSESSMENT_NOT_CURRENT`.
Saving a new profile version while approved or conditionally approved moves the asset to
`REASSESSMENT_REQUIRED`.

An asset with no state row can be suspended directly: the row is inserted as `DRAFT` and moved to
`SUSPENDED` in one transaction. This is the emergency path for existing assets.

### 7.2 The hard block

`asset_governance_state.hard_block_decision_id` is set by a suspend, revoke, or reject decision, and
the trigger allows it to be cleared only in the update that moves the asset to `APPROVED` or
`CONDITIONALLY_APPROVED`.

Without this, moving a suspended asset to `REASSESSMENT_REQUIRED` or resubmitting a rejected one
would quietly lift the block in `observe` mode. The gateway checks the hard block before the status,
so a blocked asset stays denied through every intermediate state until a new approval.

These decisions also clear `valid_until`, so a prior approval cannot come back into force.

### 7.3 Decisions

`governance_decisions` is append-only. Columns: `asset_id`, `review_id`, `kind`, `from_status`,
`to_status`, `actor_type`, `decided_by`, `decided_at`, `reason` (required), `assessment_id`,
`conditions_canonical`, `conditions_hash`, `valid_until`, `next_review_at`, `audit_event_id`
(required).

Kinds: `SUBMIT`, `ASSIGN_REVIEWER`, `REQUEST_INFORMATION`, `APPROVAL_VOTE`, `APPROVE`,
`APPROVE_CONDITIONAL`, `REJECT`, `SUSPEND`, `REVOKE`, `REQUIRE_REASSESSMENT`, `RETIRE`.

Check constraints require, for `APPROVE` and `APPROVE_CONDITIONAL`: a user, an assessment, a
`valid_until`, and a `next_review_at`; and for `APPROVE_CONDITIONAL`: non-empty conditions. Policy
version and evidence references go in the two join tables. The system actor is allowed only for
`REQUIRE_REASSESSMENT`.

### 7.4 Reviews

Review statuses are `OPEN`, `INFO_REQUESTED`, `DECIDED`, and `WITHDRAWN`. One open review per asset,
by a partial unique index on status `OPEN` or `INFO_REQUESTED`. This is the duplicate-submission
guard. `REQUEST_INFORMATION` sets the review to `INFO_REQUESTED` and leaves the asset
`UNDER_REVIEW`. The submitter responds by adding evidence and then submitting again: a submission
while the review is `INFO_REQUESTED` withdraws that review and opens a new one, recomputing the
frozen values, keeping the assigned reviewer and the `UNDER_REVIEW` status, and recording a
`SUBMIT` decision. Earlier votes do not carry over, and the assessment must still be current. While
information is requested, a reviewer may reject but not approve (`409 REVIEW_AWAITING_INFORMATION`).
Suspend, revoke, and retire close an open review as `WITHDRAWN`.

At submission the policy engine computes the required controls and required approver count, and they
are frozen on the review, so a policy change mid-review cannot silently change what was asked. The
whole policy outcome is frozen, including the applicable version IDs and the self- and
owner-approval permissions. `frozen_hash` covers the review's identity and frozen text; it is
written into the `SUBMIT` decision's audit payload, and a review read for a decision is compared
with that event, so an edit followed by a recomputed hash is still detected. The `ASSIGN_REVIEWER`
payload carries the `reviewer_id`.

`minimum_approvers` (1 or 2, from applicable policies, highest wins, default 1) is implemented with
`APPROVAL_VOTE`. A partial unique index on `(tenant_id, review_id, decided_by)` for vote and approval
kinds prevents one person counting twice. The final required approval records `APPROVE` or
`APPROVE_CONDITIONAL` and changes the state.

### 7.5 Authorization and separation of duties

Governance authority is separate from the existing `reviewer` role.

`governance_role_grants` has one role, `governance_reviewer`. Only an `admin` can grant it, the
grantee must be an active `admin` or `reviewer`, and **no one can grant it to themselves**. A
tenant therefore needs two people before any governance approval can happen. That is intended.

| Action | Who |
|--------|-----|
| Read governance data | Any authenticated user. Inline evidence content: `admin`, `reviewer` only |
| Save profile, run assessment, submit, add evidence | `admin` |
| Decide a review, verify evidence, approve a policy or methodology version, record a control assessment | Holder of `governance_reviewer` |
| Suspend or revoke | `admin`, or holder of `governance_reviewer` |
| Retire | `admin` |
| Change enforcement mode, grant or revoke the role | `admin` |
| Anything, as an agent | Never. Governance routes accept only user principals |

**Self-approval is refused by default.** The submitter may decide their own submission only if an
applicable policy explicitly sets `self_approval: permitted` and no other applicable policy prohibits
it. The same rule covers the asset's business and technical owners through `owner_approval`. When
policies conflict, the most restrictive wins. If a reviewer is assigned, only that reviewer can
decide. Refusals are audited as `authz.denied`.

## 8. Policies

A governance policy version is an immutable canonical document:

```
applicability:  risk_levels, asset_types, environments, data_categories  (all optional, ANDed)
controls:       required_human_oversight, permitted_model_providers, data_handling,
                required_evaluations, required_documentation, minimum_approvers,
                required_evidence_categories, reassessment_interval_days,
                incident_reporting, required_owners, self_approval, owner_approval
```

Both sets are closed, typed schemas. Name, description, category, severity, version, effective date,
review date, creator, approver, and activation status are all held on the version or its events.
Deny-by-validation: an unknown key is rejected.

Status changes are rows in `governance_policy_events`, so the version itself never changes. The
approver must not be the creator. Only an approved version inside its effective window can apply.
These are separate tables and routes from `policies` and `policy_versions`, which remain the runtime
rules.

`engine/policies.py` produces, for an asset, the list of applicable versions, the required controls,
and findings such as "permitted providers do not include this provider". Findings are stored on the
review and shown to the reviewer. They inform the decision; they do not make it.

## 9. Evidence

`governance_evidence` columns: `asset_id`, `category`, `description`, `source_type`,
`submitted_by`, `created_at`, `content_sha256`, and by source type:

| `source_type` | Stored | What verification can prove |
|---------------|--------|------------------------------|
| `internal_record` | One composite foreign key: assessment, decision, audit event, incident, or investigation run | The record exists in this tenant and its hash still verifies |
| `inline` | `content_text`, within the 64 KB request limit | The stored text still matches its hash |
| `external_reference` | `source_uri`, a declared hash | Only what was submitted. The hash proves integrity if the content is supplied at verification, and nothing otherwise |

Categories are the brief's ten. AEGIS does not store uploaded files in this phase.

Verification is append-only, by a holder of `governance_reviewer` who is **not the submitter**,
enforced in the service and by a trigger. `method` is `internal_record_checked`, `content_recomputed`,
or `manual_attestation`. The dashboard shows the method, so a manual attestation is not mistaken for
a checked hash. A control counts evidence only when its latest verification outcome is `VERIFIED`.

The existing `GET /evidence/{type}/{id}` route is for investigation records and stays as it is.

## 10. Compliance mapping

A framework module holds, for each control: identifier, name, an AEGIS-written description, and the
page or section of the source it was checked against. A test asserts that every shipped identifier
appears in a checked-in list taken from that source.

- **NIST AI RMF 1.0 (NIST AI 100-1):** public. Identifiers are verified against the published PDF
  during Milestone 6, and only those verified ship. As built, 19 of the source's 72 subcategories
  ship, and the framework record says `LOADED_PARTIAL` with `source_control_count` 72.
- **ISO/IEC 42001:2023:** the framework record is created with `library_status = NOT_LOADED` and
  **no controls**, because the Annex A identifiers could not be verified against an authoritative
  source. The dashboard states this. Loading it later means adding a framework module from a licensed
  copy, using identifiers and AEGIS-written descriptions rather than ISO's text. Libraries are
  seeded once per framework row, so for tenants that already exist it also needs a new migration
  that seeds the controls.

`library_status` is `NOT_LOADED`, `LOADED_PARTIAL`, or `LOADED`, so a partial library never reads as
complete.

Control status is a human assessment, append-only, at tenant level. With no row the status is
`NOT_ASSESSED`. `IMPLEMENTED` and `PARTIALLY_IMPLEMENTED` are refused unless the control has at least
one verified evidence record, returning `EVIDENCE_REQUIRED`. Every framework view carries the
statement that a mapping does not establish certification or compliance.

## 11. Gateway integration

### 11.1 Contract

```
governance facts = (mode, state or none, hard block, conditions, valid_until, now)
verdict          = enforcement.check(facts, tool, action, resource classification)
final outcome    = enforcement.combine(policy evaluation, verdict)
```

The check runs in `_decide_and_execute` and in the re-evaluation in `_execute_approved`, after the
policy evaluation and in the same transaction. The verdict is applied only when the policy result is
`ALLOW` or `REQUIRE_APPROVAL`. Hard-check and policy denials keep their reason codes.

### 11.2 Behavior

Checked in this order; the first match wins.

| # | Condition | `observe` | `enforce` | Reason code |
|---|-----------|-----------|-----------|-------------|
| 1 | Asset retired | Deny | Deny | `GOVERNANCE_RETIRED` |
| 2 | Hard block set (suspended, revoked, rejected) | Deny | Deny | `GOVERNANCE_BLOCKED` |
| 3 | Stored conditions fail their hash check | Deny | Deny | `GOVERNANCE_INTEGRITY_FAILED` |
| 4 | Approval has expired (`valid_until` passed), whatever the status | Pass, recorded | Deny | `GOVERNANCE_APPROVAL_EXPIRED` |
| 5 | No approval in force: no state row, or any status with a null `valid_until` | Pass, recorded | Deny | `GOVERNANCE_NOT_APPROVED` |
| 6 | The approval in force has a condition that denies this action | Deny | Deny | `GOVERNANCE_CONDITION_DENIED` |
| 7 | `REASSESSMENT_REQUIRED` or `UNDER_REVIEW`, with an approval in force | Pass, recorded | Hold | `GOVERNANCE_REASSESSMENT_REQUIRED` |
| 8 | The approval in force has a condition that holds this action | Hold | Hold | `GOVERNANCE_CONDITION_HOLD` |
| 9 | `APPROVED`, or `CONDITIONALLY_APPROVED` with conditions passed | Pass | Pass | None |

An approval is in force when `valid_until` is set and has not passed. Conditions come from
`current_decision_id`, and stay in force through reassessment.

Expiry is compared to the clock inside the gateway, so it does not depend on the worker. Row 4
precedes row 7, so the result does not depend on whether the worker has run yet.

Three orderings are deliberate. Submitting a reassessment does not worsen an in-force asset from a
hold to a deny (row 7 covers `UNDER_REVIEW`). A tool denied by a condition cannot become approvable
during reassessment (row 6 precedes row 7). And a reassessment does not extend an expired approval
(row 4 precedes both).

A hold uses the existing action approval flow. At re-evaluation a hold does not block an action a
person has already approved; a deny does, and cancels it. So suspending an asset cancels actions
already approved, as disabling an agent does today.

**Failures.** An exception in the check yields a deny in `enforce` with
`GOVERNANCE_EVALUATION_ERROR`. In `observe` it is recorded and does not block, because `observe`
exists to guarantee no new outage, except that rows 1 and 2 are read from the state row alone and
still deny a retired or hard-blocked asset, since a person's decision applies in both modes. A database failure aborts the transaction and returns 503 in both
modes, as it does today.

### 11.3 Conditions

A closed, typed set: `denied_tools`, `held_tools`, `denied_actions`, `hold_all`,
`max_resource_classification`. These can only restrict. `advisory_conditions` holds free text, is
shown to people, and is labeled as not enforced by the gateway.

### 11.4 Concurrency

The gateway already takes a share lock on the agent row. Suspend, revoke, and reject (and the other
writes that change what an assessment describes) take `FOR NO KEY UPDATE` on all the asset's agent
rows, in ID order, before changing state. This serializes them against in-flight evaluations even
for an asset with no state row, which a lock on the state row could not do. The order is agent
rows, then state, then the chain head, matching existing code. `FOR NO KEY UPDATE` rather than
`FOR UPDATE`, because `FOR UPDATE` also conflicts with the key share lock a foreign key check takes:
a finishing execution holds the chain head and needs that lock on the agent row for its security
event, which deadlocked against a suspension. `FOR NO KEY UPDATE` still conflicts with the
gateway's share lock.

A mode switch is not serialized against in-flight evaluations. One in-flight action may use the old
mode, the same accepted behavior as policy activation.

### 11.5 Recording

- Each policy decision, including a denied one, writes a `governance_gateway_checks` row with a
  foreign key to that decision, and adds a `governance` object to the decision's `evidence` and to the `action.decision`
  audit payload. No extra audit event is needed, so the chain's write rate does not change.
- A governance deny or hold is an ordinary `DENY` or `REQUIRE_APPROVAL` decision, so it projects to
  the existing `gateway.action_denied` or `gateway.approval_required` security event with a
  `GOVERNANCE_*` reason and feeds existing correlation.
- An `observe` pass is **not** projected as a security event. Every action from an unmanaged asset
  would otherwise create an event and a correlation pass. The checks table holds it.
- Lifecycle decisions project as a new `governance.status_changed` event type, added to the schema
  allowlist. Older audit events are unaffected, so `SCHEMA_VERSION` does not change.

### 11.6 Compatibility and migration

1. The migration creates tables only. It does not touch existing assets or give them a state.
2. Every tenant starts in `observe`. Existing gateway outcomes do not change, which the unmodified
   existing test suite demonstrates.
3. Existing assets appear as "Not governed" and are recorded as `GOVERNANCE_NOT_APPROVED` checks.
4. An admin works through them, using `GET /governance/enforcement/preflight`, which lists every
   asset that would be denied or held and how many actions each attempted recently.
5. An admin switches the tenant to `enforce`, which is audited and can be reversed.

Decisions a person made (rows 1, 2, 6, 8) apply in both modes, because nothing about migration
justifies ignoring an explicit decision.

## 12. API

All under `/api/v1/governance`, with existing conventions: `Page[...]` lists, strict schemas, the
standard error shape, and tenant taken only from the principal. Every route is covered by the
"no tenant input" guard and the authorization tests.

```
GET   /overview
GET   /assets                                   search, risk, status, owner filters
GET   /assets/{id}
POST  /assets/{id}/profile                      new profile version
POST  /assets/{id}/assess
GET   /assets/{id}/risk                         latest, with recomputation check
GET   /assets/{id}/assessments
GET   /assets/{id}/history                      decisions, assessments, profile versions
POST  /assets/{id}/submit
POST  /assets/{id}/suspend
POST  /assets/{id}/revoke
POST  /assets/{id}/reassess
POST  /assets/{id}/retire
GET   /approvals
GET   /approvals/{id}
POST  /approvals/{id}/assign
POST  /approvals/{id}/approve                   optional conditions make it conditional
POST  /approvals/{id}/reject
POST  /approvals/{id}/request-information
GET   /policies
POST  /policies
POST  /policies/{id}/versions
POST  /policies/{id}/versions/{vid}/approve
POST  /policies/{id}/versions/{vid}/activate
POST  /policies/{id}/versions/{vid}/deactivate
GET   /methodologies
POST  /methodologies
POST  /methodologies/{id}/approve
POST  /methodologies/{id}/activate
GET   /evidence
POST  /evidence
GET   /evidence/{id}
POST  /evidence/{id}/verify
GET   /frameworks
GET   /controls
POST  /controls/{id}/assess
GET   /reviews/due
GET   /enforcement
GET   /enforcement/preflight
POST  /enforcement                              409 ENFORCEMENT_MODE_UNCHANGED if already set
GET   /people                                   id and email, admin and reviewer only, for pickers
POST  /role-grants
POST  /role-grants/{id}/revoke
```

## 13. Review scheduling

`worker.py` follows `CorrelationWorker`: a polling thread, disabled in tests, with settings
`governance_worker_enabled` and `governance_review_poll_seconds`. For each due asset it records a
system `REQUIRE_REASSESSMENT` decision through the normal lifecycle, one asset per transaction. An
approved asset is due when `valid_until` or `next_review_at` has passed. A passed review date can
therefore turn a pass into a hold in `enforce`, exactly as a person's `/reassess` does; expiry
itself is computed by the gateway, so the worker never changes that verdict.

To find tenants with no tenant context it needs one new ID-only function,
`aegis_tenants_with_due_governance_reviews(p_now timestamptz)`, with a matching owner policy limited
to rows with a `next_review_at`. This is a deliberate third `SECURITY DEFINER` exception, and
`test_only_the_id_lookups_are_security_definer` gains its name.

A worker failure is logged and retried. It cannot affect the gateway, since expiry is computed there.

## 14. Frontend

A "Governance" sidebar group with a shared sub-navigation, reusing `ui.tsx` and adding the new statuses
to `StatusBadge`. Server components read through `api()`, and mutations are server actions.

| Route | View |
|-------|------|
| `/governance` | Overview: counts from stored records only, plus enforcement mode |
| `/governance/assets` | Inventory with search and filters |
| `/governance/assets/[id]` | Profile, policies, history, evidence, mappings, related incidents |
| `/governance/assets/[id]/risk` | Factor breakdown, missing information, mitigations, history |
| `/governance/approvals`, `/approvals/[id]` | Pending submissions; review and decide |
| `/governance/policies` | Library, versions, active and inactive, applicability |
| `/governance/compliance` | Controls, coverage, outstanding evidence, certification disclaimer, ISO "not loaded" |
| `/governance/reviews` | Upcoming, overdue, reassessment requests |

Every view has empty, loading, and error states. A new `PermissionDenied` component handles
`ApiError` 403, since the existing boundary treats all errors alike. Declared and assessed risk are
always labeled differently. Registering agents stays API-only, as it is today; profile editing and all
review actions are in the dashboard. Layouts use the existing responsive patterns.

`seed_demo.py` gains synthetic governance data through the real API, labeled synthetic.

## 15. Testing

Tests are written first, per milestone, against real PostgreSQL as `aegis_app`.

| Required test | File |
|---------------|------|
| Cross-tenant asset and evidence access | `security/test_governance_isolation.py` |
| Risk determinism, missing information, versioning | `unit/test_governance_risk.py` (with hypothesis), `security/test_governance_assessments.py` |
| Policy version immutability | `security/test_governance_policies.py` |
| Approval authorization, self-approval, invalid transitions, duplicates | `security/test_governance_approvals.py`, `unit/test_governance_lifecycle.py` |
| Evidence verification and hash integrity | `security/test_governance_evidence.py` |
| Compliance mapping accuracy | `security/test_governance_compliance.py` |
| Audit record immutability | `security/test_governance_audit.py` |
| Suspended, expired, missing, revoked; gateway integration | `security/test_governance_gateway.py`, `unit/test_governance_enforcement.py` |
| Review scheduling | `security/test_governance_reviews.py` |
| Concurrent transitions | `test_concurrent_*` with real threads, in the approval and gateway files |
| Failure recovery | Rollback on audit failure, worker failure, evaluation error, in the same files |
| Full workflow | `security/test_governance_workflow.py`, `frontend/e2e/governance.spec.ts` |

Specific tests this design needs:

- A suspended asset stays denied through `REASSESSMENT_REQUIRED` and `UNDER_REVIEW`, in `observe`,
  until a new approval.
- Suspending during an in-flight evaluation, with real threads, on an asset with no state row.
- Expiry gives the same verdict whether or not the worker has run.
- A policy deny keeps its reason code on a suspended asset.
- `observe` passes produce no security events.
- A grant added after approval forces reassessment.
- An admin cannot grant themselves `governance_reviewer`.

The existing suite must pass **unmodified**, apart from additions to the two catalog tests named in
this spec. New enforcement controls are added to `mutation_check.py`, and `SURVIVED` fails the
milestone.

## 16. Delivery

Branch `phase-3-governance`. One verified commit per milestone. Nothing is pushed unless asked.

| Milestone | Delivers |
|-----------|----------|
| 2 | Migration foundation, role grants, profiles, state, inventory API |
| 3 | Risk engine, methodology versions, assessments |
| 4 | Governance policies and versioning |
| 5 | Lifecycle, reviews, decisions, separation of duties |
| 6 | Evidence, verification, frameworks, NIST library |
| 7 | Gateway check, conditions, enforcement mode, preflight, worker |
| 8 | Governance Center |
| 9 | Security audit, mutation run, full regression, documentation |

Migration `0005` is split across milestones as `0005`, `0006`, and so on, so each milestone's
migration ships with its own tests.

Documentation updated in Milestone 9: `README`, `ARCHITECTURE`, `DATABASE_DESIGN`, `API_CONTRACTS`,
`THREAT_MODEL` (new threats: forged governance status, self-approval, unblock through lifecycle,
stale approval, evidence laundering, unsupported compliance claims, methodology tampering),
`DECISIONS`, `TEST_STRATEGY`, `REMEDIATION_PLAN`.

## 17. Known limits

To be stated in the product and documentation, not left implicit.

- **Assessments trust declared inputs.** Only tool access is observed. A false profile produces a
  wrong risk level. Review and verified evidence reduce this risk but do not remove it.
- **`observe` does not stop unapproved assets.** Until a tenant switches, only explicit human decisions
  are enforced.
- **Governance covers only gateway operations**, like everything else in AEGIS.
- **Asset-level, not agent-level.** All agents of an asset share its governance status.
- **Two admins can collude**, and a stolen admin session can grant the role to another account it
  controls. Both are audited, not prevented.
- **ADV4 and ADV5 limits carry over.** Someone with database control can forge these records as they
  can any other (T11, T15).
- **Default weights are judgment**, not calibrated against real outcomes.
- **Found while building** (full list in `docs/THREAT_MODEL.md`, "Governance known limits"):
  external documents over 16,000 bytes can only be attested; a verification by a reviewer whose
  grant is later revoked still counts; an expired but unprocessed approval is handled by the
  gateway and the worker only aligns the status; the review date also triggers reassessment; most
  policy controls are shown, not enforced (`reassessment_interval_days` does not bound approval
  dates); ISO/IEC 42001 can reach existing tenants only through a new migration; and the dashboard
  has no controls for adding evidence, suspending, revoking, retiring, or requesting reassessment.

## 18. Out of scope

ISO/IEC 42001 control content, certification or legal claims, evidence file storage, notifications,
custom roles, per-asset enforcement mode, more than two required approvers, LLM assistance of any kind
in governance, and the open items in `REMEDIATION_PLAN.md` other than the part of risk 5 addressed by
owner references.
