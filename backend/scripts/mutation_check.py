"""Prove the security tests can fail: remove each control and require a test to catch it.

Works on a temporary copy of the backend, so the source tree is never touched. A control
whose removal goes unnoticed is reported as SURVIVED, and the script exits non-zero.

    python scripts/mutation_check.py [text matched against mutation names]
"""

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
MIGRATION = "migrations/versions/0001_initial.py"
GATEWAY = "src/aegis/gateway/service.py"
SEC = "tests/security"
EVENTS_MIGRATION = "migrations/versions/0002_security_events.py"
INCIDENTS_MIGRATION = "migrations/versions/0003_incidents.py"
INVESTIGATION_MIGRATION = "migrations/versions/0004_investigations.py"
PROJECTION = "src/aegis/events/projection.py"
RULES = "src/aegis/correlation/rules.py"
ENGINE = "src/aegis/correlation/engine.py"
INCIDENTS = "src/aegis/incidents/service.py"
EVIDENCE = "src/aegis/investigation/evidence.py"
HYPOTHESES = "src/aegis/investigation/hypotheses.py"
INVESTIGATION = "src/aegis/investigation/service.py"
UNIT_RULES = "tests/unit/test_correlation_rules.py"
APPROVALS = "src/aegis/governance/approvals.py"
ASSETS = "src/aegis/governance/assets.py"
REGISTRY = "src/aegis/registry/service.py"
GOVERNANCE_ROUTES = "src/aegis/api/routes_governance.py"
RETIRED_MIGRATION = "migrations/versions/0010_governance_retired.py"
LIFECYCLE = f"{SEC}/test_governance_lifecycle_actions.py"
GOVERNANCE_EVIDENCE = "src/aegis/governance/evidence.py"
EVIDENCE_TESTS = f"{SEC}/test_governance_evidence.py"


@dataclass(frozen=True)
class Mutation:
    name: str
    file: str
    old: str
    new: str
    tests: str


MUTATIONS = [
    Mutation("Deny path reaches the executor", GATEWAY,
             "elif evaluation.outcome is Outcome.ALLOW:", "else:", f"{SEC}/test_gateway.py"),
    Mutation("Engine failure yields allow", GATEWAY,
             'return Evaluation(Outcome.DENY, "POLICY_EVALUATION_ERROR")',
             'return Evaluation(Outcome.ALLOW, "POLICY_EVALUATION_ERROR")',
             f"{SEC}/test_policy_enforcement.py"),
    Mutation("Policy content hash not checked", GATEWAY,
             "if version is None or sha256_hex(version.document_canonical) "
             "!= version.content_hash:",
             "if version is None:", f"{SEC}/test_policy_enforcement.py"),
    Mutation("Pending approval can execute", GATEWAY,
             'if approval is None or approval.status != "APPROVED":',
             'if approval is None or approval.status not in ("APPROVED", "PENDING"):',
             f"{SEC}/test_approval_safety.py"),
    Mutation("Re-evaluation at execution ignored", GATEWAY,
             "if evaluation.outcome is Outcome.DENY:\n                    refused",
             "if False:\n                    refused", f"{SEC}/test_approval_safety.py"),
    Mutation("Action hash not rechecked", GATEWAY,
             "elif recomputed != approval.action_hash or recomputed != request.action_hash:",
             "elif False:", f"{SEC}/test_approval_safety.py"),
    Mutation("Approval expiry not checked at execution", GATEWAY,
             "if now >= approval.expires_at:\n                refused",
             "if False:\n                refused",
             f"{SEC}/test_approval_safety.py"),
    Mutation("Idempotency key content not compared", GATEWAY,
             "if existing is not None and existing.action_hash != action_hash:", "if False:",
             f"{SEC}/test_gateway.py"),
    Mutation("Agent can execute another agent's request", GATEWAY,
             "if request is None or request.agent_id != agent.id:\n            raise NotFound()\n"
             "        # The row lock",
             "if request is None:\n            raise NotFound()\n        # The row lock",
             f"{SEC}/test_approval_safety.py"),
    Mutation("Audit write failure not fatal", GATEWAY,
             "    except Exception as error:\n        logger.exception(\"protected action failed "
             "closed\")\n        raise ServiceUnavailable() from error",
             "    except Exception as error:\n        logger.exception(\"protected action failed "
             "closed\")\n        return None", f"{SEC}/test_gateway.py"),
    Mutation("Engine ignores tool grant", "src/aegis/policy/engine.py",
             'if not facts.tool_granted:\n        return "TOOL_NOT_GRANTED"', "",
             "tests/unit/test_policy_engine.py"),
    Mutation("Engine ignores destination clearance", "src/aegis/policy/engine.py",
             'return "DESTINATION_CLEARANCE_INSUFFICIENT"', "pass",
             "tests/unit/test_policy_engine.py"),
    Mutation("Engine default allows", "src/aegis/policy/engine.py",
             'return Evaluation(Outcome.DENY, "NO_MATCHING_RULE")',
             'return Evaluation(Outcome.ALLOW, "NO_MATCHING_RULE")',
             "tests/unit/test_policy_engine.py"),
    Mutation("Hash ignores payload", "src/aegis/audit/chain.py",
             '"payload": event.payload,', "", f"{SEC}/test_audit_integrity.py"),
    Mutation("Chain link not checked", "src/aegis/audit/chain.py",
             'if event.prev_hash != previous_hash:', 'if False:',
             f"{SEC}/test_audit_integrity.py"),
    Mutation("Verification ignores head", "src/aegis/audit/chain.py",
             "if previous_hash != head.head_hash:", "if False:",
             f"{SEC}/test_audit_integrity.py"),
    Mutation("Verification ignores tail", "src/aegis/audit/chain.py",
             "if checked != head.seq:", "if False:", f"{SEC}/test_audit_integrity.py"),
    Mutation("Audit head not locked", "src/aegis/audit/chain.py",
             "select(AuditChainHead).where(AuditChainHead.tenant_id == tenant_id)"
             ".with_for_update()\n",
             "select(AuditChainHead).where(AuditChainHead.tenant_id == tenant_id)\n",
             f"{SEC}/test_audit_integrity.py"),
    Mutation("Tenant context not transaction-local", "src/aegis/db/session.py",
             "set_config('app.tenant_id', :tenant, true)",
             "set_config('app.tenant_id', :tenant, false)",
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("Revoked credential accepted", "src/aegis/security/authentication.py",
             "and credential.revoked_at is None", "", f"{SEC}/test_authn.py"),
    Mutation("Expired credential accepted", "src/aegis/security/authentication.py",
             "and (credential.expires_at is None or credential.expires_at > now)", "",
             f"{SEC}/test_authn.py"),
    Mutation("Wrong agent secret accepted", "src/aegis/security/authentication.py",
             "            and matched\n", "", f"{SEC}/test_authn.py"),
    Mutation("Inactive user accepted", "src/aegis/security/authentication.py",
             "elif user.is_active:", "else:",
             f"{SEC}/test_authn.py"),
    Mutation("JWT audience not required", "src/aegis/security/tokens.py",
             "audience=self._audience,", 'options_placeholder=None,'.replace(
                 "options_placeholder=None,", 'audience=[self._audience, "another-service"],'),
             f"{SEC}/test_authn.py"),
    Mutation("Role checks removed", "src/aegis/api/dependencies.py",
             "if user.role not in roles:", "if False:", f"{SEC}/test_authz.py"),
    Mutation("Reviewer identity not recorded", "src/aegis/approvals/service.py",
             "approval.decided_by = user.id", "pass", f"{SEC}/test_approval_safety.py"),
    Mutation("Approval state machine not checked", "src/aegis/approvals/service.py",
             "if not can_transition(approval.status, target):", "if False:",
             f"{SEC}/test_approval_safety.py"),
    Mutation("RLS not forced", MIGRATION,
             'f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",', "",
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("RLS not enabled on tenant tables", MIGRATION,
             'f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",', "",
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("Runtime role may update audit events", MIGRATION,
             '"GRANT SELECT, INSERT ON audit_events TO aegis_app",',
             '"GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON audit_events TO aegis_app",',
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("Append-only trigger absent", MIGRATION,
             'for table in ("audit_events", "policy_decisions", "policy_versions")',
             'for table in ("policy_decisions", "policy_versions")',
             f"{SEC}/test_audit_integrity.py"),
    Mutation("Approval transition trigger absent", MIGRATION,
             "CREATE TRIGGER approvals_transition BEFORE UPDATE OR DELETE ON approvals\n"
             "    FOR EACH ROW EXECUTE FUNCTION aegis_approval_transition()",
             "SELECT 1", f"{SEC}/test_approval_safety.py"),
    Mutation("Runtime role may edit policy versions", MIGRATION,
             '"GRANT SELECT, INSERT ON policy_versions TO aegis_app",',
             '"GRANT SELECT, INSERT, UPDATE, DELETE ON policy_versions TO aegis_app",',
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("Composite tenant foreign key absent", MIGRATION,
             "FOREIGN KEY (tenant_id, asset_id) REFERENCES ai_assets (tenant_id, id)",
             "FOREIGN KEY (asset_id) REFERENCES ai_assets (id)",
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("Execution uniqueness absent", MIGRATION,
             "UNIQUE (tenant_id, request_id),\n        FOREIGN KEY (tenant_id, request_id) "
             "REFERENCES action_requests (tenant_id, id)\n    )\n    \"\"\",\n    \"\"\"\n"
             "    CREATE TABLE simulated_outbox",
             "FOREIGN KEY (tenant_id, request_id) REFERENCES action_requests (tenant_id, id)\n"
             "    )\n    \"\"\",\n    \"\"\"\n    CREATE TABLE simulated_outbox",
             f"{SEC}/test_approval_safety.py"),
    # Security events
    Mutation("Audit events not projected", "src/aegis/audit/chain.py",
             "    project_audit_event(session, event)\n", "", f"{SEC}/test_security_events.py"),
    Mutation("Unknown event attributes accepted", "src/aegis/events/schema.py",
             "if expected is None:\n                raise ValueError(f\"attribute {key!r} is not "
             "allowed\")",
             "if expected is None:\n                continue", f"{SEC}/test_security_events.py"),
    Mutation("Extra event fields accepted", "src/aegis/events/schema.py",
             'model_config = ConfigDict(extra="forbid", frozen=True)',
             'model_config = ConfigDict(extra="ignore", frozen=True)',
             f"{SEC}/test_security_events.py"),
    Mutation("Tampered event passes reprojection", PROJECTION,
             "return all(getattr(event, name) == value for name, value in "
             "record.model_dump().items())",
             "return True", f"{SEC}/test_security_events.py"),
    Mutation("Altered source audit event trusted", PROJECTION,
             "if compute_event_hash(audit) != audit.event_hash:", "if False:",
             f"{SEC}/test_security_events.py"),
    Mutation("Attacker input copied into events", PROJECTION,
             '"attributes": _suppressed(audit),\n        }\n\n    return build',
             '"attributes": {"status": str(audit.payload.get("email_sha256_prefix"))},\n'
             '        }\n\n    return build',
             f"{SEC}/test_security_events.py"),
    Mutation("Failure flood not limited", "src/aegis/events/limiter.py",
             "if bucket.used >= self.limit_per_minute:", "if False:",
             f"{SEC}/test_security_events.py"),
    Mutation("Suppressed failures not counted", "src/aegis/events/limiter.py",
             "bucket.suppressed += 1", "pass", f"{SEC}/test_security_events.py"),
    Mutation("Role denials not recorded", "src/aegis/api/app.py",
             "if principal is None or not isinstance(error, Forbidden | NotFound):",
             "if True:", f"{SEC}/test_security_events.py"),
    Mutation("Execution refusals not recorded", GATEWAY,
             'event_type="approval.execution_refused"', 'event_type="test.unmapped"',
             f"{SEC}/test_security_events.py"),
    Mutation("Event source foreign key absent", EVENTS_MIGRATION,
             "FOREIGN KEY (tenant_id, source_audit_event_id) REFERENCES audit_events "
             "(tenant_id, id),\n", "", f"{SEC}/test_security_events.py"),
    Mutation("Duplicate source allowed", EVENTS_MIGRATION,
             "UNIQUE (tenant_id, source_audit_event_id),\n", "",
             f"{SEC}/test_security_events.py"),
    Mutation("Duplicate timeline guard: event links not unique", INCIDENTS_MIGRATION,
             "PRIMARY KEY (tenant_id, incident_id, event_id),\n", "",
             f"{SEC}/test_correlation.py"),
    Mutation("Event guard trigger absent", EVENTS_MIGRATION,
             "CREATE TRIGGER security_events_guard BEFORE UPDATE OR DELETE ON security_events\n"
             "    FOR EACH ROW EXECUTE FUNCTION aegis_security_event_guard()",
             "SELECT 1", f"{SEC}/test_security_events.py"),
    Mutation("Runtime role may rewrite events", EVENTS_MIGRATION,
             '"GRANT SELECT, INSERT ON security_events TO aegis_app",',
             '"GRANT SELECT, INSERT, UPDATE, DELETE ON security_events TO aegis_app",',
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("Event RLS absent", EVENTS_MIGRATION,
             '"ALTER TABLE security_events ENABLE ROW LEVEL SECURITY",', "",
             f"{SEC}/test_tenant_isolation_db.py"),
    # Correlation
    Mutation("Threshold ignored", RULES,
             "if len(candidate) >= rule.threshold and (", "if (", UNIT_RULES),
    Mutation("Window ignored", RULES,
             "ordered[end].occurred_at - first.occurred_at <= window",
             "ordered[end].occurred_at - first.occurred_at <= window * 1000", UNIT_RULES),
    Mutation("Distinct targets ignored", RULES,
             "or _distinct_targets(candidate) >= rule.min_distinct_targets", "or True",
             UNIT_RULES),
    Mutation("Rule reason filter ignored", RULES,
             "if match.reason_codes is not None and event.reason_code not in "
             "match.reason_codes:",
             "if False:", UNIT_RULES),
    Mutation("Agents share a correlation scope", RULES,
             'return None if identity is None else f"{rule.scope}:{identity}"',
             'return None if identity is None else rule.scope',
             f"{SEC}/test_correlation.py"),
    Mutation("Linked events counted again", ENGINE,
             "SecurityEvent.id.not_in(already_linked),\n", "",
             f"{SEC}/test_correlation.py"),
    Mutation("Late events cannot form an incident", ENGINE,
             "SecurityEvent.occurred_at >= event.occurred_at - window,",
             "SecurityEvent.occurred_at >= event.occurred_at,",
             f"{SEC}/test_correlation.py"),
    Mutation("Lateness limit ignored", ENGINE,
             "if event.occurred_at < earliest:", "if False:", f"{SEC}/test_correlation.py"),
    Mutation("Events not marked processed", ENGINE,
             "event.correlation_processed_at = now\n", "pass\n",
             f"{SEC}/test_correlation.py"),
    Mutation("Conflict not retried", ENGINE,
             "if conflicts > _MAX_CONFLICT_RETRIES:", "if True:",
             f"{SEC}/test_correlation.py"),
    Mutation("Duplicate active incidents allowed", INCIDENTS_MIGRATION,
             "CREATE UNIQUE INDEX incidents_one_active", "CREATE INDEX incidents_one_active",
             f"{SEC}/test_correlation.py"),
    Mutation("Tampered rule trusted", "src/aegis/correlation/store.py",
             "if sha256_hex(version.definition_canonical) != version.content_hash:", "if False:",
             f"{SEC}/test_correlation.py"),
    Mutation("Rule version not recorded", ENGINE,
             "rule_version=loaded.version.version,", "rule_version=1,",
             f"{SEC}/test_correlation.py"),
    Mutation("Incident audit events feed correlation", PROJECTION,
             '    "correlation.rule_version_created": _rule_changed,\n',
             '    "correlation.rule_version_created": _rule_changed,\n'
             '    "incident.created": _rule_changed,\n',
             f"{SEC}/test_correlation.py"),
    Mutation("Incident RLS not forced", INCIDENTS_MIGRATION,
             'f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",', "",
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("Incident link foreign key loses its tenant", INCIDENTS_MIGRATION,
             "FOREIGN KEY (tenant_id, event_id) REFERENCES security_events (tenant_id, id)",
             "FOREIGN KEY (event_id) REFERENCES security_events (id)",
             f"{SEC}/test_correlation.py"),
    # Incident lifecycle
    Mutation("Stale version accepted", INCIDENTS,
             "if incident.version != expected_version:", "if False:",
             f"{SEC}/test_incident_lifecycle.py"),
    Mutation("Invalid transition accepted by the service", INCIDENTS,
             "if not permitted or not can_transition(previous, definition.target):", "if False:",
             f"{SEC}/test_incident_lifecycle.py"),
    Mutation("Reason not required", INCIDENTS,
             "if definition.reason_required and not reason:", "if False:",
             f"{SEC}/test_incident_lifecycle.py"),
    Mutation("Investigate can reopen", INCIDENTS,
             'Verb("INVESTIGATING", allowed_from=frozenset({"OPEN", "ACKNOWLEDGED"}))',
             'Verb("INVESTIGATING")', f"{SEC}/test_incident_lifecycle.py"),
    # Both locks together. The row lock alone is redundant while the chain lock is held first, so
    # removing only it changes no behavior. That was tested, and it is not a gap.
    Mutation("Transitions take no lock", INCIDENTS,
             "lock_chain_head(session, user.tenant_id)\n"
             "        incident = session.execute(\n"
             "            select(Incident).where(Incident.id == incident_id).with_for_update()",
             "incident = session.execute(\n"
             "            select(Incident).where(Incident.id == incident_id)",
             f"{SEC}/test_incident_lifecycle.py"),
    Mutation("Reviewers can close", "src/aegis/api/routes_incidents.py",
             "incident_id: UUID, body: IncidentTransitionIn, user: AdminDep, container: "
             "ContainerDep",
             "incident_id: UUID, body: IncidentTransitionIn, user: ReviewerDep, container: "
             "ContainerDep",
             f"{SEC}/test_incident_lifecycle.py"),
    Mutation("Viewers can change incidents", "src/aegis/api/routes_incidents.py",
             "def incidents_acknowledge(\n    incident_id: UUID, body: IncidentTransitionIn, "
             "user: ReviewerDep,",
             "def incidents_acknowledge(\n    incident_id: UUID, body: IncidentTransitionIn, "
             "user: UserDep,",
             f"{SEC}/test_incident_lifecycle.py"),
    Mutation("Transition trigger absent", INCIDENTS_MIGRATION,
             "CREATE TRIGGER incidents_guard BEFORE INSERT OR UPDATE OR DELETE ON incidents\n"
             "    FOR EACH ROW EXECUTE FUNCTION aegis_incident_guard()",
             "SELECT 1", f"{SEC}/test_incident_lifecycle.py"),
    Mutation("Runtime role may change severity", INCIDENTS_MIGRATION,
             "GRANT UPDATE (status, version, event_count,",
             "GRANT UPDATE (severity, status, version, event_count,",
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("History can be rewritten", INCIDENTS_MIGRATION,
             '"GRANT SELECT, INSERT ON incident_transitions TO aegis_app",',
             '"GRANT SELECT, INSERT, UPDATE, DELETE ON incident_transitions TO aegis_app",',
             f"{SEC}/test_tenant_isolation_db.py"),
    # Investigation
    Mutation("Facts without evidence accepted by the service", EVIDENCE,
             "if kind in REQUIRES_EVIDENCE and not unique_refs:", "if False:",
             f"{SEC}/test_investigation.py"),
    Mutation("Outside evidence accepted by the service", EVIDENCE,
             "if item.type not in _COLUMN_BY_TYPE or item not in allowed_refs:",
             "if item.type not in _COLUMN_BY_TYPE:", f"{SEC}/test_investigation.py"),
    Mutation("Source and kind not tied together in the service", EVIDENCE,
             'if (source == "llm") != (kind == "ai_hypothesis"):', "if False:",
             f"{SEC}/test_investigation.py"),
    Mutation("Tampered events used as facts", EVIDENCE,
             "(verified if reprojection_matches(session, event) else failed).append(event)",
             "verified.append(event)", f"{SEC}/test_investigation.py"),
    Mutation("Tool results exposed as evidence", "src/aegis/api/routes_investigation.py",
             '"execution": (Execution, "started_at", ("request_id", "status", "finished_at")),',
             '"execution": (Execution, "started_at", ("request_id", "status", "result")),',
             f"{SEC}/test_investigation.py"),
    Mutation("Chain failure not reported", "src/aegis/investigation/findings.py",
             "    if chain.valid:\n        gaps.append(", "    if True:\n        gaps.append(",
             f"{SEC}/test_investigation.py"),
    Mutation("Evidence requirement trigger absent", INVESTIGATION_MIGRATION,
             "CREATE CONSTRAINT TRIGGER investigation_findings_require_evidence\n"
             "    AFTER INSERT ON investigation_findings\n"
             "    DEFERRABLE INITIALLY DEFERRED\n"
             "    FOR EACH ROW EXECUTE FUNCTION aegis_finding_requires_evidence()",
             "SELECT 1", f"{SEC}/test_investigation.py"),
    Mutation("Database stores LLM output as fact", INVESTIGATION_MIGRATION,
             "CHECK ((source = 'llm') = (kind = 'ai_hypothesis')),\n", "",
             f"{SEC}/test_investigation.py"),
    Mutation("Evidence reference may hold two records", INVESTIGATION_MIGRATION,
             ") = 1),\n", ") >= 1),\n", f"{SEC}/test_investigation.py"),
    Mutation("Evidence foreign key loses its tenant", INVESTIGATION_MIGRATION,
             "FOREIGN KEY (tenant_id, decision_id) REFERENCES policy_decisions (tenant_id, id),",
             "FOREIGN KEY (decision_id) REFERENCES policy_decisions (id),",
             f"{SEC}/test_investigation.py"),
    Mutation("Findings can be rewritten", INVESTIGATION_MIGRATION,
             '"GRANT SELECT, INSERT ON investigation_findings TO aegis_app",',
             '"GRANT SELECT, INSERT, UPDATE, DELETE ON investigation_findings TO aegis_app",',
             f"{SEC}/test_tenant_isolation_db.py"),
    # LLM
    Mutation("Invented citations accepted", HYPOTHESES,
             "or any(item is None or item not in offered for item in refs)", "",
             "tests/security/test_llm_investigation.py"),
    Mutation("Hypothesis with no evidence accepted", HYPOTHESES,
             "or not refs\n", "", "tests/security/test_llm_investigation.py"),
    Mutation("Extra fields in model output accepted", HYPOTHESES,
             'class _Hypothesis(BaseModel):\n    model_config = ConfigDict(extra="forbid")',
             'class _Hypothesis(BaseModel):\n    model_config = ConfigDict(extra="ignore")',
             "tests/security/test_llm_investigation.py"),
    Mutation("Tampered events offered to the model", HYPOTHESES,
             "for event in evidence.verified_events\n",
             "for event in evidence.verified_events + evidence.failed_events\n",
             "tests/security/test_llm_investigation.py"),
    Mutation("Agent name sent to the model", HYPOTHESES,
             '"rule_key": evidence.incident.rule_key,',
             '"rule_key": evidence.incident.rule_key,\n'
             '            "agent": evidence.incident.scope_key,\n'
             '            "title": evidence.incident.title,\n'
             '            "reason": evidence.verified_events[0].tool,',
             "tests/unit/test_llm_prompt_shape.py"),
    Mutation("Provider failure propagates", INVESTIGATION,
             'return "failed", None', "raise", "tests/security/test_llm_investigation.py"),
    Mutation("Timeout not enforced", INVESTIGATION,
             ".result(timeout=timeout_seconds)", ".result()",
             "tests/security/test_llm_investigation.py"),
    Mutation("Model runs inside the transaction", INVESTIGATION,
             "        prompt = build_prompt(evidence) if llm else None\n",
             "        prompt = build_prompt(evidence) if llm else None\n"
             "        if llm:\n"
             "            _ask_model(llm, prompt, llm_timeout_seconds)\n",
             "tests/security/test_llm_investigation.py"),
    Mutation("Suspension sets no hard block", APPROVALS,
             "current_decision_id=decision.id,\n               "
             "hard_block_decision_id=decision.id, valid_until=None, next_review_at=None)\n"
             "    return decision\n\n\ndef retire",
             "current_decision_id=decision.id,\n               "
             "valid_until=None, next_review_at=None)\n    return decision\n\n\ndef retire",
             LIFECYCLE),
    Mutation("Suspension keeps the approval window", APPROVALS,
             "current_decision_id=decision.id,\n               "
             "hard_block_decision_id=decision.id, valid_until=None, next_review_at=None)\n"
             "    return decision\n\n\ndef retire",
             "current_decision_id=decision.id,\n               "
             "hard_block_decision_id=decision.id)\n    return decision\n\n\ndef retire",
             LIFECYCLE),
    Mutation("Suspension leaves the review open", APPROVALS,
             "review = _withdraw_open_review(session, asset_id, now)", "review = None",
             LIFECYCLE),
    Mutation("Retirement keeps the approval window", APPROVALS,
             "current_decision_id=decision.id,\n               valid_until=None, "
             "next_review_at=None)\n    return decision\n\n\ndef _reassessment_decision",
             "current_decision_id=decision.id)\n    return decision\n\n\n"
             "def _reassessment_decision", LIFECYCLE),
    Mutation("Retired row may still change", RETIRED_MIGRATION,
             "IF OLD.status = 'RETIRED' THEN", "IF FALSE THEN", LIFECYCLE),
    Mutation("Changed profile does not force reassessment", ASSETS,
             "forces_reassessment = state is not None and state.status in APPROVED_STATUSES",
             "forces_reassessment = False", LIFECYCLE),
    Mutation("Unchanged profile saves a new version", ASSETS,
             "if current is not None and current.content_hash == content_hash:", "if False:",
             LIFECYCLE),
    Mutation("Added grant does not force reassessment", REGISTRY,
             "    mark_grant_changed(session, user, now, agent_id)\n"
             "    session.add(AgentToolGrant(",
             "    session.add(AgentToolGrant(", LIFECYCLE),
    Mutation("Added resource grant does not force reassessment", REGISTRY,
             "    mark_grant_changed(session, user, now, agent_id)\n    session.add(\n"
             "        AgentResourceGrant(",
             "    session.add(\n        AgentResourceGrant(", LIFECYCLE),
    Mutation("Grant hook acts on an unapproved asset", APPROVALS,
             "if state is None or state.status not in APPROVED_STATUSES:",
             "if state is None:", LIFECYCLE),
    Mutation("State locked before the agent rows", ASSETS,
             "    lock_asset_agents(session, asset_id)\n"
             "    return load_state_for_update(session, asset_id)",
             "    state = load_state_for_update(session, asset_id)\n"
             "    lock_asset_agents(session, asset_id)\n    return state", LIFECYCLE),
    Mutation("Reassess open to any user", GOVERNANCE_ROUTES,
             "def asset_reassess(id: UUID, body: LifecycleIn, user: SuspenderDep,",
             "def asset_reassess(id: UUID, body: LifecycleIn, user: UserDep,", LIFECYCLE),
    Mutation("Retire open to a suspender", GOVERNANCE_ROUTES,
             "def asset_retire(id: UUID, body: LifecycleIn, user: AdminDep,",
             "def asset_retire(id: UUID, body: LifecycleIn, user: SuspenderDep,", LIFECYCLE),
    Mutation("Submitter can verify own evidence", GOVERNANCE_EVIDENCE,
             "if evidence.submitted_by == user.id:", "if False:", EVIDENCE_TESTS),
    Mutation("Inline hash trusted from client", GOVERNANCE_EVIDENCE,
             'model_config = ConfigDict(extra="forbid")\n\n    source_type: Literal["inline"]\n'
             '    content_text: Annotated[str, StringConstraints(strict=True, min_length=1)]\n'
             '\n    def stored_hash(self) -> str:\n        return sha256_hex(self.content_text)\n',
             'model_config = ConfigDict(extra="allow")\n\n    source_type: Literal["inline"]\n'
             '    content_text: Annotated[str, StringConstraints(strict=True, min_length=1)]\n'
             '    content_sha256: str | None = None\n'
             '\n    def stored_hash(self) -> str:\n'
             '        return self.content_sha256 or sha256_hex(self.content_text)\n',
             EVIDENCE_TESTS),
    Mutation("Evidence not anchored to its submission event", GOVERNANCE_EVIDENCE,
             "    if outcome == VERIFIED:\n        _check_submission_event(session, evidence)\n",
             "    if outcome == VERIFIED:\n", EVIDENCE_TESTS),
    Mutation("Unverified evidence counted as verified", GOVERNANCE_EVIDENCE,
             ".join(latest, latest.c.evidence_id == GovernanceEvidence.id)\n"
             "        .where(GovernanceEvidence.asset_id == asset_id, "
             "latest.c.outcome == VERIFIED)",
             ".where(GovernanceEvidence.asset_id == asset_id)", EVIDENCE_TESTS),
]


def run_tests(root: Path, tests: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(root / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(
        [sys.executable, "-m", "pytest", tests, "-x", "-q", "--tb=no", "--show-capture=no",
         "-p", "no:cacheprovider"],
        cwd=root, env=env, capture_output=True, text=True, timeout=600,
    )


def main() -> int:
    wanted = [text.lower() for text in sys.argv[1:]]
    selected = [
        item for item in MUTATIONS
        if not wanted or any(text in item.name.lower() for text in wanted)
    ]
    survivors = []
    with tempfile.TemporaryDirectory(prefix="aegis-mutation-") as temporary:
        root = Path(temporary) / "backend"
        root.mkdir()
        for item in ("src", "migrations", "tests", "alembic.ini", "pyproject.toml"):
            source = BACKEND / item
            if source.is_dir():
                shutil.copytree(source, root / item,
                                ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
            else:
                shutil.copy(source, root / item)

        for mutation in selected:
            path = root / mutation.file
            original = path.read_text(encoding="utf-8")
            if mutation.old not in original:
                print(f"STALE     {mutation.name}: target text not found", flush=True)
                survivors.append(mutation.name)
                continue
            path.write_text(original.replace(mutation.old, mutation.new, 1), encoding="utf-8")
            try:
                result = run_tests(root, mutation.tests)
            finally:
                path.write_text(original, encoding="utf-8")
            lines = result.stdout.strip().splitlines()
            summary = lines[-1] if lines else ""
            failing = [line for line in lines if line.startswith(("FAILED", "ERROR"))]
            if result.returncode == 0:
                print(f"SURVIVED  {mutation.name} ({mutation.tests})", flush=True)
                survivors.append(mutation.name)
            else:
                caught_by = failing[0].split(" ")[1].split("::")[-1] if failing else summary
                print(f"caught    {mutation.name} <- {caught_by}", flush=True)

    print(f"\n{len(selected) - len(survivors)} of {len(selected)} removed controls were caught.")
    if survivors:
        print("Not caught:", *survivors, sep="\n  ")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
