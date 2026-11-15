"""The whole governance workflow end to end, through the public API (spec section 1, Success).

One block per step of the definition of done. The people are distinct: an admin registers,
submits, and adds evidence; a reviewer, granted governance_reviewer by that admin, verifies and
decides; two further users own the asset. The gateway is driven with a real agent key, and the
tool spy shows whether a tool really ran. The database is only read, to check that what the API
returns refers to rows that exist and say the same thing.
"""

import json
from datetime import UTC, datetime, timedelta

from aegis.canonical import canonical_json, sha256_hex
from aegis.governance.engine.risk import Methodology, RiskInputs, assess
from support import APPROVALS, ASSETS, POLICIES, decisions_of

CALC = {"operator": "add", "a": 2, "b": 3}

# Every factor of the built-in methodology, so the assessment is complete. The declared tool
# access is transmit (level 4); the asset has agents, so the real grants must be used instead.
FULL_PROFILE = {
    "asset_type": "autonomous_agent",
    "description": "Synthetic workflow agent",
    "business_purpose": "Answer synthetic internal questions for staff",
    "intended_use": "Internal document lookups and arithmetic",
    "prohibited_use": "Sending messages outside the organization",
    "responsible_team": "synthetic-platform",
    "model_provider": "synthetic-provider",
    "model_name": "synthetic-model",
    "model_version": "1",
    "deployment_environment": "production_internal",
    "data_categories": ["internal"],
    "external_exposure": "internal_users",
    "autonomy_level": "supervised",
    "human_oversight": "on_the_loop",
    "declared_tool_access": ["send_message"],
    "impact_level": "minor",
    "third_party_reliance": "vetted",
}

# A different kind of asset, which the workflow policy does not apply to.
SECOND_PROFILE = {
    "asset_type": "ai_application",
    "business_purpose": "Synthetic arithmetic helper",
    "intended_use": "Arithmetic for staff",
    "prohibited_use": "Anything but arithmetic",
    "data_categories": ["internal"],
    "external_exposure": "none",
    "autonomy_level": "advisory",
    "human_oversight": "in_the_loop",
    "impact_level": "negligible",
    "deployment_environment": "development",
    "third_party_reliance": "none",
}

APPLIES_TO_FIRST = {"asset_types": ["autonomous_agent"], "environments": ["production_internal"]}


def ok(response, status=200):
    assert response.status_code == status, response.text
    return response.json()


def active_policy(tenant, reviewer, controls) -> str:
    """Authored and activated by the admin, approved by the reviewer, as spec 8 requires."""
    policy = ok(tenant.post(POLICIES, {"name": tenant._unique("workflow-policy"),
                                       "category": "general"}), 201)
    version = ok(tenant.post(f"{POLICIES}/{policy['id']}/versions", {
        "document": {"description": "Synthetic workflow policy", "severity": "high",
                     "applicability": APPLIES_TO_FIRST, "controls": controls},
        "effective_from": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
    }), 201)
    path = f"{POLICIES}/{policy['id']}/versions/{version['id']}"
    ok(tenant.post(f"{path}/approve", headers=reviewer))
    ok(tenant.post(f"{path}/activate"))
    return path


def act(agent, tool, resource_id=None, params=None):
    return ok(agent.act(tool, resource_id=resource_id, params=params))


def check_rows(attacker_sql, request_id):
    return attacker_sql.execute(
        "SELECT mode, verdict, reason_code, governance_decision_id::text "
        "FROM governance_gateway_checks WHERE request_id = %s", (request_id,)).fetchall()


def overview(tenant):
    return ok(tenant.get("/governance/overview"))


def parsed(moment) -> datetime:
    return datetime.fromisoformat(moment) if isinstance(moment, str) else moment


def one_row(attacker_sql, sql, *params):
    rows = attacker_sql.execute(sql, params).fetchall()
    assert len(rows) == 1, (sql, params, rows)
    return rows[0]


def resolve_history(tenant, attacker_sql, asset_id) -> list[tuple[str, str | None]]:
    """Read an asset's history as a viewer, and resolve every reference in it against real rows.

    Returns the (type, decision kind) of each entry, in the order the API gave.
    """
    page = ok(tenant.get(f"{ASSETS}/{asset_id}/history", headers=tenant.viewer, limit=100))
    entries = page["items"]
    assert page["total"] == len(entries)
    events = {event["id"]: event for event in tenant.audit_events()}
    policy_versions = {version["id"] for policy in ok(tenant.get(POLICIES, limit=100))["items"]
                       for version in policy["versions"]}

    # Audit order: by the sequence of each entry's own event, strictly increasing.
    seqs = [entry["seq"] for entry in entries]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)

    for entry in entries:
        event = events[entry["audit_event_id"]]
        assert event["seq"] == entry["seq"]
        seq, event_type, subject_id, payload = one_row(
            attacker_sql, "SELECT seq, event_type, subject_id::text, payload FROM audit_events "
            "WHERE id = %s", entry["audit_event_id"])
        assert (seq, event_type, payload) == (event["seq"], event["event_type"], event["payload"])

        if entry["type"] == "decision":
            decision = entry["decision"]
            assert decision["id"] == entry["id"] and decision["kind"] == entry["kind"]
            assert event_type == "governance.decision" and subject_id == entry["id"]
            assert payload["decision_id"] == entry["id"] and payload["asset_id"] == asset_id
            assert (payload["kind"], payload["from_status"], payload["to_status"]) == (
                decision["kind"], decision["from_status"], decision["to_status"])
            assert payload["assessment_id"] == decision["assessment_id"]
            row = one_row(
                attacker_sql,
                "SELECT asset_id::text, review_id::text, kind, from_status, to_status, actor_type, "
                "decided_by::text, reason, assessment_id::text, conditions_canonical, "
                "conditions_hash, valid_until, next_review_at, audit_event_id::text "
                "FROM governance_decisions WHERE id = %s", entry["id"])
            assert row[:9] == (asset_id, decision["review_id"], decision["kind"],
                               decision["from_status"], decision["to_status"],
                               decision["actor_type"], decision["decided_by"], decision["reason"],
                               decision["assessment_id"])
            assert row[13] == entry["audit_event_id"] == decision["audit_event_id"]
            assert row[10] == decision["conditions_hash"]
            if row[9] is not None:
                assert sha256_hex(row[9]) == row[10]
                assert json.loads(row[9]) == decision["conditions"]
            for stored, shown in ((row[11], decision["valid_until"]),
                                  (row[12], decision["next_review_at"])):
                assert (stored is None) == (shown is None)
                assert stored is None or stored == parsed(shown)
            if decision["assessment_id"] is not None:
                one_row(attacker_sql, "SELECT id FROM risk_assessments WHERE id = %s "
                        "AND asset_id = %s", decision["assessment_id"], asset_id)
            if decision["review_id"] is not None:
                one_row(attacker_sql, "SELECT id FROM governance_reviews WHERE id = %s "
                        "AND asset_id = %s", decision["review_id"], asset_id)
            linked_versions = {r[0] for r in attacker_sql.execute(
                "SELECT policy_version_id::text FROM governance_decision_policy_versions "
                "WHERE decision_id = %s", (entry["id"],))}
            assert linked_versions == set(decision["policy_version_ids"])
            for version_id in decision["policy_version_ids"]:
                assert version_id in policy_versions
                one_row(attacker_sql, "SELECT id FROM governance_policy_versions WHERE id = %s",
                        version_id)
            linked_evidence = {r[0] for r in attacker_sql.execute(
                "SELECT evidence_id::text FROM governance_decision_evidence "
                "WHERE decision_id = %s", (entry["id"],))}
            assert linked_evidence == set(decision["evidence_ids"])
            for evidence_id in decision["evidence_ids"]:
                assert ok(tenant.get(f"/governance/evidence/{evidence_id}"))["asset_id"] == asset_id
                one_row(attacker_sql, "SELECT id FROM governance_evidence WHERE id = %s "
                        "AND asset_id = %s", evidence_id, asset_id)

        elif entry["type"] == "assessment":
            summary = entry["assessment"]
            assert event_type == "governance.risk_assessed" and subject_id == entry["id"]
            assert (payload["input_hash"], payload["result_hash"], payload["risk_level"]) == (
                summary["input_hash"], summary["result_hash"], summary["risk_level"])
            row = one_row(
                attacker_sql,
                "SELECT asset_id::text, profile_version_id::text, methodology_version_id::text, "
                "input_hash, result_hash, status, score, risk_level, audit_event_id::text, "
                "input_canonical, result_canonical FROM risk_assessments WHERE id = %s",
                entry["id"])
            assert row[:9] == (asset_id, summary["profile_version_id"],
                               summary["methodology_version_id"], summary["input_hash"],
                               summary["result_hash"], summary["status"], summary["score"],
                               summary["risk_level"], entry["audit_event_id"])
            assert (sha256_hex(row[9]), sha256_hex(row[10])) == (row[3], row[4])
            one_row(attacker_sql, "SELECT id FROM asset_profile_versions WHERE id = %s "
                    "AND asset_id = %s", summary["profile_version_id"], asset_id)
            one_row(attacker_sql, "SELECT id FROM risk_methodology_versions WHERE id = %s",
                    summary["methodology_version_id"])

        else:
            version = entry["profile_version"]
            assert entry["type"] == "profile_version"
            assert event_type == "governance.profile_saved" and subject_id == asset_id
            assert payload["profile_version_id"] == entry["id"]
            row = one_row(attacker_sql, "SELECT asset_id::text, version, content_hash, "
                          "profile_canonical FROM asset_profile_versions WHERE id = %s",
                          entry["id"])
            assert row[:3] == (asset_id, version["version"], version["content_hash"])
            assert sha256_hex(row[3]) == row[2] == payload["content_hash"]

    # Nothing is left out: every decision, assessment, and profile version of the asset is listed.
    for table, kind in (("governance_decisions", "decision"), ("risk_assessments", "assessment"),
                        ("asset_profile_versions", "profile_version")):
        stored = {r[0] for r in attacker_sql.execute(
            f"SELECT id::text FROM {table} WHERE asset_id = %s", (asset_id,))}
        assert stored == {entry["id"] for entry in entries if entry["type"] == kind}, table
    # And decisions come in the audit order the database holds.
    assert [entry["id"] for entry in entries if entry["type"] == "decision"] == [
        str(row[5]) for row in decisions_of(attacker_sql, asset_id)]
    return [(entry["type"], entry["kind"]) for entry in entries]


def test_complete_governance_workflow(world, tenant, attacker_sql):
    tenant.allow_everything()  # The runtime policy allows all, so only governance can deny.
    admin_id = tenant.user_id("admin")
    reviewer = tenant.reviewer
    reviewer_id = tenant.user_id("reviewer")
    grant = tenant.grant_governance("reviewer", by="admin")
    assert (grant["user_id"], grant["granted_by"]) == (reviewer_id, admin_id)
    tenant.login_as("business-owner", "viewer")
    tenant.login_as("technical-owner", "viewer")
    business_id = tenant.user_id("business-owner")
    technical_id = tenant.user_id("technical-owner")
    assert len({admin_id, reviewer_id, business_id, technical_id}) == 4
    policy_path = active_policy(tenant, reviewer, {
        "required_owners": ["business", "technical"],
        "required_evidence_categories": ["security_evaluation"],
        "required_human_oversight": ["in_the_loop"],
        "required_documentation": ["Synthetic operating runbook"],
        "minimum_approvers": 1,
    })
    policy_version_id = policy_path.rsplit("/", 1)[1]

    # 1. Register an agent, with a real key and real grants.
    document = tenant.document("internal")
    agent = tenant.agent(tools=["calculate", "read_document"], resources=[document])
    asset_id = agent.asset_id
    detail = ok(tenant.get(f"{ASSETS}/{asset_id}"))
    assert detail["governance_status"] is None and detail["profile"] is None

    # 2. Assign owners: real users of this tenant, saved as the first profile version.
    owners = {"business_owner_id": business_id, "technical_owner_id": technical_id}
    first = ok(tenant.post(f"{ASSETS}/{asset_id}/profile", owners), 201)
    assert (first["version"], first["governance_status"]) == (1, "DRAFT")
    detail = ok(tenant.get(f"{ASSETS}/{asset_id}"))
    assert detail["business_owner"]["id"] == business_id
    assert detail["technical_owner"]["id"] == technical_id
    assert detail["business_owner"]["email"].startswith("business-owner@")

    # 3. Purpose and permitted use, with every risk factor, as a second immutable version.
    second = ok(tenant.post(f"{ASSETS}/{asset_id}/profile", {**FULL_PROFILE, **owners}), 201)
    assert second["version"] == 2 and second["id"] != first["id"]
    for field in ("business_purpose", "intended_use", "prohibited_use"):
        assert second["profile"][field] == FULL_PROFILE[field]
    assert second["content_hash"] == sha256_hex(canonical_json(second["profile"]))
    detail = ok(tenant.get(f"{ASSETS}/{asset_id}"))
    assert detail["profile"]["id"] == second["id"]
    assert detail["profile"]["profile"]["prohibited_use"] == FULL_PROFILE["prohibited_use"]

    # 4. A complete assessment, whose stored record recomputes to its stored result.
    assessment = ok(tenant.post(f"{ASSETS}/{asset_id}/assess"), 201)
    assert (assessment["status"], assessment["governance_status"]) == (
        "COMPLETE", "ASSESSMENT_REQUIRED")
    assert assessment["profile_version_id"] == second["id"]
    # Tool access is read from the grants (compute and an internal read: level 2), not from the
    # declared transmit tool. Spec 6 then gives 20+10+40+30+30+10+15+5 = 160, MEDIUM.
    assert assessment["input"]["tool_access_source"] == "grants"
    assert assessment["input"]["tool_access_level"] == 2
    assert (assessment["score"], assessment["risk_level"]) == (160, "MEDIUM")
    risk = ok(tenant.get(f"{ASSETS}/{asset_id}/risk"))
    assert risk["assessment"]["id"] == assessment["id"] and risk["recomputed_matches"] is True
    input_canonical, result_canonical, methodology_text, methodology_hash = one_row(
        attacker_sql,
        "SELECT a.input_canonical, a.result_canonical, m.document_canonical, m.content_hash "
        "FROM risk_assessments a JOIN risk_methodology_versions m "
        "ON m.id = a.methodology_version_id WHERE a.id = %s", assessment["id"])
    assert sha256_hex(methodology_text) == methodology_hash
    assert sha256_hex(input_canonical) == assessment["input_hash"]
    assert sha256_hex(result_canonical) == assessment["result_hash"]
    recomputed = assess(RiskInputs.model_validate(json.loads(input_canonical)),
                        Methodology.model_validate(json.loads(methodology_text)))
    assert canonical_json(recomputed.model_dump(mode="json")) == result_canonical
    assert json.loads(result_canonical) == assessment["result"]

    # Evidence for the policy's required category: submitted by the admin, verified by the
    # reviewer, whose check recomputes the stored hash.
    evidence = ok(tenant.post("/governance/evidence", {
        "asset_id": asset_id,
        "category": "security_evaluation",
        "description": "Synthetic security evaluation summary",
        "source": {"source_type": "inline",
                   "content_text": "Synthetic evaluation: no transmit tools are granted."},
    }), 201)
    assert evidence["current_verification"] == "UNVERIFIED"
    verification = ok(tenant.post(f"/governance/evidence/{evidence['id']}/verify", {
        "outcome": "VERIFIED", "method": "content_recomputed",
        "note": "Recomputed the hash of the stored text.",
    }, headers=reviewer), 201)
    assert (verification["verified_by"], verification["scope"]) == (reviewer_id, "hash_recomputed")

    # 5 and 6. Submission by the admin; the required controls are frozen on the review.
    review = ok(tenant.post(f"{ASSETS}/{asset_id}/submit", {"reason": "Ready for review."}), 201)
    assert (review["status"], review["submitted_by"]) == ("OPEN", admin_id)
    assert (review["assessment_id"], review["profile_version_id"]) == (
        assessment["id"], second["id"])
    frozen = review["required_controls"]
    assert frozen["applicable_version_ids"] == [policy_version_id]
    assert {item["control"] for item in frozen["required_controls"]} == {
        "required_documentation", "required_evidence_categories", "required_human_oversight",
        "required_owners"}
    assert (frozen["self_approval_permitted"], frozen["owner_approval_permitted"]) == (False, False)
    assert review["required_approvers"] == 1
    # Owners are set and the evidence is verified, so the only finding is the oversight mode.
    assert [finding["control"] for finding in review["findings"]] == ["required_human_oversight"]
    assert ok(tenant.get(f"{ASSETS}/{asset_id}"))["governance_status"] == "UNDER_REVIEW"
    counts = overview(tenant)
    assert (counts["awaiting_approval"], counts["outstanding_findings"]) == (1, 1)
    assert (counts["evidence_verified"], counts["evidence_total"]) == (1, 1)
    # A stricter policy activated mid-review does not change what this review asked for.
    later_policy = active_policy(tenant, reviewer, {
        "minimum_approvers": 2, "required_evaluations": ["Synthetic red-team exercise"]})
    reread = ok(tenant.get(f"{APPROVALS}/{review['id']}"))
    assert (reread["required_controls"], reread["findings"], reread["required_approvers"]) == (
        review["required_controls"], review["findings"], 1)

    # 7. The reviewer takes the review and reads the assessment and the verified evidence.
    assigned = ok(tenant.post(f"{APPROVALS}/{review['id']}/assign",
                              {"reviewer_id": reviewer_id}, headers=reviewer))
    assert assigned["assigned_reviewer"] == reviewer_id
    seen = ok(tenant.get(f"{ASSETS}/{asset_id}/risk", headers=reviewer))
    assert seen["assessment"]["id"] == review["assessment_id"] and seen["recomputed_matches"]
    assert seen["assessment"]["result"] == assessment["result"]
    (proof,) = ok(tenant.get("/governance/evidence", headers=reviewer, asset_id=asset_id))["items"]
    assert proof["id"] == evidence["id"] and proof["current_verification"] == "VERIFIED"
    assert proof["submitted_by"] == admin_id
    assert proof["latest_verification"]["method"] == "content_recomputed"
    assert proof["latest_verification"]["verified_by"] == reviewer_id
    assert proof["content_sha256"] == sha256_hex(proof["content_text"])
    # Separation of duties: the submitter holds no grant and cannot decide.
    refused = tenant.post(f"{APPROVALS}/{review['id']}/approve", {"reason": "Self approval."})
    assert refused.status_code == 403, refused.text

    # 8. Conditional approval by the reviewer, citing the verified evidence.
    now = datetime.now(UTC)
    conditions = {"denied_tools": ["read_document"],
                  "advisory_conditions": ["Synthetic weekly output review"]}
    decision = ok(tenant.post(f"{APPROVALS}/{review['id']}/approve", {
        "reason": "Adequate, with document reads denied.",
        "valid_until": (now + timedelta(days=30)).isoformat(),
        "next_review_at": (now + timedelta(days=15)).isoformat(),
        "conditions": conditions,
        "evidence_ids": [evidence["id"]],
    }, headers=reviewer), 201)
    assert (decision["kind"], decision["governance_status"], decision["review_status"]) == (
        "APPROVE_CONDITIONAL", "CONDITIONALLY_APPROVED", "DECIDED")
    assert (decision["decided_by"], decision["assessment_id"]) == (reviewer_id, assessment["id"])
    assert decision["conditions"]["denied_tools"] == ["read_document"]
    # The frozen policy versions, not the one activated mid-review.
    assert decision["policy_version_ids"] == [policy_version_id]
    assert decision["evidence_ids"] == [evidence["id"]]
    counts = overview(tenant)
    assert (counts["conditionally_approved"], counts["awaiting_approval"],
            counts["outstanding_findings"]) == (1, 0, 0)
    ok(tenant.post(f"{later_policy}/deactivate"))

    # 9. The decision row, its audit event, and a chain that verifies.
    row = one_row(attacker_sql, "SELECT kind, decided_by::text, audit_event_id::text, "
                  "conditions_canonical, conditions_hash FROM governance_decisions WHERE id = %s",
                  decision["id"])
    assert row[:3] == ("APPROVE_CONDITIONAL", reviewer_id, decision["audit_event_id"])
    assert sha256_hex(row[3]) == row[4] == decision["conditions_hash"]
    (event,) = [item for item in tenant.audit_events("governance.decision")
                if item["id"] == decision["audit_event_id"]]
    assert (event["subject_id"], event["actor_id"]) == (decision["id"], reviewer_id)
    assert event["payload"]["kind"] == "APPROVE_CONDITIONAL"
    assert event["payload"]["assessment_id"] == assessment["id"]
    state = one_row(attacker_sql, "SELECT status, current_decision_id::text, "
                    "hard_block_decision_id FROM asset_governance_state WHERE asset_id = %s",
                    asset_id)
    assert state == ("CONDITIONALLY_APPROVED", decision["id"], None)
    chain = ok(tenant.client.post("/api/v1/audit/verify", headers=reviewer))
    assert chain["valid"] is True and chain["failure_reason"] is None
    assert chain["events_checked"] == chain["head_seq"] == len(tenant.audit_events())

    # 10. Enforce mode: the allowed tool runs, the tool the condition denies does not.
    assert tenant.set_enforcement("enforce")["enforcement_mode"] == "enforce"
    allowed = act(agent, "calculate", params=CALC)
    assert (allowed["outcome"], allowed["execution"]["status"]) == ("ALLOW", "SUCCEEDED")
    assert allowed["execution"]["result"] == {"value": 5}
    assert world.spy.calls == ["calculate"]
    denied = act(agent, "read_document", resource_id=document)
    assert (denied["outcome"], denied["reason_code"]) == ("DENY", "GOVERNANCE_CONDITION_DENIED")
    assert denied["execution"] is None
    assert world.spy.calls == ["calculate"]
    assert check_rows(attacker_sql, allowed["request_id"]) == [
        ("enforce", "PASS", None, decision["id"])]
    assert check_rows(attacker_sql, denied["request_id"]) == [
        ("enforce", "DENY", "GOVERNANCE_CONDITION_DENIED", decision["id"])]

    # 11a. A real suspension, by the reviewer: the asset is denied and its tool never runs.
    suspension = ok(tenant.post(f"{ASSETS}/{asset_id}/suspend",
                                {"reason": "Synthetic suspension."}, headers=reviewer), 201)
    assert (suspension["kind"], suspension["governance_status"]) == ("SUSPEND", "SUSPENDED")
    blocked = act(agent, "calculate", params=CALC)
    assert (blocked["outcome"], blocked["reason_code"]) == ("DENY", "GOVERNANCE_BLOCKED")
    assert blocked["execution"] is None and world.spy.calls == ["calculate"]
    assert check_rows(attacker_sql, blocked["request_id"]) == [
        ("enforce", "DENY", "GOVERNANCE_BLOCKED", suspension["id"])]
    assert overview(tenant)["suspended"] == 1

    # 11b. A second asset is approved for a day, runs, and is denied once the clock passes expiry.
    other = tenant.agent(tools=["calculate"])
    ok(tenant.post(f"{ASSETS}/{other.asset_id}/profile", {**SECOND_PROFILE, **owners}), 201)
    ok(tenant.post(f"{ASSETS}/{other.asset_id}/assess"), 201)
    other_review = ok(tenant.post(f"{ASSETS}/{other.asset_id}/submit",
                                  {"reason": "Ready for review."}), 201)
    assert other_review["required_controls"]["applicable_version_ids"] == []
    now = datetime.now(UTC)
    valid_until = now + timedelta(days=1)
    approval = ok(tenant.post(f"{APPROVALS}/{other_review['id']}/approve", {
        "reason": "Approved for one day.", "valid_until": valid_until.isoformat(),
        "next_review_at": (now + timedelta(hours=12)).isoformat(),
    }, headers=reviewer), 201)
    assert (approval["kind"], approval["governance_status"]) == ("APPROVE", "APPROVED")
    running = act(other, "calculate", params=CALC)
    assert running["outcome"] == "ALLOW" and world.spy.calls == ["calculate", "calculate"]
    world.app.state.container.clock = lambda: valid_until + timedelta(minutes=1)
    expired = act(other, "calculate", params=CALC)
    assert (expired["outcome"], expired["reason_code"]) == ("DENY", "GOVERNANCE_APPROVAL_EXPIRED")
    assert expired["execution"] is None and world.spy.calls == ["calculate", "calculate"]
    # Expiry is the gateway's clock, not a status change: the asset still reads approved.
    assert check_rows(attacker_sql, expired["request_id"]) == [
        ("enforce", "DENY", "GOVERNANCE_APPROVAL_EXPIRED", approval["id"])]
    assert ok(tenant.get(f"{ASSETS}/{other.asset_id}"))["governance_status"] == "APPROVED"
    assert overview(tenant)["overdue_reviews"] == 1
    still_blocked = act(agent, "calculate", params=CALC)
    assert still_blocked["reason_code"] == "GOVERNANCE_BLOCKED"
    assert world.spy.calls == ["calculate", "calculate"]
    world.app.state.container.clock = lambda: datetime.now(UTC)

    # 12. The history: every decision in audit order, every reference resolving to its row.
    assert resolve_history(tenant, attacker_sql, asset_id) == [
        ("profile_version", None), ("profile_version", None), ("assessment", None),
        ("decision", "SUBMIT"), ("decision", "ASSIGN_REVIEWER"),
        ("decision", "APPROVE_CONDITIONAL"), ("decision", "SUSPEND")]
    assert resolve_history(tenant, attacker_sql, other.asset_id) == [
        ("profile_version", None), ("assessment", None), ("decision", "SUBMIT"),
        ("decision", "APPROVE")]
    assert tenant.verify_audit()["valid"] is True
