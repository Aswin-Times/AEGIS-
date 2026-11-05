"""Risk assessments and methodology versions: what is recorded, from what, and who may change it."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aegis.canonical import sha256_hex
from aegis.governance.methodology import BUILT_IN_METHODOLOGY
from aegis.governance.risk import current_input_hash

ASSETS = "/governance/assets"
METHODOLOGIES = "/governance/methodologies"

LOW_PROFILE = {
    "data_categories": ["internal"],
    "external_exposure": "none",
    "autonomy_level": "advisory",
    "declared_tool_access": [],
    "human_oversight": "in_the_loop",
    "impact_level": "negligible",
    "deployment_environment": "development",
    "third_party_reliance": "none",
}
MEDIUM_PROFILE = {
    "data_categories": ["personal"],
    "external_exposure": "partners",
    "autonomy_level": "supervised",
    "declared_tool_access": [],
    "human_oversight": "on_the_loop",
    "impact_level": "moderate",
    "deployment_environment": "staging",
    "third_party_reliance": "vetted",
}
CRITICAL_PROFILE = {
    "data_categories": ["regulated"],
    "external_exposure": "public",
    "autonomy_level": "autonomous",
    "declared_tool_access": ["send_message"],
    "human_oversight": "none",
    "impact_level": "severe",
    "deployment_environment": "production_external",
    "third_party_reliance": "unvetted",
}


def save_profile(tenant, asset_id, body):
    response = tenant.post(f"{ASSETS}/{asset_id}/profile", body)
    assert response.status_code == 201, response.text
    return response.json()


def assess(tenant, asset_id, headers=None):
    return tenant.post(f"{ASSETS}/{asset_id}/assess", headers=headers)


def assessed(tenant, asset_id, profile=None):
    if profile is not None:
        save_profile(tenant, asset_id, profile)
    response = assess(tenant, asset_id)
    assert response.status_code == 201, response.text
    return response.json()


def profiled_asset(tenant, profile=None):
    asset = tenant.asset()
    save_profile(tenant, asset["id"], LOW_PROFILE if profile is None else profile)
    return asset["id"]


def agent_asset(tenant, tools=(), resources=()):
    agent = tenant.agent(tools=tools, resources=resources)
    return agent, tenant.get(f"/agents/{agent.id}").json()["asset_id"]


def risk_of(tenant, asset_id):
    response = tenant.get(f"{ASSETS}/{asset_id}/risk")
    assert response.status_code == 200, response.text
    return response.json()


def factor_level(assessment, factor_id):
    return next(f["level"] for f in assessment["result"]["factors"] if f["factor"] == factor_id)


def force(attacker_sql, sql, params=()):
    """Run SQL as a compromised database owner, with the append-only triggers switched off."""
    with attacker_sql.transaction():
        attacker_sql.execute("SET LOCAL session_replication_role = replica")
        attacker_sql.execute(sql, params)


def state_of(attacker_sql, asset_id):
    return attacker_sql.execute(
        "SELECT status, version, latest_assessment_id, hard_block_decision_id "
        "FROM asset_governance_state WHERE asset_id = %s",
        (asset_id,),
    ).fetchone()


def distinct_reviewer(tenant):
    """A second admin who holds governance_reviewer, and the first admin, who does not."""
    second = tenant.login_as("second-admin", "admin")
    tenant.grant_governance("admin", by="second-admin")
    tenant.grant_governance("second-admin", by="admin")
    return second


def changed_document(**thresholds):
    document = BUILT_IN_METHODOLOGY.model_dump(mode="json")
    document["thresholds"].update(thresholds)
    return document


def create_methodology(tenant, document, headers=None):
    return tenant.post(METHODOLOGIES, {"document": document}, headers=headers)


# Assessments


def test_assessment_without_profile_is_refused(tenant):
    asset = tenant.asset()
    refused = assess(tenant, asset["id"])
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "PROFILE_REQUIRED"
    assert tenant.audit_events("governance.risk_assessed") == []
    assert assess(tenant, str(uuid4())).status_code == 404


def test_incomplete_profile_gives_incomplete_assessment_never_low(tenant):
    partial = tenant.asset()
    save_profile(tenant, partial["id"], {"description": "only a description"})
    body = assess(tenant, partial["id"]).json()
    assert body["status"] == "INCOMPLETE"
    assert body["risk_level"] is None and body["score"] is None
    assert body["result"]["risk_level"] is None
    assert "human_oversight" in body["result"]["missing"]
    assert "tool_access" in body["result"]["missing"]

    # One missing input is enough, however low everything else is.
    nearly = {key: value for key, value in LOW_PROFILE.items() if key != "human_oversight"}
    one = assessed(tenant, tenant.asset()["id"], nearly)
    assert (one["status"], one["risk_level"], one["result"]["missing"]) == (
        "INCOMPLETE", None, ["human_oversight"],
    )
    assert one["result"]["factors"] != []


def test_database_rejects_complete_without_level(attacker_sql, tenant):
    body = assessed(tenant, tenant.asset()["id"], LOW_PROFILE)
    assert body["status"] == "COMPLETE" and body["risk_level"] == "LOW"

    def copy_with(status, score, level):
        attacker_sql.execute(
            """
            INSERT INTO risk_assessments (
                id, tenant_id, asset_id, profile_version_id, methodology_version_id,
                input_canonical, input_hash, result_canonical, result_hash, status, score,
                risk_level, assessed_by, audit_event_id, created_at)
            SELECT %s, tenant_id, asset_id, profile_version_id, methodology_version_id,
                input_canonical, input_hash, result_canonical, result_hash, %s, %s, %s,
                assessed_by, audit_event_id, created_at
            FROM risk_assessments WHERE id = %s
            """,
            (uuid4(), status, score, level, body["id"]),
        )

    for status, score, level in [
        ("COMPLETE", 20, None),
        ("COMPLETE", None, "LOW"),
        ("INCOMPLETE", None, "LOW"),
        ("INCOMPLETE", 20, None),
        ("COMPLETE", 20, "NEGLIGIBLE"),
        ("FINISHED", 20, "LOW"),
    ]:
        with pytest.raises(psycopg.errors.CheckViolation):
            copy_with(status, score, level)
    copy_with("INCOMPLETE", None, None)  # The control: a legal row goes in.


def test_assessment_records_the_inputs_and_result_it_hashed(attacker_sql, tenant):
    asset_id = tenant.asset()["id"]
    body = assessed(tenant, asset_id, MEDIUM_PROFILE)
    assert (body["status"], body["score"], body["risk_level"]) == ("COMPLETE", 185, "MEDIUM")
    assert body["methodology_version"] == 1
    canonical_input, input_hash, canonical_result, result_hash = attacker_sql.execute(
        "SELECT input_canonical, input_hash, result_canonical, result_hash "
        "FROM risk_assessments WHERE id = %s",
        (body["id"],),
    ).fetchone()
    assert sha256_hex(canonical_input) == input_hash == body["input_hash"]
    assert sha256_hex(canonical_result) == result_hash == body["result_hash"]
    assert json.loads(canonical_input) == body["input"]
    assert json.loads(canonical_result) == body["result"]


@pytest.mark.parametrize(
    ("tools", "resources", "level"),
    [
        ((), (), 0),
        (("calculate",), (), 1),
        (("read_document",), ("internal-document",), 2),
        (("read_document",), ("public-document",), 2),
        (("read_document",), ("sensitive-document",), 3),
        (("read_document",), ("internal-document", "sensitive-document"), 3),
        (("lookup_customer",), ("sensitive-customer",), 3),
        (("read_document",), ("sensitive-customer",), 2),  # Not a document: out of reach.
        (("read_document", "calculate"), ("internal-document",), 2),
        (("send_message",), ("destination",), 4),
        (("calculate", "send_message"), (), 4),
    ],
)
def test_tool_access_comes_from_grants_not_declaration(tenant, tools, resources, level):
    made = {
        "internal-document": tenant.document("internal"),
        "public-document": tenant.document("public"),
        "sensitive-document": tenant.document("sensitive"),
        "sensitive-customer": tenant.customer("sensitive"),
        "destination": tenant.destination(),
    }
    _, asset_id = agent_asset(tenant, tools, [made[name] for name in resources])
    # The profile declares no tool access at all, and a wrong declaration is ignored too.
    for declared in ([], ["calculate"] if level == 4 else ["send_message"]):
        body = assessed(tenant, asset_id, {**LOW_PROFILE, "declared_tool_access": declared})
        assert body["input"]["tool_access_level"] == level
        assert body["input"]["tool_access_source"] == "grants"
        assert factor_level(body, "tool_access") == level


def test_tool_access_takes_the_highest_across_the_assets_agents(tenant):
    _, asset_id = agent_asset(tenant, tools=("calculate",))
    second = tenant.created(
        "/agents", {"asset_id": asset_id, "name": "second-agent", "owner": "synthetic-owner"}
    )
    tenant.created(f"/agents/{second['id']}/tool-grants", {"tool": "send_message"})
    body = assessed(tenant, asset_id, LOW_PROFILE)
    assert body["input"]["tool_access_level"] == 4


def test_assets_without_agents_use_declared_tool_access(tenant):
    expected = {
        (): 0,
        ("calculate",): 1,
        ("read_document",): 3,  # No grant says what it reads, so the sensitive case is assumed.
        ("send_message",): 4,
        ("calculate", "mystery_tool"): 4,  # Not in the catalog, so nothing says it is safe.
    }
    for declared, level in expected.items():
        body = assessed(
            tenant, tenant.asset()["id"], {**LOW_PROFILE, "declared_tool_access": list(declared)}
        )
        assert body["input"]["tool_access_source"] == "declared", declared
        assert body["input"]["tool_access_level"] == level, declared

    absent = {k: v for k, v in LOW_PROFILE.items() if k != "declared_tool_access"}
    missing = assessed(tenant, tenant.asset()["id"], absent)
    assert missing["status"] == "INCOMPLETE" and missing["result"]["missing"] == ["tool_access"]
    assert "tool_access_level" not in missing["input"]


def test_reassessing_unchanged_inputs_gives_identical_result_hash(tenant):
    asset_id = tenant.asset()["id"]
    first = assessed(tenant, asset_id, MEDIUM_PROFILE)
    second = assessed(tenant, asset_id)
    assert first["id"] != second["id"]
    assert first["input_hash"] == second["input_hash"]
    assert first["result_hash"] == second["result_hash"]
    assert first["audit_event_id"] != second["audit_event_id"]

    # A changed input changes both hashes.
    third = assessed(tenant, asset_id, {**MEDIUM_PROFILE, "impact_level": "severe"})
    assert third["input_hash"] != first["input_hash"]
    assert third["result_hash"] != first["result_hash"]


def test_current_input_hash_follows_profile_and_grants(world, db, tenant):
    agent, asset_id = agent_asset(tenant)
    tools = world.app.state.container.tools

    def current():
        with db.tenant_transaction(tenant.id) as session:
            return current_input_hash(session, tools, UUID(asset_id))

    body = assessed(tenant, asset_id, LOW_PROFILE)
    assert current() == body["input_hash"]
    tenant.created(f"/agents/{agent.id}/tool-grants", {"tool": "send_message"})
    after_grant = current()
    assert after_grant != body["input_hash"]
    assert assessed(tenant, asset_id)["input_hash"] == after_grant
    save_profile(tenant, asset_id, {**LOW_PROFILE, "impact_level": "major"})
    assert current() != after_grant


def test_current_input_hash_needs_a_profile(world, db, tenant):
    asset = tenant.asset()
    with db.tenant_transaction(tenant.id) as session:
        with pytest.raises(Exception, match="profile"):
            current_input_hash(session, world.app.state.container.tools, UUID(asset["id"]))


# Recomputation


def test_get_risk_recomputes_and_reports_match(tenant):
    asset_id = tenant.asset()["id"]
    assert risk_of(tenant, asset_id) == {"assessment": None, "recomputed_matches": None}

    body = assessed(tenant, asset_id, CRITICAL_PROFILE)
    assert (body["score"], body["risk_level"]) == (400, "CRITICAL")
    read = risk_of(tenant, asset_id)
    assert read["recomputed_matches"] is True
    assert read["assessment"]["id"] == body["id"]
    assert read["assessment"]["result"] == body["result"]

    incomplete = assessed(tenant, asset_id, {"description": "now partial"})
    assert incomplete["status"] == "INCOMPLETE"
    latest = risk_of(tenant, asset_id)
    assert latest["assessment"]["id"] == incomplete["id"]
    assert latest["recomputed_matches"] is True


@pytest.mark.parametrize(
    "tamper",
    [
        "score = score + 1",
        "risk_level = CASE WHEN risk_level = 'CRITICAL' THEN 'LOW' ELSE 'CRITICAL' END",
        "result_canonical = replace(result_canonical, 'CRITICAL', 'LOW')",
        "input_canonical = replace(input_canonical, '\"external_exposure\":\"public\"', "
        "'\"external_exposure\":\"none\"')",
        "input_canonical = '{not json'",
        "input_hash = repeat('0', 64)",
        "result_hash = repeat('0', 64)",
    ],
)
def test_tampered_assessment_reports_mismatch(tenant, attacker_sql, tamper):
    asset_id = tenant.asset()["id"]
    body = assessed(tenant, asset_id, CRITICAL_PROFILE)
    assert risk_of(tenant, asset_id)["recomputed_matches"] is True
    force(attacker_sql, f"UPDATE risk_assessments SET {tamper} WHERE id = %s", (body["id"],))
    read = tenant.get(f"{ASSETS}/{asset_id}/risk")
    assert read.status_code == 200
    assert read.json()["recomputed_matches"] is False


@pytest.mark.parametrize(
    "tamper",
    [
        "content_hash = repeat('0', 64)",
        "document_canonical = replace(document_canonical, '\"medium\":100', '\"medium\":101')",
    ],
)
def test_tampered_methodology_hash_fails_closed(tenant, attacker_sql, tamper):
    asset_id = tenant.asset()["id"]
    body = assessed(tenant, asset_id, LOW_PROFILE)
    force(attacker_sql, f"UPDATE risk_methodology_versions SET {tamper} WHERE tenant_id = %s",
          (tenant.id,))

    read = tenant.get(f"{ASSETS}/{asset_id}/risk")
    assert read.status_code == 503
    assert read.json()["error"]["code"] == "METHODOLOGY_INTEGRITY_FAILED"
    # A new assessment cannot be made on a methodology that cannot be trusted either.
    refused = assess(tenant, asset_id)
    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "METHODOLOGY_INTEGRITY_FAILED"
    listing = tenant.get(f"{ASSETS}/{asset_id}/assessments").json()
    assert [item["id"] for item in listing["items"]] == [body["id"]]
    assert tenant.get(METHODOLOGIES).status_code == 503


def test_new_methodology_version_does_not_change_old_assessments(tenant):
    asset_id = tenant.asset()["id"]
    old = assessed(tenant, asset_id, MEDIUM_PROFILE)
    assert old["risk_level"] == "MEDIUM" and old["methodology_version"] == 1
    distinct_reviewer(tenant)

    created = create_methodology(tenant, changed_document(medium=10, high=20, critical=30))
    assert created.status_code == 201, created.text
    version = created.json()
    assert version["version"] == 2 and version["approved"] is False
    assert tenant.post(f"{METHODOLOGIES}/{version['id']}/approve",
                       headers=tenant.login_as("second-admin", "admin")).status_code == 200
    assert tenant.post(f"{METHODOLOGIES}/{version['id']}/activate").status_code == 200

    new = assess(tenant, asset_id).json()
    assert new["methodology_version"] == 2
    assert new["methodology_version_id"] == version["id"]
    assert (new["score"], new["risk_level"]) == (185, "CRITICAL")
    assert new["input_hash"] == old["input_hash"]
    assert new["result_hash"] != old["result_hash"]

    history = tenant.get(f"{ASSETS}/{asset_id}/assessments").json()["items"]
    assert [item["id"] for item in history] == [new["id"], old["id"]]
    original = history[1]
    assert (original["methodology_version"], original["risk_level"]) == (1, "MEDIUM")
    assert original["result_hash"] == old["result_hash"]
    assert risk_of(tenant, asset_id)["recomputed_matches"] is True


def test_assessment_history_is_ordered_by_audit_sequence_and_paged(tenant):
    asset_id = tenant.asset()["id"]
    ids = [assessed(tenant, asset_id, LOW_PROFILE)["id"]] + [
        assess(tenant, asset_id).json()["id"] for _ in range(2)
    ]
    page = tenant.get(f"{ASSETS}/{asset_id}/assessments", limit=2).json()
    assert page["total"] == 3
    assert [item["id"] for item in page["items"]] == [ids[2], ids[1]]
    assert tenant.get(f"{ASSETS}/{str(uuid4())}/assessments").status_code == 404


# Lifecycle


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("DRAFT", "ASSESSMENT_REQUIRED"),
        ("REJECTED", "ASSESSMENT_REQUIRED"),
        ("ASSESSMENT_REQUIRED", "ASSESSMENT_REQUIRED"),
        ("UNDER_REVIEW", "UNDER_REVIEW"),
        ("APPROVED", "APPROVED"),
        ("CONDITIONALLY_APPROVED", "CONDITIONALLY_APPROVED"),
        ("SUSPENDED", "SUSPENDED"),
        ("REASSESSMENT_REQUIRED", "REASSESSMENT_REQUIRED"),
    ],
)
def test_assessment_moves_only_draft_and_rejected_and_never_touches_the_block(
    tenant, attacker_sql, before, after
):
    asset_id = profiled_asset(tenant)
    block = uuid4()
    force(
        attacker_sql,
        "UPDATE asset_governance_state SET status = %s, hard_block_decision_id = %s "
        "WHERE asset_id = %s",
        (before, block, asset_id),
    )
    version_before = state_of(attacker_sql, asset_id)[1]
    body = assess(tenant, asset_id).json()
    status, version, latest, blocked_by = state_of(attacker_sql, asset_id)
    assert (status, version) == (after, version_before + 1)
    assert str(latest) == body["id"] and body["governance_status"] == after
    assert blocked_by == block


def test_first_assessment_moves_draft_to_assessment_required(tenant, attacker_sql):
    asset_id = profiled_asset(tenant)
    assert state_of(attacker_sql, asset_id)[0] == "DRAFT"
    body = assess(tenant, asset_id).json()
    assert body["governance_status"] == "ASSESSMENT_REQUIRED"
    assert state_of(attacker_sql, asset_id)[0] == "ASSESSMENT_REQUIRED"
    # An incomplete assessment counts as an assessment attempt, and is what the state points at.
    other = tenant.asset()["id"]
    save_profile(tenant, other, {})
    incomplete = assess(tenant, other).json()
    assert incomplete["status"] == "INCOMPLETE"
    assert str(state_of(attacker_sql, other)[2]) == incomplete["id"]


def test_retired_asset_cannot_be_assessed(tenant, attacker_sql):
    asset_id = profiled_asset(tenant)
    force(attacker_sql, "UPDATE asset_governance_state SET status = 'RETIRED' WHERE asset_id = %s",
          (asset_id,))
    refused = assess(tenant, asset_id)
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "ASSET_RETIRED"
    assert tenant.audit_events("governance.risk_assessed") == []


# Audit, immutability, authority


def test_assessment_is_audited_and_chain_verifies(tenant):
    asset_id = tenant.asset()["id"]
    body = assessed(tenant, asset_id, MEDIUM_PROFILE)
    events = tenant.audit_events("governance.risk_assessed")
    assert len(events) == 1
    event = events[0]
    assert event["id"] == body["audit_event_id"]
    assert event["subject_id"] == body["id"]
    payload = event["payload"]
    assert payload["input_hash"] == body["input_hash"]
    assert payload["result_hash"] == body["result_hash"]
    assert (payload["score"], payload["risk_level"]) == (185, "MEDIUM")
    assert payload["methodology_version"] == 1
    assert not any(isinstance(value, float) for value in payload.values())
    assert tenant.verify_audit()["valid"] is True


def test_assessment_is_append_only(db, tenant, attacker_sql):
    body = assessed(tenant, tenant.asset()["id"], LOW_PROFILE)
    for sql in (
        "UPDATE risk_assessments SET score = 0",
        "DELETE FROM risk_assessments",
        "UPDATE risk_methodology_versions SET content_hash = repeat('0', 64)",
        "DELETE FROM risk_methodology_versions",
        "UPDATE risk_methodology_events SET actor_id = actor_id",
        "DELETE FROM risk_methodology_events",
    ):
        with pytest.raises(DBAPIError), db.tenant_transaction(tenant.id) as session:
            session.execute(text(sql))
    for table in ("risk_assessments", "risk_methodology_versions", "risk_methodology_events"):
        with pytest.raises(psycopg.Error, match="append-only"):
            attacker_sql.execute(f"TRUNCATE {table} CASCADE")
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute("UPDATE risk_assessments SET score = 0 WHERE id = %s", (body["id"],))
    with pytest.raises(psycopg.Error, match="append-only"):
        attacker_sql.execute("DELETE FROM risk_assessments WHERE id = %s", (body["id"],))


def test_assessment_cannot_name_another_assets_profile(tenant, attacker_sql):
    first, second = profiled_asset(tenant), profiled_asset(tenant)
    body = assessed(tenant, first)
    other_profile = attacker_sql.execute(
        "SELECT current_profile_version_id FROM asset_governance_state WHERE asset_id = %s",
        (second,),
    ).fetchone()[0]
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        attacker_sql.execute(
            "UPDATE asset_governance_state SET latest_assessment_id = %s, version = version + 1 "
            "WHERE asset_id = %s",
            (body["id"], second),
        )
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        attacker_sql.execute(
            "INSERT INTO risk_assessments (id, tenant_id, asset_id, profile_version_id, "
            "methodology_version_id, input_canonical, input_hash, result_canonical, result_hash, "
            "status, assessed_by, audit_event_id) SELECT %s, tenant_id, asset_id, %s, "
            "methodology_version_id, input_canonical, input_hash, result_canonical, result_hash, "
            "'INCOMPLETE', assessed_by, audit_event_id FROM risk_assessments WHERE id = %s",
            (uuid4(), other_profile, body["id"]),
        )


@pytest.mark.parametrize("actor", ["reviewer", "viewer"])
def test_viewer_cannot_assess(tenant, actor):
    asset_id = profiled_asset(tenant)
    assert assess(tenant, asset_id, headers=tenant.login(actor)).status_code == 403
    assert tenant.audit_events("governance.risk_assessed") == []


def test_governance_reviewer_role_does_not_confer_assessment(tenant):
    tenant.grant_governance("reviewer")
    asset_id = profiled_asset(tenant)
    assert assess(tenant, asset_id, headers=tenant.login("reviewer")).status_code == 403


def test_agent_principal_cannot_use_risk_routes(tenant):
    agent = tenant.agent()
    asset_id = profiled_asset(tenant)
    for method, path in [
        ("post", f"{ASSETS}/{asset_id}/assess"),
        ("get", f"{ASSETS}/{asset_id}/risk"),
        ("get", f"{ASSETS}/{asset_id}/assessments"),
        ("get", METHODOLOGIES),
        ("post", METHODOLOGIES),
        ("post", f"{METHODOLOGIES}/{uuid4()}/approve"),
        ("post", f"{METHODOLOGIES}/{uuid4()}/activate"),
    ]:
        response = getattr(tenant.client, method)(f"/api/v1{path}", headers=agent.headers)
        assert response.status_code == 401, path


def test_any_authenticated_user_can_read_risk(tenant):
    asset_id = tenant.asset()["id"]
    assessed(tenant, asset_id, LOW_PROFILE)
    viewer = tenant.viewer
    assert tenant.get(f"{ASSETS}/{asset_id}/risk", headers=viewer).status_code == 200
    assert tenant.get(f"{ASSETS}/{asset_id}/assessments", headers=viewer).status_code == 200
    assert tenant.get(METHODOLOGIES, headers=viewer).status_code == 200


# Methodology versions


def test_built_in_methodology_is_version_one_and_counts_as_approved(tenant):
    items = tenant.get(METHODOLOGIES).json()["items"]
    assert len(items) == 1
    built_in = items[0]
    assert (built_in["version"], built_in["created_by"]) == (1, None)
    assert (built_in["approved"], built_in["approved_by"], built_in["active"]) == (
        True, None, True,
    )
    assert built_in["document"] == BUILT_IN_METHODOLOGY.model_dump(mode="json")
    assert len(tenant.audit_events("governance.methodology_seeded")) == 1
    # Reading again seeds nothing more.
    tenant.get(METHODOLOGIES)
    assert len(tenant.audit_events("governance.methodology_seeded")) == 1
    assert tenant.post(f"{METHODOLOGIES}/{built_in['id']}/activate").status_code == 200


@pytest.mark.parametrize("factor", [f.id for f in BUILT_IN_METHODOLOGY.factors])
def test_methodology_omitting_a_factor_is_refused(tenant, factor):
    document = BUILT_IN_METHODOLOGY.model_dump(mode="json")
    document["factors"] = [f for f in document["factors"] if f["id"] != factor]
    document["floors"] = [
        floor for floor in document["floors"] if factor not in floor["when"]
    ]
    document["mitigations"].pop(factor, None)
    refused = create_methodology(tenant, document)
    assert refused.status_code == 422, refused.text
    assert len(tenant.get(METHODOLOGIES).json()["items"]) == 1


def test_methodology_may_give_a_factor_no_weight_but_must_keep_it(tenant):
    document = BUILT_IN_METHODOLOGY.model_dump(mode="json")
    for factor in document["factors"]:
        if factor["id"] == "third_party_reliance":
            factor["weight"] = 0
    created = create_methodology(tenant, document)
    assert created.status_code == 201, created.text
    assert created.json()["version"] == 2


def test_invalid_methodology_documents_are_refused(tenant):
    document = BUILT_IN_METHODOLOGY.model_dump(mode="json")
    document["thresholds"] = {"medium": 200, "high": 100, "critical": 300}
    assert create_methodology(tenant, document).status_code == 422
    assert tenant.post(METHODOLOGIES, {"document": {}}).status_code == 422
    assert tenant.post(METHODOLOGIES, {}).status_code == 422
    unknown = {**BUILT_IN_METHODOLOGY.model_dump(mode="json"), "surprise": 1}
    assert create_methodology(tenant, unknown).status_code == 422


def test_methodology_approver_must_differ_from_creator(tenant):
    second = tenant.login_as("second-admin", "admin")
    tenant.grant_governance("admin", by="second-admin")  # The creator holds the role.
    version = create_methodology(tenant, changed_document(medium=90)).json()

    refused = tenant.post(f"{METHODOLOGIES}/{version['id']}/approve")
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "SELF_APPROVAL_REFUSED"
    assert tenant.audit_events("governance.methodology_approved") == []
    assert len(tenant.audit_events("authz.denied")) == 1

    # Someone else without the role cannot either.
    path = f"{METHODOLOGIES}/{version['id']}/approve"
    assert tenant.post(path, headers=second).status_code == 403
    tenant.grant_governance("second-admin", by="admin")
    approved = tenant.post(path, headers=second)
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["approved"] is True
    assert body["approved_by"] == tenant.user_id("second-admin")
    assert len(tenant.audit_events("governance.methodology_approved")) == 1

    again = tenant.post(path, headers=second)
    assert again.status_code == 409 and again.json()["error"]["code"] == "ALREADY_APPROVED"


def test_built_in_methodology_cannot_be_approved_again(tenant):
    second = tenant.login_as("second-admin", "admin")
    tenant.grant_governance("second-admin", by="admin")
    built_in = tenant.get(METHODOLOGIES).json()["items"][0]
    refused = tenant.post(f"{METHODOLOGIES}/{built_in['id']}/approve", headers=second)
    assert refused.status_code == 409


def test_only_a_governance_reviewer_approves_and_only_an_admin_authors_or_activates(tenant):
    version = create_methodology(tenant, changed_document(medium=90)).json()
    path = f"{METHODOLOGIES}/{version['id']}"
    for headers in (tenant.reviewer, tenant.viewer):
        assert create_methodology(tenant, changed_document(medium=91), headers).status_code == 403
        assert tenant.post(f"{path}/activate", headers=headers).status_code == 403
        assert tenant.post(f"{path}/approve", headers=headers).status_code == 403
    # Being an admin is not enough to approve.
    assert tenant.post(f"{path}/approve").status_code == 403

    # A reviewer who holds the role can approve but still cannot activate.
    tenant.grant_governance("reviewer")
    assert tenant.post(f"{path}/approve", headers=tenant.reviewer).status_code == 200
    assert tenant.post(f"{path}/activate", headers=tenant.reviewer).status_code == 403
    assert tenant.post(f"{path}/activate").status_code == 200


def test_unapproved_methodology_cannot_be_activated(tenant):
    version = create_methodology(tenant, changed_document(medium=90)).json()
    refused = tenant.post(f"{METHODOLOGIES}/{version['id']}/activate")
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "METHODOLOGY_NOT_APPROVED"
    assert tenant.audit_events("governance.methodology_activated") == []
    assert [i["active"] for i in tenant.get(METHODOLOGIES).json()["items"]] == [False, True]


def test_activation_switches_the_active_version_and_is_audited(tenant):
    distinct_reviewer(tenant)
    reviewer = tenant.login_as("second-admin", "admin")
    version = create_methodology(tenant, changed_document(medium=90)).json()
    tenant.post(f"{METHODOLOGIES}/{version['id']}/approve", headers=reviewer)
    tenant.post(f"{METHODOLOGIES}/{version['id']}/activate")

    items = tenant.get(METHODOLOGIES).json()["items"]
    assert [(i["version"], i["active"], i["approved"]) for i in items] == [
        (2, True, True), (1, False, True),
    ]
    events = tenant.audit_events("governance.methodology_activated")
    assert len(events) == 1 and events[0]["subject_id"] == version["id"]
    assert tenant.verify_audit()["valid"] is True

    # Going back to version one is a deliberate act of its own.
    built_in = items[1]["id"]
    assert tenant.post(f"{METHODOLOGIES}/{built_in}/activate").status_code == 200
    assert [i["active"] for i in tenant.get(METHODOLOGIES).json()["items"]] == [False, True]
    assert len(tenant.audit_events("governance.methodology_activated")) == 2


def test_methodology_versions_are_numbered_in_sequence(tenant):
    numbers = [
        create_methodology(tenant, changed_document(medium=90 + n)).json()["version"]
        for n in range(3)
    ]
    assert numbers == [2, 3, 4]
    created = tenant.audit_events("governance.methodology_created")
    assert sorted(e["payload"]["version"] for e in created) == [2, 3, 4]
    assert tenant.get(METHODOLOGIES, limit=2).json()["total"] == 4


def test_unknown_methodology_is_not_found(tenant):
    tenant.login_as("second-admin", "admin")
    tenant.grant_governance("second-admin", by="admin")
    assert tenant.post(f"{METHODOLOGIES}/{uuid4()}/activate").status_code == 404
    assert tenant.post(
        f"{METHODOLOGIES}/{uuid4()}/approve", headers=tenant.login_as("second-admin", "admin")
    ).status_code == 404


# Inventory and overview


def test_inventory_reports_assessed_risk_and_date(tenant):
    asset = tenant.asset()

    def listed():
        return next(i for i in tenant.get(ASSETS).json()["items"] if i["id"] == asset["id"])

    assert (listed()["assessed_risk"], listed()["last_assessed_at"]) == (None, None)
    assert listed()["declared_risk"] == "medium"

    body = assessed(tenant, asset["id"], CRITICAL_PROFILE)
    row = listed()
    assert row["assessed_risk"] == "CRITICAL" and row["declared_risk"] == "medium"
    assert row["last_assessed_at"] == body["assessed_at"]
    detail = tenant.get(f"{ASSETS}/{asset['id']}").json()
    assert detail["assessed_risk"] == "CRITICAL"
    assert detail["last_assessed_at"] == body["assessed_at"]

    # The latest assessment decides. An incomplete one leaves no risk level, not the old one.
    incomplete = assessed(tenant, asset["id"], {"description": "partial now"})
    row = listed()
    assert row["assessed_risk"] is None
    assert row["last_assessed_at"] == incomplete["assessed_at"]
    low = assessed(tenant, asset["id"], LOW_PROFILE)
    assert listed()["assessed_risk"] == "LOW"
    assert listed()["last_assessed_at"] == low["assessed_at"]


def test_inventory_filters_assessed_and_declared_risk_separately(tenant):
    high_declared = tenant.created(
        "/assets",
        {"name": "declared-high", "owner": "o", "risk_classification": "high",
         "intended_use": "automated test fixture", "is_synthetic": True},
    )
    low_declared = tenant.asset()  # Declared medium.
    assessed(tenant, high_declared["id"], LOW_PROFILE)
    assessed(tenant, low_declared["id"], CRITICAL_PROFILE)

    def ids(**params):
        response = tenant.get(ASSETS, **params)
        assert response.status_code == 200, response.text
        return {i["id"] for i in response.json()["items"]}

    assert ids(risk="LOW") == {high_declared["id"]}
    assert ids(risk="CRITICAL") == {low_declared["id"]}
    assert ids(risk="HIGH") == set()
    assert ids(declared_risk="high") == {high_declared["id"]}
    assert ids(declared_risk="medium") == {low_declared["id"]}
    assert ids(risk="LOW", declared_risk="medium") == set()
    for params in ({"risk": "low"}, {"risk": "extreme"}, {"declared_risk": "HIGH"},
                   {"declared_risk": "extreme"}):
        assert tenant.get(ASSETS, **params).status_code == 422


def test_overview_counts_assessed_and_unassessed_from_latest_assessments(tenant):
    assets = [tenant.asset()["id"] for _ in range(4)]
    assessed(tenant, assets[0], LOW_PROFILE)
    assessed(tenant, assets[1], CRITICAL_PROFILE)
    assessed(tenant, assets[1], {"description": "regressed to partial"})  # Latest is incomplete.
    assessed(tenant, assets[2], MEDIUM_PROFILE)
    overview = tenant.get("/governance/overview").json()
    assert overview["total_assets"] == 4
    assert overview["by_assessed_risk"] == {"LOW": 1, "MEDIUM": 1, "HIGH": 0, "CRITICAL": 0}
    assert overview["unassessed"] == 2


# Locking


def test_assess_locks_agents_before_state(urls, tenant, attacker_sql):
    """Spec 11.4: agent rows, then state, then the chain head. Suspend will take the same order."""
    _, asset_id = agent_asset(tenant, tools=("calculate",))
    save_profile(tenant, asset_id, LOW_PROFILE)
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        with psycopg.connect(urls.superuser, autocommit=True) as observer:
            # The holder plays a suspend that already has the agent rows.
            with attacker_sql.transaction():
                attacker_sql.execute(
                    "SELECT id FROM agents WHERE asset_id = %s FOR UPDATE", (asset_id,)
                )
                response = pool.submit(assess, tenant, asset_id)
                waiting = 0
                deadline = time.monotonic() + 15
                while not waiting and time.monotonic() < deadline:
                    waiting = observer.execute(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE wait_event_type = 'Lock' AND query LIKE '%FROM agents%' "
                        "AND pid <> pg_backend_pid()"
                    ).fetchone()[0]
                    time.sleep(0.05)
                assert waiting, "assess did not block on the agent rows"
                # Blocked on the agents, so it has not locked the state row yet.
                with observer.transaction():
                    observer.execute(
                        "SELECT 1 FROM asset_governance_state WHERE asset_id = %s "
                        "FOR UPDATE NOWAIT",
                        (asset_id,),
                    )
                assert not response.done()
        assert response.result(timeout=30).status_code == 201
    finally:
        pool.shutdown(wait=True)


def test_concurrent_assess_and_profile_save_never_fail_or_deadlock(tenant):
    asset_id = tenant.asset()["id"]
    save_profile(tenant, asset_id, LOW_PROFILE)
    headers = tenant.admin
    rounds = 6
    barrier = threading.Barrier(2)

    def run(call):
        barrier.wait(timeout=30)
        return call().status_code

    for number in range(rounds):
        body = {**LOW_PROFILE, "description": f"concurrent {number}"}
        with ThreadPoolExecutor(max_workers=2) as pool:
            codes = [
                pool.submit(run, lambda: tenant.post(f"{ASSETS}/{asset_id}/assess",
                                                     headers=headers)),
                pool.submit(run, lambda body=body: tenant.post(f"{ASSETS}/{asset_id}/profile", body,
                                                     headers=headers)),
            ]
            results = [code.result(timeout=60) for code in codes]
        assert all(code in (201, 409) for code in results), results

    # Every assessment that was recorded is intact, and the chain still verifies.
    assert risk_of(tenant, asset_id)["recomputed_matches"] is True
    assert tenant.verify_audit()["valid"] is True
