"""The pure governance policy engine and the closed document schema it reads."""

import ast
import json
from dataclasses import fields
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

import aegis.governance.engine.policies as engine_module
from aegis.canonical import canonical_json
from aegis.governance.engine.policies import (
    Finding,
    PolicyOutcome,
    RequiredControl,
    VersionedDocument,
    applies,
    evaluate_policies,
)
from aegis.governance.policy_schema import GovernancePolicyDocument
from aegis.governance.profile import AssetProfile

OWNER = UUID("00000000-0000-0000-0000-000000000001")


def profile(**over) -> AssetProfile:
    base = {
        "asset_type": "autonomous_agent",
        "model_provider": "Acme",
        "deployment_environment": "production_internal",
        "data_categories": ["personal"],
        "external_exposure": "internal_users",
        "human_oversight": "on_the_loop",
        "business_owner_id": OWNER,
        "technical_owner_id": OWNER,
    }
    return AssetProfile(**{**base, **over})


def document(applicability=None, severity="medium", **controls) -> GovernancePolicyDocument:
    return GovernancePolicyDocument.model_validate({
        "description": "a synthetic test policy",
        "severity": severity,
        "applicability": applicability or {},
        "controls": controls,
    })


def versioned(doc=None, name="policy", review_overdue=False, **controls) -> VersionedDocument:
    return VersionedDocument(
        version_id=uuid4(),
        policy_id=uuid4(),
        name=name,
        document=doc if doc is not None else document(**controls),
        review_overdue=review_overdue,
    )


def evaluate(documents, asset=None, risk="HIGH", verified=frozenset()):
    return evaluate_policies(documents, asset or profile(), risk, set(verified))


def test_self_approval_default_is_refused():
    outcome = evaluate([])
    assert outcome.self_approval_permitted is False
    assert outcome.owner_approval_permitted is False
    # A policy that says nothing about it does not permit it either.
    assert evaluate([versioned(minimum_approvers=2)]).self_approval_permitted is False


def test_explicit_permission_allows_self_approval():
    outcome = evaluate([versioned(self_approval="permitted", owner_approval="permitted")])
    assert outcome.self_approval_permitted is True
    assert outcome.owner_approval_permitted is True
    only_one = evaluate([versioned(self_approval="permitted")])
    assert only_one.self_approval_permitted is True
    assert only_one.owner_approval_permitted is False


def test_conflict_takes_most_restrictive():
    documents = [versioned(self_approval="permitted", owner_approval="permitted"),
                 versioned(self_approval="prohibited")]
    for ordering in (documents, documents[::-1]):
        outcome = evaluate(ordering)
        assert outcome.self_approval_permitted is False
        assert outcome.owner_approval_permitted is True


def test_a_prohibition_that_does_not_apply_does_not_count():
    prohibiting = versioned(document({"risk_levels": ["LOW"]}, self_approval="prohibited"))
    permitting = versioned(self_approval="permitted")
    assert evaluate([permitting, prohibiting], risk="HIGH").self_approval_permitted is True
    assert evaluate([permitting, prohibiting], risk="LOW").self_approval_permitted is False


def test_minimum_approvers_highest_wins_default_one():
    assert evaluate([]).minimum_approvers == 1
    assert evaluate([versioned(reassessment_interval_days=30)]).minimum_approvers == 1
    assert evaluate([versioned(minimum_approvers=1)]).minimum_approvers == 1
    assert evaluate([versioned(minimum_approvers=1),
                     versioned(minimum_approvers=2)]).minimum_approvers == 2
    inapplicable = versioned(document({"risk_levels": ["CRITICAL"]}, minimum_approvers=2))
    assert evaluate([inapplicable], risk="HIGH").minimum_approvers == 1


def test_applicability_is_anded():
    doc = document({"risk_levels": ["HIGH", "CRITICAL"], "environments": ["production_internal"],
                    "asset_types": ["autonomous_agent"], "data_categories": ["personal"]})
    assert applies(doc, profile(), "HIGH") is True
    assert applies(doc, profile(), "CRITICAL") is True  # Within one condition, any value matches.
    assert applies(doc, profile(), "LOW") is False
    assert applies(doc, profile(deployment_environment="staging"), "HIGH") is False
    assert applies(doc, profile(asset_type="model"), "HIGH") is False
    assert applies(doc, profile(data_categories=["public"]), "HIGH") is False
    assert applies(doc, profile(data_categories=["public", "personal"]), "HIGH") is True


def test_no_applicability_applies_to_everything():
    doc = document()
    assert applies(doc, AssetProfile(), None) is True


def test_missing_risk_level_does_not_match_a_risk_condition():
    assert applies(document({"risk_levels": ["LOW", "HIGH"]}), profile(), None) is False
    assert applies(document({"environments": ["staging"]}), AssetProfile(), "LOW") is False
    assert applies(document({"asset_types": ["model"]}), AssetProfile(), "LOW") is False
    assert applies(document({"data_categories": ["public"]}), AssetProfile(), "LOW") is False
    # A policy with no risk condition still applies when the level is unknown.
    assert applies(document({"environments": ["production_internal"]}), profile(), None) is True


def test_unpermitted_provider_produces_a_finding():
    item = versioned(
        document(severity="high", permitted_model_providers=["Acme", "Globex"]), name="providers"
    )
    assert evaluate([item], profile(model_provider="acme")).findings == []
    outcome = evaluate([item], profile(model_provider="Initech"))
    assert len(outcome.findings) == 1
    finding = outcome.findings[0]
    assert finding.policy_version_id == item.version_id
    assert finding.control == "permitted_model_providers"
    assert finding.severity == "high"
    assert "Initech" in finding.message and finding.message.startswith("providers:")
    unset = evaluate([item], profile(model_provider=None))
    assert [f.control for f in unset.findings] == ["permitted_model_providers"]


def test_missing_owner_produces_a_finding():
    item = versioned(required_owners=["business", "technical"])
    assert evaluate([item]).findings == []
    outcome = evaluate([item], profile(business_owner_id=None))
    assert [(f.control, "business" in f.message) for f in outcome.findings] == [
        ("required_owners", True)
    ]
    both = evaluate([item], profile(business_owner_id=None, technical_owner_id=None))
    assert len(both.findings) == 2
    only_technical = versioned(required_owners=["technical"])
    assert evaluate([only_technical], profile(business_owner_id=None)).findings == []


def test_missing_verified_evidence_category_produces_a_finding():
    item = versioned(required_evidence_categories=["risk_assessment", "model_evaluation"])
    outcome = evaluate([item], verified={"risk_assessment"})
    assert [f.control for f in outcome.findings] == ["required_evidence_categories"]
    assert "model_evaluation" in outcome.findings[0].message
    assert evaluate([item], verified={"risk_assessment", "model_evaluation"}).findings == []
    assert len(evaluate([item]).findings) == 2


def test_oversight_and_data_handling_findings():
    oversight = versioned(required_human_oversight=["in_the_loop"])
    assert [f.control for f in evaluate([oversight]).findings] == ["required_human_oversight"]
    assert evaluate([oversight], profile(human_oversight="in_the_loop")).findings == []
    assert len(evaluate([oversight], profile(human_oversight=None)).findings) == 1

    handling = versioned(data_handling={"permitted_data_categories": ["public", "internal"],
                                        "permitted_external_exposure": ["none"]})
    outcome = evaluate([handling])
    assert [f.control for f in outcome.findings] == ["data_handling", "data_handling"]
    assert "personal" in outcome.findings[0].message
    clean = profile(data_categories=["internal"], external_exposure="none")
    assert evaluate([handling], clean).findings == []


def test_review_overdue_is_reported_as_a_finding_not_a_removal():
    item = versioned(document(severity="low", minimum_approvers=2), review_overdue=True)
    outcome = evaluate([item])
    assert outcome.applicable_version_ids == [item.version_id]
    assert outcome.minimum_approvers == 2
    assert [(f.control, f.severity) for f in outcome.findings] == [("review_by", "low")]
    assert evaluate([versioned(minimum_approvers=2)]).findings == []
    # An overdue policy that does not apply to this asset says nothing about it.
    elsewhere = versioned(document({"risk_levels": ["LOW"]}), review_overdue=True)
    assert evaluate([elsewhere], risk="HIGH").findings == []


def test_findings_never_decide():
    assert {f.name for f in fields(PolicyOutcome)} == {
        "applicable_version_ids", "required_controls", "findings", "minimum_approvers",
        "self_approval_permitted", "owner_approval_permitted",
    }
    assert set(Finding.model_fields) == {"policy_version_id", "control", "severity", "message"}
    # Findings leave the approver count and the permissions as they were.
    noisy = versioned(permitted_model_providers=["Nobody"], minimum_approvers=2)
    outcome = evaluate([noisy])
    assert outcome.findings and outcome.minimum_approvers == 2
    assert outcome.self_approval_permitted is False


def test_required_controls_list_the_requirements_and_not_the_decision_rules():
    item = versioned(
        required_evaluations=["bias"], required_documentation=["model card"],
        reassessment_interval_days=90, incident_reporting=True, minimum_approvers=2,
        self_approval="permitted", owner_approval="prohibited",
        data_handling={"permitted_data_categories": ["personal"]},
    )
    controls = evaluate([item]).required_controls
    assert [c.control for c in controls] == [
        "data_handling", "incident_reporting", "reassessment_interval_days",
        "required_documentation", "required_evaluations",
    ]
    assert all(c.policy_version_id == item.version_id for c in controls)
    by_name = {c.control: c.value for c in controls}
    assert by_name["incident_reporting"] is True
    assert by_name["reassessment_interval_days"] == 90
    assert by_name["data_handling"] == {"permitted_data_categories": ["personal"]}


def test_outcome_round_trips_through_json():
    item = versioned(
        required_evaluations=["bias"], reassessment_interval_days=30,
        permitted_model_providers=["Nobody"],
        data_handling={"permitted_data_categories": ["personal"]},
    )
    outcome = evaluate([item])
    frozen = canonical_json({
        "required_controls": [c.model_dump(mode="json") for c in outcome.required_controls],
        "findings": [f.model_dump(mode="json") for f in outcome.findings],
    })
    loaded = json.loads(frozen, parse_float=lambda text: pytest.fail("a float was frozen"))
    assert [RequiredControl.model_validate(c) for c in loaded["required_controls"]] == (
        outcome.required_controls
    )
    assert [Finding.model_validate(f) for f in loaded["findings"]] == outcome.findings


def test_evaluation_is_deterministic_and_independent_of_input_order():
    documents = [
        versioned(name=f"p{n}", minimum_approvers=1 + n % 2,
                  permitted_model_providers=[f"vendor{n}"], required_evaluations=[f"e{n}"])
        for n in range(5)
    ]
    first = evaluate(documents)
    assert evaluate(documents) == first
    assert evaluate(documents[::-1]) == first
    assert first.applicable_version_ids == sorted(first.applicable_version_ids, key=str)


@pytest.mark.parametrize("bad", [
    {"surprise": 1},
    {"severity": "urgent"},
    {"description": ""},
    {"applicability": {"risk_levels": ["low"]}},
    {"applicability": {"risk_levels": []}},
    {"applicability": {"regions": ["eu"]}},
    {"controls": {"minimum_approvers": 3}},
    {"controls": {"minimum_approvers": True}},
    {"controls": {"self_approval": "maybe"}},
    {"controls": {"owner_approval": True}},
    {"controls": {"required_owners": ["legal"]}},
    {"controls": {"required_evidence_categories": ["vibes"]}},
    {"controls": {"reassessment_interval_days": 0}},
    {"controls": {"reassessment_interval_days": 1.5}},
    {"controls": {"data_handling": {"permitted_data_categories": ["secret"]}}},
    {"controls": {"data_handling": {"surprise": 1}}},
    {"controls": {"unknown_control": True}},
])
def test_document_schema_is_closed_and_typed(bad):
    base = {"description": "d", "severity": "low"}
    GovernancePolicyDocument.model_validate(base)
    with pytest.raises(ValidationError):
        GovernancePolicyDocument.model_validate({**base, **bad})


def test_document_lists_are_sets_with_one_canonical_form():
    first = document(required_evaluations=["b", "a", "b"], required_owners=["technical",
                                                                           "business"])
    second = document(required_evaluations=["a", "b"], required_owners=["business", "technical"])
    assert canonical_json(first.model_dump(mode="json")) == canonical_json(
        second.model_dump(mode="json")
    )


def test_engine_imports_no_clock_or_io():
    tree = ast.parse(Path(engine_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
    assert imported <= {
        "dataclasses", "uuid", "pydantic", "aegis.governance.policy_schema",
        "aegis.governance.profile",
    }
