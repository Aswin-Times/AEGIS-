"""The policy engine is a pure function, so every property here can be tested without I/O."""

import ast
from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

import aegis.policy.engine as engine_module
from aegis.policy.engine import (
    ActionFacts,
    AttachmentFacts,
    Outcome,
    PolicyUnavailable,
    ResourceFacts,
    evaluate,
)
from aegis.policy.schema import PolicyDocument


def allow_all() -> PolicyDocument:
    return PolicyDocument.model_validate(
        {"rules": [{"id": "all", "effect": "allow", "match": {}, "reason_code": "ALLOWED_BY_RULE"}]}
    )


def document_facts(**overrides) -> ActionFacts:
    values = dict(
        agent_active=True,
        tool="read_document",
        tool_known=True,
        action="read",
        tool_granted=True,
        params_valid=True,
        required_resource_kind="document",
        resource_id_supplied=True,
        resource=ResourceFacts(
            kind="document", classification="internal", clearance=None, granted=True
        ),
        attachment=None,
    )
    values.update(overrides)
    return ActionFacts(**values)


def message_facts(**overrides) -> ActionFacts:
    values = dict(
        tool="send_message",
        action="transmit",
        required_resource_kind="destination",
        resource=ResourceFacts(
            kind="destination", classification="internal", clearance="internal", granted=True
        ),
    )
    values.update(overrides)
    return document_facts(**values)


def rules(*items) -> PolicyDocument:
    return PolicyDocument.model_validate({"rules": list(items)})


def rule(rule_id, effect, code="SOME_REASON", **match):
    return {"id": rule_id, "effect": effect, "match": match, "reason_code": code}


# Required policies 1 to 7


def test_authorized_document_read_is_allowed():
    result = evaluate(document_facts(), allow_all())
    assert result.outcome is Outcome.ALLOW
    assert result.reason_code == "ALLOWED_BY_RULE"
    assert result.matched_rule_id == "all"


def test_ungranted_tool_is_denied_even_when_policy_allows_everything():
    result = evaluate(document_facts(tool_granted=False), allow_all())
    assert (result.outcome, result.reason_code) == (Outcome.DENY, "TOOL_NOT_GRANTED")


def test_unknown_tool_is_denied():
    result = evaluate(document_facts(tool_known=False, tool_granted=True), allow_all())
    assert (result.outcome, result.reason_code) == (Outcome.DENY, "UNKNOWN_TOOL")


def test_sensitive_attachment_to_insufficient_clearance_is_denied():
    facts = message_facts(attachment=AttachmentFacts(classification="sensitive", granted=True))
    result = evaluate(facts, allow_all())
    assert (result.outcome, result.reason_code) == (
        Outcome.DENY,
        "DESTINATION_CLEARANCE_INSUFFICIENT",
    )


def test_sensitive_attachment_to_cleared_destination_passes_the_hard_check():
    facts = message_facts(
        resource=ResourceFacts(
            kind="destination", classification="internal", clearance="sensitive", granted=True
        ),
        attachment=AttachmentFacts(classification="sensitive", granted=True),
    )
    assert evaluate(facts, allow_all()).outcome is Outcome.ALLOW


def test_ungranted_destination_is_denied():
    facts = message_facts(
        resource=ResourceFacts(
            kind="destination", classification="internal", clearance="sensitive", granted=False
        )
    )
    assert evaluate(facts, allow_all()).reason_code == "RESOURCE_NOT_GRANTED"


def test_ungranted_attachment_is_denied():
    facts = message_facts(attachment=AttachmentFacts(classification="public", granted=False))
    assert evaluate(facts, allow_all()).reason_code == "ATTACHMENT_NOT_GRANTED"


def test_unresolvable_attachment_is_denied():
    facts = message_facts(attachment=AttachmentFacts(classification=None, granted=False))
    assert evaluate(facts, allow_all()).reason_code == "ATTACHMENT_NOT_GRANTED"


def test_require_approval_rule_holds_the_action():
    policy = rules(rule("hold", "require_approval", "HOLD_OUTBOUND", tools=["send_message"]))
    result = evaluate(message_facts(), policy)
    assert (result.outcome, result.reason_code) == (Outcome.REQUIRE_APPROVAL, "HOLD_OUTBOUND")
    assert result.matched_rule_id == "hold"


def test_disabled_agent_is_denied_even_when_policy_allows_everything():
    result = evaluate(document_facts(agent_active=False), allow_all())
    assert (result.outcome, result.reason_code) == (Outcome.DENY, "AGENT_DISABLED")


def test_resource_not_visible_in_this_tenant_is_denied():
    result = evaluate(document_facts(resource=None), allow_all())
    assert (result.outcome, result.reason_code) == (Outcome.DENY, "RESOURCE_NOT_FOUND")


def test_invalid_parameters_are_denied():
    result = evaluate(document_facts(params_valid=False), allow_all())
    assert (result.outcome, result.reason_code) == (Outcome.DENY, "INVALID_PARAMETERS")


# Other hard checks


def test_missing_required_resource_is_denied():
    facts = document_facts(resource=None, resource_id_supplied=False)
    assert evaluate(facts, allow_all()).reason_code == "RESOURCE_REQUIRED"


def test_resource_on_a_tool_that_takes_none_is_denied():
    facts = document_facts(
        tool="calculate", action="compute", required_resource_kind=None, resource=None
    )
    assert evaluate(facts, allow_all()).reason_code == "RESOURCE_NOT_EXPECTED"


def test_tool_without_a_resource_can_be_allowed():
    facts = document_facts(
        tool="calculate",
        action="compute",
        required_resource_kind=None,
        resource_id_supplied=False,
        resource=None,
    )
    assert evaluate(facts, allow_all()).outcome is Outcome.ALLOW


def test_wrong_resource_kind_is_denied():
    facts = document_facts(
        resource=ResourceFacts(
            kind="customer_record", classification="internal", clearance=None, granted=True
        )
    )
    assert evaluate(facts, allow_all()).reason_code == "RESOURCE_KIND_MISMATCH"


def test_ungranted_resource_is_denied():
    facts = document_facts(
        resource=ResourceFacts(
            kind="document", classification="internal", clearance=None, granted=False
        )
    )
    assert evaluate(facts, allow_all()).reason_code == "RESOURCE_NOT_GRANTED"


# Policy availability: fail closed


@pytest.mark.parametrize("code", ["NO_ACTIVE_POLICY", "POLICY_INVALID"])
def test_unavailable_policy_is_denied(code):
    result = evaluate(document_facts(), PolicyUnavailable(code))
    assert (result.outcome, result.reason_code) == (Outcome.DENY, code)


def test_hard_checks_report_before_policy_unavailability():
    result = evaluate(document_facts(agent_active=False), PolicyUnavailable("NO_ACTIVE_POLICY"))
    assert result.reason_code == "AGENT_DISABLED"


def test_no_matching_rule_is_denied():
    assert evaluate(document_facts(), rules()).reason_code == "NO_MATCHING_RULE"
    policy = rules(rule("other", "allow", tools=["calculate"]))
    assert evaluate(document_facts(), policy).reason_code == "NO_MATCHING_RULE"


# Rule semantics


@pytest.mark.parametrize(
    "order",
    [("deny", "hold", "allow"), ("allow", "hold", "deny"), ("hold", "allow", "deny")],
)
def test_deny_overrides_regardless_of_rule_order(order):
    available = {
        "deny": rule("d", "deny", "DENIED_BY_RULE"),
        "hold": rule("h", "require_approval", "HELD"),
        "allow": rule("a", "allow", "OK_RULE"),
    }
    policy = rules(*(available[name] for name in order))
    result = evaluate(document_facts(), policy)
    assert (result.outcome, result.reason_code) == (Outcome.DENY, "DENIED_BY_RULE")


def test_require_approval_overrides_allow_regardless_of_order():
    first = rules(rule("h", "require_approval", "HELD"), rule("a", "allow", "OK_RULE"))
    second = rules(rule("a", "allow", "OK_RULE"), rule("h", "require_approval", "HELD"))
    assert evaluate(document_facts(), first).outcome is Outcome.REQUIRE_APPROVAL
    assert evaluate(document_facts(), second).outcome is Outcome.REQUIRE_APPROVAL


@pytest.mark.parametrize(
    "match, expected",
    [
        ({"tools": ["read_document"]}, True),
        ({"tools": ["calculate"]}, False),
        ({"actions": ["read"]}, True),
        ({"actions": ["transmit"]}, False),
        ({"resource_classifications": ["internal"]}, True),
        ({"resource_classifications": ["sensitive"]}, False),
        ({"resource_kinds": ["document"]}, True),
        ({"resource_kinds": ["destination"]}, False),
        ({"tools": ["read_document"], "resource_kinds": ["destination"]}, False),
        ({"attachment_classifications": ["public"]}, False),
    ],
)
def test_match_conditions(match, expected):
    policy = rules(rule("r", "allow", **match))
    assert (evaluate(document_facts(), policy).outcome is Outcome.ALLOW) is expected


def test_attachment_classification_condition():
    facts = message_facts(attachment=AttachmentFacts(classification="internal", granted=True))
    policy = rules(rule("r", "allow", attachment_classifications=["internal"]))
    assert evaluate(facts, policy).outcome is Outcome.ALLOW


def test_resource_condition_does_not_match_a_tool_with_no_resource():
    facts = document_facts(
        tool="calculate",
        action="compute",
        required_resource_kind=None,
        resource_id_supplied=False,
        resource=None,
    )
    policy = rules(rule("r", "allow", resource_classifications=["public"]))
    assert evaluate(facts, policy).outcome is Outcome.DENY


# Policy document validation


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"rules": "all"},
        {"rules": [], "default": "allow"},
        {"rules": [{"id": "a", "effect": "permit", "match": {}, "reason_code": "OK_RULE"}]},
        {"rules": [{"id": "a", "effect": "allow", "reason_code": "OK_RULE"}]},
        {"rules": [{"id": "a", "effect": "allow", "match": {"tool": ["x"]},
                    "reason_code": "OK_RULE"}]},
        {"rules": [{"id": "a", "effect": "allow", "match": {"tools": []},
                    "reason_code": "OK_RULE"}]},
        {"rules": [{"id": "a", "effect": "allow", "match": {}, "reason_code": "lowercase"}]},
        {"rules": [rule("a", "allow"), rule("a", "deny")]},
        {"rules": [rule(f"r{n}", "allow") for n in range(201)]},
    ],
)
def test_invalid_policy_documents_are_rejected(document):
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(document)


# Properties

TOOLS = ["read_document", "lookup_customer", "calculate", "send_message"]
classification = st.sampled_from(["public", "internal", "sensitive"])
resources = st.one_of(
    st.none(),
    st.builds(
        ResourceFacts,
        kind=st.sampled_from(["document", "customer_record", "destination"]),
        classification=classification,
        clearance=st.one_of(st.none(), classification),
        granted=st.booleans(),
    ),
)
attachments = st.one_of(
    st.none(),
    st.builds(
        AttachmentFacts,
        classification=st.one_of(st.none(), classification),
        granted=st.booleans(),
    ),
)
facts_strategy = st.builds(
    ActionFacts,
    agent_active=st.booleans(),
    tool=st.sampled_from(TOOLS),
    tool_known=st.booleans(),
    action=st.sampled_from(["read", "compute", "transmit"]),
    tool_granted=st.booleans(),
    params_valid=st.booleans(),
    required_resource_kind=st.sampled_from([None, "document", "customer_record", "destination"]),
    resource_id_supplied=st.booleans(),
    resource=resources,
    attachment=attachments,
)
rule_strategy = st.builds(
    lambda index, effect, tools: rule(
        f"r{index}", effect, **({"tools": tools} if tools else {})
    ),
    index=st.integers(0, 10_000),
    effect=st.sampled_from(["allow", "deny", "require_approval"]),
    tools=st.one_of(st.none(), st.lists(st.sampled_from(TOOLS), min_size=1, max_size=2)),
)
policy_strategy = st.lists(rule_strategy, max_size=6, unique_by=lambda item: item["id"]).map(
    lambda items: PolicyDocument.model_validate({"rules": items})
)


@given(facts_strategy, policy_strategy)
def test_evaluation_is_deterministic(facts, policy):
    assert evaluate(facts, policy) == evaluate(replace(facts), policy)


@given(facts_strategy, policy_strategy)
def test_rule_order_never_changes_the_outcome(facts, policy):
    reversed_policy = PolicyDocument.model_validate(
        {"rules": [item.model_dump() for item in reversed(policy.rules)]}
    )
    assert evaluate(facts, policy).outcome == evaluate(facts, reversed_policy).outcome


@given(facts_strategy, policy_strategy)
def test_allow_requires_every_hard_check_to_pass(facts, policy):
    if evaluate(facts, policy).outcome is not Outcome.DENY:
        assert facts.agent_active
        assert facts.tool_known
        assert facts.tool_granted
        assert facts.params_valid
        if facts.required_resource_kind is not None:
            assert facts.resource is not None
            assert facts.resource.granted
            assert facts.resource.kind == facts.required_resource_kind
        if facts.attachment is not None:
            assert facts.attachment.granted


@given(facts_strategy, st.lists(st.sampled_from(["deny", "require_approval"]), max_size=5))
def test_policy_without_an_allow_rule_never_allows(facts, effects):
    policy = PolicyDocument.model_validate(
        {"rules": [rule(f"r{i}", effect) for i, effect in enumerate(effects)]}
    )
    assert evaluate(facts, policy).outcome is not Outcome.ALLOW


# Purity


def test_engine_module_imports_nothing_that_can_do_io():
    tree = ast.parse(Path(engine_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
    assert imported <= {"dataclasses", "enum", "aegis.policy.schema"}
