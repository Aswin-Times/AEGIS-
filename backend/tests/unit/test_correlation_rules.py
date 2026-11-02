"""Correlation rules and window logic are pure, so their properties can be tested directly."""

import ast
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

import aegis.correlation.rules as rules_module
from aegis.correlation.rules import (
    DEFAULT_RULES,
    CorrelationRule,
    find_qualifying_window,
    matches,
    scope_key,
)

T0 = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass
class Event:
    occurred_at: datetime = T0
    event_type: str = "gateway.action_denied"
    reason_code: str = "TOOL_NOT_GRANTED"
    action: str | None = "read"
    tool: str | None = "read_document"
    resource_id: UUID | None = None
    agent_id: UUID | None = None
    actor_id: UUID | None = None
    tenant_id: UUID = field(default_factory=uuid4)
    id: UUID = field(default_factory=uuid4)
    attributes: dict = field(default_factory=dict)


def rule(**overrides) -> CorrelationRule:
    values = {
        "enabled": True,
        "title": "Test rule",
        "severity": "high",
        "threshold": 3,
        "window_seconds": 60,
        "scope": "agent",
        "match": {"event_types": ["gateway.action_denied"]},
    }
    values.update(overrides)
    return CorrelationRule.model_validate(values)


def at(seconds: float, **kwargs) -> Event:
    return Event(occurred_at=T0 + timedelta(seconds=seconds), **kwargs)


def test_all_required_scenarios_have_a_default_rule():
    assert set(DEFAULT_RULES) == {
        "repeated_unauthorized_tools",
        "repeated_transfer_denials",
        "permission_probing",
        "approval_bypass_attempts",
        "not_visible_references",
        "authentication_failures",
    }
    for definition in DEFAULT_RULES.values():
        assert isinstance(definition, CorrelationRule)


@pytest.mark.parametrize(
    "overrides",
    [
        {"threshold": 0},
        {"threshold": -1},
        {"threshold": "3"},
        {"window_seconds": 0},
        {"window_seconds": 60 * 60 * 24 * 365},
        {"severity": "catastrophic"},
        {"scope": "everyone"},
        {"match": {}},
        {"match": {"event_types": []}},
        {"match": {"event_types": ["not.an.event"]}},
        {"match": {"event_types": ["authz.denied"], "unknown": ["x"]}},
        {"match": {"event_types": ["authz.denied"], "reason_codes": ["lowercase"]}},
        {"title": ""},
        {"unexpected": True},
        {"min_distinct_targets": 0},
        {"threshold": 2, "min_distinct_targets": 3},
    ],
)
def test_invalid_rules_are_rejected(overrides):
    with pytest.raises(ValidationError):
        rule(**overrides)


def test_matching_uses_every_condition():
    definition = rule(
        match={
            "event_types": ["gateway.action_denied"],
            "reason_codes": ["TOOL_NOT_GRANTED"],
            "actions": ["transmit"],
        }
    )
    assert matches(definition, Event(action="transmit"))
    assert not matches(definition, Event(action="read"))
    assert not matches(definition, Event(action="transmit", reason_code="OTHER_REASON"))
    assert not matches(definition, Event(action="transmit", event_type="authz.denied"))


def test_not_visible_condition():
    definition = rule(
        match={"event_types": ["gateway.action_denied"], "not_visible_reference": True}
    )
    assert matches(definition, Event(attributes={"not_visible_reference": True}))
    assert not matches(definition, Event())


def test_scope_keys():
    agent, actor = uuid4(), uuid4()
    event = Event(agent_id=agent, actor_id=actor)
    assert scope_key(rule(scope="agent"), event) == f"agent:{agent}"
    assert scope_key(rule(scope="actor"), event) == f"actor:{actor}"
    assert scope_key(rule(scope="tenant"), event) == "tenant"
    assert scope_key(rule(scope="agent"), Event(agent_id=None)) is None
    assert scope_key(rule(scope="actor"), Event(actor_id=None)) is None


def test_threshold_reached_exactly():
    events = [at(0), at(10), at(20)]
    assert find_qualifying_window(rule(), events) == events


def test_below_threshold():
    assert find_qualifying_window(rule(), [at(0), at(10)]) is None


def test_window_boundary_is_inclusive():
    assert find_qualifying_window(rule(), [at(0), at(30), at(60)]) is not None
    assert find_qualifying_window(rule(), [at(0), at(30), at(60.001)]) is None


def test_earliest_qualifying_window_is_returned_whole():
    events = [at(0), at(100), at(110), at(120), at(125), at(1000)]
    assert find_qualifying_window(rule(), events) == events[1:5]


def test_distinct_targets_requirement():
    definition = rule(min_distinct_targets=3)
    same = [at(i, tool="calculate") for i in range(3)]
    assert find_qualifying_window(definition, same) is None
    varied = [at(0, tool="a"), at(1, tool="b"), at(2, tool="c")]
    assert find_qualifying_window(definition, varied) == varied


def test_distinct_targets_consider_the_resource_too():
    definition = rule(min_distinct_targets=2, threshold=2)
    events = [at(0, resource_id=uuid4()), at(1, resource_id=uuid4())]
    assert find_qualifying_window(definition, events) == events


times = st.lists(st.integers(0, 600), min_size=0, max_size=25)


@given(times, st.integers(1, 6), st.integers(1, 120), st.randoms(use_true_random=False))
def test_result_does_not_depend_on_input_order(seconds, threshold, window, random):
    definition = rule(threshold=threshold, window_seconds=window)
    events = [at(value) for value in seconds]
    shuffled = list(events)
    random.shuffle(shuffled)
    first = find_qualifying_window(definition, events)
    second = find_qualifying_window(definition, shuffled)
    assert (first and {item.id for item in first}) == (second and {item.id for item in second})


@given(times, st.integers(1, 6), st.integers(1, 120))
def test_a_result_always_satisfies_the_rule(seconds, threshold, window):
    definition = rule(threshold=threshold, window_seconds=window)
    result = find_qualifying_window(definition, [at(value) for value in seconds])
    if result is not None:
        assert len(result) >= threshold
        span = result[-1].occurred_at - result[0].occurred_at
        assert span <= timedelta(seconds=window)


@given(st.lists(st.integers(0, 600), min_size=1, max_size=25), st.integers(1, 120))
def test_too_few_events_never_qualify(seconds, window):
    assert find_qualifying_window(
        rule(threshold=len(seconds) + 1, window_seconds=window), [at(value) for value in seconds]
    ) is None


def test_rules_module_does_no_io_and_uses_no_clock():
    tree = ast.parse(Path(rules_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
    assert imported <= {"datetime", "typing", "pydantic", "aegis.events.schema"}
    assert "now" not in {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
