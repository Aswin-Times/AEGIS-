"""Approval conditions: a closed, typed set that can only restrict."""

import pytest
from pydantic import ValidationError

from aegis.errors import ValidationFailed
from aegis.gateway.tools import default_registry
from aegis.governance.conditions import Conditions, is_enforceable, validate_against_catalog

REGISTRY = default_registry()


def test_defaults_restrict_nothing():
    empty = Conditions()
    assert not is_enforceable(empty)
    assert empty.denied_tools == [] and empty.hold_all is False
    assert empty.max_resource_classification is None


@pytest.mark.parametrize(
    "fields",
    [
        {"denied_tools": ["send_message"]},
        {"held_tools": ["calculate"]},
        {"denied_actions": ["transmit"]},
        {"hold_all": True},
        {"max_resource_classification": "public"},
    ],
)
def test_each_restriction_is_enforceable(fields):
    assert is_enforceable(Conditions(**fields))


def test_advisory_text_is_not_enforceable():
    assert not is_enforceable(Conditions(advisory_conditions=["Review monthly."]))


def test_lists_are_sorted_and_deduplicated():
    conditions = Conditions(denied_tools=["send_message", "calculate", "send_message"])
    assert conditions.denied_tools == ["calculate", "send_message"]


@pytest.mark.parametrize(
    "fields",
    [
        {"unknown": True},
        {"hold_all": "yes"},
        {"denied_tools": "send_message"},
        {"denied_tools": [""]},
        {"advisory_conditions": [""]},
        {"advisory_conditions": ["  \t "]},
        {"max_resource_classification": "secret"},
    ],
)
def test_unknown_or_malformed_fields_are_refused(fields):
    with pytest.raises(ValidationError):
        Conditions(**fields)


def test_catalog_validation_accepts_catalog_names():
    validate_against_catalog(
        Conditions(denied_tools=["send_message"], held_tools=["calculate"],
                   denied_actions=["read"], hold_all=True, max_resource_classification="internal"),
        REGISTRY,
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"denied_tools": ["not_a_tool"]},
        {"held_tools": ["not_a_tool"]},
        {"denied_actions": ["not_an_action"]},
        {"denied_tools": ["calculate"], "held_tools": ["calculate", "send_message"]},
    ],
)
def test_catalog_validation_refuses_unknown_and_contradictory_sets(fields):
    with pytest.raises(ValidationFailed):
        validate_against_catalog(Conditions(**fields), REGISTRY)
