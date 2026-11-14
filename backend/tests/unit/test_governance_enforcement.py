"""The pure gateway enforcement check (spec 11.2): the table, in order, in both modes."""

import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from aegis.governance.conditions import Conditions
from aegis.governance.engine.enforcement import (
    ActionContext,
    GovernanceCheck,
    GovernanceFacts,
    Verdict,
    check,
    combine,
)
from aegis.policy.engine import Evaluation, Outcome

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(days=30)
ACTION = ActionContext(tool="read_document", action="read", resource_classification="internal")


def facts(**overrides) -> GovernanceFacts:
    base = dict(mode="enforce", status="APPROVED", hard_blocked=False, conditions=None,
                conditions_intact=True, valid_until=LATER, now=NOW)
    return GovernanceFacts(**{**base, **overrides})


V = Verdict
ROWS = [
    ("1 retired", dict(status="RETIRED"), V.DENY, V.DENY, "GOVERNANCE_RETIRED"),
    ("2 hard block", dict(status="SUSPENDED", hard_blocked=True), V.DENY, V.DENY,
     "GOVERNANCE_BLOCKED"),
    ("3 integrity", dict(conditions_intact=False), V.DENY, V.DENY,
     "GOVERNANCE_INTEGRITY_FAILED"),
    ("4 expired", dict(valid_until=NOW - timedelta(seconds=1)), V.RECORDED_DENY, V.DENY,
     "GOVERNANCE_APPROVAL_EXPIRED"),
    ("5 no state row", dict(status=None, valid_until=None), V.RECORDED_DENY, V.DENY,
     "GOVERNANCE_NOT_APPROVED"),
    ("5 null valid_until", dict(status="UNDER_REVIEW", valid_until=None), V.RECORDED_DENY,
     V.DENY, "GOVERNANCE_NOT_APPROVED"),
    ("6 condition deny", dict(status="CONDITIONALLY_APPROVED",
                              conditions=Conditions(denied_tools=["read_document"])),
     V.DENY, V.DENY, "GOVERNANCE_CONDITION_DENIED"),
    ("7 reassessment", dict(status="REASSESSMENT_REQUIRED"), V.RECORDED_HOLD, V.HOLD,
     "GOVERNANCE_REASSESSMENT_REQUIRED"),
    ("7 under review", dict(status="UNDER_REVIEW"), V.RECORDED_HOLD, V.HOLD,
     "GOVERNANCE_REASSESSMENT_REQUIRED"),
    ("8 condition hold", dict(status="CONDITIONALLY_APPROVED",
                              conditions=Conditions(held_tools=["read_document"])),
     V.HOLD, V.HOLD, "GOVERNANCE_CONDITION_HOLD"),
    ("9 approved", dict(), V.PASS, V.PASS, None),
    ("9 conditionally approved, conditions pass",
     dict(status="CONDITIONALLY_APPROVED", conditions=Conditions(denied_tools=["other"])),
     V.PASS, V.PASS, None),
]


@pytest.mark.parametrize("mode", ["observe", "enforce"])
@pytest.mark.parametrize("name,overrides,observe,enforce,code", ROWS, ids=[r[0] for r in ROWS])
def test_table_row(mode, name, overrides, observe, enforce, code):
    expected = observe if mode == "observe" else enforce
    result = check(facts(mode=mode, **overrides), ACTION)
    assert result == GovernanceCheck(expected, code)


def test_retired_beats_everything():
    result = check(facts(status="RETIRED", hard_blocked=True, conditions_intact=False,
                         valid_until=NOW - timedelta(days=1)), ACTION)
    assert result.reason_code == "GOVERNANCE_RETIRED"


def test_hard_block_beats_a_valid_approval():
    result = check(facts(hard_blocked=True, status="APPROVED", valid_until=LATER), ACTION)
    assert (result.verdict, result.reason_code) == (V.DENY, "GOVERNANCE_BLOCKED")


def test_expiry_precedes_reassessment_regardless_of_status():
    for status in ("APPROVED", "REASSESSMENT_REQUIRED", "UNDER_REVIEW", "CONDITIONALLY_APPROVED"):
        result = check(facts(status=status, valid_until=NOW - timedelta(days=1)), ACTION)
        assert result.reason_code == "GOVERNANCE_APPROVAL_EXPIRED"
        assert result.verdict is V.DENY


def test_condition_deny_precedes_reassessment_hold():
    conditions = Conditions(denied_actions=["read"])
    result = check(facts(status="REASSESSMENT_REQUIRED", conditions=conditions), ACTION)
    assert (result.verdict, result.reason_code) == (V.DENY, "GOVERNANCE_CONDITION_DENIED")


def test_under_review_with_approval_in_force_holds_in_enforce():
    assert check(facts(status="UNDER_REVIEW"), ACTION).verdict is V.HOLD


def test_under_review_with_no_approval_denies_in_enforce():
    result = check(facts(status="UNDER_REVIEW", valid_until=None), ACTION)
    assert (result.verdict, result.reason_code) == (V.DENY, "GOVERNANCE_NOT_APPROVED")


def test_exactly_at_valid_until_is_expired():
    assert check(facts(valid_until=NOW), ACTION).reason_code == "GOVERNANCE_APPROVAL_EXPIRED"
    assert check(facts(valid_until=NOW + timedelta(microseconds=1)), ACTION).verdict is V.PASS


def test_integrity_failure_denies_in_observe():
    result = check(facts(mode="observe", conditions_intact=False), ACTION)
    assert (result.verdict, result.reason_code) == (V.DENY, "GOVERNANCE_INTEGRITY_FAILED")


def test_max_resource_classification_denies_above_limit():
    conditions = Conditions(max_resource_classification="internal")
    f = facts(status="CONDITIONALLY_APPROVED", conditions=conditions)
    for classification, expected in (("public", V.PASS), ("internal", V.PASS),
                                     ("sensitive", V.DENY), ("unrecognised", V.DENY),
                                     (None, V.PASS)):
        action = replace(ACTION, resource_classification=classification)
        assert check(f, action).verdict is expected, classification
    sensitive = replace(ACTION, resource_classification="sensitive")
    assert check(f, sensitive).reason_code == "GOVERNANCE_CONDITION_DENIED"


def test_hold_all_holds_every_action():
    f = facts(status="CONDITIONALLY_APPROVED", conditions=Conditions(hold_all=True))
    assert check(f, ACTION) == GovernanceCheck(V.HOLD, "GOVERNANCE_CONDITION_HOLD")


def test_advisory_only_conditions_do_not_restrict():
    f = facts(status="CONDITIONALLY_APPROVED",
              conditions=Conditions(advisory_conditions=["Review monthly."]))
    assert check(f, ACTION).verdict is V.PASS


def test_an_approval_in_force_under_an_unexpected_status_is_not_approved():
    result = check(facts(status="DRAFT"), ACTION)
    assert (result.verdict, result.reason_code) == (V.DENY, "GOVERNANCE_NOT_APPROVED")


@pytest.mark.parametrize("mode", ["ENFORCE", "x", "", None])
def test_an_unknown_mode_enforces(mode):
    expired = dict(valid_until=NOW - timedelta(seconds=1))
    result = check(facts(mode=mode, **expired), ACTION)
    assert result == GovernanceCheck(V.DENY, "GOVERNANCE_APPROVAL_EXPIRED")
    assert check(facts(mode=mode, status="UNDER_REVIEW"), ACTION).verdict is V.HOLD


CONDITION_DENY = Conditions(denied_tools=["read_document"])
CONDITION_HOLD = Conditions(held_tools=["read_document"])
LAPSED = NOW - timedelta(seconds=1)
# (earlier row, later row, facts where both match, expected in observe, expected in enforce)
PRECEDENCE = [
    ("2 over 3", dict(hard_blocked=True, conditions_intact=False),
     (V.DENY, "GOVERNANCE_BLOCKED"), (V.DENY, "GOVERNANCE_BLOCKED")),
    ("3 over 4", dict(conditions_intact=False, valid_until=LAPSED),
     (V.DENY, "GOVERNANCE_INTEGRITY_FAILED"), (V.DENY, "GOVERNANCE_INTEGRITY_FAILED")),
    ("3 over 5", dict(conditions_intact=False, valid_until=None),
     (V.DENY, "GOVERNANCE_INTEGRITY_FAILED"), (V.DENY, "GOVERNANCE_INTEGRITY_FAILED")),
    ("3 over 7", dict(conditions_intact=False, status="REASSESSMENT_REQUIRED"),
     (V.DENY, "GOVERNANCE_INTEGRITY_FAILED"), (V.DENY, "GOVERNANCE_INTEGRITY_FAILED")),
    ("4 over 5", dict(status="DRAFT", valid_until=LAPSED),
     (V.RECORDED_DENY, "GOVERNANCE_APPROVAL_EXPIRED"), (V.DENY, "GOVERNANCE_APPROVAL_EXPIRED")),
    # Row 8 is a person's decision, which a recorded row 7 never shadows in observe.
    ("7 over 8", dict(status="REASSESSMENT_REQUIRED", conditions=CONDITION_HOLD),
     (V.HOLD, "GOVERNANCE_CONDITION_HOLD"), (V.HOLD, "GOVERNANCE_REASSESSMENT_REQUIRED")),
]


@pytest.mark.parametrize("mode", ["observe", "enforce"])
@pytest.mark.parametrize("name,overrides,observe,enforce", PRECEDENCE,
                         ids=[r[0] for r in PRECEDENCE])
def test_adjacent_rows_apply_in_table_order(mode, name, overrides, observe, enforce):
    expected = observe if mode == "observe" else enforce
    assert check(facts(mode=mode, **overrides), ACTION) == GovernanceCheck(*expected)


SHADOWED = [
    ("4 expired", dict(valid_until=LAPSED)),
    ("5 not approved", dict(status="UNDER_REVIEW", valid_until=None)),
    ("7 reassessment", dict(status="REASSESSMENT_REQUIRED")),
]


@pytest.mark.parametrize("name,overrides", SHADOWED, ids=[r[0] for r in SHADOWED])
def test_spec_11_6_observe_applies_a_condition_deny_a_recorded_row_would_shadow(name, overrides):
    f = facts(mode="observe", conditions=CONDITION_DENY, **overrides)
    assert check(f, ACTION) == GovernanceCheck(V.DENY, "GOVERNANCE_CONDITION_DENIED")


@pytest.mark.parametrize("name,overrides", SHADOWED, ids=[r[0] for r in SHADOWED])
def test_spec_11_6_observe_applies_a_condition_hold_a_recorded_row_would_shadow(name, overrides):
    f = facts(mode="observe", conditions=CONDITION_HOLD, **overrides)
    assert check(f, ACTION) == GovernanceCheck(V.HOLD, "GOVERNANCE_CONDITION_HOLD")


@pytest.mark.parametrize("name,overrides", SHADOWED[:2], ids=[r[0] for r in SHADOWED[:2]])
def test_enforce_keeps_the_first_matching_row_over_a_condition(name, overrides):
    f = facts(mode="enforce", conditions=CONDITION_DENY, **overrides)
    assert check(f, ACTION).reason_code != "GOVERNANCE_CONDITION_DENIED"


def test_observe_without_a_matching_condition_still_records_the_first_row():
    f = facts(mode="observe", conditions=Conditions(denied_tools=["other"]), valid_until=LAPSED)
    assert check(f, ACTION) == GovernanceCheck(V.RECORDED_DENY, "GOVERNANCE_APPROVAL_EXPIRED")


def test_conditions_are_untrusted_when_integrity_fails_even_in_observe():
    f = facts(mode="observe", conditions_intact=False, conditions=Conditions(hold_all=True))
    assert check(f, ACTION).reason_code == "GOVERNANCE_INTEGRITY_FAILED"


def test_a_verdict_and_its_reason_code_must_agree():
    for verdict in (V.DENY, V.HOLD, V.RECORDED_DENY, V.RECORDED_HOLD):
        with pytest.raises(ValueError):
            GovernanceCheck(verdict, None)
    with pytest.raises(ValueError):
        GovernanceCheck(V.PASS, "GOVERNANCE_RETIRED")


def test_facts_reject_naive_datetimes():
    naive = datetime(2026, 11, 13, 12, 0)
    with pytest.raises(ValueError):
        facts(now=naive)
    with pytest.raises(ValueError):
        facts(valid_until=naive)


def evaluation(outcome: Outcome) -> Evaluation:
    return Evaluation(outcome, "POLICY_REASON", "rule-1")


ALL_RESULTS = [GovernanceCheck(V.PASS, None), GovernanceCheck(V.RECORDED_DENY, "R"),
               GovernanceCheck(V.RECORDED_HOLD, "R"), GovernanceCheck(V.DENY, "GOV_DENY"),
               GovernanceCheck(V.HOLD, "GOV_HOLD")]
SEVERITY = {Outcome.ALLOW: 0, Outcome.REQUIRE_APPROVAL: 1, Outcome.DENY: 2}


@pytest.mark.parametrize("outcome", list(Outcome))
@pytest.mark.parametrize("result", ALL_RESULTS, ids=lambda r: r.verdict.value)
def test_combine_never_loosens(outcome, result):
    combined = combine(evaluation(outcome), result)
    assert SEVERITY[combined.outcome] >= SEVERITY[outcome]


def test_combine_keeps_policy_deny_reason():
    for result in ALL_RESULTS:
        assert combine(evaluation(Outcome.DENY), result) == evaluation(Outcome.DENY)


@pytest.mark.parametrize("outcome", list(Outcome))
def test_combine_recorded_verdicts_change_nothing(outcome):
    for result in (GovernanceCheck(V.PASS, None), GovernanceCheck(V.RECORDED_DENY, "R"),
                   GovernanceCheck(V.RECORDED_HOLD, "R")):
        assert combine(evaluation(outcome), result) == evaluation(outcome)


def test_combine_hold_turns_allow_into_require_approval():
    combined = combine(evaluation(Outcome.ALLOW), GovernanceCheck(V.HOLD, "GOV_HOLD"))
    assert (combined.outcome, combined.reason_code) == (Outcome.REQUIRE_APPROVAL, "GOV_HOLD")


def test_combine_hold_keeps_require_approval():
    combined = combine(evaluation(Outcome.REQUIRE_APPROVAL), GovernanceCheck(V.HOLD, "GOV_HOLD"))
    assert combined.outcome is Outcome.REQUIRE_APPROVAL


def test_combine_deny_overrides_allow_and_require_approval():
    for outcome in (Outcome.ALLOW, Outcome.REQUIRE_APPROVAL):
        combined = combine(evaluation(outcome), GovernanceCheck(V.DENY, "GOV_DENY"))
        assert (combined.outcome, combined.reason_code) == (Outcome.DENY, "GOV_DENY")


moments = st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime(2035, 1, 1),
                       timezones=st.just(UTC))
names = st.sampled_from(["read_document", "other", "send_email", "read"])
conditions_strategy = st.builds(
    Conditions,
    denied_tools=st.lists(names, max_size=3), held_tools=st.lists(names, max_size=3),
    denied_actions=st.lists(names, max_size=3), hold_all=st.booleans(),
    max_resource_classification=st.sampled_from([None, "public", "internal", "sensitive"]),
    advisory_conditions=st.lists(st.sampled_from(["Review monthly.", "Log it."]), max_size=2),
)
facts_strategy = st.builds(
    GovernanceFacts,
    # Unknown modes are outside the type on purpose: they must behave as enforce.
    mode=st.sampled_from(["observe", "enforce", "ENFORCE", "x", None]),
    status=st.one_of(st.none(), st.sampled_from(
        ["DRAFT", "ASSESSMENT_REQUIRED", "UNDER_REVIEW", "APPROVED", "CONDITIONALLY_APPROVED",
         "REJECTED", "SUSPENDED", "REASSESSMENT_REQUIRED", "RETIRED", "unknown"])),
    hard_blocked=st.booleans(),
    conditions=st.one_of(st.none(), conditions_strategy),
    conditions_intact=st.booleans(),
    valid_until=st.one_of(st.none(), moments),
    now=moments,
)
action_strategy = st.builds(
    ActionContext, tool=names, action=names,
    resource_classification=st.one_of(
        st.none(), st.sampled_from(["public", "internal", "sensitive", "other"])),
)


@given(facts_strategy, action_strategy)
def test_check_is_pure_and_total(f, action):
    first = check(f, action)
    assert check(f, action) == first
    assert isinstance(first.verdict, Verdict)
    assert (first.reason_code is None) == (first.verdict is Verdict.PASS)


@given(facts_strategy, action_strategy)
def test_a_pass_in_enforce_means_an_approval_in_force(f, action):
    result = check(f, action)
    if f.mode != "observe" and result.verdict is Verdict.PASS:
        assert f.status in {"APPROVED", "CONDITIONALLY_APPROVED"}
        assert not f.hard_blocked and f.conditions_intact
        assert f.valid_until is not None and f.now < f.valid_until


@given(facts_strategy, action_strategy)
def test_only_observe_records_and_every_other_mode_enforces(f, action):
    if f.mode != "observe":
        assert check(f, action) == check(replace(f, mode="enforce"), action)
        assert check(f, action).verdict not in (V.RECORDED_DENY, V.RECORDED_HOLD)


PROBE = """
import sys
import aegis.governance.engine.enforcement
banned = ("aegis.gateway", "aegis.db", "aegis.registry", "sqlalchemy", "psycopg",
          "anthropic", "openai", "httpx", "requests")
print([m for m in sys.modules if any(m == b or m.startswith(b + ".") for b in banned)])
"""


def test_engine_imports_no_clock_or_io():
    """A fresh interpreter, so modules other tests already imported cannot hide a dependency."""
    result = subprocess.run([sys.executable, "-c", PROBE], capture_output=True, text=True,  # noqa: S603
                            check=True)
    assert result.stdout.strip() == "[]"
