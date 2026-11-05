"""The governance state machine, as a table of allowed moves."""

from hypothesis import given
from hypothesis import strategies as st

from aegis.governance.engine.lifecycle import TRANSITIONS, GovernanceStatus, can_transition

S = GovernanceStatus


def test_nine_states_exist():
    assert {status.value for status in S} == {
        "DRAFT",
        "ASSESSMENT_REQUIRED",
        "UNDER_REVIEW",
        "APPROVED",
        "CONDITIONALLY_APPROVED",
        "REJECTED",
        "SUSPENDED",
        "REASSESSMENT_REQUIRED",
        "RETIRED",
    }
    assert set(TRANSITIONS) == set(S)


def test_transition_table_matches_spec():
    assert TRANSITIONS[S.DRAFT] == {S.ASSESSMENT_REQUIRED, S.SUSPENDED, S.RETIRED}
    assert TRANSITIONS[S.ASSESSMENT_REQUIRED] == {S.UNDER_REVIEW, S.SUSPENDED, S.RETIRED}
    assert TRANSITIONS[S.UNDER_REVIEW] == {
        S.APPROVED,
        S.CONDITIONALLY_APPROVED,
        S.REJECTED,
        S.SUSPENDED,
        S.RETIRED,
    }
    assert TRANSITIONS[S.APPROVED] == {S.REASSESSMENT_REQUIRED, S.SUSPENDED, S.RETIRED}
    assert TRANSITIONS[S.CONDITIONALLY_APPROVED] == {
        S.REASSESSMENT_REQUIRED,
        S.SUSPENDED,
        S.RETIRED,
    }
    assert TRANSITIONS[S.REJECTED] == {S.ASSESSMENT_REQUIRED, S.RETIRED}
    assert TRANSITIONS[S.SUSPENDED] == {S.REASSESSMENT_REQUIRED, S.RETIRED}
    assert TRANSITIONS[S.REASSESSMENT_REQUIRED] == {S.UNDER_REVIEW, S.SUSPENDED, S.RETIRED}
    assert TRANSITIONS[S.RETIRED] == frozenset()
    assert S.APPROVED not in TRANSITIONS[S.SUSPENDED]


def test_a_suspended_asset_cannot_skip_reassessment():
    for target in (S.APPROVED, S.CONDITIONALLY_APPROVED, S.UNDER_REVIEW):
        assert not can_transition("SUSPENDED", target)


def test_no_state_moves_to_itself():
    assert all(status not in TRANSITIONS[status] for status in S)


@given(st.sampled_from(list(S)), st.sampled_from(list(S)))
def test_can_transition_only_for_table_entries(old, new):
    assert can_transition(old, new) == (new in TRANSITIONS[old])
    assert can_transition(old.value, new.value) == (new in TRANSITIONS[old])


@given(st.text(), st.text())
def test_unknown_states_never_transition(old, new):
    names = {status.value for status in S}
    if old not in names or new not in names:
        assert not can_transition(old, new)
