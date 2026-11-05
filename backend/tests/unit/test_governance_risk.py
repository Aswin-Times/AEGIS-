"""The pure risk engine and the built-in methodology it is driven by."""

import ast
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

import aegis.governance.engine.risk as risk_module
from aegis.governance.engine.risk import (
    Methodology,
    RiskInputs,
    Thresholds,
    assess,
    risk_level_for_score,
)
from aegis.governance.methodology import BUILT_IN_METHODOLOGY as M

LOW = {
    "data_categories": ["public"],
    "external_exposure": "none",
    "autonomy_level": "advisory",
    "tool_access_level": 0,
    "tool_access_source": "grants",
    "human_oversight": "in_the_loop",
    "impact_level": "negligible",
    "deployment_environment": "development",
    "third_party_reliance": "none",
}
HIGHEST = {
    "data_categories": ["regulated"],
    "external_exposure": "public",
    "autonomy_level": "autonomous",
    "tool_access_level": 4,
    "tool_access_source": "grants",
    "human_oversight": "none",
    "impact_level": "severe",
    "deployment_environment": "production_external",
    "third_party_reliance": "unvetted",
}
FIELD_OF = {
    "data_sensitivity": "data_categories",
    "external_exposure": "external_exposure",
    "agent_autonomy": "autonomy_level",
    "tool_access": "tool_access_level",
    "human_oversight": "human_oversight",
    "business_impact": "impact_level",
    "deployment_environment": "deployment_environment",
    "third_party_reliance": "third_party_reliance",
}


def full_inputs(**over) -> RiskInputs:
    return RiskInputs(**{**LOW, **over})


def result_for(**over):
    return assess(full_inputs(**over), M)


def test_weights_sum_to_100():
    assert sum(f.weight for f in M.factors) == 100


def test_built_in_methodology_matches_the_spec():
    weights = {f.id: f.weight for f in M.factors}
    assert weights == {
        "data_sensitivity": 20,
        "external_exposure": 10,
        "agent_autonomy": 20,
        "tool_access": 15,
        "human_oversight": 15,
        "business_impact": 10,
        "deployment_environment": 5,
        "third_party_reliance": 5,
    }
    levels = {f.id: f.levels for f in M.factors}
    assert levels["data_sensitivity"] == {
        "public": 0,
        "internal": 1,
        "personal": 3,
        "confidential": 3,
        "regulated": 4,
    }
    assert levels["external_exposure"] == {
        "none": 0,
        "internal_users": 1,
        "partners": 2,
        "public": 4,
    }
    assert levels["agent_autonomy"] == {
        "advisory": 0,
        "human_approved": 1,
        "supervised": 2,
        "bounded": 3,
        "autonomous": 4,
    }
    assert levels["tool_access"] == {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4}
    assert levels["human_oversight"] == {
        "in_the_loop": 0,
        "on_the_loop": 2,
        "after_the_fact": 3,
        "none": 4,
    }
    assert levels["business_impact"] == {
        "negligible": 0,
        "minor": 1,
        "moderate": 2,
        "major": 3,
        "severe": 4,
    }
    assert levels["deployment_environment"] == {
        "development": 0,
        "test": 1,
        "staging": 2,
        "production_internal": 3,
        "production_external": 4,
    }
    assert levels["third_party_reliance"] == {
        "none": 0,
        "vetted": 1,
        "partially_vetted": 2,
        "unvetted": 4,
    }
    assert (M.thresholds.medium, M.thresholds.high, M.thresholds.critical) == (100, 200, 300)


def test_provenance_note_disclaims_any_standard():
    note = M.provenance_note.lower()
    assert "engineering judgment" in note
    assert "not" in note and "standard" in note


def test_all_factors_at_level_zero_scores_zero_low():
    result = result_for()
    assert (result.status, result.score, result.risk_level) == ("COMPLETE", 0, "LOW")
    assert result.floor_applied is None
    assert result.missing == []


def test_all_factors_at_max_scores_400_critical():
    result = assess(RiskInputs(**HIGHEST), M)
    assert result.score == 400
    assert result.risk_level == "CRITICAL"


def _with_score(target: int) -> RiskInputs:
    """Inputs scoring exactly `target`, filling factors greedily.

    Autonomy stays at advisory, so neither floor can apply. Every weight is a multiple of 5, so
    only multiples of 5 are reachable.
    """
    remaining = target
    chosen = {}
    # (field, weight, (value, level) steps)
    plan = [
        (
            "data_categories",
            20,
            [(["public"], 0), (["internal"], 1), (["personal"], 3), (["regulated"], 4)],
        ),
        (
            "external_exposure",
            10,
            [("none", 0), ("internal_users", 1), ("partners", 2), ("public", 4)],
        ),
        ("tool_access_level", 15, [(n, n) for n in range(5)]),
        (
            "human_oversight",
            15,
            [("in_the_loop", 0), ("on_the_loop", 2), ("after_the_fact", 3), ("none", 4)],
        ),
        (
            "impact_level",
            10,
            [("negligible", 0), ("minor", 1), ("moderate", 2), ("major", 3), ("severe", 4)],
        ),
        (
            "deployment_environment",
            5,
            [
                ("development", 0),
                ("test", 1),
                ("staging", 2),
                ("production_internal", 3),
                ("production_external", 4),
            ],
        ),
        (
            "third_party_reliance",
            5,
            [("none", 0), ("vetted", 1), ("partially_vetted", 2), ("unvetted", 4)],
        ),
    ]
    for field, weight, steps in plan:
        value, level = max(
            (step for step in steps if step[1] * weight <= remaining), key=lambda s: s[1]
        )
        chosen[field] = value
        remaining -= level * weight
    assert remaining == 0, f"cannot build {target}"
    return full_inputs(**chosen)


@pytest.mark.parametrize(
    ("score", "level"),
    [(0, "LOW"), (95, "LOW"), (100, "MEDIUM"), (195, "MEDIUM"), (200, "HIGH"), (295, "HIGH"),
     (300, "CRITICAL")],
)
def test_threshold_boundaries_end_to_end(score, level):
    result = assess(_with_score(score), M)
    assert (result.score, result.risk_level, result.floor_applied) == (score, level, None)


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, "LOW"),
        (99, "LOW"),
        (100, "MEDIUM"),
        (199, "MEDIUM"),
        (200, "HIGH"),
        (299, "HIGH"),
        (300, "CRITICAL"),
        (400, "CRITICAL"),
    ],
)
def test_threshold_boundaries(score, level):
    # The weight grid cannot reach 99, 199 or 299, so the comparison is tested on its own.
    assert risk_level_for_score(score, M.thresholds) == level


def test_highest_data_category_wins():
    result = result_for(data_categories=["public", "regulated"])
    data = next(f for f in result.factors if f.factor == "data_sensitivity")
    assert data.level == 4
    assert data.contribution == 80


def test_autonomy_with_sensitive_data_floors_at_high():
    result = result_for(autonomy_level="bounded", data_categories=["personal"])
    assert result.score == 20 * 3 + 20 * 3
    assert result.score < 200
    assert result.risk_level == "HIGH"
    assert result.floor_applied == "autonomy_with_sensitive_data"


def test_floor_does_not_apply_below_its_conditions():
    supervised = result_for(autonomy_level="supervised", data_categories=["regulated"])
    internal = result_for(autonomy_level="bounded", data_categories=["internal"])
    assert supervised.floor_applied is None
    assert internal.floor_applied is None


def test_floors_never_lower_the_level_and_leave_the_score_alone():
    result = assess(RiskInputs(**HIGHEST), M)
    assert result.risk_level == "CRITICAL"
    assert result.score == 400
    # The floor conditions hold, but the arithmetic already gives CRITICAL, so nothing was raised.
    assert result.floor_applied is None


def test_autonomous_no_oversight_transmit_is_critical():
    result = result_for(
        autonomy_level="autonomous", human_oversight="none", tool_access_level=4
    )
    assert result.score == 80 + 60 + 60
    assert result.score < 300
    assert result.risk_level == "CRITICAL"
    assert result.floor_applied == "unsupervised_transmit"


def test_autonomous_without_transmit_is_not_critical_by_floor():
    result = result_for(
        autonomy_level="autonomous", human_oversight="none", tool_access_level=3
    )
    assert result.floor_applied != "unsupervised_transmit"
    assert result.risk_level != "CRITICAL"


def test_the_stronger_floor_is_the_one_reported():
    result = result_for(
        autonomy_level="autonomous",
        human_oversight="none",
        tool_access_level=4,
        data_categories=["regulated"],
    )
    assert result.risk_level == "CRITICAL"
    assert result.floor_applied == "unsupervised_transmit"


@pytest.mark.parametrize("factor", list(FIELD_OF))
def test_any_missing_factor_is_incomplete_with_null_level(factor):
    field = FIELD_OF[factor]
    values = {**LOW, field: None}
    result = assess(RiskInputs(**values), M)
    assert result.status == "INCOMPLETE"
    assert result.risk_level is None
    assert result.score is None
    assert result.floor_applied is None
    assert result.mitigations == []
    assert result.missing == [factor]


def test_every_input_missing_names_every_factor_in_order():
    result = assess(RiskInputs(), M)
    assert result.status == "INCOMPLETE"
    assert result.missing == [f.id for f in M.factors]


def test_empty_data_categories_counts_as_missing():
    result = result_for(data_categories=[])
    assert result.status == "INCOMPLETE"
    assert result.missing == ["data_sensitivity"]


def test_unknown_tool_access_is_missing():
    result = result_for(tool_access_level=None, tool_access_source=None)
    assert result.missing == ["tool_access"]


def test_tool_access_level_must_be_zero_to_four():
    for bad in (-1, 5):
        with pytest.raises(ValidationError):
            RiskInputs(**{**LOW, "tool_access_level": bad})


def test_inputs_are_strict():
    with pytest.raises(ValidationError):
        RiskInputs(**{**LOW, "autonomy_level": "reckless"})
    with pytest.raises(ValidationError):
        RiskInputs(**{**LOW, "unexpected": 1})
    with pytest.raises(ValidationError):
        RiskInputs(**{**LOW, "tool_access_level": "3"})


def test_each_factor_explains_itself():
    result = assess(RiskInputs(**HIGHEST), M)
    assert [f.factor for f in result.factors] == [f.id for f in M.factors]
    for item, factor in zip(result.factors, M.factors, strict=True):
        assert item.explanation
        assert item.input_value
        assert item.weight == factor.weight
        assert item.level == 4
        assert item.contribution == factor.weight * 4


def test_the_tool_access_explanation_records_its_source():
    from_grants = result_for(tool_access_level=3, tool_access_source="grants")
    declared = result_for(tool_access_level=3, tool_access_source="declared")
    text = {
        label: next(f for f in r.factors if f.factor == "tool_access").explanation
        for label, r in (("grants", from_grants), ("declared", declared))
    }
    assert "grants" in text["grants"]
    assert "declared" in text["declared"]


def test_mitigations_come_from_the_document():
    result = assess(RiskInputs(**HIGHEST), M)
    expected = [
        text
        for factor in M.factors
        for text in M.mitigations.get(factor.id, {}).get("4", [])
    ]
    assert expected
    assert result.mitigations == expected


def test_a_level_without_an_entry_yields_no_mitigation():
    assert result_for().mitigations == []
    assert result_for(autonomy_level="supervised").mitigations == []


def test_the_built_in_document_has_text_for_levels_three_and_four_of_every_factor():
    for factor in M.factors:
        for level in ("3", "4"):
            if level in {str(v) for v in factor.levels.values()}:
                entries = M.mitigations[factor.id][level]
                assert entries and all(isinstance(t, str) and t.strip() for t in entries)


def test_a_custom_methodology_drives_the_result():
    custom = M.model_copy(update={"thresholds": Thresholds(medium=10, high=15, critical=20)})
    assert assess(full_inputs(), custom).risk_level == "LOW"
    assert assess(full_inputs(external_exposure="internal_users"), custom).risk_level == "MEDIUM"
    assert assess(full_inputs(data_categories=["internal"]), custom).risk_level == "CRITICAL"


def test_methodology_rejects_a_level_map_that_does_not_cover_the_input_values():
    document = M.model_dump()
    del document["factors"][1]["levels"]["partners"]
    with pytest.raises(ValidationError):
        Methodology.model_validate(document)


def test_methodology_rejects_unordered_thresholds():
    document = M.model_dump()
    document["thresholds"] = {"medium": 200, "high": 100, "critical": 300}
    with pytest.raises(ValidationError):
        Methodology.model_validate(document)


def test_methodology_rejects_a_floor_naming_an_unknown_factor():
    document = M.model_dump()
    document["floors"][0]["when"] = {"no_such_factor": 3}
    with pytest.raises(ValidationError):
        Methodology.model_validate(document)


def test_methodology_round_trips():
    assert Methodology.model_validate(M.model_dump(mode="json")) == M


# Properties


def inputs_strategy():
    return st.builds(
        RiskInputs,
        data_categories=st.lists(
            st.sampled_from(["public", "internal", "personal", "confidential", "regulated"]),
            max_size=5,
            unique=True,
        ),
        external_exposure=st.one_of(
            st.none(), st.sampled_from(["none", "internal_users", "partners", "public"])
        ),
        autonomy_level=st.one_of(
            st.none(),
            st.sampled_from(["advisory", "human_approved", "supervised", "bounded", "autonomous"]),
        ),
        tool_access_level=st.one_of(st.none(), st.integers(0, 4)),
        tool_access_source=st.one_of(st.none(), st.sampled_from(["grants", "declared"])),
        human_oversight=st.one_of(
            st.none(), st.sampled_from(["in_the_loop", "on_the_loop", "after_the_fact", "none"])
        ),
        impact_level=st.one_of(
            st.none(), st.sampled_from(["negligible", "minor", "moderate", "major", "severe"])
        ),
        deployment_environment=st.one_of(
            st.none(),
            st.sampled_from(
                ["development", "test", "staging", "production_internal", "production_external"]
            ),
        ),
        third_party_reliance=st.one_of(
            st.none(), st.sampled_from(["none", "vetted", "partially_vetted", "unvetted"])
        ),
    )


def complete_inputs_strategy():
    return st.builds(
        RiskInputs,
        data_categories=st.lists(
            st.sampled_from(["public", "internal", "personal", "confidential", "regulated"]),
            min_size=1,
            max_size=5,
            unique=True,
        ),
        external_exposure=st.sampled_from(["none", "internal_users", "partners", "public"]),
        autonomy_level=st.sampled_from(
            ["advisory", "human_approved", "supervised", "bounded", "autonomous"]
        ),
        tool_access_level=st.integers(0, 4),
        tool_access_source=st.sampled_from(["grants", "declared"]),
        human_oversight=st.sampled_from(["in_the_loop", "on_the_loop", "after_the_fact", "none"]),
        impact_level=st.sampled_from(["negligible", "minor", "moderate", "major", "severe"]),
        deployment_environment=st.sampled_from(
            ["development", "test", "staging", "production_internal", "production_external"]
        ),
        third_party_reliance=st.sampled_from(["none", "vetted", "partially_vetted", "unvetted"]),
    )


@given(inputs_strategy())
def test_same_inputs_same_result(inputs):
    assert assess(inputs, M) == assess(inputs, M)


@given(inputs_strategy())
def test_complete_iff_level_present(inputs):
    result = assess(inputs, M)
    assert (result.status == "COMPLETE") == (result.risk_level is not None)
    assert (result.status == "COMPLETE") == (result.score is not None)
    assert (result.status == "COMPLETE") == (result.missing == [])


@given(inputs_strategy())
def test_missing_lists_exactly_the_absent_factors(inputs):
    absent = [
        factor
        for factor, field in FIELD_OF.items()
        if getattr(inputs, field) in (None, [])
    ]
    assert assess(inputs, M).missing == absent


@given(
    complete_inputs_strategy(),
    st.sampled_from(sorted(FIELD_OF.values())),
    st.data(),
)
def test_raising_a_factor_never_lowers_the_score(inputs, field, data):
    factor = next(f for f, name in FIELD_OF.items() if name == field)
    levels = next(f for f in M.factors if f.id == factor).levels
    before = assess(inputs, M)
    if field == "data_categories":
        extra = data.draw(st.sampled_from(sorted(levels)))
        raised = inputs.model_copy(
            update={"data_categories": sorted({*inputs.data_categories, extra})}
        )
    else:
        current = levels[str(getattr(inputs, field))]
        higher = [v for v, lv in levels.items() if lv >= current]
        value = data.draw(st.sampled_from(sorted(higher)))
        raised = inputs.model_copy(
            update={field: int(value) if field == "tool_access_level" else value}
        )
    after = assess(raised, M)
    assert after.score >= before.score
    assert rank(after.risk_level) >= rank(before.risk_level)


def rank(level: str) -> int:
    return ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(level)


@given(complete_inputs_strategy())
def test_the_score_is_the_arithmetic_sum_and_floors_only_raise(inputs):
    result = assess(inputs, M)
    assert result.score == sum(item.contribution for item in result.factors)
    by_score = (
        "LOW"
        if result.score < 100
        else "MEDIUM"
        if result.score < 200
        else "HIGH"
        if result.score < 300
        else "CRITICAL"
    )
    assert rank(result.risk_level) >= rank(by_score)
    assert (result.risk_level != by_score) == (result.floor_applied is not None)


def _scalars(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _scalars(item)
    elif isinstance(value, list):
        for item in value:
            yield from _scalars(item)
    else:
        yield value


@given(inputs_strategy())
def test_result_contains_no_floats(inputs):
    dumped = assess(inputs, M).model_dump(mode="json")
    assert not any(isinstance(v, float) for v in _scalars(dumped))


def test_engine_imports_no_clock_or_io():
    tree = ast.parse(Path(risk_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
    assert imported <= {"typing", "pydantic", "aegis.governance.profile"}


def test_a_zero_weight_factor_adds_nothing_but_is_still_required():
    document = M.model_dump(mode="json")
    for factor in document["factors"]:
        if factor["id"] == "third_party_reliance":
            factor["weight"] = 0
    muted = Methodology.model_validate(document)
    unvetted = assess(full_inputs(third_party_reliance="unvetted"), muted)
    assert unvetted.score == assess(full_inputs(third_party_reliance="none"), muted).score
    assert unvetted.status == "COMPLETE"

    absent = {**LOW}
    del absent["third_party_reliance"]
    incomplete = assess(RiskInputs(**absent), muted)
    assert (incomplete.status, incomplete.risk_level, incomplete.missing) == (
        "INCOMPLETE", None, ["third_party_reliance"],
    )
