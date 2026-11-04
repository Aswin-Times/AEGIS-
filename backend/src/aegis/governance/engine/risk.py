"""The risk engine. Pure: a function of the inputs and the methodology document.

No I/O, no clock, no randomness, and no LLM. Scores are integers, because the audit chain rejects
floats. Floors only ever raise the level; the score stays the arithmetic sum.
"""

from typing import Annotated, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.governance.profile import (
    AutonomyLevel,
    DataCategory,
    Environment,
    ExternalExposure,
    HumanOversight,
    ImpactLevel,
    ThirdPartyReliance,
)

MAX_LEVEL = 4

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_RANK: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

Level = Annotated[int, Field(ge=0, le=MAX_LEVEL)]
Weight = Annotated[int, Field(ge=1, le=1000)]

# The values each input can take; a methodology's level map must cover exactly these.
_INPUT_VALUES: dict[str, tuple[str, ...]] = {
    "data_categories": get_args(DataCategory),
    "external_exposure": get_args(ExternalExposure),
    "autonomy_level": get_args(AutonomyLevel),
    "tool_access_level": tuple(str(n) for n in range(MAX_LEVEL + 1)),
    "human_oversight": get_args(HumanOversight),
    "impact_level": get_args(ImpactLevel),
    "deployment_environment": get_args(Environment),
    "third_party_reliance": get_args(ThirdPartyReliance),
}


class RiskInputs(BaseModel):
    """Everything the engine may consider. Any field left out makes the assessment incomplete."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    data_categories: list[DataCategory] | None = None
    external_exposure: ExternalExposure | None = None
    autonomy_level: AutonomyLevel | None = None
    # Already reduced to 0-4 by the caller from the asset's tool grants, so the engine never sees
    # the grants themselves. The source is recorded so the result can say where it came from.
    tool_access_level: Annotated[int, Field(ge=0, le=MAX_LEVEL)] | None = None
    tool_access_source: Literal["grants", "declared"] | None = None
    human_oversight: HumanOversight | None = None
    impact_level: ImpactLevel | None = None
    deployment_environment: Environment | None = None
    third_party_reliance: ThirdPartyReliance | None = None


class Factor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    label: str = Field(min_length=1, max_length=100)
    weight: Weight
    input: Literal[
        "data_categories",
        "external_exposure",
        "autonomy_level",
        "tool_access_level",
        "human_oversight",
        "impact_level",
        "deployment_environment",
        "third_party_reliance",
    ]
    levels: dict[str, Level]

    @model_validator(mode="after")
    def levels_cover_the_input(self) -> "Factor":
        if set(self.levels) != set(_INPUT_VALUES[self.input]):
            raise ValueError(f"Levels for {self.id} must cover exactly the values of {self.input}")
        return self


class Thresholds(BaseModel):
    """A score below `medium` is LOW; from `critical` upward it is CRITICAL."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    medium: int = Field(ge=1)
    high: int = Field(ge=1)
    critical: int = Field(ge=1)

    @model_validator(mode="after")
    def ascending(self) -> "Thresholds":
        if not self.medium < self.high < self.critical:
            raise ValueError("Thresholds must be strictly ascending")
        return self


class Floor(BaseModel):
    """If every listed factor is at least at its listed level, the risk level is at least this."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    description: str = Field(min_length=1, max_length=500)
    minimum_level: RiskLevel
    when: dict[str, Level] = Field(min_length=1)


class Methodology(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    factors: list[Factor] = Field(min_length=1, max_length=50)
    thresholds: Thresholds
    floors: list[Floor] = Field(max_length=50)
    # factor id -> level (as text, for JSON) -> recommendations
    mitigations: dict[str, dict[str, list[str]]]
    provenance_note: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def references_resolve(self) -> "Methodology":
        ids = [factor.id for factor in self.factors]
        if len(ids) != len(set(ids)):
            raise ValueError("Factor ids must be unique")
        if len({floor.id for floor in self.floors}) != len(self.floors):
            raise ValueError("Floor ids must be unique")
        for floor in self.floors:
            unknown = set(floor.when) - set(ids)
            if unknown:
                raise ValueError(f"Floor {floor.id} names unknown factors: {sorted(unknown)}")
        for factor_id, by_level in self.mitigations.items():
            if factor_id not in ids:
                raise ValueError(f"Mitigations name an unknown factor: {factor_id}")
            if set(by_level) - {str(n) for n in range(MAX_LEVEL + 1)}:
                raise ValueError(f"Mitigation levels for {factor_id} must be 0 to {MAX_LEVEL}")
        return self


class FactorResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    factor: str
    label: str
    input_value: str
    level: int
    weight: int
    contribution: int
    explanation: str


class RiskResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["COMPLETE", "INCOMPLETE"]
    score: int | None
    risk_level: RiskLevel | None
    factors: list[FactorResult]
    floor_applied: str | None
    missing: list[str]
    mitigations: list[str]


def risk_level_for_score(score: int, thresholds: Thresholds) -> RiskLevel:
    if score < thresholds.medium:
        return "LOW"
    if score < thresholds.high:
        return "MEDIUM"
    if score < thresholds.critical:
        return "HIGH"
    return "CRITICAL"


def _input_value(inputs: RiskInputs, factor: Factor) -> str | None:
    """The text the level map is keyed by, or None when the input is absent."""
    if factor.input == "data_categories":
        if not inputs.data_categories:
            return None
        # Highest wins; ties broken by name so the text never depends on list order.
        return max(inputs.data_categories, key=lambda c: (factor.levels[c], c))
    value = getattr(inputs, factor.input)
    return None if value is None else str(value)


def _explain(inputs: RiskInputs, factor: Factor, value: str, level: int, contribution: int) -> str:
    if factor.input == "data_categories":
        used = f"highest of {', '.join(sorted(inputs.data_categories))} is {value}"
    elif factor.input == "tool_access_level":
        source = inputs.tool_access_source
        used = f"tool access level {value}" + (f" from {source} tools" if source else "")
    else:
        used = f"{factor.input.replace('_', ' ')} is {value}"
    return (
        f"{factor.label}: {used}, level {level} of {MAX_LEVEL}; "
        f"weight {factor.weight} contributes {contribution}."
    )


def assess(inputs: RiskInputs, methodology: Methodology) -> RiskResult:
    results: list[FactorResult] = []
    missing: list[str] = []
    for factor in methodology.factors:
        value = _input_value(inputs, factor)
        if value is None:
            missing.append(factor.id)
            continue
        level = factor.levels[value]
        contribution = factor.weight * level
        results.append(
            FactorResult(
                factor=factor.id,
                label=factor.label,
                input_value=value,
                level=level,
                weight=factor.weight,
                contribution=contribution,
                explanation=_explain(inputs, factor, value, level, contribution),
            )
        )
    if missing:
        return RiskResult(
            status="INCOMPLETE",
            score=None,
            risk_level=None,
            factors=results,
            floor_applied=None,
            missing=missing,
            mitigations=[],
        )

    score = sum(item.contribution for item in results)
    level = risk_level_for_score(score, methodology.thresholds)
    levels = {item.factor: item.level for item in results}
    floor_applied = None
    for floor in methodology.floors:
        holds = all(levels[factor] >= minimum for factor, minimum in floor.when.items())
        if holds and _RANK[floor.minimum_level] > _RANK[level]:
            level = floor.minimum_level
            floor_applied = floor.id

    mitigations = [
        text
        for item in results
        for text in methodology.mitigations.get(item.factor, {}).get(str(item.level), [])
    ]
    return RiskResult(
        status="COMPLETE",
        score=score,
        risk_level=level,
        factors=results,
        floor_applied=floor_applied,
        missing=[],
        mitigations=mitigations,
    )
