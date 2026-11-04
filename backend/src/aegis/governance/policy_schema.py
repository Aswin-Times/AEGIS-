"""The governance policy document: a closed, typed schema (spec 8).

An unknown key is rejected, so a policy cannot carry a requirement that nothing evaluates. The
name and category of a policy live on the policy; everything else about a version, including
who approved it and whether it is active, is held outside this document.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from aegis.governance.engine.risk import RiskLevel
from aegis.governance.profile import (
    AssetType,
    DataCategory,
    Environment,
    ExternalExposure,
    HumanOversight,
    Label,
    Text,
)

EvidenceCategory = Literal[
    "risk_assessment",
    "security_evaluation",
    "architecture_documentation",
    "data_handling_documentation",
    "human_oversight_documentation",
    "model_evaluation",
    "approval_records",
    "monitoring_records",
    "incident_investigation_records",
    "periodic_review_records",
]
Severity = Literal["low", "medium", "high", "critical"]
Owner = Literal["business", "technical"]
Permission = Literal["permitted", "prohibited"]

# A list of 1 to 20 distinct values. An empty list would constrain nothing or everything, and
# the difference would not be visible in the document.
_MAX_ITEMS = 20


def _distinct(value: list | None) -> list | None:
    """These lists are sets, so equivalent documents share one canonical form and hash."""
    return None if value is None else sorted(set(value))


def _set_of(item):
    return Annotated[list[item], Field(min_length=1, max_length=_MAX_ITEMS)]


class Applicability(BaseModel):
    """Every condition given must hold; within one condition, any listed value matches."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    risk_levels: _set_of(RiskLevel) | None = None
    asset_types: _set_of(AssetType) | None = None
    environments: _set_of(Environment) | None = None
    data_categories: _set_of(DataCategory) | None = None

    _as_sets = field_validator(
        "risk_levels", "asset_types", "environments", "data_categories"
    )(_distinct)


class DataHandling(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    permitted_data_categories: _set_of(DataCategory) | None = None
    permitted_external_exposure: _set_of(ExternalExposure) | None = None

    _as_sets = field_validator(
        "permitted_data_categories", "permitted_external_exposure"
    )(_distinct)


class Controls(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    # Checked against the profile, so a mismatch becomes a finding.
    required_human_oversight: _set_of(HumanOversight) | None = None
    permitted_model_providers: _set_of(Label) | None = None
    data_handling: DataHandling | None = None
    required_owners: _set_of(Owner) | None = None
    required_evidence_categories: _set_of(EvidenceCategory) | None = None
    # Requirements for a reviewer to confirm. They are listed on the review, not computed.
    required_evaluations: _set_of(Label) | None = None
    required_documentation: _set_of(Label) | None = None
    reassessment_interval_days: Annotated[int, Field(ge=1, le=3650)] | None = None
    incident_reporting: bool | None = None
    # How a decision is made. Stricter values win when policies disagree.
    minimum_approvers: Literal[1, 2] | None = None
    self_approval: Permission | None = None
    owner_approval: Permission | None = None

    _as_sets = field_validator(
        "required_human_oversight",
        "permitted_model_providers",
        "required_owners",
        "required_evidence_categories",
        "required_evaluations",
        "required_documentation",
    )(_distinct)

    @field_validator("minimum_approvers", mode="before")
    @classmethod
    def _not_a_boolean(cls, value):
        """JSON true would otherwise pass as the integer 1."""
        if isinstance(value, bool):
            raise ValueError("minimum_approvers must be 1 or 2")
        return value


class GovernancePolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    description: Text
    severity: Severity
    applicability: Applicability = Applicability()
    controls: Controls = Controls()


PolicyName = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=200)]
PolicyCategory = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=100)]
