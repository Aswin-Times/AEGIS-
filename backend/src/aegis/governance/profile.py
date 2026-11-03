"""The asset profile: what the registrant says about an asset, every field optional.

A partial profile can be saved, so that the risk engine can name what is missing.
"""

from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from aegis.canonical import canonical_json

Text = Annotated[str, StringConstraints(min_length=1, max_length=2000)]
Label = Annotated[str, StringConstraints(min_length=1, max_length=200)]
Labels = Annotated[list[Label], Field(max_length=50)]
UserRef = Annotated[UUID, Field(strict=False)]

AssetType = Literal[
    "ai_application", "autonomous_agent", "model", "model_provider", "ai_enabled_service"
]
DataCategory = Literal["public", "internal", "personal", "confidential", "regulated"]
ExternalExposure = Literal["none", "internal_users", "partners", "public"]
AutonomyLevel = Literal["advisory", "human_approved", "supervised", "bounded", "autonomous"]
HumanOversight = Literal["in_the_loop", "on_the_loop", "after_the_fact", "none"]
ImpactLevel = Literal["negligible", "minor", "moderate", "major", "severe"]
Environment = Literal[
    "development", "test", "staging", "production_internal", "production_external"
]
ThirdPartyReliance = Literal["none", "vetted", "partially_vetted", "unvetted"]


class AssetProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_type: AssetType | None = None
    description: Text | None = None
    business_purpose: Text | None = None
    intended_use: Text | None = None
    prohibited_use: Text | None = None
    business_owner_id: UserRef | None = None
    technical_owner_id: UserRef | None = None
    responsible_team: Label | None = None
    model_provider: Label | None = None
    model_name: Label | None = None
    model_version: Label | None = None
    deployment_environment: Environment | None = None
    data_categories: Annotated[list[DataCategory], Field(max_length=5)] | None = None
    external_exposure: ExternalExposure | None = None
    external_integrations: Labels | None = None
    autonomy_level: AutonomyLevel | None = None
    human_oversight: HumanOversight | None = None
    declared_tool_access: Labels | None = None
    impact_level: ImpactLevel | None = None
    third_party_reliance: ThirdPartyReliance | None = None
    evidence_references: Labels | None = None

    @field_validator(
        "data_categories", "external_integrations", "declared_tool_access", "evidence_references"
    )
    @classmethod
    def _as_a_set(cls, value: list[str] | None) -> list[str] | None:
        """These lists are sets, so equivalent profiles share one canonical form and hash."""
        return None if value is None else sorted(set(value))


def canonical_profile(profile: AssetProfile) -> str:
    return canonical_json(profile.model_dump(mode="json", exclude_none=True))
