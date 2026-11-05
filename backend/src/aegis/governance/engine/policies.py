"""The policy engine. Pure: policy documents and an asset's facts in, requirements and findings out.

No I/O, no clock, no randomness, and no LLM. Whether a version is approved, active, or inside its
effective window is decided by the caller, which passes only the versions that apply. The outcome
informs a reviewer; it has no approve or deny field, because findings never decide.

Where policies disagree the most restrictive reading wins, and silence refuses: with no policy
saying so, nobody may approve their own submission or an asset they own.
"""

from dataclasses import dataclass
from uuid import UUID

from pydantic import BaseModel, ConfigDict, JsonValue

from aegis.governance.policy_schema import GovernancePolicyDocument, Severity
from aegis.governance.profile import AssetProfile

# Decision rules are reported as outcome fields, and the rest are requirements on the asset.
_DECISION_RULES = ("minimum_approvers", "self_approval", "owner_approval")
_DEFAULT_MINIMUM_APPROVERS = 1


@dataclass(frozen=True)
class VersionedDocument:
    version_id: UUID
    policy_id: UUID
    name: str
    document: GovernancePolicyDocument
    # Set by the service, which holds the clock. The engine only reports it.
    review_overdue: bool = False


class RequiredControl(BaseModel):
    """One control a policy version asks for. The value is JSON, so it can be frozen on a review."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version_id: UUID
    control: str
    value: JsonValue


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version_id: UUID
    control: str
    severity: Severity
    message: str


@dataclass(frozen=True)
class PolicyOutcome:
    applicable_version_ids: list[UUID]
    required_controls: list[RequiredControl]
    findings: list[Finding]
    minimum_approvers: int
    self_approval_permitted: bool
    owner_approval_permitted: bool


def applies(document: GovernancePolicyDocument, profile: AssetProfile,
            risk_level: str | None) -> bool:
    """Every condition given must hold. A fact that is not known matches no condition on it."""
    condition = document.applicability
    if condition.risk_levels is not None and risk_level not in condition.risk_levels:
        return False
    if condition.asset_types is not None and profile.asset_type not in condition.asset_types:
        return False
    if (condition.environments is not None
            and profile.deployment_environment not in condition.environments):
        return False
    if condition.data_categories is not None and not (
        set(profile.data_categories or ()) & set(condition.data_categories)
    ):
        return False
    return True


def _requirements(item: VersionedDocument) -> list[RequiredControl]:
    controls = item.document.controls.model_dump(mode="json", exclude_none=True)
    return [
        RequiredControl(policy_version_id=item.version_id, control=name, value=value)
        for name, value in sorted(controls.items())
        if name not in _DECISION_RULES
    ]


def _findings(item: VersionedDocument, profile: AssetProfile,
              verified_evidence_categories: set[str]) -> list[Finding]:
    controls = item.document.controls
    severity = item.document.severity
    found: list[Finding] = []

    def add(control: str, message: str) -> None:
        found.append(Finding(policy_version_id=item.version_id, control=control,
                             severity=severity, message=f"{item.name}: {message}"))

    if controls.permitted_model_providers is not None:
        permitted = {name.casefold() for name in controls.permitted_model_providers}
        if profile.model_provider is None:
            add("permitted_model_providers", "the model provider is not stated.")
        elif profile.model_provider.casefold() not in permitted:
            add("permitted_model_providers",
                f"the model provider {profile.model_provider!r} is not among the permitted "
                "providers.")
    if controls.required_human_oversight is not None:
        if profile.human_oversight is None:
            add("required_human_oversight", "the human oversight mode is not stated.")
        elif profile.human_oversight not in controls.required_human_oversight:
            add("required_human_oversight",
                f"human oversight is {profile.human_oversight!r}, which this policy does not "
                "accept.")
    handling = controls.data_handling
    if handling is not None:
        if handling.permitted_data_categories is not None:
            outside = sorted(set(profile.data_categories or ())
                             - set(handling.permitted_data_categories))
            if profile.data_categories is None:
                add("data_handling", "the data categories are not stated.")
            elif outside:
                add("data_handling",
                    f"the data categories {', '.join(outside)} are not permitted.")
        if handling.permitted_external_exposure is not None:
            if profile.external_exposure is None:
                add("data_handling", "the external exposure is not stated.")
            elif profile.external_exposure not in handling.permitted_external_exposure:
                add("data_handling",
                    f"the external exposure {profile.external_exposure!r} is not permitted.")
    for owner, owner_id in (("business", profile.business_owner_id),
                            ("technical", profile.technical_owner_id)):
        if owner in (controls.required_owners or ()) and owner_id is None:
            add("required_owners", f"the {owner} owner is not set.")
    for category in controls.required_evidence_categories or ():
        if category not in verified_evidence_categories:
            add("required_evidence_categories",
                f"there is no verified evidence in the category {category}.")
    if item.review_overdue:
        add("review_by", "this policy version is past its review date.")
    return found


def _permission(applicable: list[VersionedDocument], field: str) -> bool:
    """Permitted only when some policy says so and none says otherwise."""
    values = {getattr(item.document.controls, field) for item in applicable}
    return "permitted" in values and "prohibited" not in values


def evaluate_policies(documents: list[VersionedDocument], profile: AssetProfile,
                      risk_level: str | None,
                      verified_evidence_categories: set[str]) -> PolicyOutcome:
    applicable = sorted(
        (item for item in documents if applies(item.document, profile, risk_level)),
        key=lambda item: str(item.version_id),
    )
    return PolicyOutcome(
        applicable_version_ids=[item.version_id for item in applicable],
        required_controls=[control for item in applicable for control in _requirements(item)],
        findings=[
            finding
            for item in applicable
            for finding in _findings(item, profile, verified_evidence_categories)
        ],
        minimum_approvers=max(
            (item.document.controls.minimum_approvers or _DEFAULT_MINIMUM_APPROVERS
             for item in applicable),
            default=_DEFAULT_MINIMUM_APPROVERS,
        ),
        self_approval_permitted=_permission(applicable, "self_approval"),
        owner_approval_permitted=_permission(applicable, "owner_approval"),
    )
