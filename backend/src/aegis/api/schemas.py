from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from aegis.canonical import canonical_json
from aegis.correlation.rules import CorrelationRule
from aegis.policy.schema import PolicyDocument

MAX_PARAMS_CHARS = 16_384

Name = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=200)]
Classification = Literal["public", "internal", "sensitive"]
ResourceKind = Literal["document", "customer_record", "destination"]
ApprovalStatus = Literal["PENDING", "APPROVED", "REJECTED", "EXECUTED", "CANCELLED"]
Outcome = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
IncidentStatus = Literal["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"]


class In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class LoginIn(In):
    tenant_slug: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=63)]
    email: Annotated[str, StringConstraints(strict=True, min_length=3, max_length=320)]
    password: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=1024)]


class TokenOut(Out):
    access_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int


class MeOut(Out):
    id: UUID
    tenant_id: UUID
    email: str
    role: str


class AssetIn(In):
    name: Name
    owner: Name
    risk_classification: Literal["low", "medium", "high", "critical"]
    intended_use: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=2000)]
    is_synthetic: Annotated[bool, Field(strict=True)]


class AssetOut(Out):
    id: UUID
    name: str
    owner: str
    risk_classification: str
    intended_use: str
    is_synthetic: bool
    created_at: datetime | None = None


class AgentIn(In):
    asset_id: UUID
    name: Name
    owner: Name


class AgentStatusIn(In):
    status: Literal["active", "disabled"]


class CredentialIn(In):
    expires_at: datetime | None = None


class CredentialOut(Out):
    id: UUID
    created_at: datetime | None = None
    expires_at: datetime | None
    revoked_at: datetime | None


class IssuedCredentialOut(CredentialOut):
    key: str


class AgentOut(Out):
    id: UUID
    asset_id: UUID
    name: str
    owner: str
    status: str
    created_at: datetime | None = None
    tool_grants: list[str]
    resource_grants: list[UUID]
    credentials: list[CredentialOut]


class ToolGrantIn(In):
    tool: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=64)]


class ResourceGrantIn(In):
    resource_id: UUID


class GrantOut(Out):
    agent_id: UUID
    tool: str | None = None
    resource_id: UUID | None = None


class ResourceIn(In):
    kind: ResourceKind
    name: Name
    classification: Classification
    clearance: Classification | None = None
    content: dict[str, Any]
    is_synthetic: Annotated[bool, Field(strict=True)]

    @model_validator(mode="after")
    def clearance_only_on_destinations(self) -> "ResourceIn":
        if (self.kind == "destination") != (self.clearance is not None):
            raise ValueError("Destinations, and only destinations, must have a clearance")
        return self


class ResourceOut(Out):
    """Never carries content: reading it requires going through the gateway."""

    id: UUID
    kind: str
    name: str
    classification: str
    clearance: str | None
    is_synthetic: bool
    created_at: datetime | None = None


class PolicyIn(In):
    name: Name


class PolicyVersionIn(In):
    document: PolicyDocument


class ActivateIn(In):
    version_id: UUID


class PolicyVersionOut(Out):
    id: UUID
    policy_id: UUID
    version: int
    content_hash: str
    created_at: datetime | None = None
    document: dict[str, Any]


class PolicyOut(Out):
    id: UUID
    name: str
    created_at: datetime | None = None
    active_version_id: UUID | None
    versions: list[PolicyVersionOut]


class ActionIn(In):
    idempotency_key: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]
    tool: Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    resource_id: UUID | None
    params: dict[str, Any]

    @model_validator(mode="after")
    def params_are_canonicalizable_and_bounded(self) -> "ActionIn":
        # Refuses NaN and Infinity, which Python's JSON parser accepts.
        if len(canonical_json(self.params)) > MAX_PARAMS_CHARS:
            raise ValueError("params is too large")
        return self


class ExecutionOut(Out):
    status: str
    result: dict[str, Any] | None


class ActionOut(Out):
    request_id: UUID
    outcome: str
    reason_code: str
    decision_id: UUID
    policy_version_id: UUID | None
    approval_id: UUID | None
    approval_status: str | None
    execution: ExecutionOut | None


class ApprovalDecisionIn(In):
    comment: Annotated[str, StringConstraints(strict=True, max_length=2000)] | None = None


class ApprovalOut(Out):
    id: UUID
    request_id: UUID
    decision_id: UUID
    agent_id: UUID
    tool: str
    action: str | None
    resource_id: UUID | None
    params: dict[str, Any]
    action_hash: str
    status: str
    requested_at: datetime
    expires_at: datetime
    decided_by: UUID | None
    decided_at: datetime | None
    comment: str | None


class DecisionExecutionOut(Out):
    """Execution status only. Tool results stay with the agent that requested them."""

    status: str
    started_at: datetime
    finished_at: datetime | None


class DecisionOut(Out):
    id: UUID
    request_id: UUID
    agent_id: UUID
    agent_name: str
    resource_id: UUID | None
    tool: str
    action: str | None
    policy_id: UUID | None
    policy_version_id: UUID | None
    policy_version: int | None
    outcome: str
    reason_code: str
    matched_rule_id: str | None
    evaluated_at: datetime
    tool_executed: bool
    execution: DecisionExecutionOut | None


class DecisionDetailOut(DecisionOut):
    evidence: dict[str, Any]
    audit_event_ids: list[UUID]


class AuditEventOut(Out):
    id: UUID
    seq: int
    prev_hash: str
    event_hash: str
    event_type: str
    actor_type: str
    actor_id: UUID | None
    correlation_id: UUID | None
    subject_type: str | None
    subject_id: UUID | None
    policy_version_id: UUID | None
    occurred_at: datetime
    payload: dict[str, Any]


class SecurityEventOut(Out):
    id: UUID
    schema_version: int
    event_type: str
    occurred_at: datetime
    recorded_at: datetime
    actor_type: str
    actor_id: UUID | None
    asset_id: UUID | None
    agent_id: UUID | None
    agent_name: str | None = None
    action_request_id: UUID | None
    tool: str | None
    action: str | None
    resource_id: UUID | None
    decision_id: UUID | None
    approval_id: UUID | None
    execution_id: UUID | None
    correlation_id: UUID | None
    severity: str
    reason_code: str
    attributes: dict[str, Any]
    source_audit_event_id: UUID
    source_event_hash: str
    incident_ids: list[UUID] = []


class IncidentTransitionIn(In):
    expected_version: Annotated[int, Field(strict=True, ge=1)]
    reason: Annotated[str, StringConstraints(strict=True, max_length=2000)] | None = None


class IncidentTransitionOut(Out):
    id: UUID
    from_status: str | None
    to_status: str
    actor_type: str
    actor_id: UUID | None
    reason: str | None
    occurred_at: datetime
    audit_event_id: UUID


class IncidentOut(Out):
    id: UUID
    rule_version_id: UUID
    rule_key: str
    rule_version: int
    scope_type: str
    scope_key: str
    agent_id: UUID | None
    agent_name: str | None
    title: str
    severity: str
    status: str
    version: int
    event_count: int
    first_observed_at: datetime
    last_observed_at: datetime
    assigned_to: UUID | None
    assigned_to_email: str | None
    created_at: datetime
    updated_at: datetime


class IncidentDetailOut(IncidentOut):
    transitions: list[IncidentTransitionOut]
    # None if the stored rule version fails its integrity check.
    rule_definition: dict[str, Any] | None


class RuleVersionIn(In):
    definition: CorrelationRule


class CorrelationRuleOut(Out):
    rule_key: str
    version: int
    version_id: UUID
    content_hash: str
    definition: dict[str, Any]


class EvidenceRefOut(Out):
    type: str
    id: str


class TimelineItemOut(Out):
    occurred_at: datetime
    kind: str
    summary: str
    severity: str | None
    verified: bool | None
    evidence: EvidenceRefOut


class InvestigationRunOut(Out):
    id: UUID
    incident_id: UUID
    started_by: UUID | None
    engine_version: int
    input_fingerprint: str
    llm_status: str
    llm_provider: str | None
    llm_model: str | None
    llm_rejected_count: int
    llm_finished_at: datetime | None
    created_at: datetime


class FindingOut(Out):
    id: UUID
    kind: str
    source: str
    statement: str
    confidence: str | None
    position: int
    verified: bool
    evidence: list[EvidenceRefOut]


class FindingsOut(Out):
    run: InvestigationRunOut | None
    findings: list[FindingOut]


class EvidenceRecordOut(Out):
    type: str
    id: UUID
    occurred_at: datetime
    fields: dict[str, Any]


class AuditHeadOut(Out):
    seq: int
    head_hash: str


class AuditVerificationOut(Out):
    valid: bool
    events_checked: int
    head_seq: int
    head_hash: str
    failure_seq: int | None
    failure_reason: str | None


class OverviewOut(Out):
    assets: int
    agents: int
    agents_disabled: int
    decisions: dict[str, int]
    pending_approvals: int
    executions: int
    audit_events: int
    active_policy_version_id: UUID | None
    synthetic_assets: int
    active_incidents: int
    pending_correlation: int


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int
