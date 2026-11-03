"""ORM mappings. Constraints, RLS, grants, and triggers live in the Alembic migration."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Integer, LargeBinary, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    type_annotation_map = {datetime: DateTime(timezone=True), dict[str, Any]: JSONB}


def _created_at() -> Mapped[datetime]:
    return mapped_column(server_default=func.now())


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    slug: Mapped[str]
    name: Mapped[str]
    active_policy_version_id: Mapped[UUID | None]
    created_at: Mapped[datetime] = _created_at()


class User(Base):
    __tablename__ = "users"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    email: Mapped[str]
    password_hash: Mapped[str]
    role: Mapped[str]
    is_active: Mapped[bool]
    created_at: Mapped[datetime] = _created_at()


class AiAsset(Base):
    __tablename__ = "ai_assets"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    name: Mapped[str]
    owner: Mapped[str]
    risk_classification: Mapped[str]
    intended_use: Mapped[str]
    is_synthetic: Mapped[bool]
    created_at: Mapped[datetime] = _created_at()


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    asset_id: Mapped[UUID]
    name: Mapped[str]
    owner: Mapped[str]
    status: Mapped[str]
    created_at: Mapped[datetime] = _created_at()


class AgentCredential(Base):
    __tablename__ = "agent_credentials"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    agent_id: Mapped[UUID]
    secret_hash: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = _created_at()
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]


class Resource(Base):
    __tablename__ = "resources"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    kind: Mapped[str]
    name: Mapped[str]
    classification: Mapped[str]
    clearance: Mapped[str | None]
    content: Mapped[dict[str, Any]]
    is_synthetic: Mapped[bool]
    created_at: Mapped[datetime] = _created_at()


class AgentToolGrant(Base):
    __tablename__ = "agent_tool_grants"
    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    agent_id: Mapped[UUID] = mapped_column(primary_key=True)
    tool: Mapped[str] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = _created_at()


class AgentResourceGrant(Base):
    __tablename__ = "agent_resource_grants"
    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    agent_id: Mapped[UUID] = mapped_column(primary_key=True)
    resource_id: Mapped[UUID] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = _created_at()


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    name: Mapped[str]
    created_at: Mapped[datetime] = _created_at()


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    policy_id: Mapped[UUID]
    version: Mapped[int] = mapped_column(Integer)
    document_canonical: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str]
    created_by: Mapped[UUID]
    created_at: Mapped[datetime] = _created_at()


class ActionRequest(Base):
    __tablename__ = "action_requests"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    agent_id: Mapped[UUID]
    idempotency_key: Mapped[str]
    tool: Mapped[str]
    action: Mapped[str | None]
    resource_id: Mapped[UUID | None]
    params_canonical: Mapped[str] = mapped_column(Text)
    action_hash: Mapped[str]
    created_at: Mapped[datetime] = _created_at()


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    request_id: Mapped[UUID]
    agent_id: Mapped[UUID]
    resource_id: Mapped[UUID | None]
    tool: Mapped[str]
    action: Mapped[str | None]
    policy_id: Mapped[UUID | None]
    policy_version_id: Mapped[UUID | None]
    policy_version: Mapped[int | None]
    outcome: Mapped[str]
    reason_code: Mapped[str]
    matched_rule_id: Mapped[str | None]
    evaluated_at: Mapped[datetime]
    evidence: Mapped[dict[str, Any]]


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    request_id: Mapped[UUID]
    decision_id: Mapped[UUID]
    action_hash: Mapped[str]
    status: Mapped[str]
    requested_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    decided_by: Mapped[UUID | None]
    decided_at: Mapped[datetime | None]
    comment: Mapped[str | None]


class Execution(Base):
    __tablename__ = "executions"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    request_id: Mapped[UUID]
    status: Mapped[str]
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]


class SimulatedOutbox(Base):
    __tablename__ = "simulated_outbox"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    request_id: Mapped[UUID]
    destination_id: Mapped[UUID]
    body: Mapped[str]
    attachment_resource_id: Mapped[UUID | None]
    created_at: Mapped[datetime] = _created_at()


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    schema_version: Mapped[int]
    event_type: Mapped[str]
    occurred_at: Mapped[datetime]
    recorded_at: Mapped[datetime] = mapped_column(server_default=func.clock_timestamp())
    actor_type: Mapped[str]
    actor_id: Mapped[UUID | None]
    asset_id: Mapped[UUID | None]
    agent_id: Mapped[UUID | None]
    action_request_id: Mapped[UUID | None]
    tool: Mapped[str | None]
    action: Mapped[str | None]
    resource_id: Mapped[UUID | None]
    decision_id: Mapped[UUID | None]
    approval_id: Mapped[UUID | None]
    execution_id: Mapped[UUID | None]
    correlation_id: Mapped[UUID | None]
    severity: Mapped[str]
    reason_code: Mapped[str]
    attributes: Mapped[dict[str, Any]]
    source_audit_event_id: Mapped[UUID]
    source_event_hash: Mapped[str]
    correlation_processed_at: Mapped[datetime | None]


class CorrelationRuleVersion(Base):
    __tablename__ = "correlation_rule_versions"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    rule_key: Mapped[str]
    version: Mapped[int]
    definition_canonical: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str]
    created_by: Mapped[UUID | None]
    created_at: Mapped[datetime] = _created_at()


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    rule_version_id: Mapped[UUID]
    rule_key: Mapped[str]
    rule_version: Mapped[int]
    scope_type: Mapped[str]
    scope_key: Mapped[str]
    agent_id: Mapped[UUID | None]
    title: Mapped[str]
    severity: Mapped[str]
    status: Mapped[str]
    version: Mapped[int]
    event_count: Mapped[int]
    first_observed_at: Mapped[datetime]
    last_observed_at: Mapped[datetime]
    assigned_to: Mapped[UUID | None]
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _created_at()


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    incident_id: Mapped[UUID] = mapped_column(primary_key=True)
    event_id: Mapped[UUID] = mapped_column(primary_key=True)
    linked_at: Mapped[datetime] = _created_at()


class IncidentTransition(Base):
    __tablename__ = "incident_transitions"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    incident_id: Mapped[UUID]
    from_status: Mapped[str | None]
    to_status: Mapped[str]
    actor_type: Mapped[str]
    actor_id: Mapped[UUID | None]
    reason: Mapped[str | None]
    occurred_at: Mapped[datetime]
    audit_event_id: Mapped[UUID]


class InvestigationRun(Base):
    __tablename__ = "investigation_runs"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    incident_id: Mapped[UUID]
    started_by: Mapped[UUID | None]
    engine_version: Mapped[int]
    input_fingerprint: Mapped[str]
    llm_status: Mapped[str]
    llm_provider: Mapped[str | None]
    llm_model: Mapped[str | None]
    llm_rejected_count: Mapped[int]
    llm_finished_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created_at()


class InvestigationFinding(Base):
    __tablename__ = "investigation_findings"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    run_id: Mapped[UUID]
    kind: Mapped[str]
    source: Mapped[str]
    statement: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str | None]
    position: Mapped[int]
    created_at: Mapped[datetime] = _created_at()


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    finding_id: Mapped[UUID]
    security_event_id: Mapped[UUID | None]
    decision_id: Mapped[UUID | None]
    approval_id: Mapped[UUID | None]
    execution_id: Mapped[UUID | None]
    audit_event_id: Mapped[UUID | None]


class GovernanceSettings(Base):
    __tablename__ = "governance_settings"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    enforcement_mode: Mapped[str]
    active_methodology_version_id: Mapped[UUID | None]
    created_at: Mapped[datetime] = _created_at()


class GovernanceRoleGrant(Base):
    __tablename__ = "governance_role_grants"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    user_id: Mapped[UUID]
    role: Mapped[str]
    granted_by: Mapped[UUID]
    granted_at: Mapped[datetime]
    revoked_by: Mapped[UUID | None]
    revoked_at: Mapped[datetime | None]


class AuditChainHead(Base):
    __tablename__ = "audit_chain_heads"
    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    seq: Mapped[int]
    head_hash: Mapped[str]


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID]
    seq: Mapped[int]
    prev_hash: Mapped[str]
    event_hash: Mapped[str]
    event_type: Mapped[str]
    actor_type: Mapped[str]
    actor_id: Mapped[UUID | None]
    correlation_id: Mapped[UUID | None]
    subject_type: Mapped[str | None]
    subject_id: Mapped[UUID | None]
    policy_version_id: Mapped[UUID | None]
    occurred_at: Mapped[datetime]
    payload: Mapped[dict[str, Any]]
