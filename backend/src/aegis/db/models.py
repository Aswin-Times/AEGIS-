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
