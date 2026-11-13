"""Control plane writes. Each runs in the caller's tenant transaction and is audited."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.canonical import canonical_json, sha256_hex
from aegis.db.models import (
    Agent,
    AgentCredential,
    AgentResourceGrant,
    AgentToolGrant,
    AiAsset,
    Policy,
    PolicyVersion,
    Resource,
    Tenant,
)
from aegis.errors import NotFound, ValidationFailed
from aegis.gateway.tools import ToolRegistry
from aegis.governance.approvals import mark_grant_changed
from aegis.policy.schema import PolicyDocument
from aegis.security.agent_keys import format_key, generate_secret, hash_secret
from aegis.security.principals import UserPrincipal


def _audit(session: Session, user: UserPrincipal, event_type: str, subject_type: str,
           subject_id: UUID | None, now: datetime, **extra: Any) -> None:
    policy_version_id = extra.pop("policy_version_id", None)
    append_event(
        session,
        user.tenant_id,
        event_type=event_type,
        actor_type="user",
        actor_id=user.id,
        subject_type=subject_type,
        subject_id=subject_id,
        policy_version_id=policy_version_id,
        occurred_at=now,
        payload=extra,
    )


def _paged(session: Session, model: type, order: Any, limit: int, offset: int):
    items = session.execute(select(model).order_by(order).limit(limit).offset(offset))
    total = session.execute(select(func.count()).select_from(model)).scalar_one()
    return list(items.scalars()), total


# Assets


def list_assets(session: Session, *, limit: int, offset: int):
    return _paged(session, AiAsset, AiAsset.created_at.desc(), limit, offset)


def get_asset(session: Session, asset_id: UUID) -> AiAsset:
    asset = session.get(AiAsset, asset_id)
    if asset is None:
        raise NotFound()
    return asset


def create_asset(session: Session, user: UserPrincipal, now: datetime, **fields: Any) -> AiAsset:
    asset = AiAsset(id=uuid4(), tenant_id=user.tenant_id, **fields)
    session.add(asset)
    session.flush()
    _audit(session, user, "asset.created", "ai_asset", asset.id, now,
           name=asset.name, risk_classification=asset.risk_classification)
    return asset


# Agents


@dataclass(frozen=True)
class AgentDetail:
    agent: Agent
    tool_grants: list[str]
    resource_grants: list[UUID]
    credentials: list[AgentCredential]


def _agent_details(session: Session, agents: list[Agent]) -> list[AgentDetail]:
    ids = [agent.id for agent in agents]
    tools: dict[UUID, list[str]] = {}
    for grant in session.execute(
        select(AgentToolGrant).where(AgentToolGrant.agent_id.in_(ids)).order_by(AgentToolGrant.tool)
    ).scalars():
        tools.setdefault(grant.agent_id, []).append(grant.tool)
    resources: dict[UUID, list[UUID]] = {}
    for grant in session.execute(
        select(AgentResourceGrant).where(AgentResourceGrant.agent_id.in_(ids))
    ).scalars():
        resources.setdefault(grant.agent_id, []).append(grant.resource_id)
    credentials: dict[UUID, list[AgentCredential]] = {}
    for credential in session.execute(
        select(AgentCredential)
        .where(AgentCredential.agent_id.in_(ids))
        .order_by(AgentCredential.created_at)
    ).scalars():
        credentials.setdefault(credential.agent_id, []).append(credential)
    return [
        AgentDetail(
            agent, tools.get(agent.id, []), resources.get(agent.id, []),
            credentials.get(agent.id, []),
        )
        for agent in agents
    ]


def list_agents(session: Session, *, limit: int, offset: int):
    agents, total = _paged(session, Agent, Agent.created_at.desc(), limit, offset)
    return _agent_details(session, agents), total


def _agent_or_404(session: Session, agent_id: UUID) -> Agent:
    agent = session.get(Agent, agent_id)
    if agent is None:
        raise NotFound()
    return agent


def get_agent(session: Session, agent_id: UUID) -> AgentDetail:
    return _agent_details(session, [_agent_or_404(session, agent_id)])[0]


def create_agent(session: Session, user: UserPrincipal, now: datetime, *, asset_id: UUID,
                 name: str, owner: str) -> AgentDetail:
    get_asset(session, asset_id)
    agent = Agent(id=uuid4(), tenant_id=user.tenant_id, asset_id=asset_id, name=name, owner=owner,
                  status="active")
    session.add(agent)
    session.flush()
    _audit(session, user, "agent.created", "agent", agent.id, now, name=name)
    return AgentDetail(agent, [], [], [])


def set_agent_status(session: Session, user: UserPrincipal, now: datetime, agent_id: UUID,
                     status: str) -> AgentDetail:
    agent = _agent_or_404(session, agent_id)
    previous = agent.status
    agent.status = status
    session.flush()
    _audit(session, user, "agent.status_changed", "agent", agent.id, now,
           previous=previous, status=status)
    return get_agent(session, agent_id)


def issue_credential(session: Session, user: UserPrincipal, now: datetime, agent_id: UUID,
                     expires_at: datetime | None) -> tuple[AgentCredential, str]:
    _agent_or_404(session, agent_id)
    secret = generate_secret()
    credential = AgentCredential(
        id=uuid4(),
        tenant_id=user.tenant_id,
        agent_id=agent_id,
        secret_hash=hash_secret(secret),
        expires_at=expires_at,
    )
    session.add(credential)
    session.flush()
    _audit(session, user, "credential.issued", "agent_credential", credential.id, now,
           agent_id=str(agent_id))
    return credential, format_key(user.tenant_id, credential.id, secret)


def revoke_credential(session: Session, user: UserPrincipal, now: datetime, agent_id: UUID,
                      credential_id: UUID) -> AgentCredential:
    credential = session.get(AgentCredential, credential_id)
    if credential is None or credential.agent_id != agent_id:
        raise NotFound()
    if credential.revoked_at is None:
        credential.revoked_at = now
        session.flush()
        _audit(session, user, "credential.revoked", "agent_credential", credential.id, now,
               agent_id=str(agent_id))
    return credential


def add_tool_grant(session: Session, user: UserPrincipal, now: datetime, agent_id: UUID, tool: str,
                   registry: ToolRegistry) -> None:
    _agent_or_404(session, agent_id)
    if registry.get(tool) is None:
        raise ValidationFailed("This tool is not in the catalog.")
    mark_grant_changed(session, user, now, agent_id)
    session.add(AgentToolGrant(tenant_id=user.tenant_id, agent_id=agent_id, tool=tool))
    session.flush()
    _audit(session, user, "grant.tool_added", "agent", agent_id, now, tool=tool)


def remove_tool_grant(session: Session, user: UserPrincipal, now: datetime, agent_id: UUID,
                      tool: str) -> None:
    grant = session.get(AgentToolGrant, (user.tenant_id, agent_id, tool))
    if grant is None:
        raise NotFound()
    session.delete(grant)
    session.flush()
    _audit(session, user, "grant.tool_removed", "agent", agent_id, now, tool=tool)


def add_resource_grant(session: Session, user: UserPrincipal, now: datetime, agent_id: UUID,
                       resource_id: UUID) -> None:
    _agent_or_404(session, agent_id)
    if session.get(Resource, resource_id) is None:
        raise NotFound()
    mark_grant_changed(session, user, now, agent_id)
    session.add(
        AgentResourceGrant(tenant_id=user.tenant_id, agent_id=agent_id, resource_id=resource_id)
    )
    session.flush()
    _audit(session, user, "grant.resource_added", "agent", agent_id, now,
           resource_id=str(resource_id))


def remove_resource_grant(session: Session, user: UserPrincipal, now: datetime, agent_id: UUID,
                          resource_id: UUID) -> None:
    grant = session.get(AgentResourceGrant, (user.tenant_id, agent_id, resource_id))
    if grant is None:
        raise NotFound()
    session.delete(grant)
    session.flush()
    _audit(session, user, "grant.resource_removed", "agent", agent_id, now,
           resource_id=str(resource_id))


# Resources


def list_resources(session: Session, *, limit: int, offset: int):
    return _paged(session, Resource, Resource.created_at.desc(), limit, offset)


def create_resource(session: Session, user: UserPrincipal, now: datetime,
                    **fields: Any) -> Resource:
    resource = Resource(id=uuid4(), tenant_id=user.tenant_id, **fields)
    session.add(resource)
    session.flush()
    _audit(session, user, "resource.created", "resource", resource.id, now,
           kind=resource.kind, classification=resource.classification)
    return resource


# Policies


@dataclass(frozen=True)
class PolicySummary:
    policy: Policy
    versions: list[PolicyVersion]
    active_version_id: UUID | None


def list_policies(session: Session, tenant_id: UUID, *, limit: int, offset: int):
    policies, total = _paged(session, Policy, Policy.created_at.desc(), limit, offset)
    versions: dict[UUID, list[PolicyVersion]] = {}
    for version in session.execute(
        select(PolicyVersion)
        .where(PolicyVersion.policy_id.in_([policy.id for policy in policies]))
        .order_by(PolicyVersion.version.desc())
    ).scalars():
        versions.setdefault(version.policy_id, []).append(version)
    active = session.get(Tenant, tenant_id).active_policy_version_id
    return [PolicySummary(p, versions.get(p.id, []), active) for p in policies], total


def version_document(version: PolicyVersion) -> dict[str, Any]:
    return json.loads(version.document_canonical)


def create_policy(session: Session, user: UserPrincipal, now: datetime, *, name: str) -> Policy:
    policy = Policy(id=uuid4(), tenant_id=user.tenant_id, name=name)
    session.add(policy)
    session.flush()
    _audit(session, user, "policy.created", "policy", policy.id, now, name=name)
    return policy


def create_policy_version(session: Session, user: UserPrincipal, now: datetime, policy_id: UUID,
                          document: PolicyDocument) -> PolicyVersion:
    if session.get(Policy, policy_id) is None:
        raise NotFound()
    latest = session.execute(
        select(func.max(PolicyVersion.version)).where(PolicyVersion.policy_id == policy_id)
    ).scalar_one()
    canonical = canonical_json(document.model_dump(mode="json", exclude_none=True))
    version = PolicyVersion(
        id=uuid4(),
        tenant_id=user.tenant_id,
        policy_id=policy_id,
        version=(latest or 0) + 1,
        document_canonical=canonical,
        content_hash=sha256_hex(canonical),
        created_by=user.id,
    )
    session.add(version)
    session.flush()
    _audit(session, user, "policy.version_created", "policy_version", version.id, now,
           policy_version_id=version.id, version=version.version,
           content_hash=version.content_hash)
    return version


def activate_policy_version(session: Session, user: UserPrincipal, now: datetime, policy_id: UUID,
                            version_id: UUID) -> PolicyVersion:
    version = session.get(PolicyVersion, version_id)
    if version is None or version.policy_id != policy_id:
        raise NotFound()
    tenant = session.get(Tenant, user.tenant_id)
    previous = tenant.active_policy_version_id
    tenant.active_policy_version_id = version.id
    session.flush()
    _audit(session, user, "policy.activated", "policy_version", version.id, now,
           policy_version_id=version.id,
           previous_version_id=None if previous is None else str(previous))
    return version
