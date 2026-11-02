from uuid import UUID

from fastapi import APIRouter, Response

from aegis.api.dependencies import AdminDep, ContainerDep, LimitQuery, OffsetQuery, UserDep
from aegis.api.schemas import (
    ActivateIn,
    AgentIn,
    AgentOut,
    AgentStatusIn,
    AssetIn,
    AssetOut,
    CredentialIn,
    CredentialOut,
    GrantOut,
    IssuedCredentialOut,
    Page,
    PolicyIn,
    PolicyOut,
    PolicyVersionIn,
    PolicyVersionOut,
    ResourceGrantIn,
    ResourceIn,
    ResourceOut,
    ToolGrantIn,
)
from aegis.registry.service import (
    AgentDetail,
    PolicySummary,
    activate_policy_version,
    add_resource_grant,
    add_tool_grant,
    create_agent,
    create_asset,
    create_policy,
    create_policy_version,
    create_resource,
    get_agent,
    get_asset,
    issue_credential,
    list_agents,
    list_assets,
    list_policies,
    list_resources,
    remove_resource_grant,
    remove_tool_grant,
    revoke_credential,
    set_agent_status,
    version_document,
)

router = APIRouter()


def _agent_out(detail: AgentDetail) -> AgentOut:
    agent = detail.agent
    return AgentOut(
        id=agent.id,
        asset_id=agent.asset_id,
        name=agent.name,
        owner=agent.owner,
        status=agent.status,
        created_at=agent.created_at,
        tool_grants=detail.tool_grants,
        resource_grants=detail.resource_grants,
        credentials=[CredentialOut.model_validate(item) for item in detail.credentials],
    )


def _version_out(version) -> PolicyVersionOut:
    return PolicyVersionOut(
        id=version.id,
        policy_id=version.policy_id,
        version=version.version,
        content_hash=version.content_hash,
        created_at=version.created_at,
        document=version_document(version),
    )


def _policy_out(summary: PolicySummary) -> PolicyOut:
    return PolicyOut(
        id=summary.policy.id,
        name=summary.policy.name,
        created_at=summary.policy.created_at,
        active_version_id=(
            summary.active_version_id
            if any(version.id == summary.active_version_id for version in summary.versions)
            else None
        ),
        versions=[_version_out(version) for version in summary.versions],
    )


# Assets


@router.get("/assets", response_model=Page[AssetOut])
def assets_list(user: UserDep, container: ContainerDep, limit: LimitQuery = 50,
                offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        items, total = list_assets(session, limit=limit, offset=offset)
        return Page[AssetOut](
            items=[AssetOut.model_validate(item) for item in items],
            total=total, limit=limit, offset=offset,
        )


@router.get("/assets/{asset_id}", response_model=AssetOut)
def assets_get(asset_id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return AssetOut.model_validate(get_asset(session, asset_id))


@router.post("/assets", response_model=AssetOut, status_code=201)
def assets_create(body: AssetIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return AssetOut.model_validate(
            create_asset(session, user, container.clock(), **body.model_dump())
        )


# Agents


@router.get("/agents", response_model=Page[AgentOut])
def agents_list(user: UserDep, container: ContainerDep, limit: LimitQuery = 50,
                offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        items, total = list_agents(session, limit=limit, offset=offset)
        return Page[AgentOut](
            items=[_agent_out(item) for item in items], total=total, limit=limit, offset=offset
        )


@router.get("/agents/{agent_id}", response_model=AgentOut)
def agents_get(agent_id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _agent_out(get_agent(session, agent_id))


@router.post("/agents", response_model=AgentOut, status_code=201)
def agents_create(body: AgentIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _agent_out(create_agent(session, user, container.clock(), **body.model_dump()))


@router.post("/agents/{agent_id}/status", response_model=AgentOut)
def agents_set_status(agent_id: UUID, body: AgentStatusIn, user: AdminDep,
                      container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _agent_out(
            set_agent_status(session, user, container.clock(), agent_id, body.status)
        )


@router.post(
    "/agents/{agent_id}/credentials", response_model=IssuedCredentialOut, status_code=201
)
def credentials_issue(agent_id: UUID, body: CredentialIn, user: AdminDep,
                      container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        credential, key = issue_credential(
            session, user, container.clock(), agent_id, body.expires_at
        )
        return IssuedCredentialOut(
            id=credential.id,
            created_at=credential.created_at,
            expires_at=credential.expires_at,
            revoked_at=credential.revoked_at,
            key=key,
        )


@router.post("/agents/{agent_id}/credentials/{cid}/revoke", response_model=CredentialOut)
def credentials_revoke(agent_id: UUID, cid: UUID, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return CredentialOut.model_validate(
            revoke_credential(session, user, container.clock(), agent_id, cid)
        )


@router.post("/agents/{agent_id}/tool-grants", response_model=GrantOut, status_code=201)
def tool_grants_add(agent_id: UUID, body: ToolGrantIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        add_tool_grant(session, user, container.clock(), agent_id, body.tool, container.tools)
    return GrantOut(agent_id=agent_id, tool=body.tool)


@router.delete("/agents/{agent_id}/tool-grants/{tool}", status_code=204)
def tool_grants_remove(agent_id: UUID, tool: str, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        remove_tool_grant(session, user, container.clock(), agent_id, tool)
    return Response(status_code=204)


@router.post("/agents/{agent_id}/resource-grants", response_model=GrantOut, status_code=201)
def resource_grants_add(agent_id: UUID, body: ResourceGrantIn, user: AdminDep,
                        container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        add_resource_grant(session, user, container.clock(), agent_id, body.resource_id)
    return GrantOut(agent_id=agent_id, resource_id=body.resource_id)


@router.delete("/agents/{agent_id}/resource-grants/{resource_id}", status_code=204)
def resource_grants_remove(agent_id: UUID, resource_id: UUID, user: AdminDep,
                           container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        remove_resource_grant(session, user, container.clock(), agent_id, resource_id)
    return Response(status_code=204)


# Resources


@router.get("/resources", response_model=Page[ResourceOut])
def resources_list(user: UserDep, container: ContainerDep, limit: LimitQuery = 50,
                   offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        items, total = list_resources(session, limit=limit, offset=offset)
        return Page[ResourceOut](
            items=[ResourceOut.model_validate(item) for item in items],
            total=total, limit=limit, offset=offset,
        )


@router.post("/resources", response_model=ResourceOut, status_code=201)
def resources_create(body: ResourceIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return ResourceOut.model_validate(
            create_resource(session, user, container.clock(), **body.model_dump())
        )


# Policies


@router.get("/policies", response_model=Page[PolicyOut])
def policies_list(user: UserDep, container: ContainerDep, limit: LimitQuery = 50,
                  offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        items, total = list_policies(session, user.tenant_id, limit=limit, offset=offset)
        return Page[PolicyOut](
            items=[_policy_out(item) for item in items], total=total, limit=limit, offset=offset
        )


@router.post("/policies", response_model=PolicyOut, status_code=201)
def policies_create(body: PolicyIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        policy = create_policy(session, user, container.clock(), name=body.name)
        return _policy_out(PolicySummary(policy, [], None))


@router.post("/policies/{policy_id}/versions", response_model=PolicyVersionOut, status_code=201)
def policy_versions_create(policy_id: UUID, body: PolicyVersionIn, user: AdminDep,
                           container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _version_out(
            create_policy_version(session, user, container.clock(), policy_id, body.document)
        )


@router.post("/policies/{policy_id}/activate", response_model=PolicyVersionOut)
def policies_activate(policy_id: UUID, body: ActivateIn, user: AdminDep,
                      container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _version_out(
            activate_policy_version(session, user, container.clock(), policy_id, body.version_id)
        )
