import json
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query

from aegis.api.dependencies import (
    AdminDep,
    ContainerDep,
    LimitQuery,
    OffsetQuery,
    ReviewerDep,
    UserDep,
)
from aegis.api.schemas import Page
from aegis.api.schemas_governance import (
    AssetDetailOut,
    InventoryRowOut,
    OverviewOut,
    PersonOut,
    ProfileVersionOut,
    RoleGrantIn,
    RoleGrantOut,
)
from aegis.governance.assets import load_state, save_profile
from aegis.governance.engine.lifecycle import GovernanceStatus
from aegis.governance.inventory import asset_detail, list_inventory, overview
from aegis.governance.profile import AssetProfile
from aegis.governance.roles import grant_role, list_people, revoke_grant

router = APIRouter(prefix="/governance")


# People and role grants


@router.get("/people", response_model=Page[PersonOut])
def people_list(user: ReviewerDep, container: ContainerDep, limit: LimitQuery = 50,
                offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        rows, total = list_people(session, limit=limit, offset=offset)
        return Page[PersonOut](
            items=[
                PersonOut(id=person.id, email=person.email, role=person.role,
                          reviewer_grant_id=grant_id)
                for person, grant_id in rows
            ],
            total=total, limit=limit, offset=offset,
        )


@router.post("/role-grants", response_model=RoleGrantOut, status_code=201)
def role_grants_create(body: RoleGrantIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return RoleGrantOut.model_validate(
            grant_role(session, user, container.clock(), user_id=body.user_id)
        )


@router.post("/role-grants/{id}/revoke", response_model=RoleGrantOut)
def role_grants_revoke(id: UUID, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return RoleGrantOut.model_validate(revoke_grant(session, user, container.clock(), id))


# Assets


@router.get("/overview", response_model=OverviewOut)
def governance_overview(user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return OverviewOut.model_validate(overview(session, container.clock()))


@router.get("/assets", response_model=Page[InventoryRowOut])
def assets_list(
    user: UserDep,
    container: ContainerDep,
    search: Annotated[str | None, Query(max_length=200)] = None,
    risk: Literal["low", "medium", "high", "critical"] | None = None,
    status: GovernanceStatus | None = None,
    owner_id: UUID | None = None,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    with container.db.tenant_transaction(user.tenant_id) as session:
        rows, total = list_inventory(
            session, search=search, risk=risk, status=status.value if status else None,
            owner_id=owner_id, limit=limit, offset=offset,
        )
        return Page[InventoryRowOut](
            items=[InventoryRowOut.model_validate(row) for row in rows],
            total=total, limit=limit, offset=offset,
        )


@router.get("/assets/{id}", response_model=AssetDetailOut)
def asset_get(id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return AssetDetailOut.model_validate(asset_detail(session, id))


@router.post("/assets/{id}/profile", response_model=ProfileVersionOut, status_code=201)
def asset_profile_save(id: UUID, body: AssetProfile, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        version = save_profile(session, user, container.clock(), id, body)
        return ProfileVersionOut(
            id=version.id,
            asset_id=version.asset_id,
            version=version.version,
            profile=json.loads(version.profile_canonical),
            content_hash=version.content_hash,
            created_by=version.created_by,
            created_at=version.created_at,
            governance_status=load_state(session, id).status,
        )
