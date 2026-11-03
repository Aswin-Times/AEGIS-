from uuid import UUID

from fastapi import APIRouter

from aegis.api.dependencies import AdminDep, ContainerDep, LimitQuery, OffsetQuery, ReviewerDep
from aegis.api.schemas import Page
from aegis.api.schemas_governance import PersonOut, RoleGrantIn, RoleGrantOut
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
