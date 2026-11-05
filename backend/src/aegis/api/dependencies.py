from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Query, Request

from aegis.config import Settings
from aegis.db.session import Database
from aegis.errors import Forbidden, Unauthenticated
from aegis.events.limiter import FailureLimiter
from aegis.gateway.tools import ToolRegistry
from aegis.governance.roles import holds_reviewer
from aegis.llm.adapter import LlmProvider
from aegis.security import authentication
from aegis.security.principals import ADMIN, REVIEWER, AgentPrincipal, UserPrincipal
from aegis.security.tokens import TokenService


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class Container:
    settings: Settings
    db: Database
    tokens: TokenService
    tools: ToolRegistry
    failure_limiter: FailureLimiter
    clock: Callable[[], datetime] = utc_now
    llm: LlmProvider | None = None


def get_container(request: Request) -> Container:
    return request.app.state.container


ContainerDep = Annotated[Container, Depends(get_container)]


def _bearer_token(request: Request) -> str:
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise Unauthenticated()
    return token.strip()


def current_user(request: Request, container: ContainerDep) -> UserPrincipal:
    user = authentication.authenticate_user(
        container.db,
        container.tokens,
        _bearer_token(request),
        container.clock(),
        container.failure_limiter,
    )
    request.state.principal = user
    return user


def current_agent(request: Request, container: ContainerDep) -> AgentPrincipal:
    agent = authentication.authenticate_agent(
        container.db, _bearer_token(request), container.clock(), container.failure_limiter
    )
    request.state.principal = agent
    return agent


UserDep = Annotated[UserPrincipal, Depends(current_user)]
AgentDep = Annotated[AgentPrincipal, Depends(current_agent)]


def _require_roles(*roles: str):
    def check(user: UserDep) -> UserPrincipal:
        if user.role not in roles:
            raise Forbidden()
        return user

    return check


AdminDep = Annotated[UserPrincipal, Depends(_require_roles(ADMIN))]
ReviewerDep = Annotated[UserPrincipal, Depends(_require_roles(ADMIN, REVIEWER))]

def _holds_governance_reviewer(user: UserPrincipal, container: Container) -> bool:
    with container.db.tenant_transaction(user.tenant_id) as session:
        return holds_reviewer(session, user.id)


def require_governance_reviewer(user: UserDep, container: ContainerDep) -> UserPrincipal:
    """The governance_reviewer grant, not the user role, decides who may make governance calls."""
    if not _holds_governance_reviewer(user, container):
        raise Forbidden()
    return user


def require_suspender(user: UserDep, container: ContainerDep) -> UserPrincipal:
    if user.role != ADMIN and not _holds_governance_reviewer(user, container):
        raise Forbidden()
    return user


GovernanceReviewerDep = Annotated[UserPrincipal, Depends(require_governance_reviewer)]
SuspenderDep = Annotated[UserPrincipal, Depends(require_suspender)]

LimitQuery = Annotated[int, Query(ge=1, le=100)]
OffsetQuery = Annotated[int, Query(ge=0)]
