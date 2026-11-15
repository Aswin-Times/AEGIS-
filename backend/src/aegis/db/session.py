from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker


class Database:
    def __init__(self, url: str, *, pool_size: int = 10, max_overflow: int = 20) -> None:
        # hide_parameters keeps bound values out of exception text, so a logged database error
        # never carries request content such as evidence.
        self.engine = create_engine(
            url, pool_pre_ping=True, pool_size=pool_size, max_overflow=max_overflow,
            hide_parameters=True,
        )
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def tenant_transaction(self, tenant_id: UUID) -> Iterator[Session]:
        """One transaction scoped to one tenant. It commits on exit, and rolls back on error.

        The setting is transaction-local, so it cannot leak to the next user of a pooled
        connection. RLS returns nothing for code that runs without this context.
        """
        with self._sessions() as session, session.begin():
            session.execute(
                text("SELECT set_config('app.tenant_id', :tenant, true)"),
                {"tenant": str(tenant_id)},
            )
            yield session

    def resolve_tenant(self, slug: str) -> UUID | None:
        with self._sessions() as session, session.begin():
            return session.execute(select(func.aegis_resolve_tenant(slug))).scalar_one_or_none()

    def dispose(self) -> None:
        self.engine.dispose()
