"""Tenant provisioning. Runs as the owner role: the runtime role cannot create tenants."""

from uuid import UUID, uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from aegis.audit.chain import GENESIS_HASH, append_event
from aegis.db.models import AuditChainHead, Tenant, User
from aegis.security.passwords import hash_password


def _set_tenant(session: Session, tenant_id: UUID) -> None:
    session.execute(
        text("SELECT set_config('app.tenant_id', :tenant, true)"), {"tenant": str(tenant_id)}
    )


def provision_tenant(owner_url: str, *, slug: str, name: str) -> UUID:
    engine = create_engine(owner_url, hide_parameters=True)
    try:
        with Session(engine) as session, session.begin():
            tenant_id = uuid4()
            _set_tenant(session, tenant_id)
            session.add(Tenant(id=tenant_id, slug=slug, name=name))
            session.flush()
            session.add(AuditChainHead(tenant_id=tenant_id, seq=0, head_hash=GENESIS_HASH))
            session.flush()
            append_event(
                session,
                tenant_id,
                event_type="tenant.provisioned",
                actor_type="system",
                subject_type="tenant",
                subject_id=tenant_id,
                payload={"slug": slug},
            )
            return tenant_id
    finally:
        engine.dispose()


def create_user(owner_url: str, tenant_id: UUID, *, email: str, password: str, role: str) -> UUID:
    engine = create_engine(owner_url, hide_parameters=True)
    try:
        with Session(engine) as session, session.begin():
            _set_tenant(session, tenant_id)
            user_id = uuid4()
            session.add(
                User(
                    id=user_id,
                    tenant_id=tenant_id,
                    email=email.lower(),
                    password_hash=hash_password(password),
                    role=role,
                    is_active=True,
                )
            )
            session.flush()
            append_event(
                session,
                tenant_id,
                event_type="user.created",
                actor_type="system",
                subject_type="user",
                subject_id=user_id,
                payload={"role": role},
            )
            return user_id
    finally:
        engine.dispose()
