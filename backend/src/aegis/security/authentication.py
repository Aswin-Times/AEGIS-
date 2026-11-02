"""Turning presented credentials into principals. Every failure looks the same to the caller."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.canonical import sha256_hex
from aegis.db.models import AgentCredential, AuditChainHead, User
from aegis.db.session import Database
from aegis.errors import Unauthenticated
from aegis.events.limiter import FailureLimiter
from aegis.security.agent_keys import parse_key, secret_matches
from aegis.security.passwords import verify_password
from aegis.security.principals import AgentPrincipal, UserPrincipal
from aegis.security.tokens import TokenService


def _record_failure(
    session: Session,
    limiter: FailureLimiter,
    tenant_id: UUID,
    event_type: str,
    now: datetime,
    **fields,
) -> None:
    # The tenant may be attacker input, so an unknown one must not create limiter state.
    if session.get(AuditChainHead, tenant_id) is None:
        return
    admitted, suppressed = limiter.admit((tenant_id, event_type))
    if not admitted:
        return
    payload = fields.pop("payload", {})
    if suppressed:
        payload = {**payload, "suppressed_since_last": suppressed}
    append_event(
        session,
        tenant_id,
        event_type=event_type,
        actor_type="anonymous",
        occurred_at=now,
        payload=payload,
        **fields,
    )


def authenticate_agent(
    db: Database, presented: str, now: datetime, limiter: FailureLimiter
) -> AgentPrincipal:
    parsed = parse_key(presented)
    if parsed is None:
        raise Unauthenticated()

    # The tenant segment is unverified here. It only selects which RLS scope to search, and
    # an altered value finds no matching credential.
    principal = None
    with db.tenant_transaction(parsed.tenant_id) as session:
        credential = session.get(AgentCredential, parsed.credential_id)
        matched = secret_matches(parsed.secret, credential.secret_hash if credential else None)
        if (
            credential is not None
            and matched
            and credential.revoked_at is None
            and (credential.expires_at is None or credential.expires_at > now)
        ):
            principal = AgentPrincipal(
                id=credential.agent_id,
                tenant_id=credential.tenant_id,
                credential_id=credential.id,
            )
        else:
            _record_failure(
                session,
                limiter,
                parsed.tenant_id,
                "auth.agent_failed",
                now,
                subject_type="agent_credential",
                subject_id=parsed.credential_id,
            )
    if principal is None:
        raise Unauthenticated()
    return principal


def authenticate_user(
    db: Database, tokens: TokenService, presented: str, now: datetime, limiter: FailureLimiter
) -> UserPrincipal:
    claims = tokens.verify(presented)
    principal = None
    with db.tenant_transaction(claims.tenant_id) as session:
        user = session.get(User, claims.user_id)
        if user is None:
            # The signature is valid, so this token was issued by AEGIS for some other tenant's
            # user, or the signing key is compromised. Either way it is worth recording.
            _record_failure(session, limiter, claims.tenant_id, "auth.token_rejected", now)
        elif user.is_active:
            principal = UserPrincipal(
                id=user.id, tenant_id=user.tenant_id, email=user.email, role=user.role
            )
    if principal is None:
        raise Unauthenticated()
    return principal


def login(
    db: Database,
    tokens: TokenService,
    *,
    tenant_slug: str,
    email: str,
    password: str,
    now: datetime,
    limiter: FailureLimiter,
) -> str:
    email = email.lower()
    tenant_id = db.resolve_tenant(tenant_slug)
    if tenant_id is None:
        verify_password(None, password)
        raise Unauthenticated()

    token = None
    with db.tenant_transaction(tenant_id) as session:
        user = session.execute(
            select(User).where(User.email == email)
        ).scalar_one_or_none()
        valid = verify_password(user.password_hash if user else None, password)
        if user is not None and valid and user.is_active:
            token = tokens.issue(user_id=user.id, tenant_id=tenant_id, now=now)
            append_event(
                session,
                tenant_id,
                event_type="auth.login_succeeded",
                actor_type="user",
                actor_id=user.id,
                subject_type="user",
                subject_id=user.id,
                occurred_at=now,
            )
        else:
            _record_failure(
                session,
                limiter,
                tenant_id,
                "auth.login_failed",
                now,
                payload={"email_sha256_prefix": sha256_hex(email)[:16]},
            )
    if token is None:
        raise Unauthenticated()
    return token
