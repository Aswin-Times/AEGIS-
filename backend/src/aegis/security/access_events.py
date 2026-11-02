"""Record authenticated access failures. Best effort: this never changes the caller's response."""

import logging
from datetime import datetime
from uuid import UUID

from aegis.audit.chain import append_event
from aegis.db.session import Database
from aegis.events.limiter import FailureLimiter
from aegis.security.principals import AgentPrincipal, UserPrincipal

logger = logging.getLogger("aegis.security")


def record_access_failure(
    db: Database,
    limiter: FailureLimiter,
    principal: UserPrincipal | AgentPrincipal,
    *,
    event_type: str,
    requested_id: UUID | None,
    now: datetime,
) -> None:
    try:
        admitted, suppressed = limiter.admit((principal.tenant_id, event_type, principal.id))
        if not admitted:
            return
        with db.tenant_transaction(principal.tenant_id) as session:
            append_event(
                session,
                principal.tenant_id,
                event_type=event_type,
                actor_type="agent" if isinstance(principal, AgentPrincipal) else "user",
                actor_id=principal.id,
                subject_type="requested_id" if requested_id else None,
                subject_id=requested_id,
                occurred_at=now,
                payload={"suppressed_since_last": suppressed} if suppressed else {},
            )
    except Exception:
        logger.exception("could not record an access failure")
