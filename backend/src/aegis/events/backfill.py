"""Create security events for audit events that predate the projection. Safe to rerun."""

from uuid import UUID

from sqlalchemy import select

from aegis.db.models import AuditEvent, SecurityEvent
from aegis.db.session import Database
from aegis.events.projection import PROJECTED_AUDIT_TYPES, project_audit_event

_BATCH = 500


def backfill_tenant(db: Database, tenant_id: UUID) -> int:
    created = 0
    while True:
        with db.tenant_transaction(tenant_id) as session:
            missing = session.execute(
                select(AuditEvent)
                .outerjoin(
                    SecurityEvent, SecurityEvent.source_audit_event_id == AuditEvent.id
                )
                .where(
                    SecurityEvent.id.is_(None),
                    AuditEvent.event_type.in_(PROJECTED_AUDIT_TYPES),
                )
                .order_by(AuditEvent.seq)
                .limit(_BATCH)
            ).scalars().all()
            created_in_batch = sum(project_audit_event(session, audit) for audit in missing)
        created += created_in_batch
        # An ALLOW decision is projected to nothing, so a full batch can legitimately create none.
        if len(missing) < _BATCH:
            return created
