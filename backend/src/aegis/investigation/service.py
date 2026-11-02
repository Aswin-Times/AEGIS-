"""Run an investigation. It reads records and writes findings, and changes nothing else."""

from collections.abc import Callable
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from aegis.audit.chain import append_event, verify_chain
from aegis.db.models import Incident, InvestigationRun
from aegis.db.session import Database
from aegis.errors import NotFound
from aegis.investigation.evidence import add_finding, collect_evidence
from aegis.investigation.findings import ENGINE_VERSION, build_findings, input_fingerprint
from aegis.security.principals import UserPrincipal


def _incident_or_404(session: Session, incident_id: UUID) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise NotFound()
    return incident


def run_investigation(
    db: Database,
    user: UserPrincipal,
    incident_id: UUID,
    *,
    clock: Callable[[], datetime],
) -> InvestigationRun:
    # Verified in its own transaction: its read lock on the chain head would otherwise have to be
    # upgraded to append, which deadlocks against a concurrent run doing the same.
    with db.tenant_transaction(user.tenant_id) as session:
        _incident_or_404(session, incident_id)
        chain = verify_chain(session, user.tenant_id)

    with db.tenant_transaction(user.tenant_id) as session:
        incident = _incident_or_404(session, incident_id)
        evidence = collect_evidence(session, incident)
        fingerprint = input_fingerprint(evidence)
        now = clock()
        run = InvestigationRun(
            id=uuid4(),
            tenant_id=user.tenant_id,
            incident_id=incident.id,
            started_by=user.id,
            engine_version=ENGINE_VERSION,
            input_fingerprint=fingerprint,
            llm_status="not_configured",
            llm_rejected_count=0,
            created_at=now,
        )
        session.add(run)
        session.flush()
        allowed = evidence.allowed_refs
        for position, draft in enumerate(build_findings(evidence, chain)):
            add_finding(
                session,
                run,
                allowed,
                kind=draft.kind,
                source="deterministic",
                statement=draft.statement,
                refs=draft.refs,
                position=position,
            )
        append_event(
            session,
            user.tenant_id,
            event_type="investigation.completed",
            actor_type="user",
            actor_id=user.id,
            subject_type="investigation_run",
            subject_id=run.id,
            occurred_at=now,
            payload={"incident_id": str(incident.id), "input_fingerprint": fingerprint},
        )
    return run
