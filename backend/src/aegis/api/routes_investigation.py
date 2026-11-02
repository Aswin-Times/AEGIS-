"""Timelines, findings, and evidence records. Evidence never includes tool results or parameters."""

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.api.dependencies import ContainerDep, LimitQuery, OffsetQuery, ReviewerDep, UserDep
from aegis.api.schemas import (
    EvidenceRecordOut,
    EvidenceRefOut,
    FindingOut,
    FindingsOut,
    InvestigationRunOut,
    Page,
    TimelineItemOut,
)
from aegis.db.models import (
    Approval,
    AuditEvent,
    Execution,
    FindingEvidence,
    Incident,
    InvestigationFinding,
    InvestigationRun,
    PolicyDecision,
    SecurityEvent,
)
from aegis.errors import NotFound
from aegis.investigation.evidence import collect_evidence, refs_of
from aegis.investigation.service import run_investigation
from aegis.investigation.timeline import build_timeline

router = APIRouter()

EvidenceType = Literal["security_event", "policy_decision", "approval", "execution", "audit_event"]
_VERIFIED_KINDS = {"observed_fact", "rule_result"}


def _incident_or_404(session: Session, incident_id: UUID) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise NotFound()
    return incident


@router.get("/incidents/{incident_id}/timeline", response_model=Page[TimelineItemOut])
def incident_timeline(
    incident_id: UUID,
    user: UserDep,
    container: ContainerDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 500,
    offset: OffsetQuery = 0,
):
    with container.db.tenant_transaction(user.tenant_id) as session:
        evidence = collect_evidence(session, _incident_or_404(session, incident_id))
        items = build_timeline(evidence)
    return Page[TimelineItemOut](
        items=[
            TimelineItemOut(
                occurred_at=item.occurred_at,
                kind=item.kind,
                summary=item.summary,
                severity=item.severity,
                verified=item.verified,
                evidence=EvidenceRefOut(type=item.evidence_type, id=item.evidence_id),
            )
            for item in items[offset : offset + limit]
        ],
        total=len(items),
        limit=limit,
        offset=offset,
    )


@router.post(
    "/incidents/{incident_id}/investigation-runs",
    response_model=InvestigationRunOut,
    status_code=201,
)
def investigation_start(incident_id: UUID, user: ReviewerDep, container: ContainerDep):
    return InvestigationRunOut.model_validate(
        run_investigation(container.db, user, incident_id, clock=container.clock)
    )


@router.get(
    "/incidents/{incident_id}/investigation-runs", response_model=Page[InvestigationRunOut]
)
def investigation_runs(
    incident_id: UUID,
    user: UserDep,
    container: ContainerDep,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    condition = InvestigationRun.incident_id == incident_id
    with container.db.tenant_transaction(user.tenant_id) as session:
        _incident_or_404(session, incident_id)
        rows = session.execute(
            select(InvestigationRun)
            .join(AuditEvent, AuditEvent.subject_id == InvestigationRun.id)
            .where(condition)
            .order_by(AuditEvent.seq.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        total = session.execute(
            select(func.count()).select_from(InvestigationRun).where(condition)
        ).scalar_one()
        return Page[InvestigationRunOut](
            items=[InvestigationRunOut.model_validate(row) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )


def _findings_of(session: Session, run: InvestigationRun) -> list[FindingOut]:
    findings = session.execute(
        select(InvestigationFinding)
        .where(InvestigationFinding.run_id == run.id)
        .order_by(InvestigationFinding.position)
    ).scalars().all()
    cited: dict[UUID, list[EvidenceRefOut]] = {}
    for row in session.execute(
        select(FindingEvidence).where(
            FindingEvidence.finding_id.in_([finding.id for finding in findings])
        )
    ).scalars():
        item = refs_of(row)
        cited.setdefault(row.finding_id, []).append(EvidenceRefOut(type=item.type, id=item.id))
    return [
        FindingOut(
            id=finding.id,
            kind=finding.kind,
            source=finding.source,
            statement=finding.statement,
            confidence=finding.confidence,
            position=finding.position,
            # Verified is a property of the kind and source together, never a stored flag.
            verified=finding.kind in _VERIFIED_KINDS and finding.source == "deterministic",
            evidence=sorted(cited.get(finding.id, []), key=lambda ref: (ref.type, ref.id)),
        )
        for finding in findings
    ]


@router.get("/incidents/{incident_id}/findings", response_model=FindingsOut)
def incident_findings(
    incident_id: UUID,
    user: UserDep,
    container: ContainerDep,
    run_id: Annotated[UUID | None, Query()] = None,
):
    with container.db.tenant_transaction(user.tenant_id) as session:
        _incident_or_404(session, incident_id)
        query = select(InvestigationRun).where(InvestigationRun.incident_id == incident_id)
        if run_id is not None:
            run = session.execute(
                query.where(InvestigationRun.id == run_id)
            ).scalar_one_or_none()
            if run is None:
                raise NotFound()
        else:
            # Timestamps can tie, so the audit chain sequence identifies the latest run.
            run = session.execute(
                query.join(AuditEvent, AuditEvent.subject_id == InvestigationRun.id)
                .order_by(AuditEvent.seq.desc())
                .limit(1)
            ).scalar_one_or_none()
        if run is None:
            return FindingsOut(run=None, findings=[])
        return FindingsOut(
            run=InvestigationRunOut.model_validate(run), findings=_findings_of(session, run)
        )


def _fields(row: Any, names: tuple[str, ...]) -> dict[str, Any]:
    return {name: getattr(row, name) for name in names}


# Allowlists: a column added to these tables stays out of evidence until it is listed here.
_EVIDENCE: dict[str, tuple[type, str, tuple[str, ...]]] = {
    "security_event": (
        SecurityEvent,
        "occurred_at",
        (
            "event_type", "severity", "reason_code", "actor_type", "actor_id", "agent_id", "tool",
            "action", "resource_id", "decision_id", "approval_id", "execution_id",
            "correlation_id", "attributes", "source_audit_event_id", "source_event_hash",
        ),
    ),
    "policy_decision": (
        PolicyDecision,
        "evaluated_at",
        (
            "request_id", "agent_id", "resource_id", "tool", "action", "policy_id",
            "policy_version_id", "policy_version", "outcome", "reason_code", "matched_rule_id",
        ),
    ),
    "approval": (
        Approval,
        "requested_at",
        (
            "request_id", "decision_id", "action_hash", "status", "expires_at", "decided_by",
            "decided_at",
        ),
    ),
    "execution": (Execution, "started_at", ("request_id", "status", "finished_at")),
    "audit_event": (
        AuditEvent,
        "occurred_at",
        (
            "seq", "event_type", "actor_type", "actor_id", "correlation_id", "subject_type",
            "subject_id", "policy_version_id", "prev_hash", "event_hash", "payload",
        ),
    ),
}


@router.get("/evidence/{evidence_type}/{evidence_id}", response_model=EvidenceRecordOut)
def evidence_get(
    evidence_type: EvidenceType, evidence_id: UUID, user: UserDep, container: ContainerDep
):
    model, time_column, names = _EVIDENCE[evidence_type]
    with container.db.tenant_transaction(user.tenant_id) as session:
        row = session.get(model, evidence_id)
        if row is None:
            raise NotFound()
        return EvidenceRecordOut(
            type=evidence_type,
            id=evidence_id,
            occurred_at=getattr(row, time_column),
            fields=_fields(row, names),
        )
