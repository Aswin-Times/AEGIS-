"""Gather an incident's stored records, verify them, and control what findings may cite."""

from collections.abc import Iterable
from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.correlation.rules import CorrelationRule
from aegis.correlation.store import RuleIntegrityError, parse_version
from aegis.db.models import (
    Approval,
    AuditEvent,
    CorrelationRuleVersion,
    Execution,
    FindingEvidence,
    Incident,
    IncidentEvent,
    InvestigationFinding,
    InvestigationRun,
    PolicyDecision,
    SecurityEvent,
)
from aegis.events.projection import reprojection_matches

REQUIRES_EVIDENCE = {"observed_fact", "rule_result", "ai_hypothesis"}
_COLUMN_BY_TYPE = {
    "security_event": "security_event_id",
    "policy_decision": "decision_id",
    "approval": "approval_id",
    "execution": "execution_id",
    "audit_event": "audit_event_id",
}
EVIDENCE_TYPES = tuple(_COLUMN_BY_TYPE)


class EvidenceError(Exception):
    """A finding cited something it may not, or claimed to be something it is not."""


@dataclass(frozen=True)
class EvidenceRef:
    type: str
    id: str


def ref(kind: str, identifier: UUID | str) -> EvidenceRef:
    return EvidenceRef(kind, str(identifier))


@dataclass(frozen=True)
class CollectedEvidence:
    incident: Incident
    rule: CorrelationRule | None
    verified_events: list[SecurityEvent]
    failed_events: list[SecurityEvent]
    decisions: list[PolicyDecision]
    approvals: list[Approval]
    executions: list[Execution]
    audit_events: list[AuditEvent]

    @property
    def allowed_refs(self) -> frozenset[EvidenceRef]:
        groups = (
            ("security_event", self.verified_events),
            ("security_event", self.failed_events),
            ("policy_decision", self.decisions),
            ("approval", self.approvals),
            ("execution", self.executions),
            ("audit_event", self.audit_events),
        )
        return frozenset(ref(kind, row.id) for kind, rows in groups for row in rows)


def _rule_of(session: Session, incident: Incident) -> CorrelationRule | None:
    version = session.get(CorrelationRuleVersion, incident.rule_version_id)
    try:
        return parse_version(version)
    except RuleIntegrityError:
        return None


def collect_evidence(session: Session, incident: Incident) -> CollectedEvidence:
    events = session.execute(
        select(SecurityEvent)
        .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.id)
        .where(IncidentEvent.incident_id == incident.id)
        .order_by(SecurityEvent.occurred_at, SecurityEvent.recorded_at, SecurityEvent.id)
    ).scalars().all()
    verified, failed = [], []
    for event in events:
        (verified if reprojection_matches(session, event) else failed).append(event)

    request_ids = {event.action_request_id for event in events if event.action_request_id}
    decisions = session.execute(
        select(PolicyDecision)
        .where(PolicyDecision.request_id.in_(request_ids))
        .order_by(PolicyDecision.evaluated_at, PolicyDecision.id)
    ).scalars().all()
    approvals = session.execute(
        select(Approval)
        .where(Approval.request_id.in_(request_ids))
        .order_by(Approval.requested_at, Approval.id)
    ).scalars().all()
    executions = session.execute(
        select(Execution)
        .where(Execution.request_id.in_(request_ids))
        .order_by(Execution.started_at, Execution.id)
    ).scalars().all()
    audit_events = session.execute(
        select(AuditEvent)
        .where(
            AuditEvent.id.in_([event.source_audit_event_id for event in events])
            | ((AuditEvent.subject_type == "incident") & (AuditEvent.subject_id == incident.id))
        )
        .order_by(AuditEvent.seq)
    ).scalars().all()
    return CollectedEvidence(
        incident=incident,
        rule=_rule_of(session, incident),
        verified_events=verified,
        failed_events=failed,
        decisions=decisions,
        approvals=approvals,
        executions=executions,
        audit_events=audit_events,
    )


def add_finding(
    session: Session,
    run: InvestigationRun,
    allowed_refs: frozenset[EvidenceRef],
    *,
    kind: str,
    source: str,
    statement: str,
    refs: Iterable[EvidenceRef],
    position: int,
    confidence: str | None = None,
) -> InvestigationFinding:
    """The single way findings are written. The database enforces the same rules again."""
    if (source == "llm") != (kind == "ai_hypothesis"):
        raise EvidenceError(f"A {source} source cannot produce a {kind} finding")
    unique_refs = sorted(set(refs), key=lambda item: (item.type, item.id))
    if kind in REQUIRES_EVIDENCE and not unique_refs:
        raise EvidenceError(f"A {kind} finding requires evidence")
    for item in unique_refs:
        if item.type not in _COLUMN_BY_TYPE or item not in allowed_refs:
            raise EvidenceError("A finding cited a record outside this incident's evidence")

    finding = InvestigationFinding(
        id=uuid4(),
        tenant_id=run.tenant_id,
        run_id=run.id,
        kind=kind,
        source=source,
        statement=statement,
        confidence=confidence,
        position=position,
    )
    session.add(finding)
    session.flush()
    for item in unique_refs:
        session.add(
            FindingEvidence(
                id=uuid4(),
                tenant_id=run.tenant_id,
                finding_id=finding.id,
                **{_COLUMN_BY_TYPE[item.type]: UUID(item.id)},
            )
        )
    session.flush()
    return finding


def refs_of(row: FindingEvidence) -> EvidenceRef:
    for kind, column in _COLUMN_BY_TYPE.items():
        value = getattr(row, column)
        if value is not None:
            return ref(kind, value)
    raise EvidenceError("An evidence row references nothing")
