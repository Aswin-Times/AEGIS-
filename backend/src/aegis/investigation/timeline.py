"""An incident's timeline, rebuilt from stored records each time it is requested."""

from dataclasses import dataclass
from datetime import datetime

from aegis.investigation.evidence import CollectedEvidence

# Records can share a timestamp. This keeps cause before effect within the same instant.
_RANK = {"policy_decision": 0, "security_event": 1, "approval": 2, "execution": 3, "audit_event": 4}


@dataclass(frozen=True)
class TimelineItem:
    occurred_at: datetime
    kind: str
    summary: str
    severity: str | None
    verified: bool | None
    evidence_type: str
    evidence_id: str


def build_timeline(evidence: CollectedEvidence) -> list[TimelineItem]:
    items: list[TimelineItem] = []

    def add(moment, kind, summary, evidence_type, identifier, severity=None, verified=None):
        items.append(
            TimelineItem(moment, kind, summary, severity, verified, evidence_type, str(identifier))
        )

    for verified, events in ((True, evidence.verified_events), (False, evidence.failed_events)):
        for event in events:
            subject = f" ({event.tool})" if event.tool else ""
            add(
                event.occurred_at,
                event.event_type,
                f"{event.reason_code}{subject}",
                "security_event",
                event.id,
                event.severity,
                verified,
            )
    for decision in evidence.decisions:
        add(
            decision.evaluated_at,
            "policy.decision",
            f"{decision.outcome}: {decision.reason_code} ({decision.tool})",
            "policy_decision",
            decision.id,
        )
    for approval in evidence.approvals:
        add(approval.requested_at, "approval.requested", "Approval requested", "approval",
            approval.id)
        if approval.decided_at:
            add(approval.decided_at, "approval.decided", f"Approval {approval.status}", "approval",
                approval.id)
    for execution in evidence.executions:
        add(execution.started_at, "execution.started", "Execution started", "execution",
            execution.id)
        if execution.finished_at:
            add(execution.finished_at, "execution.finished", f"Execution {execution.status}",
                "execution", execution.id)
    for audit in evidence.audit_events:
        if audit.subject_type == "incident":
            add(audit.occurred_at, audit.event_type, audit.event_type, "audit_event", audit.id)

    return sorted(
        items,
        key=lambda item: (item.occurred_at, _RANK[item.evidence_type], item.kind, item.evidence_id),
    )
