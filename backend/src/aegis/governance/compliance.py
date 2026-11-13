"""Framework libraries and the status of their controls (spec 10).

A control's status is a human assessment, append-only, and the latest by audit sequence is
current. A status that claims implementation holds only while evidence linked to the control is
VERIFIED: it is refused without such evidence, and reads as EVIDENCE_REQUIRED once that evidence
stops verifying, with the stored assessment left as it was. No view claims certification.
"""

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import and_, case, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.canonical import canonical_json, sha256_hex
from aegis.db.models import (
    AuditEvent,
    GovernanceControl,
    GovernanceControlAssessment,
    GovernanceControlAssessmentEvidence,
    GovernanceEvidenceControl,
    GovernanceFramework,
)
from aegis.errors import Conflict, Forbidden, NotFound, ValidationFailed
from aegis.governance.evidence import verified_control_links
from aegis.governance.frameworks import NOT_LOADED, FrameworkDefinition
from aegis.governance.frameworks.iso_iec_42001_2023 import ISO
from aegis.governance.frameworks.nist_ai_rmf_1_0 import NIST
from aegis.governance.roles import holds_reviewer
from aegis.security.principals import UserPrincipal

FRAMEWORKS: list[FrameworkDefinition] = [NIST, ISO]

NO_CERTIFICATION_STATEMENT = (
    "A mapping to a framework does not establish certification or compliance. Control statuses "
    "are assessments recorded by people in this organization, not the finding of an auditor or "
    "certification body."
)

NOT_ASSESSED = "NOT_ASSESSED"
EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
IMPLEMENTED = "IMPLEMENTED"
PARTIALLY_IMPLEMENTED = "PARTIALLY_IMPLEMENTED"
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
NOT_APPLICABLE = "NOT_APPLICABLE"

ASSESSED_STATUSES = (IMPLEMENTED, PARTIALLY_IMPLEMENTED, NOT_IMPLEMENTED, NOT_APPLICABLE)
# The statuses that claim something is in place, and so need verified evidence.
CLAIMS = (IMPLEMENTED, PARTIALLY_IMPLEMENTED)
CURRENT_STATUSES = (NOT_ASSESSED, EVIDENCE_REQUIRED, *ASSESSED_STATUSES)


# Seeding


def _library_hash(definition: FrameworkDefinition) -> str:
    return sha256_hex(canonical_json({
        "key": definition.key,
        "version": definition.version,
        "library_status": definition.library_status,
        "controls": [
            [item.identifier, item.name, item.description, item.source_reference,
             list(item.required_evidence)]
            for item in definition.controls
        ],
    }))


def _is_seeded(session: Session) -> bool:
    frameworks = session.execute(select(func.count(GovernanceFramework.id))).scalar_one()
    controls = session.execute(select(func.count(GovernanceControl.id))).scalar_one()
    return (frameworks >= len(FRAMEWORKS)
            and controls >= sum(len(item.controls) for item in FRAMEWORKS))


def ensure_frameworks(session: Session, tenant_id: UUID, now: datetime) -> None:
    """Seed the tenant's copy of each library once. Safe when first reads race.

    Call it before anything else in the transaction writes an audit event: the order is the
    advisory lock, then the rows, then the chain head.
    """
    if _is_seeded(session):
        return
    session.execute(select(func.pg_advisory_xact_lock(
        func.hashtextextended(f"governance-frameworks:{tenant_id}", 0))))
    for definition in FRAMEWORKS:
        source_count = (None if definition.source_identifiers is None
                        else len(definition.source_identifiers))
        inserted = session.execute(
            insert(GovernanceFramework)
            .values(id=uuid4(), tenant_id=tenant_id, key=definition.key,
                    version=definition.version, name=definition.name,
                    source_url=definition.source_url, source_document=definition.source_document,
                    library_status=definition.library_status,
                    source_control_count=source_count, created_at=now)
            .on_conflict_do_nothing()
            .returning(GovernanceFramework.id)
        ).first()
        if inserted is None:
            continue
        framework_id = inserted[0]
        if definition.controls:
            session.execute(
                insert(GovernanceControl).values([
                    dict(id=uuid4(), tenant_id=tenant_id, framework_id=framework_id,
                         position=position, control_identifier=item.identifier, name=item.name,
                         description=item.description, source_reference=item.source_reference,
                         required_evidence=list(item.required_evidence), created_at=now)
                    for position, item in enumerate(definition.controls, start=1)
                ])
            )
        append_event(
            session,
            tenant_id,
            event_type="governance.framework_seeded",
            actor_type="system",
            subject_type="governance_framework",
            subject_id=framework_id,
            occurred_at=now,
            payload={
                "framework_id": str(framework_id),
                "key": definition.key,
                "version": definition.version,
                "library_status": definition.library_status,
                "control_count": len(definition.controls),
                "source_control_count": source_count,
                "library_hash": _library_hash(definition),
            },
        )


# Current status


def _latest_assessments():
    """Each control's latest assessment, by audit sequence."""
    ranked = (
        select(
            GovernanceControlAssessment.id.label("assessment_id"),
            GovernanceControlAssessment.control_id.label("control_id"),
            GovernanceControlAssessment.status.label("status"),
            func.row_number().over(
                partition_by=GovernanceControlAssessment.control_id,
                order_by=AuditEvent.seq.desc(),
            ).label("rank"),
        )
        .join(AuditEvent, AuditEvent.id == GovernanceControlAssessment.audit_event_id)
        .subquery()
    )
    return select(ranked).where(ranked.c.rank == 1).subquery()


def _support():
    """Per control, how many linked items are currently VERIFIED."""
    links = verified_control_links().subquery()
    return (
        select(links.c.control_id,
               func.count(func.distinct(links.c.evidence_id)).label("verified"))
        .group_by(links.c.control_id)
        .subquery()
    )


def _linked():
    return (
        select(GovernanceEvidenceControl.control_id,
               func.count(GovernanceEvidenceControl.evidence_id).label("linked"))
        .group_by(GovernanceEvidenceControl.control_id)
        .subquery()
    )


def _status_columns():
    latest, support, linked = _latest_assessments(), _support(), _linked()
    current = case(
        (latest.c.status.is_(None), NOT_ASSESSED),
        (and_(latest.c.status.in_(CLAIMS), support.c.control_id.is_(None)), EVIDENCE_REQUIRED),
        else_=latest.c.status,
    )
    return latest, support, linked, current


def has_verified_evidence(session: Session, control_id: UUID) -> bool:
    links = verified_control_links().subquery()
    return session.execute(
        select(links.c.evidence_id).where(links.c.control_id == control_id).limit(1)
    ).first() is not None


@dataclass(frozen=True)
class ControlRecord:
    control: GovernanceControl
    framework_key: str
    current_status: str
    latest: GovernanceControlAssessment | None
    latest_evidence_ids: list[UUID]
    verified_evidence_count: int
    linked_evidence_count: int


def _cited_evidence(session: Session, assessment_ids: Iterable[UUID]) -> dict[UUID, list[UUID]]:
    cited: dict[UUID, list[UUID]] = {}
    rows = session.execute(
        select(GovernanceControlAssessmentEvidence.assessment_id,
               GovernanceControlAssessmentEvidence.evidence_id)
        .where(GovernanceControlAssessmentEvidence.assessment_id.in_(list(assessment_ids)))
        .order_by(GovernanceControlAssessmentEvidence.evidence_id)
    ).all()
    for assessment_id, evidence_id in rows:
        cited.setdefault(assessment_id, []).append(evidence_id)
    return cited


def list_controls(session: Session, *, framework_id: UUID | None, status: str | None,
                  limit: int, offset: int) -> tuple[list[ControlRecord], int]:
    latest, support, linked, current = _status_columns()
    conditions = []
    if framework_id is not None:
        conditions.append(GovernanceControl.framework_id == framework_id)
    if status is not None:
        conditions.append(current == status)
    base = (
        select(GovernanceControl.id)
        .outerjoin(latest, latest.c.control_id == GovernanceControl.id)
        .outerjoin(support, support.c.control_id == GovernanceControl.id)
        .where(*conditions)
    )
    total = session.execute(select(func.count()).select_from(base.subquery())).scalar_one()
    rows = session.execute(
        select(GovernanceControl, GovernanceFramework.key, current, GovernanceControlAssessment,
               func.coalesce(support.c.verified, 0), func.coalesce(linked.c.linked, 0))
        .join(GovernanceFramework, GovernanceFramework.id == GovernanceControl.framework_id)
        .outerjoin(latest, latest.c.control_id == GovernanceControl.id)
        .outerjoin(GovernanceControlAssessment,
                   GovernanceControlAssessment.id == latest.c.assessment_id)
        .outerjoin(support, support.c.control_id == GovernanceControl.id)
        .outerjoin(linked, linked.c.control_id == GovernanceControl.id)
        .where(*conditions)
        .order_by(GovernanceFramework.key, GovernanceFramework.version,
                  GovernanceControl.position, GovernanceControl.id)
        .limit(limit)
        .offset(offset)
    ).all()
    cited = _cited_evidence(session, [row[3].id for row in rows if row[3] is not None])
    records = [
        ControlRecord(control, key, status_, assessment,
                      cited.get(assessment.id, []) if assessment is not None else [],
                      verified, linked_count)
        for control, key, status_, assessment, verified, linked_count in rows
    ]
    return records, total


def get_control(session: Session, control_id: UUID) -> ControlRecord:
    latest, support, linked, current = _status_columns()
    row = session.execute(
        select(GovernanceControl, GovernanceFramework.key, current, GovernanceControlAssessment,
               func.coalesce(support.c.verified, 0), func.coalesce(linked.c.linked, 0))
        .join(GovernanceFramework, GovernanceFramework.id == GovernanceControl.framework_id)
        .outerjoin(latest, latest.c.control_id == GovernanceControl.id)
        .outerjoin(GovernanceControlAssessment,
                   GovernanceControlAssessment.id == latest.c.assessment_id)
        .outerjoin(support, support.c.control_id == GovernanceControl.id)
        .outerjoin(linked, linked.c.control_id == GovernanceControl.id)
        .where(GovernanceControl.id == control_id)
    ).first()
    if row is None:
        raise NotFound()
    control, key, status, assessment, verified, linked_count = row
    cited = [] if assessment is None else _cited_evidence(session, [assessment.id]).get(
        assessment.id, [])
    return ControlRecord(control, key, status, assessment, cited, verified, linked_count)


@dataclass(frozen=True)
class FrameworkSummary:
    framework: GovernanceFramework
    control_count: int
    status_counts: dict[str, int]

    @property
    def coverage(self) -> str:
        framework = self.framework
        if framework.library_status == NOT_LOADED:
            return ("The library is not loaded: no controls are available, because its "
                    "identifiers have not been verified against an authoritative source.")
        return (f"{self.control_count} of {framework.source_control_count} {framework.name} "
                f"{framework.version} subcategories are in the library.")


def list_frameworks(session: Session) -> list[FrameworkSummary]:
    """Each library with its control count and status counts, all read from stored rows."""
    latest, support, _linked_counts, current = _status_columns()
    grouped = session.execute(
        select(GovernanceControl.framework_id, current, func.count(GovernanceControl.id))
        .outerjoin(latest, latest.c.control_id == GovernanceControl.id)
        .outerjoin(support, support.c.control_id == GovernanceControl.id)
        .group_by(GovernanceControl.framework_id, current)
    ).all()
    counts: dict[UUID, Counter] = {}
    for framework_id, status, count in grouped:
        counts.setdefault(framework_id, Counter())[status] += count
    frameworks = session.execute(
        select(GovernanceFramework).order_by(GovernanceFramework.key, GovernanceFramework.version)
    ).scalars().all()
    summaries = []
    for framework in frameworks:
        found = counts.get(framework.id, Counter())
        summaries.append(FrameworkSummary(
            framework, sum(found.values()),
            {status: found.get(status, 0) for status in CURRENT_STATUSES},
        ))
    return summaries


# Assessment


def _require_linked_evidence(session: Session, control_id: UUID,
                             evidence_ids: Iterable[UUID]) -> list[UUID]:
    """Each id must be this tenant's evidence, linked to this control. Repeats are collapsed, and
    the ids are sorted, as they are when read back."""
    unique = sorted(set(evidence_ids))
    if not unique:
        return []
    found = set(session.execute(
        select(GovernanceEvidenceControl.evidence_id).where(
            GovernanceEvidenceControl.control_id == control_id,
            GovernanceEvidenceControl.evidence_id.in_(unique),
        )
    ).scalars().all())
    if len(found) != len(unique):
        raise ValidationFailed("Each evidence item must be linked to this control.")
    return unique


def assess_control(session: Session, user: UserPrincipal, now: datetime, control_id: UUID, *,
                   status: str, note: str,
                   evidence_ids: Iterable[UUID] = ()) -> GovernanceControlAssessment:
    """Record a control's status. A claim of implementation needs verified, linked evidence."""
    if status not in ASSESSED_STATUSES:
        raise ValidationFailed("The status must be one a reviewer can record.")
    if not note.strip() or len(note) > 2000:
        raise ValidationFailed("The note must be 1 to 2000 characters.")
    control = session.get(GovernanceControl, control_id)
    if control is None:
        raise NotFound()
    if not holds_reviewer(session, user.id):
        raise Forbidden()
    cited = _require_linked_evidence(session, control.id, evidence_ids)
    if status in CLAIMS and not has_verified_evidence(session, control.id):
        raise Conflict("This status needs evidence linked to the control that a reviewer has "
                       "verified.", code="EVIDENCE_REQUIRED")

    assessment_id = uuid4()
    audit = append_event(
        session,
        user.tenant_id,
        event_type="governance.control_assessed",
        actor_type="user",
        actor_id=user.id,
        subject_type="governance_control",
        subject_id=control.id,
        occurred_at=now,
        payload={
            "assessment_id": str(assessment_id),
            "control_id": str(control.id),
            "control_identifier": control.control_identifier,
            "status": status,
            "evidence_ids": [str(item) for item in cited],
        },
    )
    assessment = GovernanceControlAssessment(
        id=assessment_id,
        tenant_id=user.tenant_id,
        control_id=control.id,
        status=status,
        note=note,
        assessed_by=user.id,
        assessed_at=now,
        audit_event_id=audit.id,
    )
    session.add(assessment)
    session.flush()
    session.add_all(
        GovernanceControlAssessmentEvidence(id=uuid4(), tenant_id=user.tenant_id,
                                            assessment_id=assessment_id, control_id=control.id,
                                            evidence_id=evidence_id)
        for evidence_id in cited
    )
    session.flush()
    return assessment
