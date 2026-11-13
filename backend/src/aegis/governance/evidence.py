"""Evidence for an asset, and its verification by someone other than the submitter (spec 9).

Verification is append-only. An item counts only while its latest verification, by audit
sequence, is VERIFIED. What a verification proves depends on the source, and the method recorded
with it says so, so an attestation is never mistaken for a checked hash.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal, get_args
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event, compute_event_hash
from aegis.canonical import sha256_hex
from aegis.db.models import (
    AiAsset,
    AuditEvent,
    GovernanceDecision,
    GovernanceEvidence,
    GovernanceEvidenceVerification,
    Incident,
    InvestigationRun,
    RiskAssessment,
)
from aegis.errors import Conflict, Forbidden, NotFound, ValidationFailed
from aegis.governance.assets import lock_asset_state, require_not_retired
from aegis.governance.policy_schema import EvidenceCategory
from aegis.governance.risk import MethodologyIntegrityError, recomputes_to_stored_result
from aegis.governance.roles import holds_reviewer
from aegis.security.principals import UserPrincipal

CATEGORIES = get_args(EvidenceCategory)
Category = EvidenceCategory

# Content is capped well under the 64 KB request limit, which also carries the other fields and
# JSON escaping. The same cap bounds the content supplied to check an external reference.
MAX_CONTENT_BYTES = 16_000

UNVERIFIED = "UNVERIFIED"
VERIFIED = "VERIFIED"
REJECTED = "REJECTED"

INTERNAL_CHECKED = "internal_record_checked"
CONTENT_RECOMPUTED = "content_recomputed"
MANUAL_ATTESTATION = "manual_attestation"

_METHODS_BY_SOURCE = {
    "internal_record": (INTERNAL_CHECKED,),
    "inline": (CONTENT_RECOMPUTED, MANUAL_ATTESTATION),
    "external_reference": (CONTENT_RECOMPUTED, MANUAL_ATTESTATION),
}

Hex64 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]


def _within_cap(text: str, name: str) -> str:
    if len(text.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValueError(f"{name} is limited to {MAX_CONTENT_BYTES} bytes")
    return text


class InternalRecordSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: Literal["internal_record"]
    record_type: Literal["assessment", "decision", "audit_event", "incident", "investigation_run"]
    record_id: UUID


class InlineSource(BaseModel):
    """The hash is computed here from the text. A hash from the client is refused as unknown."""

    model_config = ConfigDict(extra="forbid")

    source_type: Literal["inline"]
    content_text: Annotated[str, StringConstraints(strict=True, min_length=1)]

    def stored_hash(self) -> str:
        return sha256_hex(self.content_text)

    @field_validator("content_text")
    @classmethod
    def within_cap(cls, text: str) -> str:
        return _within_cap(text, "content_text")


class ExternalReferenceSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: Literal["external_reference"]
    source_uri: Annotated[
        str, StringConstraints(strict=True, pattern=r"^https?://\S+$", max_length=2048)
    ]
    content_sha256: Hex64


EvidenceSource = Annotated[
    InternalRecordSource | InlineSource | ExternalReferenceSource,
    Field(discriminator="source_type"),
]

# The column each kind of internal record is held in.
_RECORD_COLUMNS = {
    "assessment": "assessment_id",
    "decision": "decision_id",
    "audit_event": "audit_event_id",
    "incident": "incident_id",
    "investigation_run": "investigation_run_id",
}


def record_of(evidence: GovernanceEvidence) -> tuple[str, UUID] | None:
    for kind, column in _RECORD_COLUMNS.items():
        value = getattr(evidence, column)
        if value is not None:
            return kind, value
    return None


def _missing(kind: str) -> ValidationFailed:
    return ValidationFailed(f"The {kind.replace('_', ' ')} must be a record of this tenant"
                            " and, for an assessment or decision, of this asset.")


def _internal_fields(session: Session, asset_id: UUID,
                     source: InternalRecordSource) -> dict[str, object]:
    """The record column and its hash. An incident or run has none, so only existence is proved."""
    column = _RECORD_COLUMNS[source.record_type]
    fields: dict[str, object] = {column: source.record_id, "content_sha256": None}
    match source.record_type:
        case "assessment":
            row = session.get(RiskAssessment, source.record_id)
            if row is None or row.asset_id != asset_id:
                raise _missing("assessment")
            fields["content_sha256"] = row.result_hash
        case "decision":
            row = session.get(GovernanceDecision, source.record_id)
            event = None if row is None else session.get(AuditEvent, row.audit_event_id)
            if row is None or row.asset_id != asset_id or event is None:
                raise _missing("decision")
            fields["content_sha256"] = event.event_hash
        case "audit_event":
            event = session.get(AuditEvent, source.record_id)
            if event is None:
                raise _missing("audit_event")
            fields["content_sha256"] = event.event_hash
        case "incident":
            if session.get(Incident, source.record_id) is None:
                raise _missing("incident")
        case "investigation_run":
            if session.get(InvestigationRun, source.record_id) is None:
                raise _missing("investigation_run")
    return fields


def submit_evidence(session: Session, user: UserPrincipal, now: datetime, *, asset_id: UUID,
                    category: str, description: str, source: EvidenceSource,
                    control_ids: Sequence[UUID] = ()) -> GovernanceEvidence:
    """Add an item. It starts unverified and counts toward nothing until a reviewer verifies it."""
    if control_ids:
        # The link table exists, but its control foreign key and the controls arrive in Task 12.
        raise ValidationFailed("Evidence cannot be linked to controls yet.")
    if category not in CATEGORIES:
        raise ValidationFailed("Unknown evidence category.")
    if not description.strip() or len(description) > 2000:
        raise ValidationFailed("The description must be 1 to 2000 characters.")
    if session.get(AiAsset, asset_id) is None:
        raise NotFound()
    # An asset may have no governance state yet; a retired one takes no further evidence.
    require_not_retired(lock_asset_state(session, asset_id))

    fields: dict[str, object]
    if isinstance(source, InlineSource):
        fields = {"content_text": source.content_text, "content_sha256": source.stored_hash()}
    elif isinstance(source, ExternalReferenceSource):
        fields = {"source_uri": source.source_uri, "content_sha256": source.content_sha256}
    else:
        fields = _internal_fields(session, asset_id, source)

    evidence = GovernanceEvidence(
        id=uuid4(),
        tenant_id=user.tenant_id,
        asset_id=asset_id,
        category=category,
        description=description,
        source_type=source.source_type,
        submitted_by=user.id,
        created_at=now,
        **fields,
    )
    session.add(evidence)
    session.flush()
    append_event(
        session,
        user.tenant_id,
        event_type="governance.evidence_submitted",
        actor_type="user",
        actor_id=user.id,
        subject_type="governance_evidence",
        subject_id=evidence.id,
        occurred_at=now,
        payload={
            "evidence_id": str(evidence.id),
            "asset_id": str(asset_id),
            "category": category,
            "source_type": source.source_type,
            "content_sha256": evidence.content_sha256,
        },
    )
    return evidence


# Verification


def verification_scope(evidence: GovernanceEvidence, outcome: str, method: str) -> str:
    """What a verification can have shown, for the response and the dashboard.

    A rejection runs no check. Inline text is always recomputed for a VERIFIED outcome, whatever
    the method, because that check is free.
    """
    if outcome == REJECTED:
        return "judgment_only"
    if evidence.source_type == "inline" or method == CONTENT_RECOMPUTED:
        return "hash_recomputed"
    if method == MANUAL_ATTESTATION:
        return "attestation_only"
    if evidence.incident_id is not None or evidence.investigation_run_id is not None:
        return "existence_only"
    return "record_verified"


def _mismatch(what: str) -> Conflict:
    return Conflict(f"{what} does not match its recorded hash.", code="HASH_MISMATCH")


def _check_internal_record(session: Session, evidence: GovernanceEvidence) -> None:
    record = record_of(evidence)
    if record is None:
        raise _mismatch("The record")
    kind, record_id = record
    if kind == "assessment":
        assessment = session.get(RiskAssessment, record_id)
        try:
            intact = (assessment is not None
                      and recomputes_to_stored_result(session, assessment)
                      and assessment.result_hash == evidence.content_sha256)
        except MethodologyIntegrityError:
            intact = False
        if not intact:
            raise _mismatch("The assessment")
    elif kind == "decision":
        decision = session.get(GovernanceDecision, record_id)
        event = None if decision is None else session.get(AuditEvent, decision.audit_event_id)
        if (event is None or compute_event_hash(event) != event.event_hash
                or event.event_hash != evidence.content_sha256
                or event.payload.get("decision_id") != str(decision.id)):
            raise _mismatch("The decision's audit event")
    elif kind == "audit_event":
        event = session.get(AuditEvent, record_id)
        if (event is None or compute_event_hash(event) != event.event_hash
                or event.event_hash != evidence.content_sha256):
            raise _mismatch("The audit event")
    else:
        # No hash exists for these, so existence in this tenant is all that can be shown.
        model = Incident if kind == "incident" else InvestigationRun
        if session.get(model, record_id) is None:
            raise _mismatch(f"The {kind.replace('_', ' ')}")


def _check_submission_event(session: Session, evidence: GovernanceEvidence) -> None:
    """The row must still say what the audit event written at submission said it did.

    The event is hash-chained, so rewriting the row and its own hash together is not enough.
    """
    event = session.execute(
        select(AuditEvent).where(
            AuditEvent.event_type == "governance.evidence_submitted",
            AuditEvent.subject_type == "governance_evidence",
            AuditEvent.subject_id == evidence.id,
        )
    ).scalars().first()
    if event is None or compute_event_hash(event) != event.event_hash:
        raise _mismatch("The submission record")
    payload = event.payload
    if (payload.get("evidence_id") != str(evidence.id)
            or payload.get("asset_id") != str(evidence.asset_id)
            or payload.get("category") != evidence.category
            or payload.get("source_type") != evidence.source_type
            or payload.get("content_sha256") != evidence.content_sha256):
        raise _mismatch("The evidence")


def _check_content(evidence: GovernanceEvidence, content: str | None) -> None:
    if evidence.source_type == "inline":
        if content is not None:
            raise ValidationFailed("Inline evidence is checked against its stored text.")
        if sha256_hex(evidence.content_text) != evidence.content_sha256:
            raise _mismatch("The stored text")
    else:
        if content is None:
            raise ValidationFailed("Recomputing an external reference needs the content.")
        _within_cap(content, "content")
        if sha256_hex(content) != evidence.content_sha256:
            raise _mismatch("The supplied content")


def verify_evidence(session: Session, user: UserPrincipal, now: datetime, evidence_id: UUID, *,
                    outcome: str, method: str, note: str,
                    content: str | None = None) -> GovernanceEvidenceVerification:
    """Record a verification. A VERIFIED outcome by a checking method must pass the check, and a
    failed check refuses the call and writes nothing."""
    if outcome not in (VERIFIED, REJECTED):
        raise ValidationFailed("The outcome must be VERIFIED or REJECTED.")
    if not note.strip() or len(note) > 2000:
        raise ValidationFailed("The note must be 1 to 2000 characters.")
    asset_id = session.execute(
        select(GovernanceEvidence.asset_id).where(GovernanceEvidence.id == evidence_id)
    ).scalar_one_or_none()
    if asset_id is None:
        raise NotFound()
    state = lock_asset_state(session, asset_id)
    if not holds_reviewer(session, user.id):
        raise Forbidden()
    # A rejection only tightens, so it is allowed on a retired asset; a verification is not.
    if outcome == VERIFIED:
        require_not_retired(state)
    evidence = session.get(GovernanceEvidence, evidence_id)

    if evidence.submitted_by == user.id:
        raise Forbidden("You cannot verify evidence you submitted.",
                        code="SELF_VERIFICATION_REFUSED")
    if method not in _METHODS_BY_SOURCE[evidence.source_type]:
        raise ValidationFailed(f"The method {method} does not apply to this source.")
    if content is not None and not (
            evidence.source_type == "external_reference" and method == CONTENT_RECOMPUTED):
        raise ValidationFailed("Content applies only to recomputing an external reference.")

    # A rejection records a judgment and needs no check to pass. A VERIFIED outcome needs the
    # record to match its submission event, and the check its source allows: always for inline
    # text and internal records, and for an external reference when it is recomputed.
    if outcome == VERIFIED:
        _check_submission_event(session, evidence)
        if method == INTERNAL_CHECKED:
            _check_internal_record(session, evidence)
        elif method == CONTENT_RECOMPUTED or evidence.source_type == "inline":
            _check_content(evidence, content)

    verification_id = uuid4()
    audit = append_event(
        session,
        user.tenant_id,
        event_type="governance.evidence_verified",
        actor_type="user",
        actor_id=user.id,
        subject_type="governance_evidence",
        subject_id=evidence.id,
        occurred_at=now,
        payload={
            "verification_id": str(verification_id),
            "evidence_id": str(evidence.id),
            "asset_id": str(evidence.asset_id),
            "outcome": outcome,
            "method": method,
            "scope": verification_scope(evidence, outcome, method),
        },
    )
    verification = GovernanceEvidenceVerification(
        id=verification_id,
        tenant_id=user.tenant_id,
        evidence_id=evidence.id,
        outcome=outcome,
        method=method,
        note=note,
        verified_by=user.id,
        verified_at=now,
        audit_event_id=audit.id,
    )
    session.add(verification)
    session.flush()
    return verification


# Current status


def _ranked_verifications():
    """Each verification numbered newest first within its evidence, by audit sequence."""
    return (
        select(
            GovernanceEvidenceVerification.id.label("verification_id"),
            GovernanceEvidenceVerification.evidence_id.label("evidence_id"),
            GovernanceEvidenceVerification.outcome.label("outcome"),
            func.row_number().over(
                partition_by=GovernanceEvidenceVerification.evidence_id,
                order_by=AuditEvent.seq.desc(),
            ).label("rank"),
        )
        .join(AuditEvent, AuditEvent.id == GovernanceEvidenceVerification.audit_event_id)
        .subquery()
    )


def _latest_verifications():
    ranked = _ranked_verifications()
    return select(ranked).where(ranked.c.rank == 1).subquery()


def current_verification(session: Session, evidence_id: UUID) -> str:
    latest = _latest_verifications()
    outcome = session.execute(
        select(latest.c.outcome).where(latest.c.evidence_id == evidence_id)
    ).scalar_one_or_none()
    return outcome or UNVERIFIED


def verified_categories(session: Session, asset_id: UUID) -> set[str]:
    """The categories with at least one item whose current verification is VERIFIED."""
    latest = _latest_verifications()
    return set(session.execute(
        select(GovernanceEvidence.category)
        .join(latest, latest.c.evidence_id == GovernanceEvidence.id)
        .where(GovernanceEvidence.asset_id == asset_id, latest.c.outcome == VERIFIED)
    ).scalars().all())


def evidence_counts(session: Session) -> tuple[int, int]:
    """Evidence currently verified, and all evidence, for the overview."""
    latest = _latest_verifications()
    total = session.execute(select(func.count(GovernanceEvidence.id))).scalar_one()
    verified = session.execute(
        select(func.count(GovernanceEvidence.id))
        .join(latest, latest.c.evidence_id == GovernanceEvidence.id)
        .where(latest.c.outcome == VERIFIED)
    ).scalar_one()
    return verified, total


def require_asset_evidence(session: Session, asset_id: UUID,
                           evidence_ids: Iterable[UUID]) -> list[UUID]:
    """Each id must be this tenant's evidence for this asset. Repeats are collapsed."""
    unique = list(dict.fromkeys(evidence_ids))
    found = set(session.execute(
        select(GovernanceEvidence.id).where(
            GovernanceEvidence.asset_id == asset_id, GovernanceEvidence.id.in_(unique)
        )
    ).scalars().all())
    if len(found) != len(unique):
        raise ValidationFailed("Each evidence item must belong to this review's asset.")
    return unique


# Reading


@dataclass(frozen=True)
class EvidenceRecord:
    evidence: GovernanceEvidence
    latest: GovernanceEvidenceVerification | None

    @property
    def status(self) -> str:
        return self.latest.outcome if self.latest is not None else UNVERIFIED


def _records(session: Session, *conditions, status: str | None = None, limit: int | None = None,
             offset: int = 0) -> list[EvidenceRecord]:
    latest = _latest_verifications()
    statement = (
        select(GovernanceEvidence, GovernanceEvidenceVerification)
        .outerjoin(latest, latest.c.evidence_id == GovernanceEvidence.id)
        .outerjoin(GovernanceEvidenceVerification,
                   GovernanceEvidenceVerification.id == latest.c.verification_id)
        .where(*conditions)
        .order_by(GovernanceEvidence.created_at.desc(), GovernanceEvidence.id)
        .offset(offset)
    )
    if status is not None:
        statement = statement.where(func.coalesce(latest.c.outcome, UNVERIFIED) == status)
    if limit is not None:
        statement = statement.limit(limit)
    return [EvidenceRecord(evidence, verification)
            for evidence, verification in session.execute(statement).all()]


def list_evidence(session: Session, *, asset_id: UUID | None, category: str | None,
                  status: str | None, limit: int,
                  offset: int) -> tuple[list[EvidenceRecord], int]:
    conditions = []
    if asset_id is not None:
        conditions.append(GovernanceEvidence.asset_id == asset_id)
    if category is not None:
        conditions.append(GovernanceEvidence.category == category)
    latest = _latest_verifications()
    count = (
        select(func.count(GovernanceEvidence.id))
        .outerjoin(latest, latest.c.evidence_id == GovernanceEvidence.id)
        .where(*conditions)
    )
    if status is not None:
        count = count.where(func.coalesce(latest.c.outcome, UNVERIFIED) == status)
    total = session.execute(count).scalar_one()
    return _records(session, *conditions, status=status, limit=limit, offset=offset), total


def get_evidence(session: Session, evidence_id: UUID) -> EvidenceRecord:
    records = _records(session, GovernanceEvidence.id == evidence_id)
    if not records:
        raise NotFound()
    return records[0]


def verification_history(session: Session,
                         evidence_id: UUID) -> list[GovernanceEvidenceVerification]:
    """Every verification, oldest first by audit sequence."""
    return list(session.execute(
        select(GovernanceEvidenceVerification)
        .join(AuditEvent, AuditEvent.id == GovernanceEvidenceVerification.audit_event_id)
        .where(GovernanceEvidenceVerification.evidence_id == evidence_id)
        .order_by(AuditEvent.seq)
    ).scalars().all())
