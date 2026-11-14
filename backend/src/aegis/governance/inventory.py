"""Read-only views over assets and their governance state. Every figure is read from stored rows."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Select, String, cast, func, literal, or_, select, union_all
from sqlalchemy.orm import Session, aliased
from sqlalchemy.sql.elements import ColumnElement

from aegis.db.models import (
    AiAsset,
    AssetGovernanceState,
    AssetProfileVersion,
    AuditEvent,
    GovernanceDecision,
    RiskAssessment,
    RiskMethodologyVersion,
    User,
)
from aegis.errors import NotFound
from aegis.governance.approvals import outstanding_findings
from aegis.governance.enforcement_mode import get_mode
from aegis.governance.engine.lifecycle import GovernanceStatus
from aegis.governance.evidence import evidence_counts
from aegis.governance.risk import AssessmentRecord

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

_business = aliased(User)
_technical = aliased(User)

# Each asset's newest assessment, by audit sequence because timestamps can tie. An incomplete
# newest assessment has a null risk level, so it never falls back to an older complete one.
_ranked = (
    select(
        RiskAssessment.asset_id.label("asset_id"),
        RiskAssessment.risk_level.label("risk_level"),
        RiskAssessment.created_at.label("assessed_at"),
        func.row_number()
        .over(partition_by=RiskAssessment.asset_id, order_by=AuditEvent.seq.desc())
        .label("position"),
    )
    .join(AuditEvent, AuditEvent.id == RiskAssessment.audit_event_id)
    .subquery("ranked_assessments")
)
_latest = select(_ranked).where(_ranked.c.position == 1).subquery("latest_assessments")


@dataclass(frozen=True)
class OwnerRef:
    id: UUID
    email: str


@dataclass(frozen=True)
class InventoryRow:
    id: UUID
    name: str
    owner: str
    declared_risk: str
    assessed_risk: str | None
    last_assessed_at: datetime | None
    governance_status: str | None
    business_owner: OwnerRef | None
    technical_owner: OwnerRef | None
    is_synthetic: bool
    valid_until: datetime | None
    next_review_at: datetime | None
    created_at: datetime


@dataclass(frozen=True)
class CurrentProfile:
    id: UUID
    version: int
    profile: dict[str, Any]
    content_hash: str
    created_by: UUID
    created_at: datetime


@dataclass(frozen=True)
class AssetDetailView(InventoryRow):
    intended_use: str
    state_version: int | None
    state_updated_at: datetime | None
    profile: CurrentProfile | None


@dataclass(frozen=True)
class OverviewView:
    total_assets: int
    by_assessed_risk: dict[str, int]
    unassessed: int
    awaiting_approval: int
    conditionally_approved: int
    suspended: int
    overdue_reviews: int
    outstanding_findings: int
    evidence_verified: int
    evidence_total: int
    enforcement_mode: str


def _joined(statement: Select) -> Select:
    """An asset, its state row, the profile version that row points at, and its owners."""
    return (
        statement.select_from(AiAsset)
        .outerjoin(AssetGovernanceState, AssetGovernanceState.asset_id == AiAsset.id)
        .outerjoin(
            AssetProfileVersion,
            AssetProfileVersion.id == AssetGovernanceState.current_profile_version_id,
        )
        .outerjoin(_business, _business.id == AssetProfileVersion.business_owner_id)
        .outerjoin(_technical, _technical.id == AssetProfileVersion.technical_owner_id)
        .outerjoin(_latest, _latest.c.asset_id == AiAsset.id)
    )


_ROW_COLUMNS = (
    AiAsset.id.label("id"),
    AiAsset.name.label("name"),
    AiAsset.owner.label("owner"),
    AiAsset.risk_classification.label("declared_risk"),
    AiAsset.is_synthetic.label("is_synthetic"),
    AiAsset.created_at.label("created_at"),
    _latest.c.risk_level.label("assessed_risk"),
    _latest.c.assessed_at.label("last_assessed_at"),
    AiAsset.intended_use.label("intended_use"),
    AssetGovernanceState.status.label("status"),
    AssetGovernanceState.version.label("state_version"),
    AssetGovernanceState.updated_at.label("state_updated_at"),
    AssetGovernanceState.valid_until.label("valid_until"),
    AssetGovernanceState.next_review_at.label("next_review_at"),
    AssetProfileVersion.business_owner_id.label("business_id"),
    _business.email.label("business_email"),
    AssetProfileVersion.technical_owner_id.label("technical_id"),
    _technical.email.label("technical_email"),
)


def _owner(owner_id: UUID | None, email: str | None) -> OwnerRef | None:
    return OwnerRef(owner_id, email) if owner_id is not None and email is not None else None


def _row_fields(row) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "owner": row.owner,
        "declared_risk": row.declared_risk,
        # Declared risk is never a stand-in for this.
        "assessed_risk": row.assessed_risk,
        "last_assessed_at": row.last_assessed_at,
        "governance_status": row.status,
        "business_owner": _owner(row.business_id, row.business_email),
        "technical_owner": _owner(row.technical_id, row.technical_email),
        "is_synthetic": row.is_synthetic,
        "valid_until": row.valid_until,
        "next_review_at": row.next_review_at,
        "created_at": row.created_at,
    }


def like_pattern(term: str) -> str:
    """A contains-pattern in which the term's own % and _ match themselves."""
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def list_inventory(session: Session, *, search: str | None, risk: str | None,
                   declared_risk: str | None, status: str | None, owner_id: UUID | None,
                   limit: int, offset: int) -> tuple[list[InventoryRow], int]:
    """`risk` filters the assessed level and `declared_risk` the registrant's value."""
    conditions: list[ColumnElement[bool]] = []
    if search and search.strip():
        pattern = like_pattern(search.strip())
        conditions.append(
            or_(AiAsset.name.ilike(pattern, escape="\\"), AiAsset.owner.ilike(pattern, escape="\\"))
        )
    if risk:
        conditions.append(_latest.c.risk_level == risk)
    if declared_risk:
        conditions.append(AiAsset.risk_classification == declared_risk)
    if status:
        conditions.append(AssetGovernanceState.status == status)
    if owner_id:
        conditions.append(
            or_(
                AssetProfileVersion.business_owner_id == owner_id,
                AssetProfileVersion.technical_owner_id == owner_id,
            )
        )
    rows = session.execute(
        _joined(select(*_ROW_COLUMNS))
        .where(*conditions)
        .order_by(AiAsset.created_at.desc(), AiAsset.id)
        .limit(limit)
        .offset(offset)
    ).all()
    total = session.execute(_joined(select(func.count(AiAsset.id))).where(*conditions)).scalar_one()
    return [InventoryRow(**_row_fields(row)) for row in rows], total


def asset_detail(session: Session, asset_id: UUID) -> AssetDetailView:
    row = session.execute(_joined(select(*_ROW_COLUMNS)).where(AiAsset.id == asset_id)).first()
    if row is None:
        raise NotFound()
    version = session.execute(
        select(AssetProfileVersion)
        .join(
            AssetGovernanceState,
            AssetGovernanceState.current_profile_version_id == AssetProfileVersion.id,
        )
        .where(AssetGovernanceState.asset_id == asset_id)
    ).scalar_one_or_none()
    profile = None
    if version is not None:
        profile = CurrentProfile(
            id=version.id,
            version=version.version,
            profile=json.loads(version.profile_canonical),
            content_hash=version.content_hash,
            created_by=version.created_by,
            created_at=version.created_at,
        )
    return AssetDetailView(
        **_row_fields(row),
        intended_use=row.intended_use,
        state_version=row.state_version,
        state_updated_at=row.state_updated_at,
        profile=profile,
    )


def overview(session: Session, now: datetime) -> OverviewView:
    total = session.execute(select(func.count(AiAsset.id))).scalar_one()
    by_status = dict(
        session.execute(
            select(AssetGovernanceState.status, func.count()).group_by(AssetGovernanceState.status)
        ).all()
    )
    approved = (GovernanceStatus.APPROVED.value, GovernanceStatus.CONDITIONALLY_APPROVED.value)
    overdue = session.execute(
        select(func.count()).where(
            AssetGovernanceState.status.in_(approved),
            AssetGovernanceState.next_review_at <= now,
        )
    ).scalar_one()
    counts = dict(
        session.execute(
            select(_latest.c.risk_level, func.count())
            .where(_latest.c.risk_level.is_not(None))
            .group_by(_latest.c.risk_level)
        ).all()
    )
    assessed = {level: counts.get(level, 0) for level in RISK_LEVELS}
    evidence_verified, evidence_total = evidence_counts(session)
    return OverviewView(
        total_assets=total,
        by_assessed_risk=assessed,
        unassessed=total - sum(assessed.values()),
        awaiting_approval=by_status.get(GovernanceStatus.UNDER_REVIEW.value, 0),
        conditionally_approved=by_status.get(GovernanceStatus.CONDITIONALLY_APPROVED.value, 0),
        suspended=by_status.get(GovernanceStatus.SUSPENDED.value, 0),
        overdue_reviews=overdue,
        outstanding_findings=outstanding_findings(session),
        evidence_verified=evidence_verified,
        evidence_total=evidence_total,
        enforcement_mode=get_mode(session),
    )


@dataclass(frozen=True)
class HistoryEntry:
    type: str
    seq: int
    audit_event_id: UUID
    record: GovernanceDecision | AssessmentRecord | AssetProfileVersion


def asset_history(session: Session, asset_id: UUID, *, limit: int,
                  offset: int) -> tuple[list[HistoryEntry], int]:
    """Decisions, assessments, and profile versions of one asset, oldest first by audit sequence.

    A profile version carries no event of its own, so it is placed by the event that saved it,
    which names it in its payload. A row with no such event is not part of the history.
    """
    if session.get(AiAsset, asset_id) is None:
        raise NotFound()
    ordered = union_all(
        select(AuditEvent.seq.label("seq"), literal("decision").label("type"),
               GovernanceDecision.id.label("id"), AuditEvent.id.label("audit_event_id"))
        .join(AuditEvent, AuditEvent.id == GovernanceDecision.audit_event_id)
        .where(GovernanceDecision.asset_id == asset_id),
        select(AuditEvent.seq, literal("assessment"), RiskAssessment.id, AuditEvent.id)
        .join(AuditEvent, AuditEvent.id == RiskAssessment.audit_event_id)
        .where(RiskAssessment.asset_id == asset_id),
        select(AuditEvent.seq, literal("profile_version"), AssetProfileVersion.id,
               AuditEvent.id)
        .join(
            AuditEvent,
            (AuditEvent.event_type == "governance.profile_saved")
            & (AuditEvent.subject_id == asset_id)
            & (AuditEvent.payload["profile_version_id"].astext
               == cast(AssetProfileVersion.id, String)),
        )
        .where(AssetProfileVersion.asset_id == asset_id),
    ).subquery("history")
    rows = session.execute(
        select(ordered).order_by(ordered.c.seq).limit(limit).offset(offset)
    ).all()
    total = session.execute(select(func.count()).select_from(ordered)).scalar_one()

    wanted = {kind: [row.id for row in rows if row.type == kind]
              for kind in ("decision", "assessment", "profile_version")}
    decisions = {item.id: item for item in session.execute(
        select(GovernanceDecision).where(GovernanceDecision.id.in_(wanted["decision"]))
    ).scalars()}
    assessments = {row[0].id: AssessmentRecord(row[0], row[1]) for row in session.execute(
        select(RiskAssessment, RiskMethodologyVersion.version)
        .join(RiskMethodologyVersion,
              RiskMethodologyVersion.id == RiskAssessment.methodology_version_id)
        .where(RiskAssessment.id.in_(wanted["assessment"]))
    ).all()}
    profiles = {item.id: item for item in session.execute(
        select(AssetProfileVersion).where(AssetProfileVersion.id.in_(wanted["profile_version"]))
    ).scalars()}
    records = {"decision": decisions, "assessment": assessments, "profile_version": profiles}

    return [
        HistoryEntry(row.type, row.seq, row.audit_event_id, records[row.type][row.id])
        for row in rows
    ], total
