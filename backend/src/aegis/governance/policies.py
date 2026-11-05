"""Governance policies: documents, versions, approval, and activation.

Writes run in the caller's tenant transaction. A version is an immutable canonical document.
Approval and activation are rows in `governance_policy_events`, and a version's status is its
latest event by audit sequence. These tables are separate from the runtime `policies`.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.canonical import canonical_json, sha256_hex
from aegis.db.models import (
    AuditEvent,
    GovernancePolicy,
    GovernancePolicyEvent,
    GovernancePolicyVersion,
)
from aegis.errors import Conflict, Forbidden, NotFound
from aegis.governance.engine.policies import VersionedDocument
from aegis.governance.policy_schema import GovernancePolicyDocument
from aegis.security.principals import UserPrincipal


class PolicyIntegrityError(Exception):
    """A stored policy version failed its hash or validation, so it cannot be trusted.

    Callers fail closed: skipping the version could drop a requirement without anyone noticing.
    """


@dataclass(frozen=True)
class PolicyVersionView:
    id: UUID
    policy_id: UUID
    version: int
    content_hash: str
    effective_from: datetime
    review_by: datetime | None
    created_by: UUID
    created_at: datetime
    approved: bool
    approved_by: UUID | None
    approved_at: datetime | None
    active: bool
    document: dict


@dataclass(frozen=True)
class PolicyView:
    id: UUID
    name: str
    category: str
    created_by: UUID
    created_at: datetime
    versions: list[PolicyVersionView]


@dataclass(frozen=True)
class _Status:
    approval: GovernancePolicyEvent | None = None
    active: bool = False


def _canonical_document(document: GovernancePolicyDocument) -> str:
    return canonical_json(document.model_dump(mode="json", exclude_none=True))


def _instant(value: datetime | None) -> str | None:
    """A fixed-width UTC text, so the same instant hashes the same whatever zone it is read in."""
    return None if value is None else value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def version_hash(policy_id: UUID, version: int, effective_from: datetime,
                 review_by: datetime | None, document_canonical: str) -> str:
    """The hash covers everything that decides whether and how a version applies, not only the
    document: moving `effective_from` would otherwise drop a policy without failing any check."""
    return sha256_hex(canonical_json({
        "policy_id": str(policy_id),
        "version": version,
        "effective_from": _instant(effective_from),
        "review_by": _instant(review_by),
        "document": document_canonical,
    }))


def parse_version(version: GovernancePolicyVersion) -> GovernancePolicyDocument:
    expected = version_hash(version.policy_id, version.version, version.effective_from,
                            version.review_by, version.document_canonical)
    if expected != version.content_hash:
        raise PolicyIntegrityError(f"policy version {version.id} failed its hash")
    try:
        return GovernancePolicyDocument.model_validate(json.loads(version.document_canonical))
    except (ValidationError, ValueError) as error:
        raise PolicyIntegrityError(f"policy version {version.id} is invalid") from error


def _serialize_policy_changes(session: Session, tenant_id: UUID) -> None:
    """Version rows cannot be row-locked (the runtime role may not update them), so one lock per
    tenant orders name checks, version numbering, approval, and activation."""
    session.execute(
        select(func.pg_advisory_xact_lock(
            func.hashtextextended(f"governance-policy:{tenant_id}", 0)
        ))
    )


def _statuses(session: Session, version_ids: list[UUID] | None = None) -> dict[UUID, _Status]:
    """Status per version from its events, newest last by audit sequence, never by timestamp."""
    query = (
        select(GovernancePolicyEvent)
        .join(AuditEvent, AuditEvent.id == GovernancePolicyEvent.audit_event_id)
        .order_by(AuditEvent.seq)
    )
    if version_ids is not None:
        query = query.where(GovernancePolicyEvent.policy_version_id.in_(version_ids))
    statuses: dict[UUID, _Status] = {}
    for event in session.execute(query).scalars():
        current = statuses.get(event.policy_version_id, _Status())
        if event.event == "APPROVED":
            current = _Status(approval=event, active=current.active)
        else:
            current = _Status(approval=current.approval, active=event.event == "ACTIVATED")
        statuses[event.policy_version_id] = current
    return statuses


def _version_view(version: GovernancePolicyVersion, status: _Status) -> PolicyVersionView:
    approval = status.approval
    return PolicyVersionView(
        id=version.id,
        policy_id=version.policy_id,
        version=version.version,
        content_hash=version.content_hash,
        effective_from=version.effective_from,
        review_by=version.review_by,
        created_by=version.created_by,
        created_at=version.created_at,
        approved=approval is not None,
        approved_by=approval.actor_id if approval is not None else None,
        approved_at=approval.created_at if approval is not None else None,
        active=status.active,
        document=parse_version(version).model_dump(mode="json", exclude_none=True),
    )


def _policy_view(policy: GovernancePolicy, versions: list[PolicyVersionView]) -> PolicyView:
    return PolicyView(id=policy.id, name=policy.name, category=policy.category,
                      created_by=policy.created_by, created_at=policy.created_at,
                      versions=versions)


def list_policies(session: Session, *, limit: int,
                  offset: int) -> tuple[list[PolicyView], int]:
    policies = session.execute(
        select(GovernancePolicy)
        .order_by(func.lower(GovernancePolicy.name), GovernancePolicy.id)
        .limit(limit)
        .offset(offset)
    ).scalars().all()
    total = session.execute(select(func.count(GovernancePolicy.id))).scalar_one()
    versions = session.execute(
        select(GovernancePolicyVersion)
        .where(GovernancePolicyVersion.policy_id.in_([policy.id for policy in policies]))
        .order_by(GovernancePolicyVersion.version.desc())
    ).scalars().all()
    statuses = _statuses(session, [version.id for version in versions])
    by_policy: dict[UUID, list[PolicyVersionView]] = {}
    for version in versions:
        by_policy.setdefault(version.policy_id, []).append(
            _version_view(version, statuses.get(version.id, _Status()))
        )
    return [_policy_view(policy, by_policy.get(policy.id, [])) for policy in policies], total


def create_policy(session: Session, user: UserPrincipal, now: datetime, name: str,
                  category: str) -> PolicyView:
    _serialize_policy_changes(session, user.tenant_id)
    taken = session.execute(
        select(GovernancePolicy.id).where(func.lower(GovernancePolicy.name) == name.lower())
    ).first()
    if taken is not None:
        raise Conflict("A governance policy with this name already exists.",
                       code="POLICY_NAME_TAKEN")
    policy = GovernancePolicy(id=uuid4(), tenant_id=user.tenant_id, name=name, category=category,
                              created_by=user.id, created_at=now)
    session.add(policy)
    session.flush()
    append_event(
        session,
        user.tenant_id,
        event_type="governance.policy_created",
        actor_type="user",
        actor_id=user.id,
        subject_type="governance_policy",
        subject_id=policy.id,
        occurred_at=now,
        payload={"name": name, "category": category},
    )
    return _policy_view(policy, [])


def create_version(session: Session, user: UserPrincipal, now: datetime, policy_id: UUID,
                   document: GovernancePolicyDocument, effective_from: datetime,
                   review_by: datetime | None) -> PolicyVersionView:
    _serialize_policy_changes(session, user.tenant_id)
    if session.get(GovernancePolicy, policy_id) is None:
        raise NotFound()
    latest = session.execute(
        select(func.max(GovernancePolicyVersion.version)).where(
            GovernancePolicyVersion.policy_id == policy_id
        )
    ).scalar_one()
    canonical = _canonical_document(document)
    number = (latest or 0) + 1
    version = GovernancePolicyVersion(
        id=uuid4(),
        tenant_id=user.tenant_id,
        policy_id=policy_id,
        version=number,
        document_canonical=canonical,
        content_hash=version_hash(policy_id, number, effective_from, review_by, canonical),
        effective_from=effective_from,
        review_by=review_by,
        created_by=user.id,
        created_at=now,
    )
    session.add(version)
    session.flush()
    append_event(
        session,
        user.tenant_id,
        event_type="governance.policy_version_created",
        actor_type="user",
        actor_id=user.id,
        subject_type="governance_policy_version",
        subject_id=version.id,
        occurred_at=now,
        payload={
            "policy_id": str(policy_id),
            "version": version.version,
            "content_hash": version.content_hash,
            "effective_from": effective_from.isoformat(),
            "review_by": review_by.isoformat() if review_by is not None else None,
        },
    )
    return _version_view(version, _Status())


def _locked_version(session: Session, tenant_id: UUID, policy_id: UUID,
                    version_id: UUID) -> GovernancePolicyVersion:
    _serialize_policy_changes(session, tenant_id)
    version = session.get(GovernancePolicyVersion, version_id)
    if version is None or version.policy_id != policy_id:
        raise NotFound()
    parse_version(version)
    return version


def _record_event(session: Session, user: UserPrincipal, now: datetime,
                  version: GovernancePolicyVersion, event: str) -> PolicyVersionView:
    audit = append_event(
        session,
        user.tenant_id,
        event_type=f"governance.policy_version_{event.lower()}",
        actor_type="user",
        actor_id=user.id,
        subject_type="governance_policy_version",
        subject_id=version.id,
        occurred_at=now,
        payload={"policy_id": str(version.policy_id), "version": version.version,
                 "content_hash": version.content_hash},
    )
    session.add(
        GovernancePolicyEvent(
            id=uuid4(),
            tenant_id=user.tenant_id,
            policy_version_id=version.id,
            event=event,
            actor_id=user.id,
            audit_event_id=audit.id,
            created_at=now,
        )
    )
    session.flush()
    return _version_view(version, _statuses(session, [version.id])[version.id])


def _status_of(session: Session, version: GovernancePolicyVersion) -> _Status:
    return _statuses(session, [version.id]).get(version.id, _Status())


def approve_version(session: Session, user: UserPrincipal, now: datetime, policy_id: UUID,
                    version_id: UUID) -> PolicyVersionView:
    """The caller must already hold governance_reviewer; a creator cannot approve their own."""
    version = _locked_version(session, user.tenant_id, policy_id, version_id)
    if _status_of(session, version).approval is not None:
        raise Conflict("This policy version is already approved.", code="ALREADY_APPROVED")
    if version.created_by == user.id:
        raise Forbidden("You cannot approve a policy version you created.",
                        code="SELF_APPROVAL_REFUSED")
    return _record_event(session, user, now, version, "APPROVED")


def activate_version(session: Session, user: UserPrincipal, now: datetime, policy_id: UUID,
                     version_id: UUID) -> PolicyVersionView:
    version = _locked_version(session, user.tenant_id, policy_id, version_id)
    status = _status_of(session, version)
    if status.approval is None:
        raise Conflict("Only an approved policy version can be activated.",
                       code="POLICY_VERSION_NOT_APPROVED")
    if status.active:
        raise Conflict("This policy version is already active.", code="ALREADY_ACTIVE")
    return _record_event(session, user, now, version, "ACTIVATED")


def deactivate_version(session: Session, user: UserPrincipal, now: datetime, policy_id: UUID,
                       version_id: UUID) -> PolicyVersionView:
    version = _locked_version(session, user.tenant_id, policy_id, version_id)
    if not _status_of(session, version).active:
        raise Conflict("This policy version is not active.", code="NOT_ACTIVE")
    return _record_event(session, user, now, version, "DEACTIVATED")


def applicable_documents(session: Session, now: datetime) -> list[VersionedDocument]:
    """Versions that are approved, active, and inside their effective window, hash checked.

    Every approved and active version is checked, inside the window or not, and a failure raises
    PolicyIntegrityError instead of dropping the version. A version past its review date still
    applies, and is marked so the engine can report it.
    """
    active_ids = [
        version_id for version_id, status in _statuses(session).items()
        if status.approval is not None and status.active
    ]
    rows = session.execute(
        select(GovernancePolicyVersion, GovernancePolicy.name)
        .join(GovernancePolicy, GovernancePolicy.id == GovernancePolicyVersion.policy_id)
        .where(GovernancePolicyVersion.id.in_(active_ids))
        .order_by(func.lower(GovernancePolicy.name), GovernancePolicyVersion.version)
    ).all()
    documents = []
    for version, name in rows:
        document = parse_version(version)
        if now < version.effective_from:
            continue
        documents.append(
            VersionedDocument(
                version_id=version.id,
                policy_id=version.policy_id,
                name=name,
                document=document,
                review_overdue=version.review_by is not None and now > version.review_by,
            )
        )
    return documents
