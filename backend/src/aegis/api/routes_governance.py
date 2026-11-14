import json
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query

from aegis.api.dependencies import (
    AdminDep,
    ContainerDep,
    GovernanceReviewerDep,
    LimitQuery,
    OffsetQuery,
    ReviewerDep,
    SuspenderDep,
    UserDep,
)
from aegis.api.schemas import Page
from aegis.api.schemas_governance import (
    ApproveIn,
    AssessmentCreatedOut,
    AssessmentOut,
    AssessmentSummaryOut,
    AssetDecisionOut,
    AssetDetailOut,
    AssignIn,
    CompliancePage,
    ControlAssessIn,
    ControlAssessmentOut,
    ControlAssessmentSummaryOut,
    ControlOut,
    DecisionOut,
    DueReviewOut,
    EnforcementIn,
    EnforcementOut,
    EvidenceDetailOut,
    EvidenceIn,
    EvidenceOut,
    EvidenceVerificationOut,
    EvidenceVerifyIn,
    FrameworkOut,
    HistoryEntryOut,
    InventoryRowOut,
    LifecycleDecisionOut,
    LifecycleIn,
    MethodologyIn,
    MethodologyOut,
    OverviewOut,
    PersonOut,
    PolicyIn,
    PolicyOut,
    PolicyVersionIn,
    PolicyVersionOut,
    PreflightOut,
    ProfileVersionOut,
    ProfileVersionSummaryOut,
    RejectIn,
    RequestInformationIn,
    ReviewOut,
    RiskOut,
    RoleGrantIn,
    RoleGrantOut,
    SubmitIn,
)
from aegis.db.models import (
    GovernanceControlAssessment,
    GovernanceDecision,
    GovernanceEvidenceVerification,
    GovernanceReview,
)
from aegis.governance.approvals import (
    ReviewStatus,
    approve,
    assign_reviewer,
    decision_references,
    get_review,
    list_reviews,
    reject,
    request_information,
    require_reassessment,
    retire,
    submit,
    suspend,
)
from aegis.governance.assets import load_state, save_profile
from aegis.governance.compliance import (
    NO_CERTIFICATION_STATEMENT,
    ControlRecord,
    assess_control,
    ensure_frameworks,
    get_control,
    list_controls,
    list_frameworks,
)
from aegis.governance.enforcement_mode import get_mode, preflight, set_mode
from aegis.governance.engine.lifecycle import GovernanceStatus
from aegis.governance.evidence import (
    EvidenceRecord,
    get_evidence,
    linked_controls,
    list_evidence,
    record_of,
    submit_evidence,
    verification_history,
    verification_scope,
    verify_evidence,
)
from aegis.governance.inventory import asset_detail, asset_history, list_inventory, overview
from aegis.governance.policies import (
    activate_version,
    approve_version,
    create_policy,
    create_version,
    deactivate_version,
    list_policies,
)
from aegis.governance.profile import AssetProfile
from aegis.governance.reviews import list_due
from aegis.governance.risk import (
    AssessmentRecord,
    activate_methodology_version,
    approve_methodology_version,
    create_methodology_version,
    latest_assessment,
    list_assessments,
    list_methodologies,
    recomputes_to_stored_result,
    run_assessment,
)
from aegis.governance.roles import grant_role, list_people, revoke_grant
from aegis.security.principals import ADMIN, REVIEWER

router = APIRouter(prefix="/governance")


# People and role grants


@router.get("/people", response_model=Page[PersonOut])
def people_list(user: ReviewerDep, container: ContainerDep, limit: LimitQuery = 50,
                offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        rows, total = list_people(session, limit=limit, offset=offset)
        return Page[PersonOut](
            items=[
                PersonOut(id=person.id, email=person.email, role=person.role,
                          reviewer_grant_id=grant_id)
                for person, grant_id in rows
            ],
            total=total, limit=limit, offset=offset,
        )


@router.post("/role-grants", response_model=RoleGrantOut, status_code=201)
def role_grants_create(body: RoleGrantIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return RoleGrantOut.model_validate(
            grant_role(session, user, container.clock(), user_id=body.user_id)
        )


@router.post("/role-grants/{id}/revoke", response_model=RoleGrantOut)
def role_grants_revoke(id: UUID, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return RoleGrantOut.model_validate(revoke_grant(session, user, container.clock(), id))


# Assets


@router.get("/overview", response_model=OverviewOut)
def governance_overview(user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return OverviewOut.model_validate(overview(session, container.clock()))


@router.get("/assets", response_model=Page[InventoryRowOut])
def assets_list(
    user: UserDep,
    container: ContainerDep,
    search: Annotated[str | None, Query(max_length=200)] = None,
    risk: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    declared_risk: Literal["low", "medium", "high", "critical"] | None = None,
    status: GovernanceStatus | None = None,
    owner_id: UUID | None = None,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    with container.db.tenant_transaction(user.tenant_id) as session:
        rows, total = list_inventory(
            session, search=search, risk=risk, declared_risk=declared_risk,
            status=status.value if status else None, owner_id=owner_id, limit=limit,
            offset=offset,
        )
        return Page[InventoryRowOut](
            items=[InventoryRowOut.model_validate(row) for row in rows],
            total=total, limit=limit, offset=offset,
        )


@router.get("/assets/{id}", response_model=AssetDetailOut)
def asset_get(id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return AssetDetailOut.model_validate(asset_detail(session, id))


@router.post("/assets/{id}/profile", response_model=ProfileVersionOut, status_code=201)
def asset_profile_save(id: UUID, body: AssetProfile, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        version = save_profile(session, user, container.clock(), id, body)
        return ProfileVersionOut(
            id=version.id,
            asset_id=version.asset_id,
            version=version.version,
            profile=json.loads(version.profile_canonical),
            content_hash=version.content_hash,
            created_by=version.created_by,
            created_at=version.created_at,
            governance_status=load_state(session, id).status,
        )


# Risk assessments


def _summary_fields(record: AssessmentRecord) -> dict:
    assessment = record.assessment
    return {
        "id": assessment.id,
        "asset_id": assessment.asset_id,
        "profile_version_id": assessment.profile_version_id,
        "methodology_version_id": assessment.methodology_version_id,
        "methodology_version": record.methodology_version,
        "input_hash": assessment.input_hash,
        "result_hash": assessment.result_hash,
        "status": assessment.status,
        "score": assessment.score,
        "risk_level": assessment.risk_level,
        "assessed_by": assessment.assessed_by,
        "assessed_at": assessment.created_at,
        "audit_event_id": assessment.audit_event_id,
    }


def _stored_document(canonical: str) -> dict | None:
    """None if the stored text is not a JSON object, which is what a tampered row looks like."""
    try:
        document = json.loads(canonical)
    except ValueError:
        return None
    return document if isinstance(document, dict) else None


def _assessment_out(record: AssessmentRecord) -> AssessmentOut:
    return AssessmentOut(
        **_summary_fields(record),
        input=_stored_document(record.assessment.input_canonical),
        result=_stored_document(record.assessment.result_canonical),
    )


@router.post("/assets/{id}/assess", response_model=AssessmentCreatedOut, status_code=201)
def asset_assess(id: UUID, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        run_assessment(session, container.tools, user, container.clock(), id)
        record = latest_assessment(session, id)
        return AssessmentCreatedOut(
            **_assessment_out(record).model_dump(),
            governance_status=load_state(session, id).status,
        )


@router.get("/assets/{id}/risk", response_model=RiskOut)
def asset_risk(id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        record = latest_assessment(session, id)
        if record is None:
            return RiskOut(assessment=None, recomputed_matches=None)
        return RiskOut(
            assessment=_assessment_out(record),
            recomputed_matches=recomputes_to_stored_result(session, record.assessment),
        )


@router.get("/assets/{id}/assessments", response_model=Page[AssessmentSummaryOut])
def asset_assessments(id: UUID, user: UserDep, container: ContainerDep,
                      limit: LimitQuery = 50, offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        records, total = list_assessments(session, id, limit=limit, offset=offset)
        return Page[AssessmentSummaryOut](
            items=[AssessmentSummaryOut(**_summary_fields(record)) for record in records],
            total=total, limit=limit, offset=offset,
        )


# Risk methodology versions


@router.get("/methodologies", response_model=Page[MethodologyOut])
def methodologies_list(user: UserDep, container: ContainerDep, limit: LimitQuery = 50,
                       offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        views, total = list_methodologies(
            session, user.tenant_id, container.clock(), limit=limit, offset=offset
        )
        return Page[MethodologyOut](
            items=[MethodologyOut.model_validate(view) for view in views],
            total=total, limit=limit, offset=offset,
        )


@router.post("/methodologies", response_model=MethodologyOut, status_code=201)
def methodologies_create(body: MethodologyIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return MethodologyOut.model_validate(
            create_methodology_version(session, user, container.clock(), body.document)
        )


@router.post("/methodologies/{id}/approve", response_model=MethodologyOut)
def methodologies_approve(id: UUID, user: GovernanceReviewerDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return MethodologyOut.model_validate(
            approve_methodology_version(session, user, container.clock(), id)
        )


@router.post("/methodologies/{id}/activate", response_model=MethodologyOut)
def methodologies_activate(id: UUID, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return MethodologyOut.model_validate(
            activate_methodology_version(session, user, container.clock(), id)
        )


# Policies


@router.get("/policies", response_model=Page[PolicyOut])
def policies_list(user: UserDep, container: ContainerDep, limit: LimitQuery = 50,
                  offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        views, total = list_policies(session, limit=limit, offset=offset)
        return Page[PolicyOut](
            items=[PolicyOut.model_validate(view) for view in views],
            total=total, limit=limit, offset=offset,
        )


@router.post("/policies", response_model=PolicyOut, status_code=201)
def policies_create(body: PolicyIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return PolicyOut.model_validate(
            create_policy(session, user, container.clock(), body.name, body.category)
        )


@router.post("/policies/{policy_id}/versions", response_model=PolicyVersionOut, status_code=201)
def policy_versions_create(policy_id: UUID, body: PolicyVersionIn, user: AdminDep,
                           container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return PolicyVersionOut.model_validate(
            create_version(session, user, container.clock(), policy_id, body.document,
                           body.effective_from, body.review_by)
        )


@router.post("/policies/{policy_id}/versions/{id}/approve", response_model=PolicyVersionOut)
def policy_versions_approve(policy_id: UUID, id: UUID, user: GovernanceReviewerDep,
                            container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return PolicyVersionOut.model_validate(
            approve_version(session, user, container.clock(), policy_id, id)
        )


@router.post("/policies/{policy_id}/versions/{id}/activate", response_model=PolicyVersionOut)
def policy_versions_activate(policy_id: UUID, id: UUID, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return PolicyVersionOut.model_validate(
            activate_version(session, user, container.clock(), policy_id, id)
        )


@router.post("/policies/{policy_id}/versions/{id}/deactivate", response_model=PolicyVersionOut)
def policy_versions_deactivate(policy_id: UUID, id: UUID, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return PolicyVersionOut.model_validate(
            deactivate_version(session, user, container.clock(), policy_id, id)
        )


# Submission and reviews


def _review_out(review: GovernanceReview) -> ReviewOut:
    return ReviewOut(
        id=review.id,
        asset_id=review.asset_id,
        assessment_id=review.assessment_id,
        profile_version_id=review.profile_version_id,
        submitted_by=review.submitted_by,
        assigned_reviewer=review.assigned_reviewer,
        required_approvers=review.required_approvers,
        status=review.status,
        version=review.version,
        submitted_at=review.submitted_at,
        closed_at=review.closed_at,
        required_controls=json.loads(review.required_controls_canonical),
        findings=json.loads(review.findings_canonical),
    )


@router.post("/assets/{id}/submit", response_model=ReviewOut, status_code=201)
def asset_submit(id: UUID, body: SubmitIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _review_out(
            submit(session, container.tools, user, container.clock(), id, reason=body.reason)
        )


@router.get("/approvals", response_model=Page[ReviewOut])
def approvals_list(
    user: UserDep,
    container: ContainerDep,
    status: ReviewStatus | None = None,
    asset_id: UUID | None = None,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    with container.db.tenant_transaction(user.tenant_id) as session:
        reviews, total = list_reviews(
            session, status=status.value if status else None, asset_id=asset_id, limit=limit,
            offset=offset,
        )
        return Page[ReviewOut](
            items=[_review_out(review) for review in reviews],
            total=total, limit=limit, offset=offset,
        )


@router.get("/approvals/{id}", response_model=ReviewOut)
def approvals_get(id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _review_out(get_review(session, id))


@router.post("/approvals/{id}/assign", response_model=ReviewOut)
def approvals_assign(id: UUID, body: AssignIn, user: GovernanceReviewerDep,
                     container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _review_out(
            assign_reviewer(session, user, container.clock(), id, body.reviewer_id)
        )


@router.post("/approvals/{id}/request-information", response_model=ReviewOut)
def approvals_request_information(id: UUID, body: RequestInformationIn,
                                  user: GovernanceReviewerDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return _review_out(
            request_information(session, user, container.clock(), id, reason=body.reason)
        )


def _asset_decision_out(session, decision: GovernanceDecision) -> AssetDecisionOut:
    policy_versions, evidence = decision_references(session, decision)
    return AssetDecisionOut(
        id=decision.id,
        asset_id=decision.asset_id,
        review_id=decision.review_id,
        kind=decision.kind,
        from_status=decision.from_status,
        to_status=decision.to_status,
        actor_type=decision.actor_type,
        decided_by=decision.decided_by,
        decided_at=decision.decided_at,
        reason=decision.reason,
        assessment_id=decision.assessment_id,
        conditions=(None if decision.conditions_canonical is None
                    else json.loads(decision.conditions_canonical)),
        conditions_hash=decision.conditions_hash,
        valid_until=decision.valid_until,
        next_review_at=decision.next_review_at,
        audit_event_id=decision.audit_event_id,
        policy_version_ids=policy_versions,
        evidence_ids=evidence,
    )


def _decision_out(session, decision: GovernanceDecision) -> DecisionOut:
    fields = _asset_decision_out(session, decision).model_dump(exclude={"actor_type"})
    review = session.get(GovernanceReview, decision.review_id)
    return DecisionOut(
        **fields,
        review_status=review.status,
        governance_status=load_state(session, decision.asset_id).status,
    )


@router.post("/approvals/{id}/approve", response_model=DecisionOut, status_code=201)
def approvals_approve(id: UUID, body: ApproveIn, user: GovernanceReviewerDep,
                      container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        decision = approve(
            session, container.tools, user, container.clock(), id, reason=body.reason,
            valid_until=body.valid_until, next_review_at=body.next_review_at,
            conditions=body.conditions, evidence_ids=body.evidence_ids,
        )
        return _decision_out(session, decision)


@router.post("/approvals/{id}/reject", response_model=DecisionOut, status_code=201)
def approvals_reject(id: UUID, body: RejectIn, user: GovernanceReviewerDep,
                     container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        decision = reject(session, user, container.clock(), id, reason=body.reason)
        return _decision_out(session, decision)


# Suspension, reassessment, and retirement


def _lifecycle_out(session, decision: GovernanceDecision) -> LifecycleDecisionOut:
    return LifecycleDecisionOut(
        **_asset_decision_out(session, decision).model_dump(),
        governance_status=load_state(session, decision.asset_id).status,
    )


@router.post("/assets/{id}/suspend", response_model=LifecycleDecisionOut, status_code=201)
def asset_suspend(id: UUID, body: LifecycleIn, user: SuspenderDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        decision = suspend(session, user, container.clock(), id, reason=body.reason)
        return _lifecycle_out(session, decision)


@router.post("/assets/{id}/revoke", response_model=LifecycleDecisionOut, status_code=201)
def asset_revoke(id: UUID, body: LifecycleIn, user: SuspenderDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        decision = suspend(session, user, container.clock(), id, reason=body.reason,
                           kind="REVOKE")
        return _lifecycle_out(session, decision)


@router.post("/assets/{id}/reassess", response_model=LifecycleDecisionOut, status_code=201)
def asset_reassess(id: UUID, body: LifecycleIn, user: SuspenderDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        decision = require_reassessment(session, "user", user.id, container.clock(), id,
                                        reason=body.reason)
        return _lifecycle_out(session, decision)


@router.post("/assets/{id}/retire", response_model=LifecycleDecisionOut, status_code=201)
def asset_retire(id: UUID, body: LifecycleIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        decision = retire(session, user, container.clock(), id, reason=body.reason)
        return _lifecycle_out(session, decision)


@router.get("/assets/{id}/history", response_model=Page[HistoryEntryOut])
def asset_history_list(id: UUID, user: UserDep, container: ContainerDep,
                       limit: LimitQuery = 50, offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        entries, total = asset_history(session, id, limit=limit, offset=offset)
        items = []
        for entry in entries:
            common = {"type": entry.type, "seq": entry.seq,
                      "audit_event_id": entry.audit_event_id, "kind": None, "decision": None,
                      "assessment": None, "profile_version": None}
            if entry.type == "decision":
                common.update(id=entry.record.id, kind=entry.record.kind,
                              decision=_asset_decision_out(session, entry.record))
            elif entry.type == "assessment":
                common.update(id=entry.record.assessment.id,
                              assessment=AssessmentSummaryOut(**_summary_fields(entry.record)))
            else:
                version = entry.record
                common.update(id=version.id, profile_version=ProfileVersionSummaryOut(
                    id=version.id, version=version.version, content_hash=version.content_hash,
                    created_by=version.created_by, created_at=version.created_at))
            items.append(HistoryEntryOut(**common))
        return Page[HistoryEntryOut](items=items, total=total, limit=limit, offset=offset)


# Evidence


def _verification_out(evidence, verification: GovernanceEvidenceVerification
                      ) -> EvidenceVerificationOut:
    return EvidenceVerificationOut(
        id=verification.id, evidence_id=verification.evidence_id, outcome=verification.outcome,
        method=verification.method, note=verification.note, verified_by=verification.verified_by,
        verified_at=verification.verified_at, audit_event_id=verification.audit_event_id,
        scope=verification_scope(evidence, verification.outcome, verification.method),
    )


def _evidence_fields(user, record: EvidenceRecord, controls: dict[UUID, list[UUID]]) -> dict:
    evidence = record.evidence
    kind = record_of(evidence)
    return dict(
        id=evidence.id, asset_id=evidence.asset_id, category=evidence.category,
        description=evidence.description, source_type=evidence.source_type,
        submitted_by=evidence.submitted_by, created_at=evidence.created_at,
        content_sha256=evidence.content_sha256, source_uri=evidence.source_uri,
        record_type=None if kind is None else kind[0],
        record_id=None if kind is None else kind[1],
        # Inline text can hold anything, so a viewer sees the hash and metadata only.
        content_text=evidence.content_text if user.role in (ADMIN, REVIEWER) else None,
        control_ids=controls.get(evidence.id, []),
        current_verification=record.status,
        latest_verification=(None if record.latest is None
                             else _verification_out(evidence, record.latest)),
    )


@router.get("/evidence", response_model=Page[EvidenceOut])
def evidence_list(
    user: UserDep,
    container: ContainerDep,
    asset_id: UUID | None = None,
    category: str | None = None,
    verification: Literal["UNVERIFIED", "VERIFIED", "REJECTED"] | None = None,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    with container.db.tenant_transaction(user.tenant_id) as session:
        records, total = list_evidence(session, asset_id=asset_id, category=category,
                                       status=verification, limit=limit, offset=offset)
        controls = linked_controls(session, [record.evidence.id for record in records])
        return Page[EvidenceOut](
            items=[EvidenceOut(**_evidence_fields(user, record, controls)) for record in records],
            total=total, limit=limit, offset=offset,
        )


@router.post("/evidence", response_model=EvidenceOut, status_code=201)
def evidence_create(body: EvidenceIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        evidence = submit_evidence(
            session, user, container.clock(), asset_id=body.asset_id, category=body.category,
            description=body.description, source=body.source, control_ids=body.control_ids,
        )
        record = get_evidence(session, evidence.id)
        return EvidenceOut(**_evidence_fields(user, record,
                                              linked_controls(session, [evidence.id])))


@router.get("/evidence/{id}", response_model=EvidenceDetailOut)
def evidence_detail(id: UUID, user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        record = get_evidence(session, id)
        history = [_verification_out(record.evidence, item)
                   for item in verification_history(session, id)]
        return EvidenceDetailOut(**_evidence_fields(user, record, linked_controls(session, [id])),
                                 verifications=history)


@router.post("/evidence/{id}/verify", response_model=EvidenceVerificationOut, status_code=201)
def evidence_verify(id: UUID, body: EvidenceVerifyIn, user: GovernanceReviewerDep,
                    container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        verification = verify_evidence(
            session, user, container.clock(), id, outcome=body.outcome, method=body.method,
            note=body.note, content=body.content,
        )
        return _verification_out(get_evidence(session, id).evidence, verification)


# Compliance


def _assessment_fields(assessment: GovernanceControlAssessment, evidence_ids: list[UUID]) -> dict:
    return dict(
        id=assessment.id, status=assessment.status, note=assessment.note,
        assessed_by=assessment.assessed_by, assessed_at=assessment.assessed_at,
        audit_event_id=assessment.audit_event_id, evidence_ids=evidence_ids,
    )


def _control_out(record: ControlRecord) -> ControlOut:
    control = record.control
    return ControlOut(
        id=control.id, framework_id=control.framework_id, framework_key=record.framework_key,
        identifier=control.control_identifier, name=control.name,
        description=control.description, source_reference=control.source_reference,
        required_evidence=control.required_evidence, current_status=record.current_status,
        latest_assessment=(
            None if record.latest is None
            else ControlAssessmentSummaryOut(
                **_assessment_fields(record.latest, record.latest_evidence_ids))
        ),
        verified_evidence_count=record.verified_evidence_count,
        linked_evidence_count=record.linked_evidence_count,
    )


@router.get("/frameworks", response_model=CompliancePage[FrameworkOut])
def frameworks_list(user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        ensure_frameworks(session, user.tenant_id, container.clock())
        items = [
            FrameworkOut(
                id=summary.framework.id, key=summary.framework.key,
                version=summary.framework.version, name=summary.framework.name,
                source_url=summary.framework.source_url,
                source_document=summary.framework.source_document,
                library_status=summary.framework.library_status,
                control_count=summary.control_count,
                source_control_count=summary.framework.source_control_count,
                coverage=summary.coverage, status_counts=summary.status_counts,
            )
            for summary in list_frameworks(session)
        ]
        return CompliancePage[FrameworkOut](items=items, total=len(items), limit=len(items),
                                            offset=0, statement=NO_CERTIFICATION_STATEMENT)


@router.get("/controls", response_model=CompliancePage[ControlOut])
def controls_list(
    user: UserDep,
    container: ContainerDep,
    framework_id: UUID | None = None,
    status: Literal["NOT_ASSESSED", "EVIDENCE_REQUIRED", "IMPLEMENTED", "PARTIALLY_IMPLEMENTED",
                    "NOT_IMPLEMENTED", "NOT_APPLICABLE"] | None = None,
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
):
    with container.db.tenant_transaction(user.tenant_id) as session:
        ensure_frameworks(session, user.tenant_id, container.clock())
        records, total = list_controls(session, framework_id=framework_id, status=status,
                                       limit=limit, offset=offset)
        return CompliancePage[ControlOut](
            items=[_control_out(record) for record in records], total=total, limit=limit,
            offset=offset, statement=NO_CERTIFICATION_STATEMENT,
        )


@router.post("/controls/{id}/assess", response_model=ControlAssessmentOut, status_code=201)
def controls_assess(id: UUID, body: ControlAssessIn, user: GovernanceReviewerDep,
                    container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        assessment = assess_control(session, user, container.clock(), id, status=body.status,
                                    note=body.note, evidence_ids=body.evidence_ids)
        record = get_control(session, id)
        return ControlAssessmentOut(
            **_assessment_fields(assessment, record.latest_evidence_ids),
            control_id=id, current_status=record.current_status,
            statement=NO_CERTIFICATION_STATEMENT,
        )


# Scheduled reviews


@router.get("/reviews/due", response_model=Page[DueReviewOut])
def reviews_due(user: UserDep, container: ContainerDep,
                window_days: Annotated[int, Query(ge=0, le=365)] = 30,
                limit: LimitQuery = 50, offset: OffsetQuery = 0):
    with container.db.tenant_transaction(user.tenant_id) as session:
        rows, total = list_due(session, container.clock(), window_days=window_days, limit=limit,
                               offset=offset)
        return Page[DueReviewOut](
            items=[DueReviewOut.model_validate(row) for row in rows],
            total=total, limit=limit, offset=offset,
        )


# Enforcement mode


@router.get("/enforcement", response_model=EnforcementOut)
def enforcement_get(user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return EnforcementOut(enforcement_mode=get_mode(session))


@router.post("/enforcement", response_model=EnforcementOut)
def enforcement_set(body: EnforcementIn, user: AdminDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        settings = set_mode(session, user, container.clock(), mode=body.mode, reason=body.reason)
        return EnforcementOut(enforcement_mode=settings.enforcement_mode)


@router.get("/enforcement/preflight", response_model=PreflightOut)
def enforcement_preflight(user: UserDep, container: ContainerDep):
    with container.db.tenant_transaction(user.tenant_id) as session:
        return PreflightOut.model_validate(preflight(session, container.clock()))
