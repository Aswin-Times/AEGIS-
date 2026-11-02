"""Run an investigation. It reads records and writes findings, and changes nothing else.

The deterministic findings commit first. The optional LLM step happens afterwards, outside any
transaction, so a slow or failing model cannot hold locks or lose those findings.
"""

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from aegis.audit.chain import append_event, verify_chain
from aegis.db.models import Incident, InvestigationRun
from aegis.db.session import Database
from aegis.errors import NotFound
from aegis.investigation.evidence import add_finding, collect_evidence
from aegis.investigation.findings import ENGINE_VERSION, build_findings, input_fingerprint
from aegis.investigation.hypotheses import (
    OUTPUT_SCHEMA,
    SYSTEM_PROMPT,
    CheckedOutput,
    InvalidLlmOutput,
    Prompt,
    build_prompt,
    check_output,
)
from aegis.llm.adapter import LlmProvider, LlmRequest, LlmTimeout
from aegis.security.principals import UserPrincipal

logger = logging.getLogger("aegis.investigation")


def _incident_or_404(session: Session, incident_id: UUID) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise NotFound()
    return incident


def _ask_model(
    llm: LlmProvider, prompt: Prompt, timeout_seconds: float
) -> tuple[str, CheckedOutput | None]:
    """Returns (status, checked output). Nothing a provider does can raise past this."""
    request = LlmRequest(
        system=SYSTEM_PROMPT,
        user=prompt.user,
        schema=OUTPUT_SCHEMA,
        timeout_seconds=timeout_seconds,
    )
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        raw = executor.submit(llm.complete, request).result(timeout=timeout_seconds)
    except (FutureTimeout, LlmTimeout):
        logger.warning("the LLM provider timed out")
        return "timeout", None
    except Exception as error:
        # The type only: provider messages are untrusted and may echo sensitive values.
        logger.warning("the LLM provider failed: %s", type(error).__name__)
        return "failed", None
    finally:
        executor.shutdown(wait=False)

    try:
        checked = check_output(raw, prompt.offered)
    except InvalidLlmOutput:
        logger.warning("the LLM reply did not fit the required shape")
        return "invalid_output", None
    if checked.rejected_count and not checked.accepted:
        return "invalid_output", checked
    return "succeeded", checked


def _record_llm_result(
    db: Database,
    user: UserPrincipal,
    run_id: UUID,
    position: int,
    status: str,
    checked: CheckedOutput | None,
    prompt: Prompt,
    now: datetime,
) -> InvestigationRun:
    with db.tenant_transaction(user.tenant_id) as session:
        run = session.get(InvestigationRun, run_id)
        accepted = checked.accepted if checked else []
        for offset, hypothesis in enumerate(accepted):
            add_finding(
                session,
                run,
                prompt.offered,
                kind="ai_hypothesis",
                source="llm",
                statement=hypothesis.statement,
                refs=hypothesis.refs,
                position=position + offset,
                confidence=hypothesis.confidence,
            )
        run.llm_status = status
        run.llm_rejected_count = checked.rejected_count if checked else 0
        run.llm_finished_at = now
        session.flush()
        append_event(
            session,
            user.tenant_id,
            event_type="investigation.llm_completed",
            actor_type="system",
            subject_type="investigation_run",
            subject_id=run.id,
            occurred_at=now,
            payload={
                "status": status,
                "accepted": len(accepted),
                "rejected": run.llm_rejected_count,
                "provider": run.llm_provider,
                "model": run.llm_model,
            },
        )
        return run


def run_investigation(
    db: Database,
    user: UserPrincipal,
    incident_id: UUID,
    *,
    clock: Callable[[], datetime],
    llm: LlmProvider | None = None,
    llm_timeout_seconds: float = 20.0,
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
            llm_status="pending" if llm else "not_configured",
            llm_provider=llm.name if llm else None,
            llm_model=llm.model if llm else None,
            llm_rejected_count=0,
            created_at=now,
        )
        session.add(run)
        session.flush()
        allowed = evidence.allowed_refs
        drafts = build_findings(evidence, chain)
        for position, draft in enumerate(drafts):
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
        prompt = build_prompt(evidence) if llm else None

    if llm is None:
        return run

    status, checked = _ask_model(llm, prompt, llm_timeout_seconds)
    return _record_llm_result(
        db, user, run.id, len(drafts), status, checked, prompt, clock()
    )
