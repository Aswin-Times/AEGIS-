"""Deterministic findings. The same evidence always produces the same statements.

Nothing here states more than the records show, and what they cannot show is a stated gap. No
statement uses the run's own time or anything else that differs between runs.
"""

from collections import Counter
from dataclasses import dataclass, field

from aegis.audit.chain import ChainVerification
from aegis.canonical import canonical_hash
from aegis.investigation.evidence import CollectedEvidence, EvidenceRef, ref

ENGINE_VERSION = 1
_MAX_REFS = 200


@dataclass(frozen=True)
class DraftFinding:
    kind: str
    statement: str
    refs: list[EvidenceRef] = field(default_factory=list)


def input_fingerprint(evidence: CollectedEvidence) -> str:
    return canonical_hash(
        {
            "engine_version": ENGINE_VERSION,
            "incident": str(evidence.incident.id),
            "rule_version": str(evidence.incident.rule_version_id),
            "verified": [
                [str(event.id), event.source_event_hash] for event in evidence.verified_events
            ],
            "failed": [str(event.id) for event in evidence.failed_events],
            "decisions": [str(item.id) for item in evidence.decisions],
            "approvals": [[str(item.id), item.status] for item in evidence.approvals],
            "executions": [[str(item.id), item.status] for item in evidence.executions],
        }
    )


def _time(value) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def _facts(evidence: CollectedEvidence, chain: ChainVerification) -> list[DraftFinding]:
    events = evidence.verified_events
    event_refs = [ref("security_event", event.id) for event in events][:_MAX_REFS]
    facts: list[DraftFinding] = []
    if events:
        facts.append(
            DraftFinding(
                "observed_fact",
                f"{len(events)} verified security events are linked to this incident, from "
                f"{_time(events[0].occurred_at)} to {_time(events[-1].occurred_at)}.",
                event_refs,
            )
        )
    combinations = Counter((event.event_type, event.reason_code) for event in events)
    for (event_type, reason), count in sorted(combinations.items()):
        facts.append(
            DraftFinding(
                "observed_fact",
                f"{count} events of type {event_type} have reason {reason}.",
                [
                    ref("security_event", event.id)
                    for event in events
                    if (event.event_type, event.reason_code) == (event_type, reason)
                ][:_MAX_REFS],
            )
        )
    with_tool = [event for event in events if event.tool]
    if with_tool:
        tools = ", ".join(sorted({event.tool for event in with_tool}))
        facts.append(
            DraftFinding(
                "observed_fact",
                f"The requested tools were: {tools}.",
                [ref("security_event", event.id) for event in with_tool][:_MAX_REFS],
            )
        )

    executed = {execution.request_id for execution in evidence.executions}
    denied_requests = {
        event.action_request_id
        for event in events
        if event.event_type == "gateway.action_denied"
    }
    not_run = [
        decision
        for decision in evidence.decisions
        if decision.outcome == "DENY"
        and decision.request_id in denied_requests
        and decision.request_id not in executed
    ]
    if not_run:
        facts.append(
            DraftFinding(
                "observed_fact",
                f"No execution record exists for {len(not_run)} denied requests in this "
                "incident, so those tools did not run through the gateway.",
                [ref("policy_decision", decision.id) for decision in not_run][:_MAX_REFS],
            )
        )

    for status, count in sorted(Counter(item.status for item in evidence.approvals).items()):
        facts.append(
            DraftFinding(
                "observed_fact",
                f"{count} related approvals are in state {status}.",
                [ref("approval", item.id) for item in evidence.approvals if item.status == status],
            )
        )
    finished = [item for item in evidence.executions if item.status != "STARTED"]
    for status, count in sorted(Counter(item.status for item in finished).items()):
        facts.append(
            DraftFinding(
                "observed_fact",
                f"{count} related tool executions finished with status {status}.",
                [ref("execution", item.id) for item in finished if item.status == status],
            )
        )

    suppressed = [event for event in events if event.attributes.get("suppressed_since_last")]
    if suppressed:
        total = sum(event.attributes["suppressed_since_last"] for event in suppressed)
        facts.append(
            DraftFinding(
                "observed_fact",
                f"{total} further failures were counted but not individually recorded, "
                "because the failure recording limit was reached.",
                [ref("security_event", event.id) for event in suppressed][:_MAX_REFS],
            )
        )
    if chain.valid:
        cited = [
            ref("audit_event", item.id) for item in evidence.audit_events
        ][:_MAX_REFS]
        if cited:
            facts.append(
                DraftFinding(
                    "observed_fact", "The audit chain passed verification during this run.", cited
                )
            )
    return facts


def _rule_result(evidence: CollectedEvidence) -> list[DraftFinding]:
    rule = evidence.rule
    events = evidence.verified_events
    if rule is None or not events:
        return []
    incident = evidence.incident
    distinct = (
        f", across at least {rule.min_distinct_targets} distinct targets"
        if rule.min_distinct_targets
        else ""
    )
    return [
        DraftFinding(
            "rule_result",
            f"Rule {incident.rule_key} version {incident.rule_version} requires at least "
            f"{rule.threshold} matching events within {rule.window_seconds} seconds per "
            f"{rule.scope}{distinct}. {len(events)} verified events are linked to this incident.",
            [ref("security_event", event.id) for event in events][:_MAX_REFS],
        )
    ]


_RULE_GAPS = {
    "repeated_transfer_denials": (
        "A denied transfer did not run through the gateway. This does not show whether data left "
        "by any other path, and message bodies sent to approved destinations are not inspected."
    ),
    "not_visible_references": (
        "AEGIS cannot confirm that these IDs belong to another organization. A record held by "
        "another organization looks the same as one that does not exist, and AEGIS deliberately "
        "does not check."
    ),
    "permission_probing": (
        "No behavioral baseline is modeled, so this shows attempts outside registered "
        "permissions, not a measured change from earlier behavior."
    ),
    "authentication_failures": (
        "Failed authentication events do not identify the source of the attempts, and an attacker "
        "who knows this organization's identifier can trigger them."
    ),
}


def _gaps(evidence: CollectedEvidence, chain: ChainVerification) -> list[DraftFinding]:
    gaps = [
        DraftFinding(
            "evidence_gap",
            "These records do not show why these requests were made. Prompts and model context "
            "are not recorded.",
        ),
        DraftFinding(
            "evidence_gap",
            "Only actions sent through the AEGIS gateway are visible. Activity that bypasses the "
            "gateway would not appear here.",
        ),
    ]
    rule_gap = _RULE_GAPS.get(evidence.incident.rule_key)
    if rule_gap:
        gaps.append(DraftFinding("evidence_gap", rule_gap))
    if evidence.rule is None:
        gaps.append(
            DraftFinding(
                "evidence_gap",
                "The rule version recorded on this incident failed its integrity check, so its "
                "definition cannot be relied on.",
            )
        )
    for event in evidence.failed_events:
        gaps.append(
            DraftFinding(
                "evidence_gap",
                f"Security event {event.id} failed verification and was excluded from these "
                "findings.",
                [ref("security_event", event.id)],
            )
        )
    for execution in evidence.executions:
        if execution.status == "STARTED":
            gaps.append(
                DraftFinding(
                    "evidence_gap",
                    f"Execution {execution.id} has no recorded outcome. Whether the tool "
                    "completed is unknown.",
                    [ref("execution", execution.id)],
                )
            )
    if len(evidence.verified_events) > _MAX_REFS:
        gaps.append(
            DraftFinding(
                "evidence_gap",
                f"This incident has more verified events than a finding cites. Each finding "
                f"references at most {_MAX_REFS}.",
            )
        )
    if chain.valid:
        gaps.append(
            DraftFinding(
                "evidence_gap",
                "Passing chain verification cannot rule out a complete rewrite by someone with "
                "full database control, because the chain is not anchored outside the database.",
            )
        )
    else:
        gaps.append(
            DraftFinding(
                "evidence_gap",
                f"The audit chain failed verification at event {chain.failure_seq} "
                f"({chain.failure_reason}), so all records in this organization should be "
                "treated with caution.",
            )
        )
    return gaps


_RULE_ACTIONS = {
    "repeated_unauthorized_tools": "Check whether this agent's tool grants match its intended use.",
    "repeated_transfer_denials": (
        "Check whether the agent's destinations and the documents it can attach are correct."
    ),
    "permission_probing": "Review this agent's tool and resource grants for over-broad access.",
    "approval_bypass_attempts": (
        "Check why this agent retries actions without a valid approval, and whether the client "
        "handles a held action correctly."
    ),
    "not_visible_references": (
        "Find out where this actor obtained the identifiers it used. Treat a leaked identifier "
        "list as a separate question."
    ),
    "authentication_failures": (
        "Check whether a credential was recently rotated. If not, consider revoking credentials "
        "that may have been exposed."
    ),
}


def _recommendations(evidence: CollectedEvidence) -> list[DraftFinding]:
    actions = []
    specific = _RULE_ACTIONS.get(evidence.incident.rule_key)
    if specific:
        actions.append(DraftFinding("recommended_action", specific))
    if evidence.incident.agent_id:
        actions.append(
            DraftFinding(
                "recommended_action",
                "If this activity is unexpected, consider disabling the agent in the Agent "
                "Registry. AEGIS does not do this automatically.",
            )
        )
    return actions


def build_findings(evidence: CollectedEvidence, chain: ChainVerification) -> list[DraftFinding]:
    return [
        *_facts(evidence, chain),
        *_rule_result(evidence),
        *_gaps(evidence, chain),
        *_recommendations(evidence),
    ]
