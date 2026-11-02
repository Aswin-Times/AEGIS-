"""The prompt's incident block is an exact allowlist. New fields must be chosen deliberately."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from aegis.investigation.evidence import CollectedEvidence
from aegis.investigation.hypotheses import build_prompt


def test_prompt_incident_block_is_an_exact_allowlist():
    event = SimpleNamespace(
        id=uuid4(),
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        event_type="gateway.action_denied",
        severity="high",
        reason_code="UNKNOWN_TOOL",
        tool="run_shell_command",
        action=None,
    )
    incident = SimpleNamespace(
        rule_key="repeated_unauthorized_tools",
        rule_version=1,
        severity="high",
        scope_type="agent",
        scope_key="agent:private",
        title="Private title",
    )
    prompt = build_prompt(
        CollectedEvidence(
            incident=incident,
            rule=None,
            verified_events=[event],
            failed_events=[],
            decisions=[],
            approvals=[],
            executions=[],
            audit_events=[],
        )
    )
    start = prompt.user.index("<evidence>") + len("<evidence>")
    data = json.loads(prompt.user[start : prompt.user.index("</evidence>")])
    assert set(data["incident"]) == {"rule_key", "rule_version", "severity", "scope_type"}
    assert "private" not in prompt.user.lower()
    assert set(data["items"][0]) == {
        "ref", "occurred_at", "event_type", "severity", "reason_code", "tool"
    }
