"""Incident lifecycle. A database trigger enforces the same transitions independently."""

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "OPEN": {"ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"},
    "ACKNOWLEDGED": {"INVESTIGATING", "RESOLVED"},
    "INVESTIGATING": {"RESOLVED"},
    "RESOLVED": {"CLOSED", "INVESTIGATING"},
    "CLOSED": set(),
}

# At most one incident in these states per rule and scope, enforced by a partial unique index.
ACTIVE_STATUSES = ("OPEN", "ACKNOWLEDGED", "INVESTIGATING")


def can_transition(current: str, target: str) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, set())
