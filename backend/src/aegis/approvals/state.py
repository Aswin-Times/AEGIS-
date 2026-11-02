"""Approval lifecycle. A database trigger enforces the same rules independently."""

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "PENDING": {"APPROVED", "REJECTED", "CANCELLED"},
    "APPROVED": {"EXECUTED", "CANCELLED"},
    "REJECTED": set(),
    "EXECUTED": set(),
    "CANCELLED": set(),
}


def can_transition(current: str, target: str) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, set())
