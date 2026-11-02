"""The provider-independent interface. A provider turns text into text, and can do nothing else.

This package has no access to the database or to any service. Its output is untrusted data, which
the investigation code validates and stores only as an unverified hypothesis.
"""

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class LlmRequest:
    system: str
    user: str
    schema: dict[str, Any]
    timeout_seconds: float


class LlmError(Exception):
    """The provider could not produce a usable response. The message is safe to log."""


class LlmTimeout(LlmError):
    pass


class LlmRefused(LlmError):
    pass


class LlmProvider(Protocol):
    name: str
    model: str

    def complete(self, request: LlmRequest) -> str: ...
