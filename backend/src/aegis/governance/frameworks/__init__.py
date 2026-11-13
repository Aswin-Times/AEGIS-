"""Framework libraries as code, seeded into each tenant on first use (spec 10).

A library holds only identifiers checked against its source, with descriptions written for AEGIS.
`library_status` says how much of the source is present, so a partial library never reads as
complete: NOT_LOADED has no controls, LOADED_PARTIAL a checked subset, LOADED all of them.
"""

from dataclasses import dataclass

NOT_LOADED = "NOT_LOADED"
LOADED_PARTIAL = "LOADED_PARTIAL"
LOADED = "LOADED"


@dataclass(frozen=True)
class ControlDefinition:
    identifier: str
    name: str
    description: str
    # Where in the source the identifier and its meaning were checked.
    source_reference: str
    # Evidence categories (spec 9) that can show the control is in place.
    required_evidence: tuple[str, ...]


@dataclass(frozen=True)
class FrameworkDefinition:
    key: str
    version: str
    name: str
    source_url: str | None
    source_document: str
    library_status: str
    controls: list[ControlDefinition]
    # Every identifier the source defines, or None when none could be verified.
    source_identifiers: tuple[str, ...] | None
