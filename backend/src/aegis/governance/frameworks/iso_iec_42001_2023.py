"""ISO/IEC 42001:2023. The record exists, but no controls ship.

The Annex A identifiers could not be verified against an authoritative copy, so none are claimed.
Loading the library later means adding controls from a licensed copy, with identifiers and
AEGIS-written descriptions rather than ISO's text (spec 10).
"""

from aegis.governance.frameworks import NOT_LOADED, FrameworkDefinition

ISO = FrameworkDefinition(
    key="iso_iec_42001",
    version="2023",
    name="ISO/IEC 42001",
    source_url=None,
    source_document="ISO/IEC 42001:2023, artificial intelligence management system",
    library_status=NOT_LOADED,
    controls=[],
    source_identifiers=None,
)
