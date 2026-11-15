"""The shipped framework libraries say only what their sources were checked to say."""

import re

from aegis.governance.compliance import FRAMEWORKS
from aegis.governance.frameworks.iso_iec_42001_2023 import ISO
from aegis.governance.frameworks.nist_ai_rmf_1_0 import NIST
from aegis.governance.frameworks.nist_ai_rmf_1_0_identifiers import SOURCE_IDENTIFIERS
from aegis.governance.policy_schema import EvidenceCategory

CATEGORIES = set(EvidenceCategory.__args__)
TABLES = {"GOVERN": 1, "MAP": 2, "MEASURE": 3, "MANAGE": 4}
REFERENCE = re.compile(r"^NIST AI 100-1, Table ([1-4]) \(([A-Z]+)\), p\. (\d+)$")


def test_every_shipped_nist_identifier_is_in_the_source_list():
    shipped = [control.identifier for control in NIST.controls]
    assert shipped
    assert set(shipped) <= set(SOURCE_IDENTIFIERS)
    assert len(shipped) == len(set(shipped))


def test_the_source_list_is_the_whole_core():
    # 19 GOVERN, 18 MAP, 22 MEASURE, and 13 MANAGE subcategories, each once.
    assert len(SOURCE_IDENTIFIERS) == len(set(SOURCE_IDENTIFIERS)) == 72
    counts = {name: sum(item.startswith(f"{name} ") for item in SOURCE_IDENTIFIERS)
              for name in TABLES}
    assert counts == {"GOVERN": 19, "MAP": 18, "MEASURE": 22, "MANAGE": 13}


def test_nist_controls_have_source_references():
    for control in NIST.controls:
        match = REFERENCE.match(control.source_reference)
        assert match is not None, control.identifier
        table, function, page = match.groups()
        # The table and function named are the ones the identifier belongs to, and the page
        # lies within Tables 1 to 4 (printed pages 22 to 33).
        assert control.identifier.split(" ")[0] == function, control.identifier
        assert TABLES[function] == int(table), control.identifier
        assert 22 <= int(page) <= 33, control.identifier


def test_nist_library_is_partial_and_names_its_source():
    assert NIST.library_status == "LOADED_PARTIAL"
    assert len(NIST.controls) < len(SOURCE_IDENTIFIERS)
    assert NIST.source_identifiers == SOURCE_IDENTIFIERS
    assert NIST.source_url == "https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf"
    assert "NIST AI 100-1" in NIST.source_document


def test_iso_library_is_empty_and_not_loaded():
    assert ISO.controls == [] and ISO.library_status == "NOT_LOADED"
    # Nothing was verified, so no source count is claimed either.
    assert ISO.source_identifiers is None


def test_shipped_descriptions_are_not_empty():
    for control in NIST.controls:
        assert control.name.strip() and control.description.strip(), control.identifier
        assert len(control.name) <= 200 and len(control.description) <= 2000


def test_required_evidence_uses_the_evidence_categories():
    for control in NIST.controls:
        assert control.required_evidence, control.identifier
        assert set(control.required_evidence) <= CATEGORIES, control.identifier


def test_frameworks_are_listed_once_each():
    assert [(item.key, item.version) for item in FRAMEWORKS] == [
        (NIST.key, NIST.version), (ISO.key, ISO.version)]
