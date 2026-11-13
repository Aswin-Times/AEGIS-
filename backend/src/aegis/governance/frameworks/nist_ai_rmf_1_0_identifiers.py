"""Every subcategory identifier in the AI RMF Core, as published.

Source: NIST AI 100-1, Artificial Intelligence Risk Management Framework (AI RMF 1.0),
January 2023, https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf, retrieved 2026-11-13
(SHA-256 7576edb531d9848825814ee88e28b1795d3a84b435b4b797d3670eafdc4a89f1).

The text was extracted with pypdf, every line of the form "GOVERN 1.1:" in Tables 1 to 4
(printed pages 22 to 33) was collected, and the list was checked against those pages by reading
them. Shipped controls must come from this list; a test enforces it.
"""

SOURCE_IDENTIFIERS: tuple[str, ...] = (
    # Table 1, GOVERN: 19
    "GOVERN 1.1", "GOVERN 1.2", "GOVERN 1.3", "GOVERN 1.4", "GOVERN 1.5", "GOVERN 1.6",
    "GOVERN 1.7", "GOVERN 2.1", "GOVERN 2.2", "GOVERN 2.3", "GOVERN 3.1", "GOVERN 3.2",
    "GOVERN 4.1", "GOVERN 4.2", "GOVERN 4.3", "GOVERN 5.1", "GOVERN 5.2", "GOVERN 6.1",
    "GOVERN 6.2",
    # Table 2, MAP: 18
    "MAP 1.1", "MAP 1.2", "MAP 1.3", "MAP 1.4", "MAP 1.5", "MAP 1.6", "MAP 2.1", "MAP 2.2",
    "MAP 2.3", "MAP 3.1", "MAP 3.2", "MAP 3.3", "MAP 3.4", "MAP 3.5", "MAP 4.1", "MAP 4.2",
    "MAP 5.1", "MAP 5.2",
    # Table 3, MEASURE: 22
    "MEASURE 1.1", "MEASURE 1.2", "MEASURE 1.3", "MEASURE 2.1", "MEASURE 2.2", "MEASURE 2.3",
    "MEASURE 2.4", "MEASURE 2.5", "MEASURE 2.6", "MEASURE 2.7", "MEASURE 2.8", "MEASURE 2.9",
    "MEASURE 2.10", "MEASURE 2.11", "MEASURE 2.12", "MEASURE 2.13", "MEASURE 3.1",
    "MEASURE 3.2", "MEASURE 3.3", "MEASURE 4.1", "MEASURE 4.2", "MEASURE 4.3",
    # Table 4, MANAGE: 13
    "MANAGE 1.1", "MANAGE 1.2", "MANAGE 1.3", "MANAGE 1.4", "MANAGE 2.1", "MANAGE 2.2",
    "MANAGE 2.3", "MANAGE 2.4", "MANAGE 3.1", "MANAGE 3.2", "MANAGE 4.1", "MANAGE 4.2",
    "MANAGE 4.3",
)
