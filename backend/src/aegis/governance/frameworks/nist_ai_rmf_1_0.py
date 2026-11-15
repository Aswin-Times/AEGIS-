"""NIST AI RMF 1.0 (NIST AI 100-1), a checked subset of the Core subcategories.

Only subcategories that an AEGIS capability relates to ship: governance roles, risk tolerance,
the AI inventory, third-party risk, human oversight, evaluation, incident response, and
monitoring. Each identifier is in SOURCE_IDENTIFIERS, and each was read in its table at the page
given. Names and descriptions are AEGIS's own summaries, not NIST's wording. Pages are the
printed page numbers.
"""

from aegis.governance.frameworks import LOADED_PARTIAL, ControlDefinition, FrameworkDefinition
from aegis.governance.frameworks.nist_ai_rmf_1_0_identifiers import SOURCE_IDENTIFIERS


def _govern(page: int) -> str:
    return f"NIST AI 100-1, Table 1 (GOVERN), p. {page}"


def _map(page: int) -> str:
    return f"NIST AI 100-1, Table 2 (MAP), p. {page}"


def _measure(page: int) -> str:
    return f"NIST AI 100-1, Table 3 (MEASURE), p. {page}"


def _manage(page: int) -> str:
    return f"NIST AI 100-1, Table 4 (MANAGE), p. {page}"


CONTROLS = [
    ControlDefinition(
        "GOVERN 1.3", "Risk management scaled to risk tolerance",
        "How much risk management an AI system receives is set by the organization's own "
        "stated tolerance for risk.",
        _govern(22), ("risk_assessment", "approval_records"),
    ),
    ControlDefinition(
        "GOVERN 1.5", "Planned monitoring and periodic review",
        "The risk management process and its results are watched continuously and reviewed on "
        "a planned schedule, with the people responsible and the review frequency defined.",
        _govern(23), ("periodic_review_records", "monitoring_records"),
    ),
    ControlDefinition(
        "GOVERN 1.6", "AI system inventory",
        "The organization keeps a list of its AI systems, and resources it according to its "
        "risk priorities.",
        _govern(23), ("architecture_documentation", "approval_records"),
    ),
    ControlDefinition(
        "GOVERN 2.1", "Documented risk roles and responsibilities",
        "Who maps, measures, and manages AI risk, and how they communicate about it, is "
        "written down and understood by the people and teams concerned.",
        _govern(23), ("approval_records", "human_oversight_documentation"),
    ),
    ControlDefinition(
        "GOVERN 3.2", "Roles for human oversight",
        "Policies set out, and keep distinct, the responsibilities of people who work "
        "alongside AI systems and of those who oversee them.",
        _govern(23), ("human_oversight_documentation",),
    ),
    ControlDefinition(
        "GOVERN 4.3", "Testing and incident identification practices",
        "The organization's practices make it possible to test AI systems, to recognize "
        "incidents, and to share what was learned.",
        _govern(24), ("security_evaluation", "model_evaluation", "incident_investigation_records"),
    ),
    ControlDefinition(
        "GOVERN 6.1", "Third-party AI risk policies",
        "Policies cover the AI risks that come from outside parties, including the risk of "
        "infringing another party's intellectual property or other rights.",
        _govern(24), ("risk_assessment", "data_handling_documentation"),
    ),
    ControlDefinition(
        "GOVERN 6.2", "Contingency for third-party failures",
        "There are fallback processes for failures or incidents in outside data or AI systems "
        "that have been judged high risk.",
        _govern(24), ("incident_investigation_records", "architecture_documentation"),
    ),
    ControlDefinition(
        "MAP 1.5", "Risk tolerances set and recorded",
        "The organization decides how much AI risk it will accept, and keeps a record of that "
        "decision.",
        _map(26), ("risk_assessment", "approval_records"),
    ),
    ControlDefinition(
        "MAP 3.5", "Human oversight processes",
        "The processes by which people oversee an AI system are defined, evaluated, and "
        "recorded, consistent with the organization's governance policies.",
        _map(27), ("human_oversight_documentation",),
    ),
    ControlDefinition(
        "MAP 4.2", "Risk controls for each component",
        "The internal controls that address risk in each part of an AI system, outside AI "
        "technology included, are identified and recorded.",
        _map(27), ("architecture_documentation", "security_evaluation"),
    ),
    ControlDefinition(
        "MEASURE 2.4", "Monitoring in production",
        "After deployment, how the AI system and its parts function and behave is monitored.",
        _measure(29), ("monitoring_records",),
    ),
    ControlDefinition(
        "MEASURE 2.7", "Security and resilience evaluation",
        "The AI system's security and its ability to withstand and recover from problems are "
        "evaluated, and the results recorded.",
        _measure(30), ("security_evaluation",),
    ),
    ControlDefinition(
        "MEASURE 3.1", "Tracking risks over time",
        "People, methods, and records are in place to find and follow known, unexpected, and "
        "newly arising AI risks regularly, based on how the system performs where it is "
        "actually used.",
        _measure(30), ("monitoring_records", "risk_assessment"),
    ),
    ControlDefinition(
        "MANAGE 1.1", "Decision to proceed",
        "Someone determines whether the AI system serves its intended purpose and objectives, "
        "and whether its development or deployment should go ahead.",
        _manage(32), ("approval_records", "model_evaluation"),
    ),
    ControlDefinition(
        "MANAGE 2.4", "Means to override or deactivate",
        "Mechanisms exist and are used, with assigned responsibility, to replace, disengage, or "
        "switch off an AI system whose behavior or results do not match its intended use.",
        _manage(32), ("human_oversight_documentation", "approval_records"),
    ),
    ControlDefinition(
        "MANAGE 3.1", "Monitoring third-party resources",
        "The AI risks and benefits of outside resources are monitored regularly, and the risk "
        "controls applied to them are recorded.",
        _manage(32), ("monitoring_records", "risk_assessment"),
    ),
    ControlDefinition(
        "MANAGE 4.1", "Post-deployment monitoring plans",
        "Monitoring plans for deployed systems are in effect, covering feedback from users, "
        "appeal and override, decommissioning, incident response, recovery, and change "
        "management.",
        _manage(33), ("monitoring_records", "incident_investigation_records"),
    ),
    ControlDefinition(
        "MANAGE 4.3", "Incident tracking and communication",
        "Incidents and errors are reported to those affected, and the processes for tracking, "
        "responding to, and recovering from them are followed and recorded.",
        _manage(33), ("incident_investigation_records",),
    ),
]

NIST = FrameworkDefinition(
    key="nist_ai_rmf",
    version="1.0",
    name="NIST AI RMF",
    source_url="https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf",
    source_document="NIST AI 100-1, Artificial Intelligence Risk Management Framework "
                    "(AI RMF 1.0), January 2023",
    library_status=LOADED_PARTIAL,
    controls=CONTROLS,
    source_identifiers=SOURCE_IDENTIFIERS,
)
