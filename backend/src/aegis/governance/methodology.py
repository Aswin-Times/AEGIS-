"""The built-in risk methodology, version 1: the document the risk engine is driven by."""

from aegis.governance.engine.risk import Methodology

BUILT_IN_METHODOLOGY = Methodology.model_validate(
    {
        "factors": [
            {
                "id": "data_sensitivity",
                "label": "Data sensitivity",
                "weight": 20,
                "input": "data_categories",
                "levels": {
                    "public": 0,
                    "internal": 1,
                    "personal": 3,
                    "confidential": 3,
                    "regulated": 4,
                },
            },
            {
                "id": "external_exposure",
                "label": "External exposure",
                "weight": 10,
                "input": "external_exposure",
                "levels": {"none": 0, "internal_users": 1, "partners": 2, "public": 4},
            },
            {
                "id": "agent_autonomy",
                "label": "Agent autonomy",
                "weight": 20,
                "input": "autonomy_level",
                "levels": {
                    "advisory": 0,
                    "human_approved": 1,
                    "supervised": 2,
                    "bounded": 3,
                    "autonomous": 4,
                },
            },
            {
                "id": "tool_access",
                "label": "Tool access",
                "weight": 15,
                "input": "tool_access_level",
                "levels": {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4},
            },
            {
                "id": "human_oversight",
                "label": "Human oversight",
                "weight": 15,
                "input": "human_oversight",
                "levels": {"in_the_loop": 0, "on_the_loop": 2, "after_the_fact": 3, "none": 4},
            },
            {
                "id": "business_impact",
                "label": "Business and user impact",
                "weight": 10,
                "input": "impact_level",
                "levels": {"negligible": 0, "minor": 1, "moderate": 2, "major": 3, "severe": 4},
            },
            {
                "id": "deployment_environment",
                "label": "Deployment environment",
                "weight": 5,
                "input": "deployment_environment",
                "levels": {
                    "development": 0,
                    "test": 1,
                    "staging": 2,
                    "production_internal": 3,
                    "production_external": 4,
                },
            },
            {
                "id": "third_party_reliance",
                "label": "Third-party reliance",
                "weight": 5,
                "input": "third_party_reliance",
                "levels": {"none": 0, "vetted": 1, "partially_vetted": 2, "unvetted": 4},
            },
        ],
        "thresholds": {"medium": 100, "high": 200, "critical": 300},
        "floors": [
            {
                "id": "autonomy_with_sensitive_data",
                "description": (
                    "An asset that acts with bounded or full autonomy on personal, confidential, "
                    "or regulated data is at least HIGH, however low its other factors are."
                ),
                "minimum_level": "HIGH",
                "when": {"agent_autonomy": 3, "data_sensitivity": 3},
            },
            {
                "id": "unsupervised_transmit",
                "description": (
                    "A fully autonomous asset with no human oversight and a tool that can "
                    "transmit data out is CRITICAL, however low its other factors are."
                ),
                "minimum_level": "CRITICAL",
                "when": {"agent_autonomy": 4, "human_oversight": 4, "tool_access": 4},
            },
        ],
        "mitigations": {
            "data_sensitivity": {
                "3": [
                    "Limit the asset to the minimum personal or confidential data its purpose "
                    "needs, and record why each category is required.",
                    "Keep prompts, outputs, and logs that contain this data under the same "
                    "retention and access limits as the source data.",
                ],
                "4": [
                    "Confirm there is a documented legal or contractual basis for processing "
                    "regulated data with this asset before it is approved.",
                    "Have the data owner approve this use explicitly, and review that approval "
                    "whenever the asset's data sources change.",
                ],
            },
            "external_exposure": {
                "4": [
                    "Test the asset against hostile input before release, since anyone on the "
                    "public internet can reach it.",
                    "Apply rate limits and abuse monitoring, and decide in advance who can "
                    "switch the asset off if it is misused.",
                ],
            },
            "agent_autonomy": {
                "3": [
                    "Bound what the agent can do in one run, and require a person to approve "
                    "any action outside that bound.",
                    "Review a sample of the agent's recorded actions on a fixed schedule.",
                ],
                "4": [
                    "Require human approval for consequential or irreversible actions until "
                    "the agent has a reviewed track record.",
                    "Keep a tested way to stop the agent immediately, owned by a named person.",
                ],
            },
            "tool_access": {
                "3": [
                    "Grant read access to sensitive resources only for the specific resources "
                    "the task needs, and review those grants periodically.",
                ],
                "4": [
                    "Require approval before the agent transmits data outside the organization, "
                    "and restrict the destinations it may send to.",
                    "Remove any transmit tool that the asset's purpose does not strictly need.",
                ],
            },
            "human_oversight": {
                "3": [
                    "Review the asset's outputs and actions at a regular interval, and name the "
                    "reviewer responsible for doing so.",
                ],
                "4": [
                    "Add a point where a person can review or approve what the asset does, "
                    "before relying on it for anything consequential.",
                    "If no oversight is possible, document why and have the risk accepted by a "
                    "named senior owner.",
                ],
            },
            "business_impact": {
                "3": [
                    "Define a fallback process so the business can continue if the asset "
                    "fails or must be switched off.",
                ],
                "4": [
                    "Run a documented impact review with the business owner before approval, "
                    "and repeat it when the asset's use changes.",
                    "Agree in advance how errors that affect people will be detected, "
                    "corrected, and reported.",
                ],
            },
            "deployment_environment": {
                "3": [
                    "Confirm the asset has been tested in a pre-production environment that "
                    "matches production before it is released.",
                ],
                "4": [
                    "Keep a release and rollback procedure for the asset, and monitor it "
                    "closely after each change.",
                ],
            },
            "third_party_reliance": {
                "4": [
                    "Assess the third-party provider before relying on it: where data goes, "
                    "how it is retained, and what happens if the provider changes or fails.",
                    "Record a contract or terms review for the provider and plan for its "
                    "replacement.",
                ],
            },
        },
        "provenance_note": (
            "These weights, level maps, thresholds, and floors are engineering judgment, not "
            "values taken from any standard or regulation. They are a starting point for "
            "consistent, explainable scoring, and an organization should review them before "
            "relying on them."
        ),
    }
)
