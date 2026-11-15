"""Synthetic governance data for the demo tenant, created through the real API only.

Each asset is taken as far as its target state, so the Governance Center has something at every
stage. Every step first looks at what already exists, so running the seed again creates nothing
twice and picks up where an interrupted run stopped. Nothing here changes the enforcement mode or
any policy: the tenant stays in observe mode.

The people are the demo tenant's own users. The admin submits and the reviewer decides, so the
submitter and the approver are two different people, as the API requires. Nobody grants a role to
themselves: the admin grants governance_reviewer to the reviewer.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx

SYNTHETIC_TEAM = "Synthetic Platform Team"

# Every input low, so each asset below changes only what it is about.
LOW_PROFILE = {
    "asset_type": "ai_application",
    "description": "Synthetic profile for the demo. Not a real system.",
    "data_categories": ["public"],
    "external_exposure": "none",
    "autonomy_level": "advisory",
    "human_oversight": "in_the_loop",
    "declared_tool_access": [],
    "impact_level": "negligible",
    "deployment_environment": "development",
    "third_party_reliance": "none",
}


@dataclass(frozen=True)
class Spec:
    name: str
    intended_use: str
    # How far the seed takes the asset: incomplete, awaiting, approved, conditional, suspended.
    target: str
    profile: dict = field(default_factory=lambda: dict(LOW_PROFILE))
    evidence: str | None = None


SPECS = (
    Spec(
        "Synthetic Draft Incomplete Assessment",
        "A synthetic asset whose profile is incomplete, so its assessment has no risk level.",
        "incomplete",
        profile={"autonomy_level": "advisory"},
    ),
    Spec(
        "Synthetic Awaiting Approval Assistant",
        "A synthetic asset submitted for approval and waiting for a reviewer.",
        "awaiting",
        evidence="unverified",
    ),
    Spec(
        "Synthetic Approved Summarizer",
        "A synthetic asset approved by a reviewer who is not its submitter.",
        "approved",
    ),
    Spec(
        "Synthetic Conditionally Approved Router",
        "A synthetic asset approved with conditions the gateway enforces.",
        "conditional",
    ),
    Spec(
        "Synthetic Suspended Classifier",
        "A synthetic asset that was approved and then suspended by an administrator.",
        "suspended",
    ),
    Spec(
        "Synthetic Evidence Verified Analyzer",
        "A synthetic asset approved with evidence that a different reviewer verified.",
        "approved",
        evidence="verified",
    ),
)

# Created last: the e2e helper newRestrictedAgent attaches agents to the newest asset, and an
# asset suspended by the seed would turn those agents' test denials into GOVERNANCE_BLOCKED.
NOT_GOVERNED = (
    "Synthetic Not Governed Chatbot",
    "A synthetic asset with no governance state: no profile, assessment, or approval.",
)

_TERMINAL = {
    "incomplete": {"ASSESSMENT_REQUIRED"},
    "awaiting": {"UNDER_REVIEW"},
    "approved": {"APPROVED"},
    "conditional": {"CONDITIONALLY_APPROVED"},
    "suspended": {"SUSPENDED"},
}


class Seeder:
    def __init__(self, client: httpx.Client, admin: dict, reviewer: dict) -> None:
        self.client = client
        self.admin = admin
        self.reviewer = reviewer
        self.now = datetime.now(UTC)

    def get(self, path: str, headers: dict | None = None, **params) -> dict:
        response = self.client.get(path, headers=headers or self.admin, params=params)
        return response.raise_for_status().json()

    def post(self, path: str, body: dict, headers: dict | None = None) -> dict:
        response = self.client.post(path, json=body, headers=headers or self.admin)
        return response.raise_for_status().json()

    def listing(self, path: str, **params) -> list[dict]:
        items: list[dict] = []
        while True:
            page = self.get(path, limit=100, offset=len(items), **params)
            items.extend(page["items"])
            if not page["items"] or len(items) >= page["total"]:
                return items

    def asset(self, name: str, intended_use: str) -> dict:
        existing = next((a for a in self.listing("/assets") if a["name"] == name), None)
        if existing is not None:
            return existing
        return self.post(
            "/assets",
            {
                "name": name,
                "owner": SYNTHETIC_TEAM,
                "risk_classification": "low",
                "intended_use": f"{intended_use} Synthetic demo data.",
                "is_synthetic": True,
            },
        )

    def grant_reviewer(self, reviewer_email: str) -> None:
        people = self.listing("/governance/people")
        person = next(p for p in people if p["email"] == reviewer_email)
        if person["reviewer_grant_id"] is None:
            self.post("/governance/role-grants", {"user_id": person["id"]})

    # Evidence and controls

    def control(self, framework_prefix: str, position: int) -> dict:
        frameworks = self.get("/governance/frameworks")["items"]
        framework = next(f for f in frameworks if f["key"].startswith(framework_prefix))
        controls = self.listing("/governance/controls", framework_id=framework["id"])
        return controls[position]

    def evidence_for(self, asset: dict, control: dict, description: str) -> dict:
        existing = self.listing("/governance/evidence", asset_id=asset["id"])
        found = next((e for e in existing if e["description"] == description), None)
        if found is not None:
            return found
        return self.post(
            "/governance/evidence",
            {
                "asset_id": asset["id"],
                "category": "architecture_documentation",
                "description": description,
                "source": {
                    "source_type": "inline",
                    "content_text": "Synthetic architecture notes for the demo. Not a real system.",
                },
                "control_ids": [control["id"]],
            },
        )

    def verify(self, evidence: dict) -> dict:
        # Any earlier verification, a person's rejection included, stands: the seed never
        # overwrites a decision someone made.
        if evidence["latest_verification"] is not None:
            return evidence
        self.post(
            f"/governance/evidence/{evidence['id']}/verify",
            {
                "outcome": "VERIFIED",
                "method": "content_recomputed",
                "note": "Synthetic verification: the stored text still matches its hash.",
            },
            self.reviewer,
        )
        return self.get(f"/governance/evidence/{evidence['id']}")

    def assess_control(self, control: dict, evidence: dict) -> None:
        if control["latest_assessment"] is not None:
            return
        self.post(
            f"/governance/controls/{control['id']}/assess",
            {
                "status": "PARTIALLY_IMPLEMENTED",
                "note": "Synthetic assessment, backed by evidence a reviewer verified.",
                "evidence_ids": [evidence["id"]],
            },
            self.reviewer,
        )

    # Lifecycle

    def conditions(self, spec: Spec) -> dict | None:
        if spec.target != "conditional":
            return None
        return {
            "held_tools": ["send_message"],
            "advisory_conditions": ["Synthetic condition: review outputs weekly."],
        }

    def approve(self, review_id: str, spec: Spec, evidence_ids: list[str]) -> None:
        body = {
            "reason": "Synthetic approval for the demo.",
            "valid_until": (self.now + timedelta(days=120)).isoformat(),
            "next_review_at": (self.now + timedelta(days=20 if spec.target == "approved" else 60))
            .isoformat(),
            "evidence_ids": evidence_ids,
        }
        conditions = self.conditions(spec)
        if conditions is not None:
            body["conditions"] = conditions
        self.post(f"/governance/approvals/{review_id}/approve", body, self.reviewer)

    def advance(self, spec: Spec) -> None:
        asset = self.asset(spec.name, spec.intended_use)
        detail = self.get(f"/governance/assets/{asset['id']}")
        if detail["profile"] is None:
            self.post(f"/governance/assets/{asset['id']}/profile", spec.profile)
        if detail["last_assessed_at"] is None:
            self.post(f"/governance/assets/{asset['id']}/assess", {})

        evidence_ids: list[str] = []
        if spec.evidence is not None:
            control = self.control("nist", 0 if spec.evidence == "verified" else 1)
            title = f"{spec.name}: synthetic architecture notes"
            evidence = self.evidence_for(asset, control, title)
            if spec.evidence == "verified":
                evidence = self.verify(evidence)
                # A rejected item cannot back a claim, so it is neither assessed nor cited.
                if evidence["current_verification"] == "VERIFIED":
                    self.assess_control(control, evidence)
                    evidence_ids = [evidence["id"]]

        # Each pass does the one next step the current status calls for, so an interrupted run
        # resumes and a finished one does nothing.
        for _ in range(4):
            status = self.get(f"/governance/assets/{asset['id']}")["governance_status"]
            if status in _TERMINAL[spec.target] or status is None:
                return
            if status == "ASSESSMENT_REQUIRED":
                if spec.target == "incomplete":
                    return
                self.post(
                    f"/governance/assets/{asset['id']}/submit",
                    {"reason": "Synthetic submission for the demo."},
                )
            elif status == "UNDER_REVIEW":
                review = next(
                    r for r in self.listing("/governance/approvals", asset_id=asset["id"])
                    if r["status"] in ("OPEN", "INFO_REQUESTED")
                )
                self.approve(review["id"], spec, evidence_ids)
            elif status == "APPROVED" and spec.target == "suspended":
                self.post(
                    f"/governance/assets/{asset['id']}/suspend",
                    {"reason": "Synthetic suspension for the demo."},
                )
            else:
                return

    def run(self, reviewer_email: str) -> None:
        self.grant_reviewer(reviewer_email)
        for spec in SPECS:
            self.advance(spec)
        self.asset(*NOT_GOVERNED)


def seed_governance(base_url: str, admin_login: dict, reviewer_login: dict) -> None:
    """Both logins are {tenant_slug, email, password}. The passwords are never printed."""
    with httpx.Client(base_url=f"{base_url}/api/v1", timeout=30) as client:
        headers = []
        for login in (admin_login, reviewer_login):
            token = client.post("/auth/login", json=login).raise_for_status().json()
            headers.append({"Authorization": f"Bearer {token['access_token']}"})
        Seeder(client, headers[0], headers[1]).run(reviewer_login["email"])
