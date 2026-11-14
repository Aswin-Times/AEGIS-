// Response shapes of /api/v1/governance, copied from backend/src/aegis/api/schemas_governance.py.

export type GovernanceStatusCode =
  | "DRAFT"
  | "ASSESSMENT_REQUIRED"
  | "UNDER_REVIEW"
  | "APPROVED"
  | "CONDITIONALLY_APPROVED"
  | "REJECTED"
  | "SUSPENDED"
  | "REASSESSMENT_REQUIRED"
  | "RETIRED";

export const GOVERNANCE_STATUSES: GovernanceStatusCode[] = [
  "DRAFT",
  "ASSESSMENT_REQUIRED",
  "UNDER_REVIEW",
  "APPROVED",
  "CONDITIONALLY_APPROVED",
  "REJECTED",
  "SUSPENDED",
  "REASSESSMENT_REQUIRED",
  "RETIRED",
];

export const ASSESSED_RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export const DECLARED_RISK_LEVELS = ["low", "medium", "high", "critical"] as const;

export type GovernanceOverview = {
  total_assets: number;
  by_assessed_risk: Record<string, number>;
  unassessed: number;
  awaiting_approval: number;
  conditionally_approved: number;
  suspended: number;
  overdue_reviews: number;
  outstanding_findings: number;
  evidence_verified: number;
  evidence_total: number;
  enforcement_mode: string;
};

export type Owner = { id: string; email: string };

export type InventoryRow = {
  id: string;
  name: string;
  owner: string;
  declared_risk: string;
  assessed_risk: string | null;
  last_assessed_at: string | null;
  // Null when the asset has no governance state yet.
  governance_status: string | null;
  business_owner: Owner | null;
  technical_owner: Owner | null;
  is_synthetic: boolean;
  valid_until: string | null;
  next_review_at: string | null;
  created_at: string;
};
