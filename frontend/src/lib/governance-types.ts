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

// Asset profile. The values are the closed vocabularies of backend/src/aegis/governance/profile.py.

export const ASSET_TYPES = [
  "ai_application",
  "autonomous_agent",
  "model",
  "model_provider",
  "ai_enabled_service",
] as const;
export const DATA_CATEGORIES = [
  "public",
  "internal",
  "personal",
  "confidential",
  "regulated",
] as const;
export const EXTERNAL_EXPOSURES = ["none", "internal_users", "partners", "public"] as const;
export const AUTONOMY_LEVELS = [
  "advisory",
  "human_approved",
  "supervised",
  "bounded",
  "autonomous",
] as const;
export const HUMAN_OVERSIGHT = ["in_the_loop", "on_the_loop", "after_the_fact", "none"] as const;
export const IMPACT_LEVELS = ["negligible", "minor", "moderate", "major", "severe"] as const;
export const ENVIRONMENTS = [
  "development",
  "test",
  "staging",
  "production_internal",
  "production_external",
] as const;
export const THIRD_PARTY_RELIANCE = ["none", "vetted", "partially_vetted", "unvetted"] as const;

export type AssetProfile = {
  asset_type?: string;
  description?: string;
  business_purpose?: string;
  intended_use?: string;
  prohibited_use?: string;
  business_owner_id?: string;
  technical_owner_id?: string;
  responsible_team?: string;
  model_provider?: string;
  model_name?: string;
  model_version?: string;
  deployment_environment?: string;
  data_categories?: string[];
  external_exposure?: string;
  external_integrations?: string[];
  autonomy_level?: string;
  human_oversight?: string;
  declared_tool_access?: string[];
  impact_level?: string;
  third_party_reliance?: string;
  evidence_references?: string[];
};

export type CurrentProfile = {
  id: string;
  version: number;
  profile: AssetProfile;
  content_hash: string;
  created_by: string;
  created_at: string;
};

export type AssetDetail = InventoryRow & {
  intended_use: string;
  state_version: number | null;
  state_updated_at: string | null;
  profile: CurrentProfile | null;
};

export type Person = {
  id: string;
  email: string;
  role: string;
  reviewer_grant_id: string | null;
};

export type ProfileVersion = {
  id: string;
  asset_id: string;
  version: number;
  governance_status: string;
};

// Risk assessments

export type FactorResult = {
  factor: string;
  label: string;
  input_value: string;
  level: number;
  weight: number;
  contribution: number;
  explanation: string;
};

export type RiskResult = {
  status: "COMPLETE" | "INCOMPLETE";
  score: number | null;
  risk_level: string | null;
  factors: FactorResult[];
  floor_applied: string | null;
  missing: string[];
  mitigations: string[];
};

export type AssessmentSummary = {
  id: string;
  asset_id: string;
  profile_version_id: string;
  methodology_version_id: string;
  methodology_version: number;
  input_hash: string;
  result_hash: string;
  status: "COMPLETE" | "INCOMPLETE";
  score: number | null;
  risk_level: string | null;
  assessed_by: string;
  assessed_at: string;
  audit_event_id: string;
};

export type Assessment = AssessmentSummary & {
  // Null only if the stored text is not a JSON object, which means the row was altered.
  input: Record<string, unknown> | null;
  result: RiskResult | null;
};

export type RiskResponse = {
  assessment: Assessment | null;
  recomputed_matches: boolean | null;
};

export type Methodology = {
  id: string;
  version: number;
  content_hash: string;
  created_by: string | null;
  created_at: string;
  approved: boolean;
  approved_by: string | null;
  approved_at: string | null;
  active: boolean;
  document: {
    factors: {
      id: string;
      label: string;
      weight: number;
      input: string;
      levels: Record<string, number>;
    }[];
    thresholds: { medium: number; high: number; critical: number };
    floors: { id: string; description: string; minimum_level: string }[];
    mitigations: Record<string, Record<string, string[]>>;
    provenance_note: string;
  };
};

// Policies, reviews, history

export type PolicyDocument = {
  description: string;
  severity: string;
  applicability?: {
    risk_levels?: string[];
    asset_types?: string[];
    environments?: string[];
    data_categories?: string[];
  };
  controls?: Record<string, unknown>;
};

export type PolicyVersion = {
  id: string;
  policy_id: string;
  version: number;
  content_hash: string;
  effective_from: string;
  review_by: string | null;
  created_by: string;
  created_at: string;
  approved: boolean;
  approved_by: string | null;
  approved_at: string | null;
  active: boolean;
  document: PolicyDocument;
};

export type GovernancePolicy = {
  id: string;
  name: string;
  category: string;
  created_by: string;
  created_at: string;
  versions: PolicyVersion[];
};

export type Review = {
  id: string;
  asset_id: string;
  assessment_id: string;
  profile_version_id: string;
  submitted_by: string;
  assigned_reviewer: string | null;
  status: string;
  required_approvers: number;
  version: number;
  submitted_at: string;
  closed_at: string | null;
  // What the policy engine asked for when the review was opened, frozen at that moment.
  required_controls: {
    applicable_version_ids: string[];
    required_controls: { policy_version_id: string; control: string; value: unknown }[];
    minimum_approvers: number;
    // Frozen too. Silence in every policy means not permitted.
    self_approval_permitted: boolean;
    owner_approval_permitted: boolean;
  };
  findings: {
    policy_version_id: string | null;
    control: string;
    severity: string;
    message: string;
  }[];
};

// The closed set of conditions an approval can carry. Backend: governance/conditions.py.
export type Conditions = {
  denied_tools: string[];
  held_tools: string[];
  denied_actions: string[];
  hold_all: boolean;
  max_resource_classification: string | null;
  advisory_conditions: string[];
};

export const RESOURCE_CLASSIFICATIONS = ["public", "internal", "sensitive"] as const;

export type AssetDecision = {
  id: string;
  review_id: string | null;
  kind: string;
  from_status: string;
  to_status: string;
  actor_type: string;
  decided_by: string | null;
  decided_at: string;
  reason: string;
  conditions: Conditions | null;
  conditions_hash: string | null;
  valid_until: string | null;
  next_review_at: string | null;
  policy_version_ids: string[];
  evidence_ids: string[];
};

export type ProfileVersionSummary = {
  id: string;
  version: number;
  content_hash: string;
  created_by: string;
  created_at: string;
};

export type HistoryEntry = {
  type: "decision" | "assessment" | "profile_version";
  // The audit sequence of the event that records this entry, which is what orders the history.
  seq: number;
  id: string;
  audit_event_id: string;
  kind: string | null;
  decision: AssetDecision | null;
  assessment: AssessmentSummary | null;
  profile_version: ProfileVersionSummary | null;
};

// Evidence and compliance mappings

export type EvidenceVerification = {
  id: string;
  outcome: string;
  method: string;
  note: string;
  verified_at: string;
  // hash_recomputed, record_verified, existence_only, attestation_only, or judgment_only.
  scope: string;
};

export type Evidence = {
  id: string;
  asset_id: string;
  category: string;
  description: string;
  source_type: "internal_record" | "inline" | "external_reference";
  created_at: string;
  content_sha256: string | null;
  source_uri: string | null;
  record_type: string | null;
  record_id: string | null;
  // Inline text, for admins and reviewers only.
  content_text?: string | null;
  control_ids: string[];
  current_verification: string;
  latest_verification: EvidenceVerification | null;
};

export type Framework = {
  id: string;
  key: string;
  version: string;
  name: string;
  source_url: string | null;
  source_document: string;
  library_status: "NOT_LOADED" | "LOADED_PARTIAL" | "LOADED";
  control_count: number;
  source_control_count: number | null;
  coverage: string;
  status_counts: Record<string, number>;
};

export type ControlAssessment = {
  id: string;
  status: string;
  note: string;
  assessed_by: string;
  assessed_at: string;
  evidence_ids: string[];
};

export type Control = {
  id: string;
  framework_id: string;
  framework_key: string;
  identifier: string;
  name: string;
  description: string;
  source_reference: string;
  required_evidence: string[];
  // The API's derived status: EVIDENCE_REQUIRED when a claim has no verified evidence behind it.
  current_status: string;
  latest_assessment: ControlAssessment | null;
  verified_evidence_count: number;
  linked_evidence_count: number;
};

export type DueReview = {
  asset_id: string;
  name: string;
  governance_status: string;
  next_review_at: string;
  valid_until: string | null;
  overdue: boolean;
  expired: boolean;
};

export type PreflightItem = {
  asset_id: string;
  name: string;
  governance_status: string | null;
  verdict: "DENY" | "HOLD";
  reason_code: string;
  recent_actions: number;
  recent_not_passed: number;
};

export type Preflight = {
  enforcement_mode: string;
  since: string;
  assets_checked: number;
  would_deny: number;
  would_hold: number;
  items: PreflightItem[];
};

// Every compliance response carries the statement that a mapping is not a certification.
export type CompliancePage<T> = {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  statement: string;
};

export type RelatedIncident = {
  id: string;
  title: string;
  severity: string;
  status: string;
  agent_name: string | null;
  event_count: number;
  last_observed_at: string;
};

export type ProfileFormState = {
  error?: string;
  fieldErrors?: Record<string, string>;
  // Shown with role="status" after a save or an assessment.
  saved?: string;
  // What was submitted, so a refused form keeps the values that were typed.
  values?: Record<string, string | string[]>;
};

// Shown by the decision forms. Field errors are keyed by the form's field names.
export type DecisionFormState = {
  error?: string;
  // The API's own error code, such as ASSESSMENT_NOT_CURRENT or SELF_APPROVAL_REFUSED.
  code?: string;
  fieldErrors?: Record<string, string>;
  saved?: string;
};

// Control statuses as the API derives them, in the order a reader meets them.
export const CONTROL_STATUSES = [
  "NOT_ASSESSED",
  "EVIDENCE_REQUIRED",
  "IMPLEMENTED",
  "PARTIALLY_IMPLEMENTED",
  "NOT_IMPLEMENTED",
  "NOT_APPLICABLE",
] as const;
