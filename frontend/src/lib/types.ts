export type Page<T> = { items: T[]; total: number; limit: number; offset: number };

export type Me = { id: string; tenant_id: string; email: string; role: string };

export type Overview = {
  assets: number;
  synthetic_assets: number;
  agents: number;
  agents_disabled: number;
  decisions: { ALLOW: number; DENY: number; REQUIRE_APPROVAL: number };
  pending_approvals: number;
  executions: number;
  audit_events: number;
  active_policy_version_id: string | null;
};

export type Asset = {
  id: string;
  name: string;
  owner: string;
  risk_classification: string;
  intended_use: string;
  is_synthetic: boolean;
  created_at: string;
};

export type Credential = {
  id: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
};

export type Agent = {
  id: string;
  asset_id: string;
  name: string;
  owner: string;
  status: string;
  created_at: string;
  tool_grants: string[];
  resource_grants: string[];
  credentials: Credential[];
};

export type PolicyRule = {
  id: string;
  effect: string;
  match: Record<string, string[]>;
  reason_code: string;
};

export type PolicyVersion = {
  id: string;
  policy_id: string;
  version: number;
  content_hash: string;
  created_at: string;
  document: { rules: PolicyRule[] };
};

export type Policy = {
  id: string;
  name: string;
  created_at: string;
  active_version_id: string | null;
  versions: PolicyVersion[];
};

export type Decision = {
  id: string;
  request_id: string;
  agent_id: string;
  agent_name: string;
  resource_id: string | null;
  tool: string;
  action: string | null;
  policy_id: string | null;
  policy_version_id: string | null;
  policy_version: number | null;
  outcome: string;
  reason_code: string;
  matched_rule_id: string | null;
  evaluated_at: string;
  tool_executed: boolean;
  execution: { status: string; started_at: string; finished_at: string | null } | null;
};

export type DecisionDetail = Decision & {
  evidence: Record<string, unknown>;
  audit_event_ids: string[];
};

export type Approval = {
  id: string;
  request_id: string;
  decision_id: string;
  agent_id: string;
  tool: string;
  action: string | null;
  resource_id: string | null;
  params: Record<string, unknown>;
  action_hash: string;
  status: string;
  requested_at: string;
  expires_at: string;
  decided_by: string | null;
  decided_at: string | null;
  comment: string | null;
};

export type AuditEvent = {
  id: string;
  seq: number;
  prev_hash: string;
  event_hash: string;
  event_type: string;
  actor_type: string;
  actor_id: string | null;
  correlation_id: string | null;
  subject_type: string | null;
  subject_id: string | null;
  policy_version_id: string | null;
  occurred_at: string;
  payload: Record<string, unknown>;
};

export type AuditHead = { seq: number; head_hash: string };

export type AuditVerification = {
  valid: boolean;
  events_checked: number;
  head_seq: number;
  head_hash: string;
  failure_seq: number | null;
  failure_reason: string | null;
};
