// What each mode does, as spec 11 states it. Decisions a person made (suspension, retirement,
// conditions) apply in both modes, so neither note may say that checks never block.
export const MODE_NOTE: Record<string, string> = {
  observe:
    "Where no approval is in force, checks are recorded and do not block actions. Decisions a person made, such as suspension, retirement and conditions, still apply.",
  enforce:
    "An asset with no approval in force, including a Not governed one, is denied. Decisions a person made still apply.",
};

// What each reason code means, from the gateway behavior table in spec 11.2.
export const REASON_TEXT: Record<string, string> = {
  GOVERNANCE_NOT_APPROVED: "No approval is in force.",
  GOVERNANCE_APPROVAL_EXPIRED: "The approval has expired.",
  GOVERNANCE_REASSESSMENT_REQUIRED: "Reassessment or review is open on an approval in force.",
  GOVERNANCE_RETIRED: "The asset is retired.",
  GOVERNANCE_BLOCKED: "A person suspended, revoked or rejected the asset.",
  GOVERNANCE_INTEGRITY_FAILED: "The stored conditions failed their integrity check.",
  GOVERNANCE_CONDITION_DENIED: "A condition of the approval denies the action.",
  GOVERNANCE_CONDITION_HOLD: "A condition of the approval holds the action.",
};
