import Link from "next/link";
import { Cell, EmptyState, Panel, RiskLabel, StatusBadge, Table } from "@/components/ui";
import { formatTime, shortId } from "@/lib/format";
import type {
  AssessmentSummary,
  AssetDetail,
  GovernancePolicy,
  Review,
} from "@/lib/governance-types";
import { ProfileSummary } from "../../assets/[id]/profile-summary";

/** A review is OPEN until a decision closes it, which is not the same as an open incident. */
export const reviewStatus = (status: string) => (status === "OPEN" ? "AWAITING_DECISION" : status);

export function policyLabel(policies: GovernancePolicy[], versionId: string | null): string {
  if (!versionId) return "No policy";
  for (const policy of policies) {
    const version = policy.versions.find((item) => item.id === versionId);
    if (version) return `${policy.name}, version ${version.version}`;
  }
  return `Policy version ${shortId(versionId)}`;
}

const Fact = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div>
    <dt className="text-xs text-muted">{label}</dt>{" "}
    <dd className="break-words">{children}</dd>
  </div>
);

const permitted = (value: boolean) =>
  value ? "Permitted by policy (frozen at submission)" : "Not permitted (frozen at submission)";

export function ReviewSummary({
  review,
  submitReason,
  counted,
  recorded,
  label,
}: {
  review: Review;
  submitReason: string | null;
  // Null when this account cannot see who still holds the role.
  counted: number | null;
  recorded: number;
  label: (id: string | null) => string;
}) {
  const frozen = review.required_controls;
  return (
    <Panel title="Review summary">
      <dl className="grid gap-x-6 gap-y-2 p-3 sm:grid-cols-2">
        <Fact label="Status">
          <StatusBadge value={reviewStatus(review.status)} />
        </Fact>
        <Fact label="Submitted">
          {formatTime(review.submitted_at)} by {label(review.submitted_by)}
        </Fact>
        <Fact label="Submission reason">
          {submitReason ?? <span className="text-muted">Not found in the history</span>}
        </Fact>
        <Fact label="Assigned reviewer">
          {review.assigned_reviewer ? label(review.assigned_reviewer) : "Not assigned"}
        </Fact>
        <Fact label="Approvals needed">{review.required_approvers}</Fact>
        <Fact label="Approvals counted">
          {counted === null ? (
            <>
              {recorded} recorded; this account cannot see which voters still hold the role, so
              it cannot show how many still count
            </>
          ) : (
            `${counted} of ${review.required_approvers}`
          )}
        </Fact>
        <Fact label="Self-approval by the submitter">{permitted(frozen.self_approval_permitted)}</Fact>
        <Fact label="Approval by an asset owner">{permitted(frozen.owner_approval_permitted)}</Fact>
        {review.closed_at && <Fact label="Closed">{formatTime(review.closed_at)}</Fact>}
      </dl>
    </Panel>
  );
}

export function FrozenAssessment({
  review,
  assessment,
  assetId,
}: {
  review: Review;
  assessment: AssessmentSummary | undefined;
  assetId: string;
}) {
  return (
    <Panel title="Frozen assessment">
      {assessment ? (
        <dl className="grid gap-x-6 gap-y-2 p-3 sm:grid-cols-2">
          <Fact label="Assessment">
            <StatusBadge value={assessment.status} />
          </Fact>
          <Fact label="Result">
            {assessment.risk_level ? (
              <RiskLabel kind="assessed" value={assessment.risk_level} />
            ) : (
              "No risk level: the assessment is incomplete"
            )}
            {assessment.score !== null && ` (score ${assessment.score})`}
          </Fact>
          <Fact label="Methodology">Version {assessment.methodology_version}</Fact>
          <Fact label="Assessed">{formatTime(assessment.assessed_at)}</Fact>
          <Fact label="Input hash">
            <span className="font-mono text-xs">{assessment.input_hash.slice(0, 16)}</span>
          </Fact>
          <Fact label="Details">
            <Link className="underline" href={`/governance/assets/${assetId}/risk`}>
              View the risk assessment page
            </Link>{" "}
            <span className="text-xs text-muted">(shows the latest assessment)</span>
          </Fact>
        </dl>
      ) : (
        <p role="alert" className="p-3 text-deny">
          The assessment {shortId(review.assessment_id)} this review froze was not found, so it
          cannot be shown.
        </p>
      )}
    </Panel>
  );
}

export function FrozenProfile({
  review,
  asset,
  versionNumber,
}: {
  review: Review;
  asset: AssetDetail;
  versionNumber: number | null;
}) {
  const changed = asset.profile?.id !== review.profile_version_id;
  const frozen = versionNumber === null ? shortId(review.profile_version_id) : `version ${versionNumber}`;
  return (
    <Panel title="Frozen profile">
      <p className="border-b border-line px-3 py-2 text-xs text-muted">
        This review froze profile {frozen}.
      </p>
      {changed ? (
        <p className="p-3">
          The asset&apos;s profile has changed since this review was submitted
          {asset.profile ? ` (it is now version ${asset.profile.version})` : ""}. The API returns
          only the current profile, so the frozen content is not shown. An approval of this
          review is refused with ASSESSMENT_NOT_CURRENT until the asset is resubmitted. Rejecting
          is still possible.
        </p>
      ) : (
        <ProfileSummary asset={asset} />
      )}
    </Panel>
  );
}

const valueText = (value: unknown) =>
  Array.isArray(value) ? value.map(String).join(", ") : typeof value === "object" ? JSON.stringify(value) : String(value);

export function RequiredControls({
  review,
  policies,
}: {
  review: Review;
  policies: GovernancePolicy[];
}) {
  const frozen = review.required_controls;
  return (
    <Panel title="Required controls">
      <p className="border-b border-line px-3 py-2 text-xs text-muted">
        Frozen when the review was submitted, so a later policy change does not alter what was
        asked. Policy versions that applied:{" "}
        {frozen.applicable_version_ids.length === 0
          ? "none"
          : frozen.applicable_version_ids.map((id) => policyLabel(policies, id)).join("; ")}
        .
      </p>
      {frozen.required_controls.length === 0 ? (
        <EmptyState title="No required controls" detail="No applicable policy asked for any." />
      ) : (
        <Table head={["Control", "Required value", "Policy"]}>
          {frozen.required_controls.map((item, index) => (
            <tr key={`${item.policy_version_id}-${item.control}-${index}`}>
              <Cell mono>{item.control}</Cell>
              <Cell>{valueText(item.value)}</Cell>
              <Cell>{policyLabel(policies, item.policy_version_id)}</Cell>
            </tr>
          ))}
        </Table>
      )}
    </Panel>
  );
}

export function Findings({ review, policies }: { review: Review; policies: GovernancePolicy[] }) {
  return (
    <Panel title="Findings">
      <p className="border-b border-line px-3 py-2 text-xs text-muted">
        Findings inform the decision. They do not make it.
      </p>
      {review.findings.length === 0 ? (
        <EmptyState title="No findings" detail="The policy check raised nothing at submission." />
      ) : (
        <Table head={["Severity", "Control", "Finding", "Policy"]}>
          {review.findings.map((finding, index) => (
            <tr key={`${finding.control}-${index}`}>
              <Cell>
                <StatusBadge value={finding.severity} />
              </Cell>
              <Cell mono>{finding.control}</Cell>
              <Cell>{finding.message}</Cell>
              <Cell>{policyLabel(policies, finding.policy_version_id)}</Cell>
            </tr>
          ))}
        </Table>
      )}
    </Panel>
  );
}
