import Link from "next/link";
import { notFound } from "next/navigation";
import { EvidenceTable } from "@/components/evidence-table";
import { PermissionDenied } from "@/components/permission-denied";
import { PageHeader, Panel } from "@/components/ui";
import { loadAccess } from "@/lib/access";
import { allPages } from "@/lib/all-pages";
import { ApiError, api } from "@/lib/api";
import type {
  AssessmentSummary,
  AssetDecision,
  AssetDetail,
  Evidence,
  GovernancePolicy,
  HistoryEntry,
  Review,
} from "@/lib/governance-types";
import type { Page } from "@/lib/types";
import { AssignForm } from "./assign-form";
import { DecisionForm } from "./decision-form";
import { ConditionsPanel, DecisionHistory } from "./review-decisions";
import {
  Findings,
  FrozenAssessment,
  FrozenProfile,
  RequiredControls,
  ReviewSummary,
} from "./review-panels";

export const metadata = { title: "Review | AEGIS" };

const OPEN = new Set(["OPEN", "INFO_REQUESTED"]);
const APPROVALS = new Set(["APPROVAL_VOTE", "APPROVE", "APPROVE_CONDITIONAL"]);

async function load(id: string) {
  const review = await api<Review>(`/governance/approvals/${encodeURIComponent(id)}`);
  const asset = encodeURIComponent(review.asset_id);
  const [detail, history, assessments, evidence, policies, access] = await Promise.all([
    api<AssetDetail>(`/governance/assets/${asset}`),
    allPages<Page<HistoryEntry>>(`/governance/assets/${asset}/history`),
    allPages<Page<AssessmentSummary>>(`/governance/assets/${asset}/assessments`),
    allPages<Page<Evidence>>(`/governance/evidence?asset_id=${asset}`),
    allPages<Page<GovernancePolicy>>("/governance/policies"),
    loadAccess(),
  ]);
  return { review, detail, history, assessments, evidence, policies, access };
}

export default async function ReviewPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let data: Awaited<ReturnType<typeof load>>;
  try {
    data = await load(id);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    throw error;
  }
  const { review, detail, history, assessments, evidence, policies, access } = data;

  const decisions: AssetDecision[] = history.items
    .filter((entry) => entry.type === "decision" && entry.decision?.review_id === review.id)
    .map((entry) => entry.decision!);
  const votes = decisions.filter((decision) => APPROVALS.has(decision.kind));
  const holderIds = new Set(access.holders.map((person) => person.id));
  // Who still holds the role is visible only to admins and reviewers.
  const counted =
    access.people.length === 0
      ? null
      : votes.filter((vote) => vote.decided_by !== null && holderIds.has(vote.decided_by)).length;
  const submitReason = decisions.find((decision) => decision.kind === "SUBMIT")?.reason ?? null;
  const versionNumber =
    history.items.find(
      (entry) => entry.type === "profile_version" && entry.id === review.profile_version_id,
    )?.profile_version?.version ?? null;
  // The conditions an approval now has to carry: those of any earlier vote, as the API requires.
  const bound = votes.find((vote) => vote.conditions !== null)?.conditions ?? null;
  const open = OPEN.has(review.status);
  const label = access.label;

  return (
    <>
      <PageHeader
        title={detail.name}
        description="Review of this AI asset. What is shown is what the reviewer decides on, as stored."
      >
        <Link
          href={`/governance/assets/${detail.id}`}
          className="rounded border border-line px-3 py-1.5 hover:bg-subtle"
        >
          View the asset
        </Link>
      </PageHeader>

      <div className="space-y-4">
        <ReviewSummary
          review={review}
          submitReason={submitReason}
          counted={counted}
          recorded={votes.length}
          label={label}
        />
        <FrozenAssessment
          review={review}
          assetId={detail.id}
          assessment={assessments.items.find((item) => item.id === review.assessment_id)}
        />
        <FrozenProfile review={review} asset={detail} versionNumber={versionNumber} />
        <RequiredControls review={review} policies={policies.items} />
        <Findings review={review} policies={policies.items} />
        <Panel title="Evidence">
          <p className="border-b border-line px-3 py-2 text-xs text-muted">
            Evidence recorded for this asset now, with the check each item received. An
            attestation is a reviewer&apos;s statement, not a recomputed hash.
          </p>
          <EvidenceTable items={evidence.items} />
        </Panel>
        <ConditionsPanel decisions={decisions} label={label} />
        <DecisionHistory
          decisions={decisions}
          label={label}
          evidenceNames={new Map(evidence.items.map((item) => [item.id, item.description]))}
        />

        {open && access.holder && (
          <Panel title="Reviewer assignment">
            <AssignForm
              reviewId={review.id}
              assigned={review.assigned_reviewer}
              holders={access.holders.map(({ id: holderId, email }) => ({ id: holderId, email }))}
            />
          </Panel>
        )}
        {access.holder && (
          <Panel title="Decide this review">
            <DecisionForm
              reviewId={review.id}
              open={open}
              assetName={detail.name}
              awaitingInformation={review.status === "INFO_REQUESTED"}
              bound={bound}
              evidence={evidence.items.map((item) => ({
                id: item.id,
                description: item.description,
                verification: item.current_verification,
              }))}
              needed={review.required_approvers}
              counted={counted}
              alreadyVoted={votes.some((vote) => vote.decided_by === access.me.id)}
            />
          </Panel>
        )}
        {open && !access.holder && (
          <Panel title="Decide this review">
            <div className="p-3">
              <PermissionDenied title="Your account cannot decide this review">
                Deciding needs the governance reviewer role, which an administrator grants to
                another admin or reviewer. You can read everything on this page. The AEGIS API
                refuses a decision from your account.
              </PermissionDenied>
            </div>
          </Panel>
        )}
      </div>
    </>
  );
}
