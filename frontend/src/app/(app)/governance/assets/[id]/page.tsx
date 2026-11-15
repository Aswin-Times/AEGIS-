import Link from "next/link";
import { notFound } from "next/navigation";
import {
  Cell,
  EmptyState,
  PageHeader,
  Panel,
  RiskLabel,
  StatusBadge,
  Table,
} from "@/components/ui";
import { EvidenceTable } from "@/components/evidence-table";
import { PermissionDenied } from "@/components/permission-denied";
import { allPages } from "@/lib/all-pages";
import { ApiError, api } from "@/lib/api";
import { formatTime, humanize, shortId } from "@/lib/format";
import type {
  AssetDetail,
  CompliancePage,
  Control,
  Evidence,
  Framework,
  GovernancePolicy,
  HistoryEntry,
  Person,
  RelatedIncident,
  Review,
  RiskResponse,
} from "@/lib/governance-types";
import type { Me, Page } from "@/lib/types";
import { AssessForm } from "./assess-form";
import { AssetSummary, staleNote } from "./asset-summary";
import { ProfileForm } from "./profile-form";
import { ProfileSummary } from "./profile-summary";
import { SubmitForm } from "./submit-form";

export const metadata = { title: "AI asset | AEGIS" };

// Statuses from which an administrator can submit (spec 7.1), and open review statuses.
const SUBMITTABLE = ["ASSESSMENT_REQUIRED", "REASSESSMENT_REQUIRED"];
const OPEN_REVIEW = ["OPEN", "INFO_REQUESTED"];

const LIBRARY_STATUS: Record<string, string> = {
  NOT_LOADED: "Not loaded",
  LOADED_PARTIAL: "Partially loaded",
  LOADED: "Loaded",
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      <Panel title={title}>{children}</Panel>
    </div>
  );
}

function historyDetail(entry: HistoryEntry) {
  if (entry.type === "profile_version" && entry.profile_version) {
    return (
      <>
        Profile saved as version {entry.profile_version.version}
        <div className="font-mono text-xs text-muted">
          hash {entry.profile_version.content_hash.slice(0, 12)}
        </div>
      </>
    );
  }
  if (entry.type === "assessment" && entry.assessment) {
    const a = entry.assessment;
    return (
      <div className="flex flex-wrap items-center gap-2">
        Assessment, methodology version {a.methodology_version}
        <StatusBadge value={a.status} />
        {a.risk_level ? (
          <RiskLabel kind="assessed" value={a.risk_level} />
        ) : (
          <span className="text-xs text-muted">no risk level</span>
        )}
        {a.score !== null && <span className="text-xs text-muted">score {a.score}</span>}
      </div>
    );
  }
  if (entry.type === "decision" && entry.decision) {
    const d = entry.decision;
    return (
      <>
        <div className="flex flex-wrap items-center gap-2">
          Decision: {humanize(d.kind)}
          <StatusBadge value={d.from_status} />
          to
          <StatusBadge value={d.to_status} />
        </div>
        <div className="text-xs text-muted">{d.reason}</div>
      </>
    );
  }
  return null;
}

async function load(id: string) {
  const assetPath = encodeURIComponent(id);
  const me = await api<Me>("/auth/me");
  const admin = me.role === "admin";
  const [asset, history, evidence, reviews, policies, incidents, frameworks, people, risk] =
    await Promise.all([
      api<AssetDetail>(`/governance/assets/${assetPath}`),
      allPages<Page<HistoryEntry>>(`/governance/assets/${assetPath}/history`),
      allPages<Page<Evidence>>(`/governance/evidence?asset_id=${assetPath}`),
      api<Page<Review>>(`/governance/approvals?asset_id=${assetPath}&limit=1`),
      allPages<Page<GovernancePolicy>>("/governance/policies"),
      api<Page<RelatedIncident>>(`/incidents?asset_id=${assetPath}&limit=25`),
      api<CompliancePage<Framework>>("/governance/frameworks"),
      // The owner pickers list real users, and only an administrator can edit the profile.
      admin ? allPages<Page<Person>>("/governance/people") : Promise.resolve(null),
      api<RiskResponse>(`/governance/assets/${assetPath}/risk`),
    ]);
  const linked = new Set(evidence.items.flatMap((item) => item.control_ids));
  const controls = linked.size > 0 ? await allPages<CompliancePage<Control>>("/governance/controls") : null;
  return { admin, asset, history, evidence, reviews, policies, incidents, frameworks, people,
    controls, linked, risk };
}

export default async function AssetPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let data: Awaited<ReturnType<typeof load>>;
  try {
    data = await load(id);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    throw error;
  }
  const { admin, asset, history, evidence, reviews, policies, incidents, frameworks, people,
    controls, linked, risk } = data;

  const review = reviews.items[0];
  const openReview = review && OPEN_REVIEW.includes(review.status) ? review : null;
  // A review waiting for information is answered by submitting again, which replaces it.
  const canSubmit =
    SUBMITTABLE.includes(asset.governance_status ?? "") || openReview?.status === "INFO_REQUESTED";
  const versions = new Map(
    policies.items.flatMap((policy) =>
      policy.versions.map((version) => [version.id, { policy, version }] as const),
    ),
  );
  const mapped = controls?.items.filter((control) => linked.has(control.id)) ?? [];
  const evidenceOf = (controlId: string) =>
    evidence.items.filter((item) => item.control_ids.includes(controlId));

  return (
    <>
      <PageHeader
        title={asset.name}
        description={asset.intended_use}
      >
        {admin && <AssessForm assetId={asset.id} />}
      </PageHeader>
      <AssetSummary asset={asset} stale={staleNote(asset, risk, history.items)} />

      <Section title="Profile">
        <p className="border-b border-line px-3 py-2 text-xs text-muted">
          {asset.profile
            ? `Version ${asset.profile.version}, saved ${formatTime(asset.profile.created_at)}. Each save is a new immutable version.`
            : "No profile has been saved yet. The risk assessment names what is missing."}
        </p>
        {admin && people ? (
          <ProfileForm
            assetId={asset.id}
            versionId={asset.profile?.id ?? null}
            profile={asset.profile?.profile ?? {}}
            people={people.items}
          />
        ) : (
          <ProfileSummary asset={asset} />
        )}
      </Section>

      {admin && (
        <Section title="Submission">
          {openReview && (
            <p role="status" className="border-b border-line px-3 py-2 text-sm">
              Submitted for review on {formatTime(openReview.submitted_at)}.{" "}
              {openReview.status === "INFO_REQUESTED"
                ? "The reviewer has asked for information; submitting again replaces the review."
                : "The review is awaiting a decision."}{" "}
              <Link href={`/governance/approvals/${openReview.id}`} className="underline">
                Open the review
              </Link>
            </p>
          )}
          {canSubmit ? (
            <SubmitForm assetId={asset.id} />
          ) : (
            !openReview && (
              <p className="px-3 py-2 text-sm text-muted">
                An asset can be submitted once a complete assessment of its current profile exists,
                while it is in Assessment required or Reassessment required.
              </p>
            )
          )}
        </Section>
      )}

      <Section title="Policies">
        {!review ? (
          <EmptyState
            title="Not submitted for review"
            detail="Policies are matched when an asset is submitted, and the result is frozen on the review."
          />
        ) : (
          <>
            <p className="border-b border-line px-3 py-2 text-xs text-muted">
              Frozen when the asset was submitted on {formatTime(review.submitted_at)} (review{" "}
              {humanize(review.status)}). Policies in force now may differ. Minimum approvers:{" "}
              {review.required_controls.minimum_approvers}.
            </p>
            {review.required_controls.applicable_version_ids.length === 0 ? (
              <EmptyState
                title="No policy applied"
                detail="No active policy version matched this asset when it was submitted."
              />
            ) : (
              <Table head={["Policy", "Version", "Required controls"]}>
                {review.required_controls.applicable_version_ids.map((versionId) => {
                  const known = versions.get(versionId);
                  const controlsOf = review.required_controls.required_controls.filter(
                    (item) => item.policy_version_id === versionId,
                  );
                  return (
                    <tr key={versionId}>
                      <Cell>
                        {known?.policy.name ?? `Policy version ${shortId(versionId)}`}
                        {known && (
                          <div className="text-xs text-muted">{known.version.document.description}</div>
                        )}
                      </Cell>
                      <Cell>{known ? `Version ${known.version.version}` : "Unknown"}</Cell>
                      <Cell>
                        {controlsOf.length === 0 ? (
                          <span className="text-muted">None listed</span>
                        ) : (
                          <ul className="space-y-1">
                            {controlsOf.map((item) => (
                              <li key={item.control}>
                                <code className="text-xs">{item.control}</code>:{" "}
                                <span className="break-all text-xs">{JSON.stringify(item.value)}</span>
                              </li>
                            ))}
                          </ul>
                        )}
                      </Cell>
                    </tr>
                  );
                })}
              </Table>
            )}
            {review.findings.length > 0 && (
              <ul className="space-y-1 border-t border-line px-3 py-2">
                {review.findings.map((finding, index) => (
                  <li key={index} className="flex flex-wrap items-center gap-2">
                    <StatusBadge value={finding.severity} />
                    {finding.message}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </Section>

      <Section title="History">
        {history.items.length === 0 ? (
          <EmptyState
            title="No history yet"
            detail="Profile versions, assessments and decisions appear here in audit order."
          />
        ) : (
          <Table head={["Audit sequence", "Record", "Recorded"]}>
            {history.items.map((entry) => (
              <tr key={`${entry.type}-${entry.id}`}>
                <Cell mono>{entry.seq}</Cell>
                <Cell>{historyDetail(entry)}</Cell>
                <Cell mono>
                  {formatTime(
                    entry.decision?.decided_at ??
                      entry.assessment?.assessed_at ??
                      entry.profile_version?.created_at,
                  )}
                </Cell>
              </tr>
            ))}
          </Table>
        )}
      </Section>

      <Section title="Evidence">
        <EvidenceTable items={evidence.items} />
      </Section>

      <Section title="Control mappings">
        <p className="border-b border-line px-3 py-2 text-sm">{frameworks.statement}</p>
        <ul className="divide-y divide-line">
          {frameworks.items.map((framework) => (
            <li key={framework.id} className="px-3 py-2">
              <span className="font-medium">{framework.name}</span>{" "}
              <span className="text-xs text-muted">version {framework.version}</span>
              <div className="text-sm">
                Library: {LIBRARY_STATUS[framework.library_status] ?? framework.library_status}.{" "}
                {framework.coverage}
              </div>
            </li>
          ))}
        </ul>
        {mapped.length === 0 ? (
          <p className="border-t border-line px-3 py-3 text-muted">
            No evidence for this asset is linked to a control.
          </p>
        ) : (
          <Table head={["Control", "Name", "Framework", "Organization-level status", "Linked evidence"]}>
            {mapped.map((control) => (
              <tr key={control.id}>
                <Cell mono>{control.identifier}</Cell>
                <Cell>{control.name}</Cell>
                <Cell>{control.framework_key}</Cell>
                <Cell>
                  <StatusBadge value={control.current_status} />
                </Cell>
                <Cell>{evidenceOf(control.id).map((item) => item.description).join("; ")}</Cell>
              </tr>
            ))}
          </Table>
        )}
      </Section>

      <Section title="Related incidents">
        {incidents.items.length === 0 ? (
          <EmptyState
            title="No related incidents"
            detail="Incidents raised for the agents registered under this asset appear here."
          />
        ) : (
          <Table head={["Incident", "Severity", "Status", "Agent", "Last observed"]}>
            {incidents.items.map((incident) => (
              <tr key={incident.id}>
                <Cell>
                  <Link href={`/incidents/${incident.id}`} className="underline">
                    {incident.title}
                  </Link>
                </Cell>
                <Cell>
                  <StatusBadge value={incident.severity} />
                </Cell>
                <Cell>
                  <StatusBadge value={incident.status} />
                </Cell>
                <Cell>{incident.agent_name ?? "None"}</Cell>
                <Cell mono>{formatTime(incident.last_observed_at)}</Cell>
              </tr>
            ))}
          </Table>
        )}
        {incidents.total > incidents.items.length && (
          <p className="border-t border-line px-3 py-2 text-xs text-muted">
            Showing {incidents.items.length} of {incidents.total}.
          </p>
        )}
      </Section>
    </>
  );
}
