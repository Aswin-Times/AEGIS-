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
import { PermissionDenied } from "@/components/permission-denied";
import { ApiError, api } from "@/lib/api";
import { formatTime, humanize, shortId } from "@/lib/format";
import type {
  AssetDetail,
  AssetProfile,
  CompliancePage,
  Control,
  Evidence,
  Framework,
  GovernancePolicy,
  HistoryEntry,
  Person,
  RelatedIncident,
  Review,
} from "@/lib/governance-types";
import type { Me, Page } from "@/lib/types";
import { AssessForm } from "./assess-form";
import { AssetSummary } from "./asset-summary";
import { ProfileForm } from "./profile-form";

export const metadata = { title: "AI asset | AEGIS" };

const PROFILE_ROWS: [keyof AssetProfile, string][] = [
  ["asset_type", "Asset type"],
  ["description", "Description"],
  ["business_purpose", "Business purpose"],
  ["intended_use", "Intended use"],
  ["prohibited_use", "Prohibited use"],
  ["responsible_team", "Responsible team"],
  ["model_provider", "Model provider"],
  ["model_name", "Model name"],
  ["model_version", "Model version"],
  ["deployment_environment", "Deployment environment"],
  ["data_categories", "Data categories"],
  ["external_exposure", "External exposure"],
  ["external_integrations", "External integrations"],
  ["autonomy_level", "Autonomy level"],
  ["human_oversight", "Human oversight"],
  ["declared_tool_access", "Declared tool access"],
  ["impact_level", "Impact level"],
  ["third_party_reliance", "Third-party reliance"],
  ["evidence_references", "Evidence references"],
];
const VOCABULARY_FIELDS = new Set<keyof AssetProfile>([
  "asset_type",
  "deployment_environment",
  "external_exposure",
  "autonomy_level",
  "human_oversight",
  "impact_level",
  "third_party_reliance",
]);

const LIBRARY_STATUS: Record<string, string> = {
  NOT_LOADED: "Not loaded",
  LOADED_PARTIAL: "Partially loaded",
  LOADED: "Loaded",
};

// What a verification can have shown. A claim is never stronger than the check that ran.
const SCOPE: Record<string, string> = {
  hash_recomputed: "The hash was recomputed from the content and matched.",
  record_verified: "The internal record exists in this organization and its hash still verifies.",
  existence_only: "Existence only. The record exists, but its content was not recomputed.",
  attestation_only:
    "Manual attestation. Nothing was recomputed. A reviewer states that this is so.",
  judgment_only: "A reviewer rejected this evidence. No check was run.",
};

const SOURCE: Record<string, string> = {
  internal_record: "Internal record",
  inline: "Inline text",
  external_reference: "External reference",
};

async function allPages<T extends { id: string }>(path: string): Promise<CompliancePage<T>> {
  const first = await api<CompliancePage<T>>(`${path}${path.includes("?") ? "&" : "?"}limit=100`);
  const items = [...first.items];
  while (items.length < first.total && items.length % 100 === 0) {
    const more = await api<CompliancePage<T>>(
      `${path}${path.includes("?") ? "&" : "?"}limit=100&offset=${items.length}`,
    );
    if (more.items.length === 0) break;
    items.push(...more.items);
  }
  return { ...first, items };
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      <Panel title={title}>{children}</Panel>
    </div>
  );
}

function profileValue(
  name: keyof AssetProfile,
  profile: AssetProfile,
  asset: AssetDetail,
): string | null {
  if (name === "business_owner_id") return asset.business_owner?.email ?? null;
  if (name === "technical_owner_id") return asset.technical_owner?.email ?? null;
  const value = profile[name];
  if (value === undefined) return null;
  if (Array.isArray(value)) return value.length ? value.map(humanizeIfCode).join(", ") : null;
  return VOCABULARY_FIELDS.has(name) ? humanize(value) : value;
}

const humanizeIfCode = (value: string) => (/^[a-z_]+$/.test(value) ? humanize(value) : value);

function ProfileSummary({ asset }: { asset: AssetDetail }) {
  const profile = asset.profile?.profile ?? {};
  return (
    <dl className="grid gap-x-6 gap-y-2 p-3 sm:grid-cols-2">
      {PROFILE_ROWS.map(([name, label]) => {
        const value = profileValue(name, profile, asset);
        return (
          <div key={name}>
            <dt className="text-xs text-muted">{label}</dt>
            <dd className="whitespace-pre-wrap break-words">
              {value ?? <span className="text-muted">Not stated</span>}
            </dd>
          </div>
        );
      })}
    </dl>
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

function EvidenceTable({ items }: { items: Evidence[] }) {
  if (items.length === 0) {
    return (
      <EmptyState
        title="No evidence recorded"
        detail="Evidence submitted for this asset, and how it was checked, is listed here."
      />
    );
  }
  return (
    <Table head={["Evidence", "Category", "Source", "Verification", "How it was checked"]}>
      {items.map((item) => {
        const check = item.latest_verification;
        return (
          <tr key={item.id}>
            <Cell>{item.description}</Cell>
            <Cell>{humanize(item.category)}</Cell>
            <Cell>
              {SOURCE[item.source_type] ?? item.source_type}
              {item.record_type && (
                <div className="text-xs text-muted">{humanize(item.record_type)}</div>
              )}
              {item.source_uri && (
                <div className="break-all text-xs text-muted">{item.source_uri}</div>
              )}
              {item.content_sha256 && (
                <div className="font-mono text-xs text-muted">
                  {item.source_type === "external_reference" ? "declared hash " : "hash "}
                  {item.content_sha256.slice(0, 12)}
                </div>
              )}
            </Cell>
            <Cell>
              <StatusBadge value={item.current_verification} />
              {check && <div className="mt-1 text-xs text-muted">{formatTime(check.verified_at)}</div>}
            </Cell>
            <Cell>
              {check ? (
                <>
                  <div>Method: {humanize(check.method)}</div>
                  <div className="text-xs">{SCOPE[check.scope] ?? humanize(check.scope)}</div>
                  <div className="text-xs text-muted">Note: {check.note}</div>
                </>
              ) : (
                <span className="text-muted">Not checked</span>
              )}
            </Cell>
          </tr>
        );
      })}
    </Table>
  );
}

async function load(id: string) {
  const assetPath = encodeURIComponent(id);
  const me = await api<Me>("/auth/me");
  const admin = me.role === "admin";
  const [asset, history, evidence, reviews, policies, incidents, frameworks, people] =
    await Promise.all([
      api<AssetDetail>(`/governance/assets/${assetPath}`),
      api<Page<HistoryEntry>>(`/governance/assets/${assetPath}/history?limit=100`),
      api<Page<Evidence>>(`/governance/evidence?asset_id=${assetPath}&limit=100`),
      api<Page<Review>>(`/governance/approvals?asset_id=${assetPath}&limit=1`),
      api<Page<GovernancePolicy>>("/governance/policies?limit=100"),
      api<Page<RelatedIncident>>(`/incidents?asset_id=${assetPath}&limit=25`),
      api<CompliancePage<Framework>>("/governance/frameworks"),
      // The owner pickers list real users, and only an administrator can edit the profile.
      admin ? api<Page<Person>>("/governance/people?limit=100") : Promise.resolve(null),
    ]);
  const linked = new Set(evidence.items.flatMap((item) => item.control_ids));
  const controls = linked.size > 0 ? await allPages<Control>("/governance/controls") : null;
  return { admin, asset, history, evidence, reviews, policies, incidents, frameworks, people,
    controls, linked };
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
    controls, linked } = data;

  const review = reviews.items[0];
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
      <AssetSummary asset={asset} />

      <Section title="Profile">
        <p className="border-b border-line px-3 py-2 text-xs text-muted">
          {asset.profile
            ? `Version ${asset.profile.version}, saved ${formatTime(asset.profile.created_at)}. Each save is a new immutable version.`
            : "No profile has been saved yet. The risk assessment names what is missing."}
        </p>
        {admin && people ? (
          <ProfileForm
            assetId={asset.id}
            profile={asset.profile?.profile ?? {}}
            people={people.items}
          />
        ) : (
          <ProfileSummary asset={asset} />
        )}
      </Section>

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
