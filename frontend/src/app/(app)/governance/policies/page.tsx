import { PermissionDenied } from "@/components/permission-denied";
import { Cell, EmptyState, PageHeader, Panel, StatusBadge, Table } from "@/components/ui";
import { loadAccess } from "@/lib/access";
import { allPages } from "@/lib/all-pages";
import { ApiError } from "@/lib/api";
import { formatTime, humanize } from "@/lib/format";
import type { GovernancePolicy, PolicyDocument, PolicyVersion } from "@/lib/governance-types";
import type { Page } from "@/lib/types";
import { VersionActions } from "./version-actions";

export const metadata = { title: "Policy library | AEGIS" };

const APPLICABILITY: [keyof NonNullable<PolicyDocument["applicability"]>, string][] = [
  ["risk_levels", "Assessed risk"],
  ["asset_types", "Asset types"],
  ["environments", "Environments"],
  ["data_categories", "Data categories"],
];

function applicability(document: PolicyDocument): string {
  const parts = APPLICABILITY.flatMap(([key, label]) => {
    const values = document.applicability?.[key];
    return values?.length ? [`${label}: ${values.map(humanize).join(", ")}`] : [];
  });
  return parts.length ? parts.join(". ") : "Applies to every asset";
}

/** A requirement as the document states it, flattened to words. */
function requirement(key: string, value: unknown): string {
  if (Array.isArray(value)) return `${humanize(key)}: ${value.map(String).join(", ")}`;
  if (value !== null && typeof value === "object") {
    const inner = Object.entries(value).map(([name, item]) => requirement(name, item));
    return `${humanize(key)} (${inner.join("; ")})`;
  }
  return `${humanize(key)}: ${String(value)}`;
}

function status(version: PolicyVersion): string {
  if (version.active) return "active";
  return version.approved ? "APPROVED_NOT_ACTIVE" : "DRAFT";
}

export default async function PoliciesPage() {
  let policies: Page<GovernancePolicy>;
  let access: Awaited<ReturnType<typeof loadAccess>>;
  try {
    [policies, access] = await Promise.all([
      allPages<Page<GovernancePolicy>>("/governance/policies"),
      loadAccess(),
    ]);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    throw error;
  }
  const rows = policies.items.flatMap((policy): { policy: GovernancePolicy; version: PolicyVersion | null }[] =>
    policy.versions.length === 0
      ? [{ policy, version: null }]
      : policy.versions.map((version) => ({ policy, version })),
  );
  const controls = access.holder || access.admin;

  return (
    <>
      <PageHeader
        title="Policy library"
        description="Governance policy versions, what each applies to, and who approved it. A version is never edited: a change is a new version, with its own approval."
      />
      <p className="mb-3 max-w-3xl text-sm text-muted">
        These are this organization&apos;s own rules, checked against asset profiles when a review
        is submitted. Active means approved and switched on; a version applies only from its effective date. An active version is not a statement that any asset complies with it, or with
        any standard. The API does not say whether an approved version that is not active was never
        activated or was deactivated. Policies and new versions are created through the API.
      </p>
      <Panel title="Policy versions">
        {rows.length === 0 ? (
          <EmptyState
            title="No policies"
            detail="No governance policy has been created in this organization."
          />
        ) : (
          <Table
            head={[
              "Policy",
              "Version",
              "Status",
              "Applies to",
              "Requirements",
              "Approver",
              "Effective from",
              ...(controls ? ["Actions"] : []),
            ]}
          >
            {rows.map(({ policy, version }) => (
              <tr key={version?.id ?? policy.id}>
                <Cell>
                  {policy.name}
                  <div className="text-xs text-muted">{humanize(policy.category)}</div>
                </Cell>
                {version === null ? (
                  <Cell>
                    <span className="text-muted">No versions</span>
                  </Cell>
                ) : (
                  <>
                    <Cell>
                      Version {version.version}
                      <div className="text-xs text-muted">{version.document.description}</div>
                    </Cell>
                    <Cell>
                      <StatusBadge value={status(version)} />
                      {!version.approved && <div className="text-xs text-muted">Not approved</div>}
                    </Cell>
                    <Cell>{applicability(version.document)}</Cell>
                    <Cell>
                      {Object.entries(version.document.controls ?? {}).length === 0 ? (
                        <span className="text-muted">None stated</span>
                      ) : (
                        <ul className="space-y-0.5">
                          {Object.entries(version.document.controls ?? {}).map(([key, value]) => (
                            <li key={key}>{requirement(key, value)}</li>
                          ))}
                        </ul>
                      )}
                    </Cell>
                    <Cell>
                      {version.approved ? (
                        <>
                          {access.label(version.approved_by)}
                          <div className="text-xs text-muted">{formatTime(version.approved_at)}</div>
                        </>
                      ) : (
                        <span className="text-muted">None</span>
                      )}
                    </Cell>
                    <Cell>
                      {formatTime(version.effective_from)}
                      {version.review_by && (
                        <div className="text-xs text-muted">
                          Review by {formatTime(version.review_by)}
                        </div>
                      )}
                    </Cell>
                  </>
                )}
                {controls && (
                  <Cell>
                    {version && (
                      <VersionActions
                        policyId={policy.id}
                        versionId={version.id}
                        name={policy.name}
                        version={version.version}
                        approved={version.approved}
                        active={version.active}
                        canApprove={access.holder}
                        canActivate={access.admin}
                      />
                    )}
                  </Cell>
                )}
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
