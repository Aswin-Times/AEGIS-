import type { ReactNode } from "react";
import { EmptyState, PageHeader, Panel } from "@/components/ui";
import { PermissionDenied } from "@/components/permission-denied";
import { Tile } from "@/components/tile";
import { ApiError, api } from "@/lib/api";
import { MODE_NOTE } from "@/lib/enforcement-text";
import { humanize } from "@/lib/format";
import type { GovernanceOverview } from "@/lib/governance-types";

export const metadata = { title: "Governance Center | AEGIS" };

function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mb-4">
      <h2 className="mb-2 text-sm font-semibold">{title}</h2>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{children}</div>
    </div>
  );
}

export default async function GovernanceOverviewPage() {
  let overview: GovernanceOverview;
  try {
    overview = await api<GovernanceOverview>("/governance/overview");
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    throw error;
  }
  const risk = (level: string) => String(overview.by_assessed_risk[level] ?? 0);

  return (
    <>
      <PageHeader
        title="Governance Center"
        description="Where AI assets stand in review, from this organization's own records."
      />
      {overview.total_assets === 0 && (
        <div className="mb-4">
          <Panel>
            <EmptyState
              title="No AI assets to govern"
              detail="Register an AI asset, and it appears here and in the inventory."
            />
          </Panel>
        </div>
      )}
      <Group title="Inventory">
        <Tile label="AI assets" value={String(overview.total_assets)} />
        <Tile
          label="Unassessed"
          value={String(overview.unassessed)}
          note="No complete assessment. Not counted in any risk level."
        />
      </Group>
      <Group title="Assessed risk">
        <Tile label="Assessed risk: Low" value={risk("LOW")} />
        <Tile label="Assessed risk: Medium" value={risk("MEDIUM")} />
        <Tile label="Assessed risk: High" value={risk("HIGH")} />
        <Tile label="Assessed risk: Critical" value={risk("CRITICAL")} />
      </Group>
      <Group title="Review">
        <Tile label="Awaiting approval" value={String(overview.awaiting_approval)} />
        <Tile label="Conditionally approved" value={String(overview.conditionally_approved)} />
        <Tile label="Suspended" value={String(overview.suspended)} />
        <Tile
          label="Reviews owed past date"
          value={String(overview.overdue_reviews)}
          note="Assets past their review date that are reassessment required or under review. Can overlap awaiting approval."
        />
      </Group>
      <Group title="Findings and evidence">
        <Tile label="Outstanding findings" value={String(overview.outstanding_findings)} />
        <Tile
          label="Evidence verified"
          value={`${overview.evidence_verified} of ${overview.evidence_total}`}
          note="Verified evidence items out of all evidence recorded."
        />
      </Group>
      <section
        aria-label="Enforcement mode"
        className="rounded-md border border-line bg-surface p-3"
      >
        <h2 className="text-sm font-semibold">Enforcement mode</h2>
        <p>
          <strong>{humanize(overview.enforcement_mode)}</strong>
        </p>
        <p className="text-xs text-muted">
          {MODE_NOTE[overview.enforcement_mode] ?? "Set by an administrator."}
        </p>
      </section>
    </>
  );
}
