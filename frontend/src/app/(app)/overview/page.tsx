import Link from "next/link";
import { Cell, EmptyState, PageHeader, Panel, StatusBadge, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { formatTime, humanize } from "@/lib/format";
import type { Decision, Overview, Page } from "@/lib/types";

export const metadata = { title: "Overview | AEGIS" };

function Stat({ label, value, href }: { label: string; value: number | string; href: string }) {
  return (
    <Link href={href} className="rounded-md border border-line bg-surface p-3 hover:bg-subtle">
      <div className="text-xs text-muted">{label}</div>
      <div className="text-xl font-semibold tabular-nums">{value}</div>
    </Link>
  );
}

export default async function OverviewPage() {
  const [overview, recent] = await Promise.all([
    api<Overview>("/overview"),
    api<Page<Decision>>("/decisions?limit=8"),
  ]);
  const synthetic =
    overview.assets > 0 && overview.synthetic_assets === overview.assets
      ? "All registered assets in this organization are marked synthetic."
      : `${overview.synthetic_assets} of ${overview.assets} registered assets are marked synthetic.`;

  return (
    <>
      <PageHeader
        title="Overview"
        description={`Every number is a count of stored records. ${synthetic}`}
      />
      <div className="mb-4 grid grid-cols-2 gap-2 md:grid-cols-5 xl:grid-cols-9">
        <Stat label="Active incidents" value={overview.active_incidents} href="/incidents" />
        <Stat label="AI assets" value={overview.assets} href="/assets" />
        <Stat label="Agents" value={overview.agents} href="/agents" />
        <Stat label="Disabled agents" value={overview.agents_disabled} href="/agents" />
        <Stat label="Allowed" value={overview.decisions.ALLOW} href="/decisions?outcome=ALLOW" />
        <Stat label="Denied" value={overview.decisions.DENY} href="/decisions?outcome=DENY" />
        <Stat
          label="Pending approvals"
          value={overview.pending_approvals}
          href="/approvals?status=PENDING"
        />
        <Stat label="Tool executions" value={overview.executions} href="/decisions" />
        <Stat label="Audit events" value={overview.audit_events} href="/audit" />
      </div>
      {overview.active_policy_version_id === null && (
        <p role="alert" className="mb-4 rounded-md bg-deny-bg p-3 text-deny">
          No policy is active, so every protected action is being denied.
        </p>
      )}
      {overview.pending_correlation > 0 && (
        <p className="mb-4 rounded-md bg-hold-bg p-3 text-hold">
          {overview.pending_correlation} security events are waiting for correlation. Incidents may
          not yet reflect them. If this number does not fall, correlation has stopped, and the API
          logs say why.
        </p>
      )}
      <Panel title="Recent decisions">
        {recent.items.length === 0 ? (
          <EmptyState
            title="No decisions yet"
            detail="Decisions appear here when an agent submits an action to the gateway."
          />
        ) : (
          <Table head={["Time", "Agent", "Tool", "Outcome", "Reason", "Tool ran"]}>
            {recent.items.map((decision) => (
              <tr key={decision.id}>
                <Cell mono>{formatTime(decision.evaluated_at)}</Cell>
                <Cell>{decision.agent_name}</Cell>
                <Cell mono>{decision.tool}</Cell>
                <Cell>
                  <StatusBadge value={decision.outcome} />
                </Cell>
                <Cell>
                  <Link className="underline" href={`/decisions/${decision.id}`}>
                    {humanize(decision.reason_code)}
                  </Link>
                </Cell>
                <Cell>{decision.tool_executed ? "Yes" : "No"}</Cell>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
