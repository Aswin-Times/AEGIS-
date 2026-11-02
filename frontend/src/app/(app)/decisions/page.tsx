import Link from "next/link";
import {
  Cell,
  EmptyState,
  FilterLinks,
  PageHeader,
  Pagination,
  Panel,
  StatusBadge,
  Table,
} from "@/components/ui";
import { api, query } from "@/lib/api";
import { formatTime, humanize, pageOffset } from "@/lib/format";
import type { Decision, Page } from "@/lib/types";

export const metadata = { title: "Policy Decisions | AEGIS" };

const OUTCOMES = ["ALLOW", "DENY", "REQUIRE_APPROVAL"];

export default async function DecisionsPage({
  searchParams,
}: {
  searchParams: Promise<{ outcome?: string; offset?: string }>;
}) {
  const { outcome: rawOutcome, offset } = await searchParams;
  const outcome = rawOutcome && OUTCOMES.includes(rawOutcome) ? rawOutcome : undefined;
  const page = await api<Page<Decision>>(
    `/decisions${query({ outcome, offset: pageOffset(offset) })}`,
  );
  return (
    <>
      <PageHeader
        title="Policy Decisions"
        description="Each policy decision made at the gateway, and whether a tool actually ran."
      />
      <FilterLinks
        basePath="/decisions"
        name="outcome"
        current={outcome}
        options={[
          { value: undefined, label: "All" },
          { value: "DENY", label: "Denied" },
          { value: "ALLOW", label: "Allowed" },
          { value: "REQUIRE_APPROVAL", label: "Held for approval" },
        ]}
      />
      <Panel>
        {page.items.length === 0 ? (
          <EmptyState
            title="No matching decisions"
            detail="Decisions appear here when an agent submits an action to the gateway."
          />
        ) : (
          <Table
            head={["Time", "Agent", "Tool", "Outcome", "Reason", "Policy", "Execution", "Evidence"]}
          >
            {page.items.map((decision) => (
              <tr key={decision.id}>
                <Cell mono>{formatTime(decision.evaluated_at)}</Cell>
                <Cell>{decision.agent_name}</Cell>
                <Cell mono>{decision.tool}</Cell>
                <Cell>
                  <StatusBadge value={decision.outcome} />
                </Cell>
                <Cell>{humanize(decision.reason_code)}</Cell>
                <Cell>
                  {decision.policy_version === null ? "None" : `v${decision.policy_version}`}
                </Cell>
                <Cell>
                  {decision.execution ? (
                    <StatusBadge value={decision.execution.status} />
                  ) : (
                    <span className="text-muted">Tool did not run</span>
                  )}
                </Cell>
                <Cell>
                  <Link className="underline" href={`/decisions/${decision.id}`}>
                    View
                  </Link>
                </Cell>
              </tr>
            ))}
          </Table>
        )}
        <Pagination basePath="/decisions" {...page} params={{ outcome }} />
      </Panel>
    </>
  );
}
