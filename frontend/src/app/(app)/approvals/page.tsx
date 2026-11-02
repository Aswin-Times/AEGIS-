import { ConfirmAction } from "@/components/confirm-action";
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
import { formatTime, pageOffset, shortId } from "@/lib/format";
import type { Approval, Me, Page } from "@/lib/types";
import { decideApproval } from "./actions";

export const metadata = { title: "Approval Queue | AEGIS" };

const STATUSES = ["PENDING", "APPROVED", "REJECTED", "EXECUTED", "CANCELLED"];

function ActionSummary({ approval }: { approval: Approval }) {
  return (
    <dl className="space-y-1">
      <div>
        <dt className="inline text-muted">Tool: </dt>
        <dd className="inline font-mono text-xs">{approval.tool}</dd>
      </div>
      <div>
        <dt className="inline text-muted">Resource: </dt>
        <dd className="inline break-all font-mono text-xs">{approval.resource_id ?? "None"}</dd>
      </div>
      <div>
        <dt className="text-muted">Exact parameters:</dt>
        <dd>
          <pre className="mt-1 max-h-48 overflow-auto rounded bg-subtle p-2 font-mono text-xs">
            {JSON.stringify(approval.params, null, 2)}
          </pre>
        </dd>
      </div>
      <div>
        <dt className="inline text-muted">Action hash: </dt>
        <dd className="inline break-all font-mono text-xs">{approval.action_hash}</dd>
      </div>
    </dl>
  );
}

export default async function ApprovalsPage({
  searchParams,
}: {
  searchParams: Promise<{ status?: string; offset?: string }>;
}) {
  const { status: rawStatus, offset } = await searchParams;
  const status = rawStatus && STATUSES.includes(rawStatus) ? rawStatus : undefined;
  const [page, me] = await Promise.all([
    api<Page<Approval>>(`/approvals${query({ status, offset: pageOffset(offset) })}`),
    api<Me>("/auth/me"),
  ]);
  const canDecide = me.role === "admin" || me.role === "reviewer";

  return (
    <>
      <PageHeader
        title="Approval Queue"
        description="Held actions stay unexecuted until approved. An approval covers one exact action, can be used once, and is checked again against current policy when the agent executes it."
      />
      <FilterLinks
        basePath="/approvals"
        name="status"
        current={status}
        options={[
          { value: undefined, label: "All" },
          ...STATUSES.map((value) => ({
            value,
            label: value.charAt(0) + value.slice(1).toLowerCase(),
          })),
        ]}
      />
      <Panel>
        {page.items.length === 0 ? (
          <EmptyState
            title="Nothing here"
            detail="Actions appear here when a policy rule requires approval."
          />
        ) : (
          <Table head={["Requested", "Tool", "Parameters", "Status", "Expires", "Decision"]}>
            {page.items.map((approval) => (
              <tr key={approval.id}>
                <Cell mono>{formatTime(approval.requested_at)}</Cell>
                <Cell mono>{approval.tool}</Cell>
                <Cell mono>
                  <span className="block max-w-xs truncate">{JSON.stringify(approval.params)}</span>
                </Cell>
                <Cell>
                  <StatusBadge value={approval.status} />
                </Cell>
                <Cell mono>{formatTime(approval.expires_at)}</Cell>
                <Cell>
                  {approval.status === "PENDING" && canDecide ? (
                    <div className="flex flex-wrap gap-1">
                      <ConfirmAction
                        trigger="Approve"
                        triggerLabel={`Approve ${shortId(approval.id)}`}
                        title="Approve this exact action?"
                        confirmLabel="Approve action"
                        action={decideApproval}
                        fields={{ approval_id: approval.id, decision: "approve" }}
                      >
                        <ActionSummary approval={approval} />
                      </ConfirmAction>
                      <ConfirmAction
                        trigger="Reject"
                        triggerLabel={`Reject ${shortId(approval.id)}`}
                        title="Reject this action?"
                        confirmLabel="Reject action"
                        danger
                        action={decideApproval}
                        fields={{ approval_id: approval.id, decision: "reject" }}
                      >
                        <ActionSummary approval={approval} />
                      </ConfirmAction>
                    </div>
                  ) : approval.decided_at ? (
                    <span className="text-xs text-muted">{formatTime(approval.decided_at)}</span>
                  ) : (
                    <span className="text-xs text-muted">Awaiting a reviewer</span>
                  )}
                </Cell>
              </tr>
            ))}
          </Table>
        )}
        <Pagination basePath="/approvals" {...page} params={{ status }} />
      </Panel>
    </>
  );
}
