import { Cell, EmptyState, PageHeader, Pagination, Panel, Table } from "@/components/ui";
import { api, query } from "@/lib/api";
import { formatTime, pageOffset, shortId } from "@/lib/format";
import type { AuditEvent, AuditHead, Me, Page } from "@/lib/types";
import { VerifyPanel } from "./verify-panel";

export const metadata = { title: "Audit Records | AEGIS" };

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ offset?: string }>;
}) {
  const { offset } = await searchParams;
  const [page, head, me] = await Promise.all([
    api<Page<AuditEvent>>(`/audit/events${query({ offset: pageOffset(offset) })}`),
    api<AuditHead>("/audit/head"),
    api<Me>("/auth/me"),
  ]);
  return (
    <>
      <PageHeader
        title="Audit Records"
        description={`Append-only, hash-chained events. Chain head: event ${head.seq}, ${head.head_hash.slice(0, 16)}.`}
      />
      <VerifyPanel canVerify={me.role === "admin" || me.role === "reviewer"} />
      <Panel>
        {page.items.length === 0 ? (
          <EmptyState title="No audit events" detail="Events appear as actions are recorded." />
        ) : (
          <Table head={["#", "Time", "Event", "Actor", "Correlation", "Details", "Hash"]}>
            {page.items.map((event) => (
              <tr key={event.id}>
                <Cell mono>{event.seq}</Cell>
                <Cell mono>{formatTime(event.occurred_at)}</Cell>
                <Cell mono>{event.event_type}</Cell>
                <Cell>
                  {event.actor_type}
                  {event.actor_id && (
                    <span className="ml-1 font-mono text-xs text-muted">
                      {shortId(event.actor_id)}
                    </span>
                  )}
                </Cell>
                <Cell mono>{event.correlation_id ? shortId(event.correlation_id) : "None"}</Cell>
                <Cell mono>
                  <span className="block max-w-sm truncate" title={JSON.stringify(event.payload)}>
                    {JSON.stringify(event.payload)}
                  </span>
                </Cell>
                <Cell mono>{event.event_hash.slice(0, 12)}</Cell>
              </tr>
            ))}
          </Table>
        )}
        <Pagination basePath="/audit" {...page} />
      </Panel>
    </>
  );
}
