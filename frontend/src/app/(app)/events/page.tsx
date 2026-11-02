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
import { formatTime, pageOffset, shortId } from "@/lib/format";
import type { Page, SecurityEvent } from "@/lib/types";

export const metadata = { title: "Security Events | AEGIS" };

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const UUID = /^[0-9a-f-]{36}$/i;

export default async function EventsPage({
  searchParams,
}: {
  searchParams: Promise<{ severity?: string; agent_id?: string; offset?: string }>;
}) {
  const { severity: rawSeverity, agent_id: rawAgent, offset } = await searchParams;
  const severity = rawSeverity && SEVERITIES.includes(rawSeverity) ? rawSeverity : undefined;
  const agentId = rawAgent && UUID.test(rawAgent) ? rawAgent : undefined;
  const page = await api<Page<SecurityEvent>>(
    `/events${query({ severity, agent_id: agentId, offset: pageOffset(offset) })}`,
  );

  return (
    <>
      <PageHeader
        title="Security Events"
        description="Security-relevant activity recorded by AEGIS itself. Events never hold parameters, message bodies, or tool results, and there is no way to submit one."
      />
      <FilterLinks
        basePath="/events"
        name="severity"
        current={severity}
        options={[
          { value: undefined, label: "All" },
          ...SEVERITIES.map((value) => ({
            value,
            label: value.charAt(0).toUpperCase() + value.slice(1),
          })),
        ]}
      />
      <Panel>
        {page.items.length === 0 ? (
          <EmptyState
            title="No matching events"
            detail="Events appear here as agents and people use AEGIS."
          />
        ) : (
          <Table
            head={[
              "Time",
              "Event",
              "Severity",
              "Reason",
              "Agent",
              "Tool and action",
              "Decision",
              "Incident",
            ]}
          >
            {page.items.map((event) => (
              <tr key={event.id}>
                <Cell mono>{formatTime(event.occurred_at)}</Cell>
                <Cell mono>
                  <Link className="underline" href={`/evidence/security_event/${event.id}`}>
                    {event.event_type}
                  </Link>
                </Cell>
                <Cell>
                  <StatusBadge value={event.severity} />
                </Cell>
                <Cell mono>{event.reason_code}</Cell>
                <Cell>{event.agent_name ?? <span className="text-muted">None</span>}</Cell>
                <Cell mono>
                  {event.tool ? `${event.tool}${event.action ? ` (${event.action})` : ""}` : "None"}
                </Cell>
                <Cell mono>
                  {event.decision_id ? (
                    <Link className="underline" href={`/decisions/${event.decision_id}`}>
                      {shortId(event.decision_id)}
                    </Link>
                  ) : (
                    "None"
                  )}
                </Cell>
                <Cell mono>
                  {event.incident_ids.length > 0
                    ? event.incident_ids.map((id) => (
                        <Link key={id} className="mr-1 underline" href={`/incidents/${id}`}>
                          {shortId(id)}
                        </Link>
                      ))
                    : "None"}
                </Cell>
              </tr>
            ))}
          </Table>
        )}
        <Pagination
          basePath="/events"
          {...page}
          params={{ severity, agent_id: agentId }}
        />
      </Panel>
    </>
  );
}
