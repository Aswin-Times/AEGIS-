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
import type { Incident, Page } from "@/lib/types";

export const metadata = { title: "Incidents | AEGIS" };

const STATUSES = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export default async function IncidentsPage({
  searchParams,
}: {
  searchParams: Promise<{ status?: string; severity?: string; offset?: string }>;
}) {
  const { status: rawStatus, severity: rawSeverity, offset } = await searchParams;
  const status = rawStatus && STATUSES.includes(rawStatus) ? rawStatus : undefined;
  const severity = rawSeverity && SEVERITIES.includes(rawSeverity) ? rawSeverity : undefined;
  const page = await api<Page<Incident>>(
    `/incidents${query({ status, severity, offset: pageOffset(offset) })}`,
  );

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Patterns found by explicit, versioned correlation rules. An incident is a question for a reviewer, not a verdict, and it has no effect on what agents may do."
      />
      <FilterLinks
        basePath="/incidents"
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
            title="No matching incidents"
            detail="An incident appears when a correlation rule's threshold is reached."
          />
        ) : (
          <Table
            head={[
              "Incident",
              "Severity",
              "Status",
              "Detection rule",
              "Agent",
              "First event",
              "Last event",
              "Events",
              "Assigned",
            ]}
          >
            {page.items.map((incident) => (
              <tr key={incident.id}>
                <Cell mono>
                  <Link className="underline" href={`/incidents/${incident.id}`}>
                    {shortId(incident.id)}
                  </Link>
                </Cell>
                <Cell>
                  <StatusBadge value={incident.severity} />
                </Cell>
                <Cell>
                  <StatusBadge value={incident.status} />
                </Cell>
                <Cell>{incident.title}</Cell>
                <Cell>{incident.agent_name ?? <span className="text-muted">None</span>}</Cell>
                <Cell mono>{formatTime(incident.first_observed_at)}</Cell>
                <Cell mono>{formatTime(incident.last_observed_at)}</Cell>
                <Cell>{incident.event_count}</Cell>
                <Cell>
                  {incident.assigned_to_email ?? <span className="text-muted">Unassigned</span>}
                </Cell>
              </tr>
            ))}
          </Table>
        )}
        <Pagination basePath="/incidents" {...page} params={{ status, severity }} />
      </Panel>
    </>
  );
}
