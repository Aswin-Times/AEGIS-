import Link from "next/link";
import { ComplianceStatement } from "@/components/compliance-statement";
import { LoadFailure } from "@/components/load-failure";
import { PermissionDenied } from "@/components/permission-denied";
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
import { ApiError, api, query } from "@/lib/api";
import { formatTime, humanize, pageOffset } from "@/lib/format";
import {
  CONTROL_STATUSES,
  type CompliancePage as Compliance,
  type Control,
  type Framework,
} from "@/lib/governance-types";
import { FrameworkPanel } from "./framework-panel";

export const metadata = { title: "Compliance mapping | AEGIS" };

const PAGE_SIZE = 25;

type Search = { framework?: string; status?: string; offset?: string };

/** The API's refusal, as words. A 403 is the caller's to render as PermissionDenied. */
function refusal(error: unknown): string | null {
  if (error instanceof ApiError && error.status !== 403 && error.status < 500) return error.message;
  return null;
}

export default async function CompliancePage({
  searchParams,
}: {
  searchParams: Promise<Search>;
}) {
  const raw = await searchParams;
  let frameworks: Compliance<Framework>;
  try {
    frameworks = await api<Compliance<Framework>>("/governance/frameworks");
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    const message = refusal(error);
    if (message === null) throw error;
    return (
      <>
        <PageHeader title="Compliance mapping" />
        <LoadFailure what="Frameworks" message={message} />
      </>
    );
  }

  // The first framework that has controls, unless the address names one.
  const selected = raw.framework || frameworks.items.find((item) => item.control_count > 0)?.id;
  const status = CONTROL_STATUSES.find((value) => value === raw.status);
  const offset = pageOffset(raw.offset);
  const framework = frameworks.items.find((item) => item.id === selected);

  let controls: Compliance<Control> | null = null;
  let failure: string | null = null;
  if (selected) {
    try {
      controls = await api<Compliance<Control>>(
        `/governance/controls${query({ framework_id: selected, status, limit: PAGE_SIZE, offset })}`,
      );
    } catch (error) {
      if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
      failure = refusal(error);
      if (failure === null) throw error;
    }
  }
  const params = { framework: raw.framework, status };

  return (
    <>
      <PageHeader
        title="Compliance mapping"
        description="Where this organization's own assessments map to framework controls, from stored records."
      />
      <ComplianceStatement text={frameworks.statement} />
      <p className="mb-4 max-w-3xl text-sm text-muted">
        A control&apos;s status is the one the API derives from the latest assessment a person
        recorded. Implemented and Partially implemented appear only while at least one linked
        evidence item is verified. Unverified or rejected evidence does not count, and a claim
        without verified evidence behind it shows as Evidence required.
      </p>

      <div className="mb-4 grid gap-3 md:grid-cols-2">
        {frameworks.items.map((item) => (
          <FrameworkPanel key={item.id} framework={item} selected={item.id === selected} />
        ))}
      </div>

      <Panel title="Controls">
        <div className="p-3">
          {framework && (
            <p className="mb-2 text-sm text-muted">
              Controls of {framework.name}, version {framework.version}.
            </p>
          )}
          {selected && (
            <FilterLinks
              basePath="/governance/compliance"
              name="status"
              current={status}
              params={{ framework: raw.framework }}
              options={[
                { value: undefined, label: "Any status" },
                ...CONTROL_STATUSES.map((value) => ({ value, label: humanize(value) })),
              ]}
            />
          )}
        </div>
        {failure !== null ? (
          <div className="p-3">
            <LoadFailure what="Controls" message={failure} />
          </div>
        ) : controls === null ? (
          <EmptyState
            title="No controls are loaded for this framework"
            detail="No framework in this organization has controls in its library."
          />
        ) : framework?.control_count === 0 ? (
          <EmptyState
            title="No controls are loaded for this framework"
            detail={`${framework.name} has no controls in its library, so there is nothing to assess.`}
          />
        ) : controls.items.length === 0 ? (
          <EmptyState title="No controls match" detail="No stored control has this status." />
        ) : (
          <>
            <Table head={["Control", "Name", "Status", "Evidence", "Last assessed"]}>
              {controls.items.map((control) => (
                <tr key={control.id}>
                  <Cell>
                    <Link
                      className="underline"
                      href={`/governance/compliance/controls/${control.id}`}
                    >
                      {control.identifier}
                    </Link>
                  </Cell>
                  <Cell>{control.name}</Cell>
                  <Cell>
                    <StatusBadge value={control.current_status} />
                  </Cell>
                  <Cell>
                    {control.verified_evidence_count} verified of {control.linked_evidence_count}{" "}
                    linked
                  </Cell>
                  <Cell>
                    {control.latest_assessment ? (
                      formatTime(control.latest_assessment.assessed_at)
                    ) : (
                      <span className="text-muted">Never</span>
                    )}
                  </Cell>
                </tr>
              ))}
            </Table>
            <Pagination
              basePath="/governance/compliance"
              total={controls.total}
              limit={controls.limit}
              offset={controls.offset}
              params={params}
            />
          </>
        )}
      </Panel>
    </>
  );
}
