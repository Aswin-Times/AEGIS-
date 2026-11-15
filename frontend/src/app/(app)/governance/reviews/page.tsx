import Link from "next/link";
import { LoadFailure } from "@/components/load-failure";
import { PermissionDenied } from "@/components/permission-denied";
import { Tile } from "@/components/tile";
import {
  Cell,
  EmptyState,
  FilterLinks,
  PageHeader,
  Panel,
  StatusBadge,
  Table,
} from "@/components/ui";
import { allPages } from "@/lib/all-pages";
import { ApiError, query } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { DueReview, InventoryRow } from "@/lib/governance-types";
import type { Page } from "@/lib/types";

export const metadata = { title: "Review center | AEGIS" };

const WINDOWS = ["30", "90", "180", "365"];
const DEFAULT_WINDOW = "30";

function Dates({ review }: { review: Pick<DueReview, "next_review_at" | "valid_until" | "expired"> }) {
  return (
    <>
      <Cell>{formatTime(review.next_review_at)}</Cell>
      <Cell>
        {formatTime(review.valid_until)}
        {review.expired && <div className="text-xs text-deny">Approval expired</div>}
      </Cell>
    </>
  );
}

function AssetCell({ id, name }: { id: string; name: string }) {
  return (
    <Cell>
      <Link className="underline" href={`/governance/assets/${id}`}>
        {name}
      </Link>
    </Cell>
  );
}

function DueTable({ rows, empty }: { rows: DueReview[]; empty: { title: string; detail: string } }) {
  if (rows.length === 0) return <EmptyState {...empty} />;
  return (
    <Table head={["Asset", "Status", "Review date", "Approval valid until"]}>
      {rows.map((row) => (
        <tr key={row.asset_id}>
          <AssetCell id={row.asset_id} name={row.name} />
          <Cell>
            <StatusBadge value={row.governance_status} />
          </Cell>
          <Dates review={row} />
        </tr>
      ))}
    </Table>
  );
}

export default async function ReviewsPage({
  searchParams,
}: {
  searchParams: Promise<{ window?: string }>;
}) {
  const { window: raw } = await searchParams;
  // Sent to the API as given, so a value it refuses is shown as its refusal.
  const window = raw ?? DEFAULT_WINDOW;
  let due: Page<DueReview>;
  let requests: Page<InventoryRow>;
  try {
    [due, requests] = await Promise.all([
      allPages<Page<DueReview>>(`/governance/reviews/due${query({ window_days: window })}`),
      allPages<Page<InventoryRow>>(`/governance/assets${query({ status: "REASSESSMENT_REQUIRED" })}`),
    ]);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    if (error instanceof ApiError && error.status < 500) {
      return (
        <>
          <PageHeader title="Review center" />
          <LoadFailure what="Reviews" message={error.message} />
        </>
      );
    }
    throw error;
  }
  const overdue = due.items.filter((item) => item.overdue);
  const upcoming = due.items.filter((item) => !item.overdue);

  return (
    <>
      <PageHeader
        title="Review center"
        description="Approvals whose review date is near or past, and assets that were sent back for reassessment, from stored records."
      />
      <FilterLinks
        basePath="/governance/reviews"
        name="window"
        current={window}
        options={WINDOWS.map((value) => ({ value, label: `Next ${value} days` }))}
      />
      <p className="mb-3 max-w-3xl text-sm text-muted">
        Lists review dates within the next {window} days, plus every review already past its date.
        A review stays listed until a new approval sets the next date. The dates are the ones set
        when each approval was decided.
      </p>
      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        <Tile
          label="Upcoming"
          value={String(upcoming.length)}
          note={`Review dates within the next ${window} days.`}
        />
        <Tile
          label="Reviews owed past date"
          value={String(overdue.length)}
          note="Counts approved, conditionally approved, reassessment required, and under review assets whose review date has passed. It can overlap Awaiting approval on the overview."
        />
        <Tile
          label="Reassessment requested"
          value={String(requests.items.length)}
          note="Assets whose status is reassessment required."
        />
      </div>

      <div className="space-y-4">
        <Panel title="Upcoming reviews">
          <DueTable
            rows={upcoming}
            empty={{
              title: "No reviews are due",
              detail: `No asset has a review date within the next ${window} days.`,
            }}
          />
        </Panel>
        <Panel title="Past their review date">
          <DueTable
            rows={overdue}
            empty={{
              title: "No reviews are past their date",
              detail: "No asset is past the review date set when it was approved.",
            }}
          />
        </Panel>
        <Panel title="Reassessment requests">
          {requests.items.length === 0 ? (
            <EmptyState
              title="No reassessment requests"
              detail="No asset is waiting for reassessment."
            />
          ) : (
            <Table head={["Asset", "Status", "Review date", "Approval valid until"]}>
              {requests.items.map((row) => (
                <tr key={row.id}>
                  <AssetCell id={row.id} name={row.name} />
                  <Cell>
                    <StatusBadge value={row.governance_status ?? "REASSESSMENT_REQUIRED"} />
                  </Cell>
                  <Cell>{formatTime(row.next_review_at)}</Cell>
                  <Cell>{formatTime(row.valid_until)}</Cell>
                </tr>
              ))}
            </Table>
          )}
        </Panel>
      </div>
    </>
  );
}
