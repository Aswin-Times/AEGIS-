import Link from "next/link";
import { PermissionDenied } from "@/components/permission-denied";
import {
  Cell,
  EmptyState,
  FilterLinks,
  PageHeader,
  Pagination,
  Panel,
  StatusBadge,
  SyntheticBadge,
  Table,
} from "@/components/ui";
import { loadAccess } from "@/lib/access";
import { ApiError, api, query } from "@/lib/api";
import { formatTime, pageOffset } from "@/lib/format";
import type { AssetDetail, Review } from "@/lib/governance-types";
import type { Page } from "@/lib/types";
import { reviewStatus } from "./[id]/review-panels";

export const metadata = { title: "Approval Center | AEGIS" };

const LIMIT = 50;
const STATUSES = ["OPEN", "INFO_REQUESTED", "DECIDED", "WITHDRAWN"];

export default async function ApprovalsPage({
  searchParams,
}: {
  searchParams: Promise<{ status?: string; offset?: string }>;
}) {
  const params = await searchParams;
  const status = params.status && STATUSES.includes(params.status) ? params.status : undefined;
  const offset = pageOffset(params.offset);

  let reviews: Page<Review>;
  let assets: Map<string, AssetDetail>;
  let access: Awaited<ReturnType<typeof loadAccess>>;
  try {
    reviews = await api<Page<Review>>(
      `/governance/approvals${query({ status, limit: LIMIT, offset })}`,
    );
    // Names come from the asset records the reviews point at, never from a guess.
    const ids = [...new Set(reviews.items.map((review) => review.asset_id))];
    const found = await Promise.all(
      ids.map((id) => api<AssetDetail>(`/governance/assets/${encodeURIComponent(id)}`)),
    );
    assets = new Map(found.map((asset) => [asset.id, asset]));
    access = await loadAccess();
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    throw error;
  }

  return (
    <>
      <PageHeader
        title="Approval Center"
        description="Submissions waiting for a decision, and the ones already decided. Open a review to see what was frozen at submission and to decide it."
      />
      <FilterLinks
        basePath="/governance/approvals"
        name="status"
        current={status}
        options={[
          { value: undefined, label: "All" },
          { value: "OPEN", label: "Awaiting decision" },
          { value: "INFO_REQUESTED", label: "Information requested" },
          { value: "DECIDED", label: "Decided" },
          { value: "WITHDRAWN", label: "Withdrawn" },
        ]}
      />
      <Panel title="Reviews">
        {reviews.items.length === 0 ? (
          <EmptyState
            title="No reviews"
            detail={
              status
                ? "No review has this status."
                : "Nothing has been submitted for approval yet. A submission appears here."
            }
          />
        ) : (
          <Table
            head={[
              "AI asset",
              "Status",
              "Approvals needed",
              "Submitted",
              "Submitted by",
              "Assigned reviewer",
            ]}
          >
            {reviews.items.map((review) => {
              const asset = assets.get(review.asset_id);
              return (
                <tr key={review.id}>
                  <Cell>
                    <Link className="underline" href={`/governance/approvals/${review.id}`}>
                      {asset?.name ?? review.asset_id.slice(0, 8)}
                    </Link>
                    {asset?.is_synthetic && (
                      <div className="mt-1">
                        <SyntheticBadge />
                      </div>
                    )}
                  </Cell>
                  <Cell>
                    <StatusBadge value={reviewStatus(review.status)} />
                  </Cell>
                  <Cell>{review.required_approvers}</Cell>
                  <Cell mono>{formatTime(review.submitted_at)}</Cell>
                  <Cell>{access.label(review.submitted_by)}</Cell>
                  <Cell>
                    {review.assigned_reviewer ? access.label(review.assigned_reviewer) : "Not assigned"}
                  </Cell>
                </tr>
              );
            })}
          </Table>
        )}
        <Pagination
          basePath="/governance/approvals"
          total={reviews.total}
          limit={LIMIT}
          offset={offset}
          params={{ status }}
        />
      </Panel>
    </>
  );
}
