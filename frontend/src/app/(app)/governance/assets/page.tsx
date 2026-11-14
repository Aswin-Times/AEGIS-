import {
  Cell,
  EmptyState,
  NotGovernedBadge,
  PageHeader,
  Pagination,
  Panel,
  RiskLabel,
  StatusBadge,
  SyntheticBadge,
  Table,
} from "@/components/ui";
import { PermissionDenied } from "@/components/permission-denied";
import { ApiError, api, query } from "@/lib/api";
import { formatTime, humanize, pageOffset } from "@/lib/format";
import {
  ASSESSED_RISK_LEVELS,
  DECLARED_RISK_LEVELS,
  GOVERNANCE_STATUSES,
  type InventoryRow,
} from "@/lib/governance-types";
import type { Page } from "@/lib/types";

export const metadata = { title: "AI asset inventory | AEGIS" };

type Search = {
  search?: string;
  declared_risk?: string;
  risk?: string;
  status?: string;
  offset?: string;
};

const only = (value: string | undefined, allowed: readonly string[]) =>
  value !== undefined && allowed.includes(value) ? value : undefined;

const FIELD = "mt-1 block rounded border border-line bg-surface px-2 py-1 text-ink";

function Select({
  label,
  name,
  current,
  values,
}: {
  label: string;
  name: string;
  current: string | undefined;
  values: readonly string[];
}) {
  return (
    <label className="block text-xs text-muted">
      {label}
      <select name={name} defaultValue={current ?? ""} className={FIELD}>
        <option value="">Any</option>
        {values.map((value) => (
          <option key={value} value={value}>
            {humanize(value)}
          </option>
        ))}
      </select>
    </label>
  );
}

export default async function InventoryPage({
  searchParams,
}: {
  searchParams: Promise<Search>;
}) {
  const raw = await searchParams;
  const filters = {
    search: raw.search?.trim().slice(0, 200) || undefined,
    declared_risk: only(raw.declared_risk, DECLARED_RISK_LEVELS),
    risk: only(raw.risk, ASSESSED_RISK_LEVELS),
    status: only(raw.status, GOVERNANCE_STATUSES),
  };
  const offset = pageOffset(raw.offset);

  let page: Page<InventoryRow>;
  try {
    page = await api<Page<InventoryRow>>(`/governance/assets${query({ ...filters, offset })}`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    throw error;
  }
  const filtered = Object.values(filters).some(Boolean);

  return (
    <>
      <PageHeader
        title="AI asset inventory"
        description="Every registered AI asset, with its declared risk and its governance state. An asset with no governance state is shown as not governed."
      />
      <form
        method="get"
        aria-label="Filter inventory"
        className="mb-3 flex flex-wrap items-end gap-3"
      >
        <label className="block text-xs text-muted">
          Search
          <input
            type="search"
            name="search"
            defaultValue={filters.search}
            maxLength={200}
            className={`${FIELD} w-56`}
          />
        </label>
        <Select
          label="Declared risk"
          name="declared_risk"
          current={filters.declared_risk}
          values={DECLARED_RISK_LEVELS}
        />
        <Select
          label="Assessed risk"
          name="risk"
          current={filters.risk}
          values={ASSESSED_RISK_LEVELS}
        />
        <Select
          label="Governance status"
          name="status"
          current={filters.status}
          values={GOVERNANCE_STATUSES}
        />
        <button type="submit" className="rounded border border-line px-3 py-1 hover:bg-subtle">
          Apply filters
        </button>
        {filtered && (
          <a href="/governance/assets" className="py-1 underline">
            Clear filters
          </a>
        )}
      </form>
      <Panel>
        {page.items.length === 0 ? (
          <EmptyState
            title="No AI assets match"
            detail={
              filtered
                ? "No asset matches these filters. Clear a filter to see more."
                : "No AI assets are registered in this organization yet."
            }
          />
        ) : (
          <Table
            head={[
              "Name",
              "Owner",
              "Declared risk",
              "Assessed risk",
              "Governance status",
              "Next review",
              "Registered",
            ]}
          >
            {page.items.map((asset) => (
              <tr key={asset.id}>
                <Cell>
                  <div className="flex flex-wrap items-center gap-2">
                    {asset.name}
                    {asset.is_synthetic && <SyntheticBadge />}
                  </div>
                </Cell>
                <Cell>
                  {asset.owner}
                  {asset.business_owner && (
                    <div className="text-xs text-muted">Business: {asset.business_owner.email}</div>
                  )}
                  {asset.technical_owner && (
                    <div className="text-xs text-muted">
                      Technical: {asset.technical_owner.email}
                    </div>
                  )}
                </Cell>
                <Cell>
                  <RiskLabel kind="declared" value={asset.declared_risk} />
                </Cell>
                <Cell>
                  {asset.assessed_risk ? (
                    <RiskLabel kind="assessed" value={asset.assessed_risk} />
                  ) : asset.last_assessed_at ? (
                    <StatusBadge value="INCOMPLETE" />
                  ) : (
                    <span className="text-muted">Not assessed</span>
                  )}
                </Cell>
                <Cell>
                  {asset.governance_status ? (
                    <StatusBadge value={asset.governance_status} />
                  ) : (
                    <NotGovernedBadge />
                  )}
                </Cell>
                <Cell mono>{formatTime(asset.next_review_at)}</Cell>
                <Cell mono>{formatTime(asset.created_at)}</Cell>
              </tr>
            ))}
          </Table>
        )}
        <Pagination basePath="/governance/assets" {...page} params={filters} />
      </Panel>
    </>
  );
}
