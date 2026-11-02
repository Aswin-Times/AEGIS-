import {
  Cell,
  EmptyState,
  PageHeader,
  Pagination,
  Panel,
  StatusBadge,
  SyntheticBadge,
  Table,
} from "@/components/ui";
import { api, query } from "@/lib/api";
import { formatTime, pageOffset } from "@/lib/format";
import type { Asset, Page } from "@/lib/types";

export const metadata = { title: "AI Assets | AEGIS" };

export default async function AssetsPage({
  searchParams,
}: {
  searchParams: Promise<{ offset?: string }>;
}) {
  const { offset } = await searchParams;
  const page = await api<Page<Asset>>(`/assets${query({ offset: pageOffset(offset) })}`);
  return (
    <>
      <PageHeader title="AI Assets" description="Registered AI applications and their owners." />
      <Panel>
        {page.items.length === 0 ? (
          <EmptyState
            title="No AI assets registered"
            detail="An administrator can register one with POST /api/v1/assets."
          />
        ) : (
          <Table head={["Name", "Owner", "Risk", "Intended use", "Registered"]}>
            {page.items.map((asset) => (
              <tr key={asset.id}>
                <Cell>
                  <div className="flex flex-wrap items-center gap-2">
                    {asset.name}
                    {asset.is_synthetic && <SyntheticBadge />}
                  </div>
                </Cell>
                <Cell>{asset.owner}</Cell>
                <Cell>
                  <StatusBadge value={asset.risk_classification} />
                </Cell>
                <Cell>{asset.intended_use}</Cell>
                <Cell mono>{formatTime(asset.created_at)}</Cell>
              </tr>
            ))}
          </Table>
        )}
        <Pagination basePath="/assets" {...page} />
      </Panel>
    </>
  );
}
