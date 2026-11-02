import { Cell, EmptyState, PageHeader, Panel, StatusBadge, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { Page, Policy } from "@/lib/types";

export const metadata = { title: "Policies | AEGIS" };

function describeMatch(match: Record<string, string[]>): string {
  const parts = Object.entries(match).map(
    ([key, values]) => `${key.replaceAll("_", " ")}: ${values.join(", ")}`,
  );
  return parts.length > 0 ? parts.join("; ") : "Every action that passes the fixed checks";
}

export default async function PoliciesPage() {
  const page = await api<Page<Policy>>("/policies?limit=100");
  return (
    <>
      <PageHeader
        title="Policies"
        description="Any deny wins, then any approval requirement, then any allow. If no rule matches, the action is denied. Rules cannot override grants or agent status."
      />
      {page.items.length === 0 ? (
        <Panel>
          <EmptyState
            title="No policies"
            detail="Until a policy is active, every protected action is denied."
          />
        </Panel>
      ) : (
        <div className="space-y-4">
          {page.items.map((policy) => (
            <Panel key={policy.id} title={policy.name}>
              {policy.versions.length === 0 ? (
                <EmptyState title="No versions" detail="This policy has no rules yet." />
              ) : (
                policy.versions.map((version) => (
                  <div key={version.id} className="border-b border-line last:border-b-0">
                    <div className="flex flex-wrap items-center gap-3 px-3 py-2 text-xs text-muted">
                      <span className="font-medium text-ink">Version {version.version}</span>
                      {version.id === policy.active_version_id && (
                        <span className="rounded bg-allow-bg px-1.5 py-0.5 font-medium text-allow">
                          Active
                        </span>
                      )}
                      <span>Created {formatTime(version.created_at)}</span>
                      <span className="font-mono">SHA-256 {version.content_hash.slice(0, 16)}</span>
                    </div>
                    <Table head={["Rule", "Effect", "Applies to", "Reason code"]}>
                      {version.document.rules.map((rule) => (
                        <tr key={rule.id}>
                          <Cell mono>{rule.id}</Cell>
                          <Cell>
                            <StatusBadge value={rule.effect} />
                          </Cell>
                          <Cell>{describeMatch(rule.match)}</Cell>
                          <Cell mono>{rule.reason_code}</Cell>
                        </tr>
                      ))}
                    </Table>
                  </div>
                ))
              )}
            </Panel>
          ))}
        </div>
      )}
    </>
  );
}
