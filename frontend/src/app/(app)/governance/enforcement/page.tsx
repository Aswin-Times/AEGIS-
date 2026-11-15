import Link from "next/link";
import { LoadFailure } from "@/components/load-failure";
import { PermissionDenied } from "@/components/permission-denied";
import { Tile } from "@/components/tile";
import {
  Cell,
  EmptyState,
  NotGovernedBadge,
  PageHeader,
  Panel,
  StatusBadge,
  Table,
} from "@/components/ui";
import { ApiError, api } from "@/lib/api";
import { MODE_NOTE, REASON_TEXT } from "@/lib/enforcement-text";
import { formatTime, humanize } from "@/lib/format";
import type { Preflight } from "@/lib/governance-types";
import type { Me } from "@/lib/types";
import { ModeForm } from "./mode-form";

export const metadata = { title: "Enforcement | AEGIS" };

export default async function EnforcementPage() {
  let preflight: Preflight;
  let me: Me;
  try {
    [preflight, me] = await Promise.all([
      api<Preflight>("/governance/enforcement/preflight"),
      api<Me>("/auth/me"),
    ]);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    if (error instanceof ApiError && error.status < 500) {
      return (
        <>
          <PageHeader title="Enforcement" />
          <LoadFailure what="Enforcement" message={error.message} />
        </>
      );
    }
    throw error;
  }
  const mode = preflight.enforcement_mode;
  const target = mode === "enforce" ? "observe" : "enforce";

  return (
    <>
      <PageHeader
        title="Enforcement"
        description="Whether the gateway blocks actions of assets that have no approval in force, and which assets that would affect."
      />

      <div className="mb-4">
        <Panel title="Enforcement mode">
          <div className="space-y-2 p-3">
            <p>
              <strong>{humanize(mode)}</strong>
            </p>
            <p className="text-sm text-muted">{MODE_NOTE[mode] ?? "Set by an administrator."}</p>
            {me.role === "admin" ? (
              <ModeForm target={target} />
            ) : (
              <p className="text-sm text-muted">
                Only an administrator can change the mode. The API refuses the change for any other
                role.
              </p>
            )}
          </div>
        </Panel>
      </div>

      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        <Tile label="Assets checked" value={String(preflight.assets_checked)} />
        <Tile
          label="Would deny"
          value={String(preflight.would_deny)}
          note="Assets whose actions enforce mode would deny."
        />
        <Tile
          label="Would hold"
          value={String(preflight.would_hold)}
          note="Assets whose actions enforce mode would hold for approval."
        />
      </div>

      <Panel title="What enforce mode would block">
        <p className="px-3 py-2 text-sm text-muted">
          This list changes nothing: it only reads stored records. Each asset is checked as enforce
          mode would check it for any action. A condition that names one tool already applies in
          both modes, so it is not listed. Recent checks are the ones the gateway
          recorded since {formatTime(preflight.since)}. A check that did not pass had a deny or
          hold verdict, whether the gateway applied it or, in observe mode, only recorded it.
        </p>
        {preflight.items.length === 0 ? (
          <EmptyState
            title="Enforce mode would block nothing"
            detail={`${preflight.assets_checked} assets were checked, and each has an approval in force or no decision that enforce mode would change.`}
          />
        ) : (
          <Table
            head={[
              "Asset",
              "Governance status",
              "In enforce mode",
              "Reason",
              "Recent checks",
              "Recent checks not passed",
            ]}
          >
            {preflight.items.map((item) => (
              <tr key={item.asset_id}>
                <Cell>
                  <Link className="underline" href={`/governance/assets/${item.asset_id}`}>
                    {item.name}
                  </Link>
                </Cell>
                <Cell>
                  {item.governance_status === null ? (
                    <NotGovernedBadge />
                  ) : (
                    <StatusBadge value={item.governance_status} />
                  )}
                </Cell>
                <Cell>
                  <StatusBadge value={item.verdict === "DENY" ? "DENY" : "REQUIRE_APPROVAL"} />
                </Cell>
                <Cell>
                  <span className="font-mono text-xs">{item.reason_code}</span>
                  {REASON_TEXT[item.reason_code] && (
                    <div className="text-xs text-muted">{REASON_TEXT[item.reason_code]}</div>
                  )}
                </Cell>
                <Cell>{item.recent_actions}</Cell>
                <Cell>{item.recent_not_passed}</Cell>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
