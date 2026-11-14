import { Cell, EmptyState, Panel, StatusBadge, Table } from "@/components/ui";
import { formatTime, humanize } from "@/lib/format";
import type { AssetDecision, Conditions } from "@/lib/governance-types";

/**
 * The wording follows backend/src/aegis/governance/conditions.py: every field but
 * advisory_conditions is enforced by the gateway, and that one is only shown to people.
 */
export function ConditionsList({ conditions }: { conditions: Partial<Conditions> }) {
  const rows: { label: string; value: string; enforced: boolean }[] = [];
  const listed = (label: string, values: string[] | undefined) => {
    if (values?.length) rows.push({ label, value: values.join(", "), enforced: true });
  };
  listed("Denied tools", conditions.denied_tools);
  listed("Held tools", conditions.held_tools);
  listed("Denied actions", conditions.denied_actions);
  if (conditions.hold_all) {
    rows.push({ label: "Hold every action for approval", value: "Yes", enforced: true });
  }
  if (conditions.max_resource_classification) {
    rows.push({
      label: "Highest resource classification",
      value: humanize(conditions.max_resource_classification),
      enforced: true,
    });
  }
  for (const text of conditions.advisory_conditions ?? []) {
    rows.push({ label: "Advisory condition", value: text, enforced: false });
  }
  if (rows.length === 0) return <p className="text-muted">Contains nothing.</p>;
  return (
    <ul className="space-y-1">
      {rows.map((row, index) => (
        <li key={`${row.label}-${index}`}>
          {row.label}: <span className="break-words">{row.value}</span>{" "}
          <span className="whitespace-nowrap rounded border border-line px-1.5 py-0.5 text-xs text-muted">
            {row.enforced ? "Enforced by the gateway" : "Advisory, not enforced"}
          </span>
        </li>
      ))}
    </ul>
  );
}

const CLOSING = new Set(["APPROVE", "APPROVE_CONDITIONAL"]);

export function ConditionsPanel({
  decisions,
  label,
}: {
  decisions: AssetDecision[];
  label: (id: string | null) => string;
}) {
  const withConditions = decisions.filter((decision) => decision.conditions !== null);
  return (
    <Panel title="Conditions on this review">
      <p className="border-b border-line px-3 py-2 text-xs text-muted">
        Conditions of every vote bind every later approval, even from a voter who no longer
        counts, so an approval must carry exactly them. They take effect only through the final
        approval.
      </p>
      {withConditions.length === 0 ? (
        <EmptyState title="No conditions" detail="No vote on this review has set any." />
      ) : (
        <ul className="divide-y divide-line">
          {withConditions.map((decision) => (
            <li key={decision.id} className="p-3">
              <p className="mb-1 text-xs text-muted">
                {CLOSING.has(decision.kind) ? "Final approval" : "Vote"} by{" "}
                {label(decision.decided_by)}, {formatTime(decision.decided_at)}
              </p>
              <ConditionsList conditions={decision.conditions!} />
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function DecisionHistory({
  decisions,
  label,
  evidenceNames,
}: {
  decisions: AssetDecision[];
  label: (id: string | null) => string;
  evidenceNames: Map<string, string>;
}) {
  return (
    <Panel title="Decision history">
      {decisions.length === 0 ? (
        <EmptyState title="No decisions" detail="Nothing has been recorded on this review." />
      ) : (
        <Table head={["When", "Decision", "By", "Reason", "Detail"]}>
          {decisions.map((decision) => (
            <tr key={decision.id}>
              <Cell mono>{formatTime(decision.decided_at)}</Cell>
              <Cell>{humanize(decision.kind)}</Cell>
              <Cell>{decision.actor_type === "system" ? "System" : label(decision.decided_by)}</Cell>
              <Cell>{decision.reason}</Cell>
              <Cell>
                {decision.from_status !== decision.to_status && (
                  <div className="flex flex-wrap items-center gap-1">
                    <StatusBadge value={decision.from_status} /> to{" "}
                    <StatusBadge value={decision.to_status} />
                  </div>
                )}
                {decision.valid_until && (
                  <div className="text-xs text-muted">
                    Valid until {formatTime(decision.valid_until)}
                    {decision.next_review_at && `, review by ${formatTime(decision.next_review_at)}`}
                  </div>
                )}
                {decision.conditions && (
                  <div className="text-xs text-muted">Conditions recorded</div>
                )}
                {decision.evidence_ids.length > 0 && (
                  <div className="text-xs text-muted">
                    Evidence:{" "}
                    {decision.evidence_ids.map((id) => evidenceNames.get(id) ?? id.slice(0, 8)).join("; ")}
                  </div>
                )}
              </Cell>
            </tr>
          ))}
        </Table>
      )}
    </Panel>
  );
}
