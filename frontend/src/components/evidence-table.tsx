import { Cell, EmptyState, StatusBadge, Table } from "@/components/ui";
import { formatTime, humanize } from "@/lib/format";
import type { Evidence } from "@/lib/governance-types";

// What a verification can have shown. A claim is never stronger than the check that ran.
const SCOPE: Record<string, string> = {
  hash_recomputed: "The hash was recomputed from the content and matched.",
  record_verified: "The internal record exists in this organization and its hash still verifies.",
  existence_only: "Existence only. The record exists, but its content was not recomputed.",
  attestation_only:
    "Manual attestation. Nothing was recomputed. A reviewer states that this is so.",
  judgment_only: "A reviewer rejected this evidence. No check was run.",
};

const SOURCE: Record<string, string> = {
  internal_record: "Internal record",
  inline: "Inline text",
  external_reference: "External reference",
};

export function EvidenceTable({ items }: { items: Evidence[] }) {
  if (items.length === 0) {
    return (
      <EmptyState
        title="No evidence recorded"
        detail="Evidence submitted for this asset, and how it was checked, is listed here."
      />
    );
  }
  return (
    <Table head={["Evidence", "Category", "Source", "Verification", "How it was checked"]}>
      {items.map((item) => {
        const check = item.latest_verification;
        return (
          <tr key={item.id}>
            <Cell>{item.description}</Cell>
            <Cell>{humanize(item.category)}</Cell>
            <Cell>
              {SOURCE[item.source_type] ?? item.source_type}
              {item.record_type && (
                <div className="text-xs text-muted">{humanize(item.record_type)}</div>
              )}
              {item.source_uri && (
                <div className="break-all text-xs text-muted">{item.source_uri}</div>
              )}
              {item.content_sha256 && (
                <div className="font-mono text-xs text-muted">
                  {item.source_type === "external_reference" ? "declared hash " : "hash "}
                  {item.content_sha256.slice(0, 12)}
                </div>
              )}
            </Cell>
            <Cell>
              <StatusBadge value={item.current_verification} />
              {check && <div className="mt-1 text-xs text-muted">{formatTime(check.verified_at)}</div>}
            </Cell>
            <Cell>
              {check ? (
                <>
                  <div>Method: {humanize(check.method)}</div>
                  <div className="text-xs">{SCOPE[check.scope] ?? humanize(check.scope)}</div>
                  <div className="text-xs text-muted">Note: {check.note}</div>
                </>
              ) : (
                <span className="text-muted">Not checked</span>
              )}
            </Cell>
          </tr>
        );
      })}
    </Table>
  );
}
