import { Library } from "lucide-react";
import Link from "next/link";
import { Panel } from "@/components/ui";
import { humanize } from "@/lib/format";
import { CONTROL_STATUSES, type Framework } from "@/lib/governance-types";

// What each library status means. A partial library is never presented as the whole framework.
const LIBRARY: Record<Framework["library_status"], { label: string; meaning: string }> = {
  NOT_LOADED: {
    label: "Not loaded",
    meaning: "No controls are available for this framework.",
  },
  LOADED_PARTIAL: {
    label: "Partial library",
    meaning:
      "Only identifiers that were checked against the source are included. This is not the whole framework.",
  },
  LOADED: { label: "Loaded", meaning: "Every identifier the source defines is included." },
};

/** One framework as the API reports it: its library status, counts, and status counts. */
export function FrameworkPanel({
  framework,
  selected,
}: {
  framework: Framework;
  selected: boolean;
}) {
  const library = LIBRARY[framework.library_status];
  // NIST AI RMF calls its controls subcategories. No other framework is assumed to.
  const unit = framework.key.startsWith("nist") ? "subcategories" : "controls";
  const counted =
    framework.source_control_count === null
      ? `${framework.control_count} controls`
      : `${framework.control_count} of ${framework.source_control_count} ${unit}`;
  return (
    <Panel title={framework.name}>
      <div className="space-y-2 p-3">
        <p className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1 rounded border border-line px-1.5 py-0.5 text-xs font-medium">
            <Library aria-hidden size={12} />
            {library.label}
          </span>
          <span className="text-xs text-muted">Version {framework.version}</span>
        </p>
        <p>
          <strong>{counted}</strong>
          <span className="text-muted"> in the library</span>
        </p>
        <p className="text-xs text-muted">{library.meaning}</p>
        <p className="text-xs text-muted">{framework.coverage}</p>
        <p className="text-xs text-muted">
          Source: {framework.source_document}
          {framework.source_url && (
            <>
              {" "}
              (
              <a
                className="underline"
                href={framework.source_url}
                rel="noopener noreferrer"
                target="_blank"
              >
                published text
              </a>
              )
            </>
          )}
        </p>
        {framework.control_count > 0 && (
          <>
            <dl className="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
              {CONTROL_STATUSES.map((status) => (
                <div key={status} className="flex justify-between gap-2">
                  <dt className="text-muted">{humanize(status)}</dt>
                  <dd className="font-medium">{framework.status_counts[status] ?? 0}</dd>
                </div>
              ))}
            </dl>
            {selected ? (
              <p className="text-xs text-muted">Its controls are listed below.</p>
            ) : (
              <Link
                className="inline-block text-sm underline"
                href={`/governance/compliance?framework=${framework.id}`}
              >
                View controls<span className="sr-only"> of {framework.name}</span>
              </Link>
            )}
          </>
        )}
      </div>
    </Panel>
  );
}
