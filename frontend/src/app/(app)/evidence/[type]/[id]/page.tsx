import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader, Panel } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { formatTime, humanize } from "@/lib/format";
import type { EvidenceRecord } from "@/lib/types";

export const metadata = { title: "Evidence record | AEGIS" };

// Fields that point at another evidence record, so a reviewer can follow the chain.
const LINKED_FIELDS: Record<string, string> = {
  decision_id: "policy_decision",
  approval_id: "approval",
  execution_id: "execution",
  source_audit_event_id: "audit_event",
};

function FieldValue({ name, value }: { name: string; value: unknown }) {
  if (value === null || value === undefined) return <span className="text-muted">None</span>;
  const target = LINKED_FIELDS[name];
  if (target && typeof value === "string") {
    return (
      <Link className="break-all font-mono text-xs underline" href={`/evidence/${target}/${value}`}>
        {value}
      </Link>
    );
  }
  const text = typeof value === "object" ? JSON.stringify(value, null, 2) : String(value);
  return typeof value === "object" ? (
    <pre className="overflow-x-auto font-mono text-xs">{text}</pre>
  ) : (
    <span className="break-all font-mono text-xs">{text}</span>
  );
}

export default async function EvidencePage({
  params,
}: {
  params: Promise<{ type: string; id: string }>;
}) {
  const { type, id } = await params;
  let record: EvidenceRecord;
  try {
    record = await api<EvidenceRecord>(
      `/evidence/${encodeURIComponent(type)}/${encodeURIComponent(id)}`,
    );
  } catch (error) {
    if (error instanceof ApiError && [404, 422].includes(error.status)) notFound();
    throw error;
  }

  return (
    <>
      <PageHeader
        title={humanize(record.type)}
        description={`Stored record ${record.id}, from ${formatTime(record.occurred_at)}. Tool results, parameters, and message bodies are never shown here.`}
      />
      <Panel>
        <dl className="divide-y divide-line">
          {Object.entries(record.fields).map(([name, value]) => (
            <div key={name} className="grid grid-cols-1 gap-1 px-3 py-2 sm:grid-cols-[14rem_1fr]">
              <dt className="text-xs text-muted">{humanize(name)}</dt>
              <dd className="min-w-0">
                <FieldValue name={name} value={value} />
              </dd>
            </div>
          ))}
        </dl>
      </Panel>
    </>
  );
}
