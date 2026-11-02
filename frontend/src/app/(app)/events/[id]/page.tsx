import { CheckCircle2, ShieldBan } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import type { ReactNode } from "react";
import { PageHeader, Panel, StatusBadge } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { formatTime, humanize } from "@/lib/format";
import type { DecisionDetail } from "@/lib/types";

export const metadata = { title: "Decision evidence | AEGIS" };

function Row({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-1 gap-1 px-3 py-2 sm:grid-cols-[12rem_1fr]">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : ""}>{children}</dd>
    </div>
  );
}

export default async function DecisionPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let decision: DecisionDetail;
  try {
    decision = await api<DecisionDetail>(`/decisions/${encodeURIComponent(id)}`);
  } catch (error) {
    if (error instanceof ApiError && [404, 422].includes(error.status)) notFound();
    throw error;
  }

  return (
    <>
      <PageHeader title="Decision evidence" description={humanize(decision.reason_code)}>
        <StatusBadge value={decision.outcome} />
      </PageHeader>
      <div className="mb-4 flex items-start gap-2 rounded-md border border-line bg-surface p-3">
        {decision.tool_executed ? (
          <CheckCircle2 aria-hidden size={18} className="mt-0.5 text-allow" />
        ) : (
          <ShieldBan aria-hidden size={18} className="mt-0.5 text-deny" />
        )}
        <p>
          {decision.tool_executed
            ? `An execution record exists for this request, with status ${decision.execution?.status}.`
            : `The tool did not run. No execution record exists for this request.`}
        </p>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Decision">
          <dl className="divide-y divide-line">
            <Row label="Decision ID" mono>{decision.id}</Row>
            <Row label="Request ID" mono>{decision.request_id}</Row>
            <Row label="Agent">{decision.agent_name}</Row>
            <Row label="Tool" mono>{decision.tool}</Row>
            <Row label="Action" mono>{decision.action ?? "None"}</Row>
            <Row label="Resource ID" mono>{decision.resource_id ?? "None"}</Row>
            <Row label="Reason code" mono>{decision.reason_code}</Row>
            <Row label="Matched rule" mono>{decision.matched_rule_id ?? "None"}</Row>
            <Row label="Policy version">
              {decision.policy_version === null ? "None" : `v${decision.policy_version}`}
            </Row>
            <Row label="Evaluated at" mono>{formatTime(decision.evaluated_at)}</Row>
          </dl>
        </Panel>
        <div className="space-y-4">
          <Panel title="Audit events for this request">
            <ul className="divide-y divide-line">
              {decision.audit_event_ids.map((eventId) => (
                <li key={eventId} className="break-all px-3 py-2 font-mono text-xs">
                  {eventId}
                </li>
              ))}
            </ul>
            <div className="border-t border-line px-3 py-2 text-xs">
              <Link className="underline" href="/audit">
                Open audit records and verify the chain
              </Link>
            </div>
          </Panel>
          <Panel title="Facts the engine evaluated">
            <pre className="overflow-x-auto p-3 font-mono text-xs">
              {JSON.stringify(decision.evidence, null, 2)}
            </pre>
          </Panel>
        </div>
      </div>
    </>
  );
}
