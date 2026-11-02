import { FlaskConical } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import type { ReactNode } from "react";
import { ConfirmAction } from "@/components/confirm-action";
import { Cell, EmptyState, PageHeader, Panel, StatusBadge, Table } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { formatTime, shortId } from "@/lib/format";
import type {
  EvidenceRef,
  Finding,
  Findings,
  IncidentDetail,
  Me,
  Page,
  SecurityEvent,
  TimelineItem,
} from "@/lib/types";
import { moveIncident } from "./actions";
import { InvestigationButton } from "./investigation-button";

export const metadata = { title: "Incident | AEGIS" };

const EVIDENCE_LABEL: Record<string, string> = {
  security_event: "security event",
  policy_decision: "policy decision",
  approval: "approval",
  execution: "execution",
  audit_event: "audit event",
};

const CONTROLS: {
  verb: string;
  label: string;
  title: string;
  confirm: string;
  from: string[];
  reason: boolean;
  adminOnly?: boolean;
  danger?: boolean;
  detail: string;
}[] = [
  {
    verb: "acknowledge",
    label: "Acknowledge",
    title: "Acknowledge this incident?",
    confirm: "Acknowledge incident",
    from: ["OPEN"],
    reason: false,
    detail: "This records that you have seen it, and assigns it to you if it is unassigned.",
  },
  {
    verb: "investigate",
    label: "Investigate",
    title: "Start investigating this incident?",
    confirm: "Start investigating",
    from: ["OPEN", "ACKNOWLEDGED"],
    reason: false,
    detail: "This marks the incident as under investigation. It does not change any agent.",
  },
  {
    verb: "resolve",
    label: "Resolve",
    title: "Resolve this incident?",
    confirm: "Resolve incident",
    from: ["OPEN", "ACKNOWLEDGED", "INVESTIGATING"],
    reason: true,
    detail: "New matching events will count toward a new incident, not this one.",
  },
  {
    verb: "reopen",
    label: "Reopen",
    title: "Reopen this incident?",
    confirm: "Reopen incident",
    from: ["RESOLVED"],
    reason: true,
    detail: "This returns the incident to investigation.",
  },
  {
    verb: "close",
    label: "Close incident",
    title: "Close this incident?",
    confirm: "Close incident",
    from: ["RESOLVED"],
    reason: true,
    adminOnly: true,
    danger: true,
    detail: "Closing is final. A closed incident cannot be reopened.",
  },
];

const LLM_STATUS: Record<string, string> = {
  not_configured:
    "No AI provider is configured. Every finding above comes from stored records, and none depends on a model.",
  pending: "The AI step did not finish, so there are no hypotheses from this run.",
  timeout: "The AI provider timed out. The findings above are unaffected.",
  failed: "The AI provider failed. The findings above are unaffected.",
  invalid_output:
    "The AI reply was rejected because it was invalid or cited records it was not given. The findings above are unaffected.",
  succeeded: "These came from an AI model. They are not verified, and no action depends on them.",
};

function EvidenceLinks({ refs }: { refs: EvidenceRef[] }) {
  if (refs.length === 0) return null;
  return (
    <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs">
      {refs.map((ref) => (
        <Link
          key={`${ref.type}-${ref.id}`}
          href={`/evidence/${ref.type}/${ref.id}`}
          className="font-mono text-muted underline hover:text-ink"
        >
          {EVIDENCE_LABEL[ref.type] ?? ref.type} {shortId(ref.id)}
        </Link>
      ))}
    </div>
  );
}

function FindingList({ findings, empty }: { findings: Finding[]; empty?: string }) {
  if (findings.length === 0) {
    return empty ? <p className="px-3 py-2 text-muted">{empty}</p> : null;
  }
  return (
    <ul className="divide-y divide-line">
      {findings.map((finding) => (
        <li key={finding.id} className="px-3 py-2">
          <p>{finding.statement}</p>
          {finding.confidence && (
            <p className="text-xs text-muted">Model-stated confidence: {finding.confidence}</p>
          )}
          <EvidenceLinks refs={finding.evidence} />
        </li>
      ))}
    </ul>
  );
}

function Stat({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export default async function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const path = `/incidents/${encodeURIComponent(id)}`;
  let incident: IncidentDetail;
  try {
    incident = await api<IncidentDetail>(path);
  } catch (error) {
    if (error instanceof ApiError && [404, 422].includes(error.status)) notFound();
    throw error;
  }
  const [timeline, results, events, me] = await Promise.all([
    api<Page<TimelineItem>>(`${path}/timeline`),
    api<Findings>(`${path}/findings`),
    api<Page<SecurityEvent>>(`${path}/events?limit=100`),
    api<Me>("/auth/me"),
  ]);

  const canReview = me.role === "admin" || me.role === "reviewer";
  const ofKind = (kind: string) => results.findings.filter((finding) => finding.kind === kind);
  const controls = CONTROLS.filter(
    (control) =>
      control.from.includes(incident.status) &&
      (control.adminOnly ? me.role === "admin" : canReview),
  );
  const decisions = timeline.items.filter((item) => item.evidence.type === "policy_decision");
  const auditHistory = timeline.items.filter((item) => item.evidence.type === "audit_event");
  const resources = [
    ...new Set(events.items.map((event) => event.resource_id).filter((value) => value !== null)),
  ];

  return (
    <>
      <PageHeader title={incident.title} description={`Incident ${incident.id}`}>
        <div className="flex items-center gap-2">
          <StatusBadge value={incident.severity} />
          <span data-testid="incident-status" className="contents">
            <StatusBadge value={incident.status} />
          </span>
        </div>
      </PageHeader>

      <div className="mb-4 rounded-md border border-line bg-surface p-3">
        <dl className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          <Stat label="Detection rule">
            <span className="font-mono text-xs">
              {incident.rule_key} v{incident.rule_version}
            </span>
          </Stat>
          <Stat label="Agent">
            {incident.agent_name ?? <span className="text-muted">None</span>}
          </Stat>
          <Stat label="Related events">{incident.event_count}</Stat>
          <Stat label="First event">
            <span className="font-mono text-xs">{formatTime(incident.first_observed_at)}</span>
          </Stat>
          <Stat label="Last event">
            <span className="font-mono text-xs">{formatTime(incident.last_observed_at)}</span>
          </Stat>
          <Stat label="Assigned">
            {incident.assigned_to_email ?? <span className="text-muted">Unassigned</span>}
          </Stat>
        </dl>
        {incident.rule_definition === null && (
          <p role="alert" className="mt-2 text-sm text-deny">
            The rule version recorded on this incident failed its integrity check.
          </p>
        )}
        {(controls.length > 0 || canReview) && (
          <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-3">
            {canReview && <InvestigationButton incidentId={incident.id} />}
            {controls.map((control) => (
              <ConfirmAction
                key={control.verb}
                trigger={control.label}
                triggerLabel={control.label}
                title={control.title}
                confirmLabel={control.confirm}
                danger={control.danger}
                action={moveIncident}
                fields={{
                  incident_id: incident.id,
                  verb: control.verb,
                  expected_version: String(incident.version),
                }}
                extra={
                  control.reason ? (
                    <label className="mb-3 block text-sm">
                      Reason
                      <textarea
                        name="reason"
                        required
                        maxLength={2000}
                        rows={3}
                        className="mt-1 w-full rounded border border-line bg-surface p-2"
                      />
                    </label>
                  ) : null
                }
              >
                {control.detail}
              </ConfirmAction>
            ))}
          </div>
        )}
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="min-w-0 space-y-4">
          {results.run === null ? (
            <Panel title="Findings">
              <EmptyState
                title="No investigation has been run"
                detail="A reviewer can run one. It reads stored records and changes nothing else."
              />
            </Panel>
          ) : (
            <>
              <Panel title="Verified facts">
                <FindingList
                  findings={ofKind("observed_fact")}
                  empty="No verified facts could be established."
                />
              </Panel>
              <Panel title="Rule result">
                <FindingList
                  findings={ofKind("rule_result")}
                  empty="The rule result could not be established."
                />
              </Panel>
              <Panel title="What the records cannot show">
                <FindingList findings={ofKind("evidence_gap")} />
              </Panel>
              <Panel title="Recommended actions">
                <p className="border-b border-line px-3 py-2 text-xs text-muted">
                  Suggestions only. AEGIS performs none of these.
                </p>
                <FindingList findings={ofKind("recommended_action")} />
              </Panel>
              <section
                aria-label="AI hypotheses"
                className="rounded-md border border-dashed border-hold bg-surface"
              >
                <h2 className="flex items-center gap-2 border-b border-line px-3 py-2 text-sm font-semibold">
                  <FlaskConical aria-hidden size={14} className="text-hold" />
                  AI hypotheses (unverified)
                </h2>
                <p className="border-b border-line px-3 py-2 text-xs text-muted">
                  {LLM_STATUS[results.run.llm_status] ?? results.run.llm_status}
                  {results.run.llm_rejected_count > 0 &&
                    ` ${results.run.llm_rejected_count} unsupported claims were rejected.`}
                </p>
                <FindingList findings={ofKind("ai_hypothesis")} />
              </section>
              <p className="text-xs text-muted">
                Run {shortId(results.run.id)} at {formatTime(results.run.created_at)}. Evidence
                fingerprint {results.run.input_fingerprint.slice(0, 16)}.
              </p>
            </>
          )}
        </div>

        <div className="min-w-0 space-y-4">
          <Panel title="Evidence timeline">
            <ol className="divide-y divide-line">
              {timeline.items.map((item, index) => (
                <li key={`${item.evidence.id}-${item.kind}-${index}`} className="px-3 py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-muted">
                      {formatTime(item.occurred_at)}
                    </span>
                    <span className="font-mono text-xs font-medium">{item.kind}</span>
                    {item.severity && <StatusBadge value={item.severity} />}
                    {item.verified === false && (
                      <span className="rounded bg-deny-bg px-1.5 py-0.5 text-xs font-medium text-deny">
                        Failed verification
                      </span>
                    )}
                  </div>
                  <p className="text-sm">{item.summary}</p>
                  <EvidenceLinks refs={[item.evidence]} />
                </li>
              ))}
            </ol>
          </Panel>

          <Panel title="State changes">
            <Table head={["Time", "Change", "By", "Reason", "Audit"]}>
              {incident.transitions.map((transition) => (
                <tr key={transition.id}>
                  <Cell mono>{formatTime(transition.occurred_at)}</Cell>
                  <Cell>
                    {transition.from_status ? `${transition.from_status} to ` : ""}
                    {transition.to_status}
                  </Cell>
                  <Cell>
                    {transition.actor_id === me.id ? me.email : transition.actor_type}
                    {transition.actor_id && transition.actor_id !== me.id && (
                      <span className="ml-1 font-mono text-xs text-muted">
                        {shortId(transition.actor_id)}
                      </span>
                    )}
                  </Cell>
                  <Cell>{transition.reason ?? <span className="text-muted">None</span>}</Cell>
                  <Cell mono>
                    <Link
                      className="underline"
                      href={`/evidence/audit_event/${transition.audit_event_id}`}
                    >
                      {shortId(transition.audit_event_id)}
                    </Link>
                  </Cell>
                </tr>
              ))}
            </Table>
          </Panel>

          <Panel title="Related policy decisions">
            {decisions.length === 0 ? (
              <p className="px-3 py-2 text-muted">None linked to this incident.</p>
            ) : (
              <ul className="divide-y divide-line">
                {decisions.map((item) => (
                  <li key={item.evidence.id} className="px-3 py-2 text-sm">
                    <Link className="underline" href={`/decisions/${item.evidence.id}`}>
                      {item.summary}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel title="Related references">
            <dl className="space-y-2 p-3 text-sm">
              <Stat label="Agent">
                {incident.agent_id ? (
                  <span className="break-all font-mono text-xs">{incident.agent_id}</span>
                ) : (
                  "None"
                )}
              </Stat>
              <Stat label="Requested resource IDs">
                {resources.length === 0 ? (
                  "None"
                ) : (
                  <ul className="break-all font-mono text-xs">
                    {resources.map((resource) => (
                      <li key={resource}>{resource}</li>
                    ))}
                  </ul>
                )}
              </Stat>
            </dl>
          </Panel>

          <Panel title="Audit history">
            <ul className="divide-y divide-line">
              {auditHistory.map((item) => (
                <li key={item.evidence.id} className="px-3 py-2">
                  <span className="mr-2 font-mono text-xs text-muted">
                    {formatTime(item.occurred_at)}
                  </span>
                  <Link
                    className="font-mono text-xs underline"
                    href={`/evidence/audit_event/${item.evidence.id}`}
                  >
                    {item.kind}
                  </Link>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>
    </>
  );
}
