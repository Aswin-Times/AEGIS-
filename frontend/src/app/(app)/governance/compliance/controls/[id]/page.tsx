import Link from "next/link";
import { notFound } from "next/navigation";
import { ComplianceStatement } from "@/components/compliance-statement";
import { EvidenceTable } from "@/components/evidence-table";
import { PermissionDenied } from "@/components/permission-denied";
import { PageHeader, Panel, StatusBadge } from "@/components/ui";
import { loadAccess } from "@/lib/access";
import { allPages } from "@/lib/all-pages";
import { ApiError } from "@/lib/api";
import { formatTime, humanize } from "@/lib/format";
import type {
  CompliancePage,
  Control,
  Evidence,
  InventoryRow,
} from "@/lib/governance-types";
import type { Page } from "@/lib/types";
import { AssessControl, VerifyEvidence } from "../../control-forms";

export const metadata = { title: "Control | AEGIS" };

// What the derived status means, in the words of the API's own rule.
const MEANING: Record<string, string> = {
  NOT_ASSESSED: "No assessment has been recorded for this control.",
  EVIDENCE_REQUIRED:
    "The latest assessment claims implementation, but no linked evidence is currently verified, so the claim is not counted.",
  IMPLEMENTED: "As the latest assessment records it, with verified linked evidence behind it.",
  PARTIALLY_IMPLEMENTED:
    "As the latest assessment records it, with verified linked evidence behind it.",
  NOT_IMPLEMENTED: "As the latest assessment records it.",
  NOT_APPLICABLE: "As the latest assessment records it.",
};

async function load(id: string) {
  const [controls, evidence, assets, access] = await Promise.all([
    allPages<CompliancePage<Control>>("/governance/controls"),
    allPages<Page<Evidence>>("/governance/evidence"),
    allPages<Page<InventoryRow>>("/governance/assets"),
    loadAccess(),
  ]);
  const control = controls.items.find((item) => item.id === id);
  if (!control) notFound();
  return {
    control,
    statement: controls.statement,
    linked: evidence.items.filter((item) => item.control_ids.includes(id)),
    assets: new Map(assets.items.map((asset) => [asset.id, asset.name])),
    access,
  };
}

export default async function ControlPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let data: Awaited<ReturnType<typeof load>>;
  try {
    data = await load(id);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    throw error;
  }
  const { control, linked, assets, access, statement } = data;
  const assessment = control.latest_assessment;
  const choices = linked.map((item) => ({
    id: item.id,
    description: item.description,
    verification: item.current_verification,
  }));

  return (
    <>
      <PageHeader title={control.identifier} description={control.name}>
        <Link className="text-sm underline" href={`/governance/compliance?framework=${control.framework_id}`}>
          Back to the controls
        </Link>
      </PageHeader>
      <ComplianceStatement text={statement} />

      <div className="space-y-4">
        <Panel title="Status">
          <div className="space-y-1 p-3">
            <p>
              <StatusBadge value={control.current_status} />
            </p>
            <p className="text-sm">{MEANING[control.current_status] ?? ""}</p>
            <p className="text-sm">
              {control.linked_evidence_count} linked evidence, {control.verified_evidence_count}{" "}
              verified
            </p>
            {assessment ? (
              <div className="text-sm">
                <p>
                  Latest assessment recorded: <strong>{humanize(assessment.status)}</strong> by{" "}
                  {access.label(assessment.assessed_by)}, {formatTime(assessment.assessed_at)}
                </p>
                <p className="text-muted">Note: {assessment.note}</p>
                <p className="text-muted">
                  Cited {assessment.evidence_ids.length} evidence item
                  {assessment.evidence_ids.length === 1 ? "" : "s"}.
                </p>
              </div>
            ) : (
              <p className="text-sm text-muted">No assessment has been recorded yet.</p>
            )}
          </div>
        </Panel>

        <Panel title="About this control">
          <div className="space-y-2 p-3 text-sm">
            <p>{control.description}</p>
            <p className="text-muted">Checked against: {control.source_reference}</p>
            <div>
              <h3 className="font-medium">Evidence this control expects</h3>
              {control.required_evidence.length === 0 ? (
                <p className="text-muted">The library names none.</p>
              ) : (
                <ul className="list-disc pl-5">
                  {control.required_evidence.map((item) => (
                    <li key={item}>{humanize(item)}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </Panel>

        <Panel title="Linked evidence">
          <p className="px-3 py-2 text-sm text-muted">
            Only evidence whose latest verification is Verified counts. Unverified or rejected
            evidence is listed here, and does not count toward the status. The method shows what a
            verification can have proved: an attestation or an existence check is not a recomputed
            hash.
          </p>
          <EvidenceTable
            items={linked}
            assets={assets}
            emptyDetail="No evidence is linked to this control, so no claim of implementation can be counted."
          />
        </Panel>

        {access.holder ? (
          <Panel title="Record an assessment or verify evidence">
            <div className="space-y-3 p-3">
              <AssessControl
                controlId={control.id}
                identifier={control.identifier}
                evidence={choices}
              />
              {linked.length > 0 && (
                <ul className="divide-y divide-line">
                  {linked.map((item) => (
                    <li key={item.id} className="flex flex-wrap items-start justify-between gap-2 py-2">
                      <div className="min-w-0 text-sm">
                        <p>{item.description}</p>
                        {item.source_type === "inline" && item.content_text && (
                          <p className="break-words text-xs text-muted">
                            Text: {item.content_text.slice(0, 300)}
                            {item.content_text.length > 300 ? "..." : ""}
                          </p>
                        )}
                      </div>
                      <VerifyEvidence
                        evidenceId={item.id}
                        controlId={control.id}
                        description={item.description}
                        sourceType={item.source_type}
                      />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Panel>
        ) : (
          <Panel title="Assessments and verification">
            <p className="p-3 text-sm text-muted">
              Recording an assessment or verifying evidence needs the governance reviewer role.
              Your account does not hold it, and the API refuses these actions for it.
            </p>
          </Panel>
        )}
      </div>
    </>
  );
}
