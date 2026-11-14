import Link from "next/link";
import { notFound } from "next/navigation";
import {
  Cell,
  EmptyState,
  PageHeader,
  Panel,
  RiskLabel,
  StatusBadge,
  Table,
} from "@/components/ui";
import { PermissionDenied } from "@/components/permission-denied";
import { ApiError, api } from "@/lib/api";
import { formatTime, humanize, shortId } from "@/lib/format";
import type {
  AssessmentSummary,
  AssetDetail,
  Methodology,
  RiskResponse,
} from "@/lib/governance-types";
import type { Me, Page } from "@/lib/types";
import { AssessForm } from "../assess-form";
import { AssetSummary } from "../asset-summary";

export const metadata = { title: "Risk assessment | AEGIS" };

// The spec's wording. Shown on every risk page, whatever the methodology document adds.
const JUDGMENT_STATEMENT =
  "The weights, level maps, thresholds, and floors are engineering judgment, not values taken from any standard or regulation. Review them before relying on the result.";

const TOOL_ACCESS_HINT =
  "Register an agent with grants for this asset, or list declared tool access in the profile.";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      <Panel title={title}>{children}</Panel>
    </div>
  );
}

async function load(id: string) {
  const assetPath = encodeURIComponent(id);
  const me = await api<Me>("/auth/me");
  const [asset, risk, history, methodologies] = await Promise.all([
    api<AssetDetail>(`/governance/assets/${assetPath}`),
    api<RiskResponse>(`/governance/assets/${assetPath}/risk`),
    api<Page<AssessmentSummary>>(`/governance/assets/${assetPath}/assessments?limit=25`),
    api<Page<Methodology>>("/governance/methodologies?limit=100"),
  ]);
  return { admin: me.role === "admin", asset, risk, history, methodologies };
}

export default async function RiskPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let data: Awaited<ReturnType<typeof load>>;
  try {
    data = await load(id);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
    throw error;
  }
  const { admin, asset, risk, history, methodologies } = data;
  const { assessment } = risk;
  const result = assessment?.result ?? null;

  // The methodology the stored assessment used. With no assessment, the one the next would use.
  const methodology = assessment
    ? methodologies.items.find((item) => item.id === assessment.methodology_version_id)
    : methodologies.items.find((item) => item.active);
  const document = methodology?.document;
  const maxScore = document
    ? document.factors.reduce(
        (sum, factor) => sum + factor.weight * Math.max(...Object.values(factor.levels)),
        0,
      )
    : null;
  const factorOf = (factorId: string) => document?.factors.find((item) => item.id === factorId);
  const floor = result?.floor_applied
    ? document?.floors.find((item) => item.id === result.floor_applied)
    : undefined;

  return (
    <>
      <PageHeader
        title="Risk assessment"
        description={`${asset.name}. Computed from the stored profile and the methodology below. The same inputs always give the same result.`}
      >
        {admin && <AssessForm assetId={asset.id} />}
      </PageHeader>
      <AssetSummary asset={asset} />

      <Section title="Result">
        {!assessment ? (
          <EmptyState
            title="This asset has not been assessed"
            detail="There is no assessed risk level. The declared risk above is the registrant's own claim."
          />
        ) : (
          <div className="space-y-2 p-3">
            <div className="flex flex-wrap items-center gap-3">
              <StatusBadge value={assessment.status} />
              {assessment.risk_level ? (
                <>
                  <RiskLabel kind="assessed" value={assessment.risk_level} />
                  <span>
                    Score {assessment.score}
                    {maxScore !== null && ` of ${maxScore}`}
                  </span>
                </>
              ) : (
                <span className="font-medium">No risk level</span>
              )}
            </div>
            {!assessment.risk_level && (
              <p>
                Required inputs are missing, so no score and no risk level is calculated. An
                incomplete assessment is never treated as low risk.
              </p>
            )}
            <p className="text-xs text-muted">
              Run {formatTime(assessment.assessed_at)} by user {shortId(assessment.assessed_by)}.
              Methodology version {assessment.methodology_version}.
            </p>
            {risk.recomputed_matches === true && (
              <p className="text-xs text-muted">
                Recomputed now from the stored input and methodology: matches the stored result.
              </p>
            )}
            {risk.recomputed_matches === false && (
              <p role="alert" className="text-sm text-deny">
                Recomputed now from the stored input and methodology: does not match the stored
                result. Do not rely on this assessment.
              </p>
            )}
            {!result && (
              <p role="alert" className="text-sm text-deny">
                The stored result could not be read, so no factors are shown.
              </p>
            )}
          </div>
        )}
      </Section>

      {result && result.missing.length > 0 && (
        <Section title="Missing inputs">
          <ul className="divide-y divide-line">
            {result.missing.map((factorId) => {
              const factor = factorOf(factorId);
              return (
                <li key={factorId} className="px-3 py-2">
                  <span className="font-medium">{factor?.label ?? humanize(factorId)}</span>
                  {factor && (
                    <span className="text-muted"> needs {humanize(factor.input).toLowerCase()}</span>
                  )}
                  {factor?.input === "tool_access_level" && (
                    <div className="text-xs text-muted">{TOOL_ACCESS_HINT}</div>
                  )}
                </li>
              );
            })}
          </ul>
        </Section>
      )}

      {result && (
        <Section title="Factors">
          {result.factors.length === 0 ? (
            <EmptyState title="No factor could be scored" detail="Every input is missing." />
          ) : (
            <>
              {result.status === "INCOMPLETE" && (
                <p className="border-b border-line px-3 py-2 text-xs text-muted">
                  Factors that could be scored. No total is calculated while inputs are missing.
                </p>
              )}
              <Table head={["Factor", "Input", "Level", "Weight", "Contribution", "Explanation"]}>
                {result.factors.map((factor) => (
                  <tr key={factor.factor}>
                    <Cell>{factor.label}</Cell>
                    <Cell>{humanize(factor.input_value)}</Cell>
                    <Cell mono>{factor.level}</Cell>
                    <Cell mono>{factor.weight}</Cell>
                    <Cell mono>{factor.contribution}</Cell>
                    <Cell>
                      <span className="text-xs text-muted">{factor.explanation}</span>
                    </Cell>
                  </tr>
                ))}
              </Table>
            </>
          )}
        </Section>
      )}

      {result?.status === "COMPLETE" && (
        <>
          <Section title="Floors">
            {result.floor_applied ? (
              <p className="p-3">
                Floor applied: {floor?.description ?? humanize(result.floor_applied)}
                {floor && (
                  <>
                    {" "}
                    It raised the level to at least <strong>{humanize(floor.minimum_level)}</strong>
                    .
                  </>
                )}{" "}
                The score stays the sum of the contributions.
              </p>
            ) : (
              <p className="p-3">No floor applied to this result.</p>
            )}
            {document && document.floors.length > 0 && (
              <ul className="space-y-1 border-t border-line px-3 py-2 text-xs text-muted">
                {document.floors.map((item) => (
                  <li key={item.id}>
                    {item.description} Minimum level {humanize(item.minimum_level)}.
                  </li>
                ))}
              </ul>
            )}
          </Section>
          <Section title="Mitigations">
            {result.mitigations.length === 0 ? (
              <p className="p-3">This methodology lists no mitigations for this result.</p>
            ) : (
              <ul className="list-disc space-y-1 py-3 pl-8 pr-3">
                {result.mitigations.map((text, index) => (
                  <li key={index}>{text}</li>
                ))}
              </ul>
            )}
          </Section>
        </>
      )}

      <Section title="Methodology">
        <div className="space-y-2 p-3">
          <p>{JUDGMENT_STATEMENT}</p>
          {methodology ? (
            <>
              <p>
                {!assessment && "Active methodology, which the next assessment would use. "}
                Version {methodology.version}.{" "}
                {methodology.created_by === null && "Built-in methodology. "}Approved:{" "}
                {methodology.approved ? "yes" : "no"}. Active: {methodology.active ? "yes" : "no"}.
              </p>
              <p className="text-xs text-muted">{methodology.document.provenance_note}</p>
              <p className="text-xs text-muted">
                Thresholds: score below {methodology.document.thresholds.medium} is Low, below{" "}
                {methodology.document.thresholds.high} is Medium, below{" "}
                {methodology.document.thresholds.critical} is High, otherwise Critical.
              </p>
              <p className="break-all font-mono text-xs text-muted">
                content hash {methodology.content_hash}
              </p>
            </>
          ) : (
            <p className="text-muted">
              The methodology document for this assessment could not be loaded.
            </p>
          )}
        </div>
      </Section>

      <Section title="Assessment history">
        {history.items.length === 0 ? (
          <EmptyState title="No assessments" detail="Each assessment run is listed here." />
        ) : (
          <Table head={["Run", "Status", "Result", "Score", "Methodology version"]}>
            {history.items.map((item) => (
              <tr key={item.id}>
                <Cell mono>{formatTime(item.assessed_at)}</Cell>
                <Cell>
                  <StatusBadge value={item.status} />
                </Cell>
                <Cell>
                  {item.risk_level ? (
                    <RiskLabel kind="assessed" value={item.risk_level} />
                  ) : (
                    <span className="text-muted">No risk level</span>
                  )}
                </Cell>
                <Cell mono>{item.score ?? "None"}</Cell>
                <Cell mono>{item.methodology_version}</Cell>
              </tr>
            ))}
          </Table>
        )}
      </Section>

      <p>
        <Link href={`/governance/assets/${asset.id}`} className="underline">
          Back to the asset
        </Link>
      </p>
    </>
  );
}
