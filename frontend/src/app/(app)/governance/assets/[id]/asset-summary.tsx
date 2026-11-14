import { AlertTriangle } from "lucide-react";
import Link from "next/link";
import { NotGovernedBadge, RiskLabel, StatusBadge, SyntheticBadge } from "@/components/ui";
import { formatTime } from "@/lib/format";
import type { AssetDetail, HistoryEntry, RiskResponse } from "@/lib/governance-types";

/**
 * An assessment describes the profile it was run on. When the profile has changed since, the
 * stored level is out of date, and every reader is told so.
 */
export function staleNote(
  asset: AssetDetail,
  risk: RiskResponse,
  history: HistoryEntry[],
): string | null {
  const assessment = risk.assessment;
  if (!assessment || !asset.profile || assessment.profile_version_id === asset.profile.id) {
    return null;
  }
  const assessed = history.find(
    (entry) => entry.type === "profile_version" && entry.id === assessment.profile_version_id,
  )?.profile_version?.version;
  return `Assessed against ${assessed === undefined ? "an earlier profile version" : `profile version ${assessed}`}; the current profile is version ${asset.profile.version}; reassessment needed`;
}

function Item({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  );
}

/** What the inventory row says about an asset. Declared and assessed risk are labeled apart. */
export function AssetSummary({ asset, stale }: { asset: AssetDetail; stale: string | null }) {
  return (
    <section
      aria-label="Summary"
      className="mb-4 rounded-md border border-line bg-surface p-3"
    >
      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Item label="Registered owner">{asset.owner}</Item>
        <Item label="Declared risk">
          <RiskLabel kind="declared" value={asset.declared_risk} />
        </Item>
        <Item label="Assessed risk">
          {asset.assessed_risk ? (
            <RiskLabel kind="assessed" value={asset.assessed_risk} />
          ) : asset.last_assessed_at ? (
            <span className="inline-flex flex-wrap items-center gap-1">
              <StatusBadge value="INCOMPLETE" />
              <span className="text-xs text-muted">no risk level</span>
            </span>
          ) : (
            <span className="text-muted">Not assessed</span>
          )}
        </Item>
        <Item label="Governance status">
          {asset.governance_status ? (
            <StatusBadge value={asset.governance_status} />
          ) : (
            <NotGovernedBadge />
          )}
        </Item>
        <Item label="Business owner">{asset.business_owner?.email ?? "Not stated"}</Item>
        <Item label="Technical owner">{asset.technical_owner?.email ?? "Not stated"}</Item>
        <Item label="Approval valid until">{formatTime(asset.valid_until)}</Item>
        <Item label="Next review">{formatTime(asset.next_review_at)}</Item>
      </dl>
      {stale && (
        <p className="mt-3 flex items-center gap-1.5 font-medium text-hold">
          <AlertTriangle aria-hidden size={14} />
          {stale}.
        </p>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-3">
        {asset.is_synthetic && <SyntheticBadge />}
        <span className="text-xs text-muted">Registered {formatTime(asset.created_at)}</span>
        <Link href={`/governance/assets/${asset.id}/risk`} className="underline">
          View risk assessment
        </Link>
        <Link href="/governance/assets" className="underline">
          Back to inventory
        </Link>
      </div>
    </section>
  );
}
