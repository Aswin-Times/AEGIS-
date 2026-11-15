import { humanize } from "@/lib/format";
import type { AssetDetail, AssetProfile } from "@/lib/governance-types";

const PROFILE_ROWS: [keyof AssetProfile, string][] = [
  ["asset_type", "Asset type"],
  ["description", "Description"],
  ["business_purpose", "Business purpose"],
  ["intended_use", "Intended use"],
  ["prohibited_use", "Prohibited use"],
  ["responsible_team", "Responsible team"],
  ["model_provider", "Model provider"],
  ["model_name", "Model name"],
  ["model_version", "Model version"],
  ["deployment_environment", "Deployment environment"],
  ["data_categories", "Data categories"],
  ["external_exposure", "External exposure"],
  ["external_integrations", "External integrations"],
  ["autonomy_level", "Autonomy level"],
  ["human_oversight", "Human oversight"],
  ["declared_tool_access", "Declared tool access"],
  ["impact_level", "Impact level"],
  ["third_party_reliance", "Third-party reliance"],
  ["evidence_references", "Evidence references"],
];
const VOCABULARY_FIELDS = new Set<keyof AssetProfile>([
  "asset_type",
  "deployment_environment",
  "external_exposure",
  "autonomy_level",
  "human_oversight",
  "impact_level",
  "third_party_reliance",
]);

function profileValue(
  name: keyof AssetProfile,
  profile: AssetProfile,
  asset: AssetDetail,
): string | null {
  if (name === "business_owner_id") return asset.business_owner?.email ?? null;
  if (name === "technical_owner_id") return asset.technical_owner?.email ?? null;
  const value = profile[name];
  if (value === undefined) return null;
  if (Array.isArray(value)) return value.length ? value.map(humanizeIfCode).join(", ") : null;
  return VOCABULARY_FIELDS.has(name) ? humanize(value) : value;
}

const humanizeIfCode = (value: string) => (/^[a-z_]+$/.test(value) ? humanize(value) : value);

export function ProfileSummary({ asset }: { asset: AssetDetail }) {
  const profile = asset.profile?.profile ?? {};
  return (
    <dl className="grid gap-x-6 gap-y-2 p-3 sm:grid-cols-2">
      {PROFILE_ROWS.map(([name, label]) => {
        const value = profileValue(name, profile, asset);
        return (
          <div key={name}>
            <dt className="text-xs text-muted">{label}</dt>
            <dd className="whitespace-pre-wrap break-words">
              {value ?? <span className="text-muted">Not stated</span>}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}
