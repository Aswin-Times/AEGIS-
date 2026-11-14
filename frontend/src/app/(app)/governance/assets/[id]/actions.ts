"use server";

import { revalidatePath } from "next/cache";
import { api, ApiError } from "@/lib/api";
import {
  ASSET_TYPES,
  AUTONOMY_LEVELS,
  DATA_CATEGORIES,
  ENVIRONMENTS,
  EXTERNAL_EXPOSURES,
  HUMAN_OVERSIGHT,
  IMPACT_LEVELS,
  THIRD_PARTY_RELIANCE,
  type AssessmentSummary,
  type AssetProfile,
  type Person,
  type ProfileFormState,
  type ProfileVersion,
} from "@/lib/governance-types";
import type { Page } from "@/lib/types";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TEXT_MAX = 2000;
const LABEL_MAX = 200;
const LIST_MAX = 50;

const ENUMS: Record<string, readonly string[]> = {
  asset_type: ASSET_TYPES,
  deployment_environment: ENVIRONMENTS,
  external_exposure: EXTERNAL_EXPOSURES,
  autonomy_level: AUTONOMY_LEVELS,
  human_oversight: HUMAN_OVERSIGHT,
  impact_level: IMPACT_LEVELS,
  third_party_reliance: THIRD_PARTY_RELIANCE,
};
const TEXTS = ["description", "business_purpose", "intended_use", "prohibited_use"];
const LABELS = ["responsible_team", "model_provider", "model_name", "model_version"];
const LISTS = ["external_integrations", "declared_tool_access", "evidence_references"];
const OWNERS = ["business_owner_id", "technical_owner_id"];

const text = (form: FormData, name: string) => String(form.get(name) ?? "").trim();

async function people(): Promise<Set<string>> {
  const ids = new Set<string>();
  for (let offset = 0; ; offset += 100) {
    const page = await api<Page<Person>>(`/governance/people?limit=100&offset=${offset}`);
    page.items.forEach((person) => ids.add(person.id));
    if (offset + 100 >= page.total) return ids;
  }
}

/** Checks every field on the server as well, since a form post can carry anything. */
async function parseProfile(form: FormData) {
  const profile: Record<string, unknown> = {};
  const fieldErrors: Record<string, string> = {};
  const values: Record<string, string | string[]> = {};

  for (const [name, allowed] of Object.entries(ENUMS)) {
    const value = text(form, name);
    values[name] = value;
    if (!value) continue;
    if (allowed.includes(value)) profile[name] = value;
    else fieldErrors[name] = "Choose one of the listed values.";
  }
  for (const name of [...TEXTS, ...LABELS]) {
    const value = text(form, name);
    values[name] = value;
    const max = TEXTS.includes(name) ? TEXT_MAX : LABEL_MAX;
    if (!value) continue;
    if (value.length > max) fieldErrors[name] = `Use at most ${max} characters.`;
    else profile[name] = value;
  }
  for (const name of LISTS) {
    const raw = String(form.get(name) ?? "");
    values[name] = raw;
    const items = [...new Set(raw.split("\n").map((line) => line.trim()).filter(Boolean))];
    if (items.length === 0) continue;
    if (items.length > LIST_MAX) fieldErrors[name] = `Use at most ${LIST_MAX} entries.`;
    else if (items.some((item) => item.length > LABEL_MAX)) {
      fieldErrors[name] = `Each entry may have at most ${LABEL_MAX} characters.`;
    } else profile[name] = items;
  }

  const categories = form.getAll("data_categories").map(String);
  values.data_categories = categories;
  if (categories.some((value) => !(DATA_CATEGORIES as readonly string[]).includes(value))) {
    fieldErrors.data_categories = "Choose from the listed categories.";
  } else if (categories.length > 0) {
    profile.data_categories = [...new Set(categories)];
  }

  // Owners must be people of this organization, so the server checks them against the real list.
  const picked = OWNERS.filter((name) => text(form, name));
  for (const name of OWNERS) values[name] = text(form, name);
  if (picked.length > 0) {
    const known = await people();
    for (const name of picked) {
      const value = text(form, name);
      if (UUID.test(value) && known.has(value)) profile[name] = value;
      else fieldErrors[name] = "Choose a person from the list.";
    }
  }
  return { profile, fieldErrors, values };
}

function refused(error: unknown, action: string): ProfileFormState {
  if (error instanceof ApiError && error.status === 403) {
    return { error: `Only an administrator can ${action}.` };
  }
  if (error instanceof ApiError && error.status < 500) return { error: error.message };
  throw error;
}

export async function saveProfile(
  _: ProfileFormState,
  form: FormData,
): Promise<ProfileFormState> {
  const assetId = text(form, "asset_id");
  if (!UUID.test(assetId)) return { error: "That asset was not found." };
  const { profile, fieldErrors, values } = await parseProfile(form);
  if (Object.keys(fieldErrors).length > 0) {
    return { error: "Some fields need attention.", fieldErrors, values };
  }
  let saved: ProfileVersion;
  try {
    saved = await api<ProfileVersion>(`/governance/assets/${assetId}/profile`, {
      method: "POST",
      body: profile satisfies AssetProfile,
    });
  } catch (error) {
    return { ...refused(error, "change a profile"), values };
  }
  revalidatePath(`/governance/assets/${assetId}`);
  revalidatePath("/governance/assets");
  return { saved: `Profile saved as version ${saved.version}.` };
}

export async function runAssessment(
  _: ProfileFormState,
  form: FormData,
): Promise<ProfileFormState> {
  const assetId = text(form, "asset_id");
  if (!UUID.test(assetId)) return { error: "That asset was not found." };
  let assessment: AssessmentSummary;
  try {
    assessment = await api<AssessmentSummary>(`/governance/assets/${assetId}/assess`, {
      method: "POST",
    });
  } catch (error) {
    return refused(error, "run an assessment");
  }
  revalidatePath(`/governance/assets/${assetId}`, "layout");
  revalidatePath("/governance/assets");
  return {
    saved:
      assessment.status === "COMPLETE"
        ? "Assessment recorded. It is complete."
        : "Assessment recorded. It is incomplete, so it has no risk level.",
  };
}
