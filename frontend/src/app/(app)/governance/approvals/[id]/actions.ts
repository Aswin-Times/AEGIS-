"use server";

import { revalidatePath } from "next/cache";
import { api, ApiError } from "@/lib/api";
import { type DecisionFormState, RESOURCE_CLASSIFICATIONS } from "@/lib/governance-types";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LOCAL_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;
const REASON_MAX = 2000;
const NAME_MAX = 100;
const NAMES_MAX = 50;
const ADVISORY_MAX = 1000;
const ADVISORY_COUNT = 20;
const EVIDENCE_MAX = 50;

const text = (form: FormData, name: string) => String(form.get(name) ?? "").trim();
const lines = (form: FormData, name: string) => [
  ...new Set(
    String(form.get(name) ?? "")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
  ),
];

function reasonOf(form: FormData, errors: Record<string, string>): string {
  const reason = text(form, "reason");
  if (!reason) errors.reason = "Give a reason. It is recorded with the decision.";
  else if (reason.length > REASON_MAX) errors.reason = `Use at most ${REASON_MAX} characters.`;
  return reason;
}

/** Dates arrive as UTC wall-clock text and leave as aware ISO datetimes, never as a naive string. */
function aware(form: FormData, name: string, label: string, errors: Record<string, string>) {
  const raw = text(form, name);
  if (!raw) {
    errors[name] = `Give a ${label}. An approval has an end.`;
    return null;
  }
  const date = LOCAL_DATETIME.test(raw)
    ? new Date(`${raw}${raw.length === 16 ? ":00" : ""}Z`)
    : new Date(Number.NaN);
  if (Number.isNaN(date.getTime())) {
    errors[name] = `Give the ${label} as a date and time.`;
    return null;
  }
  return date;
}

function conditionsOf(form: FormData, errors: Record<string, string>) {
  const denied_tools = lines(form, "denied_tools");
  const held_tools = lines(form, "held_tools");
  const denied_actions = lines(form, "denied_actions");
  const advisory_conditions = lines(form, "advisory_conditions");
  const hold_all = text(form, "hold_all") === "on";
  const classification = text(form, "max_resource_classification");

  for (const [name, values] of [
    ["denied_tools", denied_tools],
    ["held_tools", held_tools],
    ["denied_actions", denied_actions],
  ] as const) {
    if (values.length > NAMES_MAX) errors[name] = `Use at most ${NAMES_MAX} entries.`;
    else if (values.some((value) => value.length > NAME_MAX)) {
      errors[name] = `Each entry may have at most ${NAME_MAX} characters.`;
    }
  }
  if (advisory_conditions.length > ADVISORY_COUNT) {
    errors.advisory_conditions = `Use at most ${ADVISORY_COUNT} entries.`;
  } else if (advisory_conditions.some((value) => value.length > ADVISORY_MAX)) {
    errors.advisory_conditions = `Each entry may have at most ${ADVISORY_MAX} characters.`;
  }
  if (classification && !(RESOURCE_CLASSIFICATIONS as readonly string[]).includes(classification)) {
    errors.max_resource_classification = "Choose one of the listed values.";
  }
  const empty =
    !denied_tools.length &&
    !held_tools.length &&
    !denied_actions.length &&
    !advisory_conditions.length &&
    !hold_all &&
    !classification;
  if (empty) errors.conditions = "Add at least one condition, or choose Approve.";
  return {
    denied_tools,
    held_tools,
    denied_actions,
    hold_all,
    max_resource_classification: classification || null,
    advisory_conditions,
  };
}

// The API reports some field problems only in the message, so these name the field they are about.
const MESSAGE_FIELDS: [RegExp, string][] = [
  [/^valid_until/, "valid_until"],
  [/^next_review_at/, "next_review_at"],
  [/^denied_tools/, "denied_tools"],
  [/^held_tools/, "held_tools"],
  [/^denied_actions/, "denied_actions"],
  [/^A tool cannot be both denied and held/, "held_tools"],
  [/^Conditions were given/, "conditions"],
];
const BODY_FIELDS = new Set([
  "reason",
  "valid_until",
  "next_review_at",
  "denied_tools",
  "held_tools",
  "denied_actions",
  "advisory_conditions",
  "max_resource_classification",
  "evidence_ids",
]);

/** The API's own words, with the field they concern where the API says which one. */
function refused(error: unknown): DecisionFormState {
  if (!(error instanceof ApiError) || error.status >= 500) throw error;
  const fieldErrors: Record<string, string> = {};
  for (const location of error.fields) {
    const name = location.split(".").find((part) => BODY_FIELDS.has(part));
    if (name) fieldErrors[name] = "The API did not accept this value.";
  }
  for (const [pattern, name] of MESSAGE_FIELDS) {
    if (pattern.test(error.message)) fieldErrors[name] = error.message;
  }
  return {
    error: error.message,
    code: error.code,
    ...(Object.keys(fieldErrors).length > 0 ? { fieldErrors } : {}),
  };
}

function reviewOf(form: FormData) {
  const id = text(form, "review_id");
  return UUID.test(id) ? id : null;
}

function done(id: string, saved: string): DecisionFormState {
  revalidatePath(`/governance/approvals/${id}`);
  revalidatePath("/governance/approvals");
  revalidatePath("/governance/assets", "layout");
  revalidatePath("/governance");
  return { saved };
}

export async function approveReview(
  _: DecisionFormState,
  form: FormData,
): Promise<DecisionFormState> {
  const id = reviewOf(form);
  if (!id) return { error: "That review was not found." };
  const fieldErrors: Record<string, string> = {};
  const reason = reasonOf(form, fieldErrors);
  const validUntil = aware(form, "valid_until", "valid until date", fieldErrors);
  const nextReview = aware(form, "next_review_at", "next review date", fieldErrors);
  if (validUntil && nextReview && nextReview > validUntil) {
    fieldErrors.next_review_at = "The next review must be on or before the valid until date.";
  }
  const conditional = text(form, "conditional") === "1";
  const conditions = conditional ? conditionsOf(form, fieldErrors) : null;
  const evidence = [...new Set(text(form, "evidence_ids").split(",").filter(Boolean))];
  if (evidence.length > EVIDENCE_MAX || evidence.some((value) => !UUID.test(value))) {
    fieldErrors.evidence_ids = "Choose evidence from the list.";
  }
  if (Object.keys(fieldErrors).length > 0) {
    return { error: "Some fields need attention.", fieldErrors };
  }
  try {
    await api(`/governance/approvals/${id}/approve`, {
      method: "POST",
      body: {
        reason,
        valid_until: validUntil!.toISOString(),
        next_review_at: nextReview!.toISOString(),
        evidence_ids: evidence,
        ...(conditions ? { conditions } : {}),
      },
    });
  } catch (error) {
    return refused(error);
  }
  return done(id, conditional ? "Decision recorded: approved with conditions." : "Decision recorded: approved.");
}

export async function rejectReview(
  _: DecisionFormState,
  form: FormData,
): Promise<DecisionFormState> {
  const id = reviewOf(form);
  if (!id) return { error: "That review was not found." };
  const fieldErrors: Record<string, string> = {};
  const reason = reasonOf(form, fieldErrors);
  if (Object.keys(fieldErrors).length > 0) {
    return { error: "Some fields need attention.", fieldErrors };
  }
  try {
    await api(`/governance/approvals/${id}/reject`, { method: "POST", body: { reason } });
  } catch (error) {
    return refused(error);
  }
  return done(id, "Decision recorded: rejected.");
}

export async function requestInformation(
  _: DecisionFormState,
  form: FormData,
): Promise<DecisionFormState> {
  const id = reviewOf(form);
  if (!id) return { error: "That review was not found." };
  const fieldErrors: Record<string, string> = {};
  const reason = reasonOf(form, fieldErrors);
  if (Object.keys(fieldErrors).length > 0) {
    return { error: "Some fields need attention.", fieldErrors };
  }
  try {
    await api(`/governance/approvals/${id}/request-information`, {
      method: "POST",
      body: { reason },
    });
  } catch (error) {
    return refused(error);
  }
  return done(id, "Decision recorded: information requested.");
}

export async function assignReviewer(
  _: DecisionFormState,
  form: FormData,
): Promise<DecisionFormState> {
  const id = reviewOf(form);
  if (!id) return { error: "That review was not found." };
  const reviewer = text(form, "reviewer_id");
  if (!UUID.test(reviewer)) {
    return { error: "Choose a reviewer.", fieldErrors: { reviewer_id: "Choose a reviewer." } };
  }
  try {
    await api(`/governance/approvals/${id}/assign`, {
      method: "POST",
      body: { reviewer_id: reviewer },
    });
  } catch (error) {
    return refused(error);
  }
  return done(id, "Reviewer assigned.");
}
