"use server";

import { revalidatePath } from "next/cache";
import { type ActionState } from "@/components/confirm-action";
import { api, ApiError } from "@/lib/api";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NOTE_MAX = 2000;
const CITED_MAX = 50;
const STATUSES = ["IMPLEMENTED", "PARTIALLY_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_APPLICABLE"];
const OUTCOMES = ["VERIFIED", "REJECTED"];
const METHODS = ["internal_record_checked", "content_recomputed", "manual_attestation"];
const BODY_FIELDS = new Set(["status", "note", "evidence_ids", "outcome", "method", "content"]);

const text = (form: FormData, name: string) => String(form.get(name) ?? "").trim();

function noteOf(form: FormData, errors: Record<string, string>): string {
  const note = text(form, "note");
  if (!note) errors.note = "Give a note. It is recorded with the entry.";
  else if (note.length > NOTE_MAX) errors.note = `Use at most ${NOTE_MAX} characters.`;
  return note;
}

/** The API's own words, with the field they concern where the API says which one. */
function refused(error: unknown): ActionState {
  if (!(error instanceof ApiError) || error.status >= 500) throw error;
  const fieldErrors: Record<string, string> = {};
  for (const location of error.fields) {
    const name = location.split(".").find((part) => BODY_FIELDS.has(part));
    if (name) fieldErrors[name] = "The API did not accept this value.";
  }
  return {
    error: error.message,
    code: error.code,
    ...(Object.keys(fieldErrors).length > 0 ? { fieldErrors } : {}),
  };
}

function refresh(controlId: string) {
  revalidatePath(`/governance/compliance/controls/${controlId}`);
  revalidatePath("/governance/compliance");
  revalidatePath("/governance/assets", "layout");
  revalidatePath("/governance");
}

/** A control's status is a person's assessment. The API decides who may record it, and when. */
export async function assessControl(_: ActionState, form: FormData): Promise<ActionState> {
  const id = text(form, "control_id");
  if (!UUID.test(id)) return { error: "That control was not found." };
  const fieldErrors: Record<string, string> = {};
  const status = text(form, "status");
  if (!STATUSES.includes(status)) fieldErrors.status = "Choose one of the listed statuses.";
  const note = noteOf(form, fieldErrors);
  const evidence = [...new Set(form.getAll("evidence_ids").map(String))];
  if (evidence.length > CITED_MAX || evidence.some((value) => !UUID.test(value))) {
    fieldErrors.evidence_ids = "Choose evidence from the list.";
  }
  if (Object.keys(fieldErrors).length > 0) {
    return { error: "Some fields need attention.", fieldErrors };
  }
  try {
    await api(`/governance/controls/${id}/assess`, {
      method: "POST",
      body: { status, note, evidence_ids: evidence },
    });
  } catch (error) {
    return refused(error);
  }
  refresh(id);
  return {};
}

/** A verification is append-only: the latest one for an item decides whether it counts. */
export async function verifyEvidence(_: ActionState, form: FormData): Promise<ActionState> {
  const id = text(form, "evidence_id");
  const control = text(form, "control_id");
  if (!UUID.test(id) || !UUID.test(control)) return { error: "That evidence was not found." };
  const fieldErrors: Record<string, string> = {};
  const outcome = text(form, "outcome");
  if (!OUTCOMES.includes(outcome)) fieldErrors.outcome = "Choose Verified or Rejected.";
  const method = text(form, "method");
  if (!METHODS.includes(method)) fieldErrors.method = "Choose one of the listed methods.";
  const note = noteOf(form, fieldErrors);
  const content = String(form.get("content") ?? "");
  if (Object.keys(fieldErrors).length > 0) {
    return { error: "Some fields need attention.", fieldErrors };
  }
  try {
    await api(`/governance/evidence/${id}/verify`, {
      method: "POST",
      body: { outcome, method, note, ...(content.trim() ? { content } : {}) },
    });
  } catch (error) {
    return refused(error);
  }
  refresh(control);
  return {};
}
