"use server";

import { revalidatePath } from "next/cache";
import { type ActionState } from "@/components/confirm-action";
import { api, ApiError } from "@/lib/api";

const REASON_MAX = 2000;
const MODES = ["observe", "enforce"];

/**
 * Admin only, and the API decides again: a non-admin gets its refusal back as text. The reason is
 * recorded in the audit chain with the change.
 */
export async function setEnforcementMode(_: ActionState, form: FormData): Promise<ActionState> {
  const mode = String(form.get("mode") ?? "");
  if (!MODES.includes(mode)) return { error: "Choose observe or enforce." };
  const reason = String(form.get("reason") ?? "").trim();
  if (!reason) {
    return {
      error: "Some fields need attention.",
      fieldErrors: { reason: "Give a reason. It is recorded in the audit log with the change." },
    };
  }
  if (reason.length > REASON_MAX) {
    return {
      error: "Some fields need attention.",
      fieldErrors: { reason: `Use at most ${REASON_MAX} characters.` },
    };
  }
  try {
    await api("/governance/enforcement", { method: "POST", body: { mode, reason } });
  } catch (error) {
    if (!(error instanceof ApiError) || error.status >= 500) throw error;
    // Someone else changed it first: the page behind the dialog should show what is now true.
    if (error.code === "ENFORCEMENT_MODE_UNCHANGED") revalidatePath("/governance/enforcement");
    return { error: error.message, code: error.code };
  }
  revalidatePath("/governance/enforcement");
  revalidatePath("/governance");
  return {};
}
