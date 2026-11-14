"use server";

import { revalidatePath } from "next/cache";
import { type ActionState } from "@/components/confirm-action";
import { api, ApiError } from "@/lib/api";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Every change is a new event on a version, never an edit of it. The API decides who may do it
 * and says why when it refuses, so its message is what the page shows.
 */
async function change(form: FormData, step: "approve" | "activate" | "deactivate"): Promise<ActionState> {
  const policy = String(form.get("policy_id") ?? "");
  const version = String(form.get("version_id") ?? "");
  if (!UUID.test(policy) || !UUID.test(version)) return { error: "That policy version was not found." };
  try {
    await api(`/governance/policies/${policy}/versions/${version}/${step}`, {
      method: "POST",
      body: {},
    });
  } catch (error) {
    if (error instanceof ApiError && error.status < 500) return { error: error.message };
    throw error;
  }
  revalidatePath("/governance/policies");
  return {};
}

export async function approveVersion(_: ActionState, form: FormData) {
  return change(form, "approve");
}

export async function activateVersion(_: ActionState, form: FormData) {
  return change(form, "activate");
}

export async function deactivateVersion(_: ActionState, form: FormData) {
  return change(form, "deactivate");
}
