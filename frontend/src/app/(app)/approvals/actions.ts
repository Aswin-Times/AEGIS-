"use server";

import { revalidatePath } from "next/cache";
import type { ActionState } from "@/components/confirm-action";
import { api, ApiError } from "@/lib/api";

export async function decideApproval(_: ActionState, form: FormData): Promise<ActionState> {
  const id = String(form.get("approval_id"));
  const decision = form.get("decision") === "approve" ? "approve" : "reject";
  try {
    await api(`/approvals/${encodeURIComponent(id)}/${decision}`, { method: "POST", body: {} });
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return { error: "Only a reviewer or administrator can decide approvals." };
    }
    if (error instanceof ApiError && error.status === 409) {
      revalidatePath("/approvals");
      return { error: "This approval was already decided or has expired." };
    }
    if (error instanceof ApiError) return { error: error.message };
    throw error;
  }
  revalidatePath("/approvals");
  return {};
}
