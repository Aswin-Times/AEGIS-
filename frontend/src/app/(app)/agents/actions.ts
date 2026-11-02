"use server";

import { revalidatePath } from "next/cache";
import type { ActionState } from "@/components/confirm-action";
import { api, ApiError } from "@/lib/api";

export async function setAgentStatus(_: ActionState, form: FormData): Promise<ActionState> {
  const id = String(form.get("agent_id"));
  try {
    await api(`/agents/${encodeURIComponent(id)}/status`, {
      method: "POST",
      body: { status: String(form.get("status")) },
    });
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return { error: "Only an administrator can change agent status." };
    }
    if (error instanceof ApiError) return { error: error.message };
    throw error;
  }
  revalidatePath("/agents");
  return {};
}
