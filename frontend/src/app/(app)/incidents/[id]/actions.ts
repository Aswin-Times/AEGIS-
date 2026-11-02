"use server";

import { revalidatePath } from "next/cache";
import type { ActionState } from "@/components/confirm-action";
import { api, ApiError } from "@/lib/api";

const VERBS = new Set(["acknowledge", "investigate", "resolve", "reopen", "close"]);

export async function moveIncident(_: ActionState, form: FormData): Promise<ActionState> {
  const id = String(form.get("incident_id"));
  const verb = String(form.get("verb"));
  if (!VERBS.has(verb)) return { error: "That change is not available." };
  const reason = String(form.get("reason") ?? "").trim();
  try {
    await api(`/incidents/${encodeURIComponent(id)}/${verb}`, {
      method: "POST",
      body: {
        expected_version: Number(form.get("expected_version")),
        ...(reason ? { reason } : {}),
      },
    });
  } catch (error) {
    if (error instanceof ApiError && error.code === "INCIDENT_VERSION_CONFLICT") {
      revalidatePath(`/incidents/${id}`);
      return { error: "Someone else changed this incident. Review it and try again." };
    }
    if (error instanceof ApiError && error.code === "ACTIVE_INCIDENT_EXISTS") {
      return { error: "A newer active incident already covers this rule and scope." };
    }
    if (error instanceof ApiError && error.status === 403) {
      return { error: "Your role does not allow this change." };
    }
    if (error instanceof ApiError && error.status < 500) return { error: error.message };
    throw error;
  }
  revalidatePath(`/incidents/${id}`);
  return {};
}

export async function runInvestigation(_: ActionState, form: FormData): Promise<ActionState> {
  const id = String(form.get("incident_id"));
  try {
    await api(`/incidents/${encodeURIComponent(id)}/investigation-runs`, { method: "POST" });
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return { error: "Your role does not allow running an investigation." };
    }
    if (error instanceof ApiError && error.status < 500) return { error: error.message };
    throw error;
  }
  revalidatePath(`/incidents/${id}`);
  return {};
}
