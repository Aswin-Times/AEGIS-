"use server";

import { api, ApiError } from "@/lib/api";
import type { AuditVerification } from "@/lib/types";

export type VerifyState = { result?: AuditVerification; error?: string };

export async function verifyAudit(): Promise<VerifyState> {
  try {
    return { result: await api<AuditVerification>("/audit/verify", { method: "POST" }) };
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return { error: "Only a reviewer or administrator can run verification." };
    }
    if (error instanceof ApiError) return { error: error.message };
    throw error;
  }
}
