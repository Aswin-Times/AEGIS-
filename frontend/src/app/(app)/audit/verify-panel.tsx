"use client";

import { CheckCircle2, XCircle } from "lucide-react";
import { useActionState } from "react";
import { verifyAudit, type VerifyState } from "./actions";

export function VerifyPanel({ canVerify }: { canVerify: boolean }) {
  const [state, action, pending] = useActionState<VerifyState>(() => verifyAudit(), {});
  const result = state.result;
  return (
    <section className="mb-4 rounded-md border border-line bg-surface p-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-3xl text-muted">
          Verification recomputes every hash in this organization&apos;s chain. It detects edits,
          removals, and reordering. It cannot detect someone with full database control rewriting
          the whole chain, because the head is not yet anchored outside the database.
        </p>
        {canVerify && (
          <form action={action}>
            <button
              type="submit"
              disabled={pending}
              className="rounded bg-accent px-3 py-1.5 font-medium text-accent-ink disabled:opacity-60"
            >
              {pending ? "Verifying" : "Verify chain"}
            </button>
          </form>
        )}
      </div>
      {state.error && (
        <p role="alert" className="mt-2 text-deny">
          {state.error}
        </p>
      )}
      {result && (
        <p role="status" className={`mt-2 flex items-center gap-2 font-medium ${result.valid ? "text-allow" : "text-deny"}`}>
          {result.valid ? <CheckCircle2 aria-hidden size={16} /> : <XCircle aria-hidden size={16} />}
          {result.valid
            ? `Chain intact: ${result.events_checked} events checked.`
            : `Verification failed at event ${result.failure_seq}: ${result.failure_reason}. ${result.events_checked} events passed before it.`}
        </p>
      )}
    </section>
  );
}
