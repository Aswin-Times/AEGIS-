"use client";

import { useActionState } from "react";
import { runInvestigation } from "./actions";

export function InvestigationButton({ incidentId }: { incidentId: string }) {
  const [state, action, pending] = useActionState(runInvestigation, {});
  return (
    <form action={action}>
      <input type="hidden" name="incident_id" value={incidentId} />
      <button
        type="submit"
        disabled={pending}
        className="rounded bg-accent px-3 py-1.5 font-medium text-accent-ink disabled:opacity-60"
      >
        {pending ? "Investigating" : "Run investigation"}
      </button>
      {state.error && (
        <p role="alert" className="mt-1 text-sm text-deny">
          {state.error}
        </p>
      )}
    </form>
  );
}
