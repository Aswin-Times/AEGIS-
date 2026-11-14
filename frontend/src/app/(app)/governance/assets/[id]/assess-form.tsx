"use client";

import { useActionState } from "react";
import type { ProfileFormState } from "@/lib/governance-types";
import { runAssessment } from "./actions";

/** Rendered only for administrators. The API refuses the request from anyone else. */
export function AssessForm({ assetId }: { assetId: string }) {
  const [state, action, pending] = useActionState<ProfileFormState, FormData>(runAssessment, {});
  return (
    <form action={action}>
      <input type="hidden" name="asset_id" value={assetId} />
      <button
        type="submit"
        disabled={pending}
        className="rounded border border-line px-3 py-1.5 hover:bg-subtle disabled:opacity-60"
      >
        {pending ? "Assessing" : "Run risk assessment"}
      </button>
      {state.error && (
        <p role="alert" className="mt-1 text-sm text-deny">
          {state.error}
        </p>
      )}
      {state.saved && (
        <p role="status" className="mt-1 text-sm">
          {state.saved}
        </p>
      )}
    </form>
  );
}
