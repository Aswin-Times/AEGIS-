"use client";

import { useActionState } from "react";
import { CONTROL, Field } from "@/components/form-field";
import type { DecisionFormState } from "@/lib/governance-types";
import { assignReviewer } from "./actions";

/** Shown to holders of governance_reviewer. The API refuses anyone else, and says why. */
export function AssignForm({
  reviewId,
  assigned,
  holders,
}: {
  reviewId: string;
  assigned: string | null;
  holders: { id: string; email: string }[];
}) {
  const [state, action, pending] = useActionState<DecisionFormState, FormData>(assignReviewer, {});
  return (
    <form action={action} className="space-y-2 p-3">
      <input type="hidden" name="review_id" value={reviewId} />
      <Field
        label="Assign reviewer"
        hint="Once someone is assigned, only they can decide this review."
        error={state.fieldErrors?.reviewer_id}
      >
        {({ id, describedBy, invalid }) => (
          <select
            id={id}
            name="reviewer_id"
            defaultValue={assigned ?? ""}
            aria-invalid={invalid || undefined}
            aria-describedby={describedBy}
            className={CONTROL}
          >
            <option value="">Choose a reviewer</option>
            {holders.map((person) => (
              <option key={person.id} value={person.id}>
                {person.email}
              </option>
            ))}
          </select>
        )}
      </Field>
      <button
        type="submit"
        disabled={pending}
        className="rounded border border-line px-3 py-1.5 hover:bg-subtle disabled:opacity-60"
      >
        {pending ? "Assigning" : "Assign reviewer"}
      </button>
      {state.error && !state.fieldErrors?.reviewer_id && (
        <p role="alert" className="text-sm text-deny">
          {state.error}
        </p>
      )}
      {state.saved && (
        <p role="status" className="text-sm">
          {state.saved}
        </p>
      )}
    </form>
  );
}
