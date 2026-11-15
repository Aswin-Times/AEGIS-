"use client";

import { useActionState } from "react";
import { CONTROL, Field } from "@/components/form-field";
import type { DecisionFormState } from "@/lib/governance-types";
import { assignReviewer } from "./actions";

type AssignState = DecisionFormState & { attempt?: number; chosen?: string };

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
  // React resets a form after its action, and an uncontrolled select returns to the value it
  // mounted with. So the select is remounted after every result: from the new assignee after a
  // success, or from the choice that was refused.
  const [state, action, pending] = useActionState<AssignState, FormData>(
    async (previous, data) => ({
      ...(await assignReviewer(previous, data)),
      attempt: (previous.attempt ?? 0) + 1,
      chosen: String(data.get("reviewer_id") ?? ""),
    }),
    {},
  );
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
            key={state.attempt ?? 0}
            id={id}
            name="reviewer_id"
            defaultValue={state.error ? state.chosen : (assigned ?? "")}
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
