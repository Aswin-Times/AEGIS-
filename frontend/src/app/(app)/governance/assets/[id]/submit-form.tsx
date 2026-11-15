"use client";

import { useActionState } from "react";
import { CONTROL, Field } from "@/components/form-field";
import type { ProfileFormState } from "@/lib/governance-types";
import { submitForReview } from "./actions";

/** Rendered only for administrators. The API refuses the request from anyone else. */
export function SubmitForm({ assetId }: { assetId: string }) {
  const [state, action, pending] = useActionState<ProfileFormState, FormData>(submitForReview, {});
  const typed = state.values?.reason;
  return (
    <form action={action} aria-label="Submit for review" className="grid gap-2 p-3">
      <input type="hidden" name="asset_id" value={assetId} />
      <Field
        label="Submission reason"
        hint="Recorded with the submission. Applicable policies are matched now and frozen on the review."
        error={state.fieldErrors?.reason}
      >
        {({ id, describedBy, invalid }) => (
          <textarea
            id={id}
            name="reason"
            rows={2}
            defaultValue={typeof typed === "string" ? typed : ""}
            aria-describedby={describedBy}
            aria-invalid={invalid}
            className={CONTROL}
          />
        )}
      </Field>
      <div>
        <button
          type="submit"
          disabled={pending}
          className="rounded bg-accent px-3 py-1.5 font-medium text-accent-ink disabled:opacity-60"
        >
          {pending ? "Submitting" : "Submit for review"}
        </button>
      </div>
      {state.error && (
        <p role="alert" className="text-sm text-deny">
          {state.error}
        </p>
      )}
      {state.saved && (
        <p role="status" className="text-sm text-allow">
          {state.saved}
        </p>
      )}
    </form>
  );
}
