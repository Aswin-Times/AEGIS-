"use client";

import { type ActionState, ConfirmAction, valueOf } from "@/components/confirm-action";
import { CONTROL, Field } from "@/components/form-field";
import { setEnforcementMode } from "./actions";

// What switching to each mode does, as spec 11 states it.
const EFFECT: Record<string, string> = {
  enforce:
    "In enforce mode an asset with no approval in force is denied, including a Not governed one. Decisions a person made, such as suspension, retirement and conditions, apply as they do now. The list on this page shows which assets this would block.",
  observe:
    "In observe mode checks are recorded, and an action is not blocked only because no approval is in force. Decisions a person made, such as suspension, retirement and conditions, still apply, so switching to observe does not lift a suspension.",
};

/** The target is fixed when the page renders, so a change made meanwhile comes back as a conflict. */
export function ModeForm({ target }: { target: "observe" | "enforce" }) {
  return (
    <ConfirmAction
      trigger={`Switch to ${target} mode`}
      triggerLabel={`Switch to ${target} mode`}
      title={`Switch to ${target} mode?`}
      confirmLabel={`Confirm switch to ${target}`}
      danger={target === "enforce"}
      action={setEnforcementMode}
      fields={{ mode: target }}
      extra={(state: ActionState) => (
        <div className="mb-3">
          <Field
            label="Reason"
            hint="Recorded in the audit log with the change."
            error={state.fieldErrors?.reason}
          >
            {({ id, describedBy, invalid }) => (
              <textarea
                id={id}
                name="reason"
                rows={3}
                maxLength={2000}
                defaultValue={valueOf(state, "reason")}
                aria-invalid={invalid || undefined}
                aria-describedby={describedBy}
                className={CONTROL}
              />
            )}
          </Field>
        </div>
      )}
    >
      <p>{EFFECT[target]}</p>
      <p className="mt-2">The change is audited, and it can be reversed.</p>
    </ConfirmAction>
  );
}
