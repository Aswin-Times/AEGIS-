"use client";

import { type ReactNode, useActionState, useEffect, useId, useRef } from "react";
import { useFormStatus } from "react-dom";

export type ActionState = {
  error?: string;
  // The API's own error code, such as ENFORCEMENT_MODE_UNCHANGED.
  code?: string;
  // Keyed by the form's field names, so a field can be marked invalid and described.
  fieldErrors?: Record<string, string>;
  // After a refusal, what was submitted, so fields can start from it (see `submittedValues`).
  values?: Record<string, string | string[]>;
  // Changes on every result. React resets a form after its action, and an uncontrolled select or
  // radio returns to the default it mounted with, so the fields are remounted from `values`.
  attempt?: number;
};

/** Every field of a submission, a name given more than once as a list. */
export function submittedValues(data: FormData): Record<string, string | string[]> {
  const values: Record<string, string | string[]> = {};
  for (const name of new Set(data.keys())) {
    const all = data.getAll(name).map(String);
    values[name] = all.length === 1 ? all[0]! : all;
  }
  return values;
}

/** A submitted value as text, or the fallback when nothing was submitted under that name. */
export function valueOf(state: ActionState, name: string, fallback = ""): string {
  const value = state.values?.[name];
  return typeof value === "string" ? value : fallback;
}

/** Submitted values under a name as a list, for checkboxes. */
export function valuesOf(state: ActionState, name: string): string[] {
  const value = state.values?.[name];
  return value === undefined ? [] : Array.isArray(value) ? value : [value];
}

function Submit({ label, danger }: { label: string; danger?: boolean }) {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className={`rounded px-3 py-1.5 text-sm font-medium disabled:opacity-60 ${
        danger ? "bg-deny text-surface" : "bg-accent text-accent-ink"
      }`}
    >
      {pending ? "Working" : label}
    </button>
  );
}

/** Sensitive actions state exactly what will happen, and need a second, explicit click. */
export function ConfirmAction({
  trigger,
  triggerLabel,
  title,
  children,
  confirmLabel,
  danger,
  action,
  fields,
  extra,
}: {
  trigger: string;
  triggerLabel: string;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  action: (state: ActionState, formData: FormData) => Promise<ActionState>;
  fields: Record<string, string>;
  // A function receives the last result, so fields can show their own errors.
  extra?: ReactNode | ((state: ActionState) => ReactNode);
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const [state, formAction] = useActionState<ActionState, FormData>(async (previous, data) => {
    const result = await action(previous, data);
    const attempt = (previous.attempt ?? 0) + 1;
    if (!result.error) {
      dialog.current?.close();
      return { ...result, attempt };
    }
    // A refused submission keeps what was chosen, so sending it again sends the same thing.
    return { ...result, values: submittedValues(data), attempt };
  }, {});

  // After a refusal, focus goes to the first field marked invalid, else to the message.
  useEffect(() => {
    if (!state.error) return;
    const root = dialog.current;
    const target = root?.querySelector<HTMLElement>('[aria-invalid="true"]') ?? root?.querySelector<HTMLElement>("[role=alert]");
    target?.focus();
  }, [state]);

  return (
    <>
      <button
        type="button"
        aria-label={triggerLabel}
        onClick={() => dialog.current?.showModal()}
        className="rounded border border-line bg-surface px-2 py-1 text-xs font-medium hover:bg-subtle"
      >
        {trigger}
      </button>
      <dialog
        ref={dialog}
        aria-labelledby={titleId}
        className="m-auto w-full max-w-lg rounded-md border border-line bg-surface p-4 text-ink"
      >
        <h2 id={titleId} className="mb-2 font-semibold">
          {title}
        </h2>
        <div className="mb-3 text-sm">{children}</div>
        <form action={formAction}>
          {Object.entries(fields).map(([name, value]) => (
            <input key={name} type="hidden" name={name} value={value} />
          ))}
          <div key={state.attempt ?? 0}>
            {typeof extra === "function" ? extra(state) : extra}
          </div>
          {state.error && (
            <p role="alert" tabIndex={-1} className="mb-2 text-sm text-deny">
              {state.error}
              {state.code && <span className="block text-xs text-muted">Code: {state.code}</span>}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => dialog.current?.close()}
              className="rounded border border-line px-3 py-1.5 text-sm"
            >
              Cancel
            </button>
            <Submit label={confirmLabel} danger={danger} />
          </div>
        </form>
      </dialog>
    </>
  );
}
