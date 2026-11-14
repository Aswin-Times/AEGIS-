"use client";

import { type ReactNode, useActionState, useEffect, useId, useRef } from "react";
import { useFormStatus } from "react-dom";

export type ActionState = {
  error?: string;
  // The API's own error code, such as ENFORCEMENT_MODE_UNCHANGED.
  code?: string;
  // Keyed by the form's field names, so a field can be marked invalid and described.
  fieldErrors?: Record<string, string>;
};

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
  const [state, formAction] = useActionState(async (previous: ActionState, data: FormData) => {
    const result = await action(previous, data);
    if (!result.error) dialog.current?.close();
    return result;
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
          {typeof extra === "function" ? extra(state) : extra}
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
