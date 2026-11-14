"use client";

import { type ReactNode, useId } from "react";

export const CONTROL =
  "mt-1 block w-full rounded border border-line bg-surface px-2 py-1 text-ink aria-[invalid=true]:border-deny";

export function Field({
  label,
  error,
  hint,
  children,
}: {
  label: string;
  error?: string;
  hint?: string;
  children: (props: { id: string; describedBy?: string; invalid: boolean }) => ReactNode;
}) {
  const id = useId();
  const errorId = `${id}-error`;
  const hintId = `${id}-hint`;
  const describedBy = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(" ");
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
      </label>
      {hint && (
        <p id={hintId} className="text-xs text-muted">
          {hint}
        </p>
      )}
      {children({ id, describedBy: describedBy || undefined, invalid: Boolean(error) })}
      {error && (
        <p id={errorId} className="mt-1 text-xs text-deny">
          {error}
        </p>
      )}
    </div>
  );
}
