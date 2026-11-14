"use client";

import type { ReactNode } from "react";
import { CONTROL, Field } from "@/components/form-field";
import { humanize } from "@/lib/format";

export type ConditionValues = {
  denied_tools: string;
  held_tools: string;
  denied_actions: string;
  hold_all: boolean;
  max_resource_classification: string;
  advisory_conditions: string;
};

const GROUP_ERROR = "decision-conditions-error";

function List({
  name,
  label,
  hint,
  value,
  error,
  groupError,
  onChange,
}: {
  name: keyof ConditionValues;
  label: string;
  hint: string;
  value: string;
  error?: string;
  groupError: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <Field label={label} hint={hint} error={error}>
      {({ id, describedBy, invalid }) => (
        <textarea
          id={id}
          name={name}
          rows={2}
          value={value}
          aria-invalid={invalid || groupError || undefined}
          aria-describedby={[describedBy, groupError ? GROUP_ERROR : null].filter(Boolean).join(" ") || undefined}
          onChange={(event) => onChange(event.target.value)}
          className={CONTROL}
        />
      )}
    </Field>
  );
}

/** Which conditions the gateway enforces and which it only shows is stated, not implied. */
export function ConditionsFields({
  values,
  onChange,
  errors,
  classifications,
  bound,
}: {
  values: ConditionValues;
  onChange: (values: ConditionValues) => void;
  errors: Record<string, string>;
  classifications: readonly string[];
  bound: boolean;
}): ReactNode {
  const set = (patch: Partial<ConditionValues>) => onChange({ ...values, ...patch });
  const groupError = Boolean(errors.conditions);
  return (
    <fieldset className="space-y-3 rounded border border-line p-3">
      <legend className="px-1 text-sm font-medium">Conditions</legend>
      <p className="text-xs text-muted">
        The gateway enforces tool, action, hold, and classification conditions. Advisory
        conditions are shown to people and are not enforced.
        {bound &&
          " Earlier votes set conditions, and every approval must carry exactly those, so these fields start from them."}
      </p>
      {groupError && (
        <p id={GROUP_ERROR} className="text-xs text-deny">
          {errors.conditions}
        </p>
      )}
      <List
        name="denied_tools"
        label="Denied tools"
        hint="One tool name per line. Enforced: the gateway denies these tools."
        value={values.denied_tools}
        error={errors.denied_tools}
        groupError={groupError}
        onChange={(value) => set({ denied_tools: value })}
      />
      <List
        name="held_tools"
        label="Held tools"
        hint="One tool name per line. Enforced: the gateway holds these tools for approval."
        value={values.held_tools}
        error={errors.held_tools}
        groupError={groupError}
        onChange={(value) => set({ held_tools: value })}
      />
      <List
        name="denied_actions"
        label="Denied actions"
        hint="One action per line. Enforced: the gateway denies these actions."
        value={values.denied_actions}
        error={errors.denied_actions}
        groupError={groupError}
        onChange={(value) => set({ denied_actions: value })}
      />
      <label className="flex items-center gap-1.5 text-sm">
        <input
          type="checkbox"
          name="hold_all"
          checked={values.hold_all}
          aria-invalid={groupError || undefined}
          aria-describedby={groupError ? GROUP_ERROR : undefined}
          onChange={(event) => set({ hold_all: event.target.checked })}
        />
        Hold every action for approval (enforced)
      </label>
      <Field
        label="Highest resource classification"
        hint="Enforced: the gateway denies access to anything above this."
        error={errors.max_resource_classification}
      >
        {({ id, describedBy, invalid }) => (
          <select
            id={id}
            name="max_resource_classification"
            value={values.max_resource_classification}
            aria-invalid={invalid || groupError || undefined}
            aria-describedby={[describedBy, groupError ? GROUP_ERROR : null].filter(Boolean).join(" ") || undefined}
            onChange={(event) => set({ max_resource_classification: event.target.value })}
            className={CONTROL}
          >
            <option value="">No limit</option>
            {classifications.map((value) => (
              <option key={value} value={value}>
                {humanize(value)}
              </option>
            ))}
          </select>
        )}
      </Field>
      <List
        name="advisory_conditions"
        label="Advisory conditions"
        hint="One per line. Advisory, not enforced: shown to people only."
        value={values.advisory_conditions}
        error={errors.advisory_conditions}
        groupError={groupError}
        onChange={(value) => set({ advisory_conditions: value })}
      />
    </fieldset>
  );
}
