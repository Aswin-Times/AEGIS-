"use client";

import { type ReactNode, useActionState, useId } from "react";
import {
  ASSET_TYPES,
  AUTONOMY_LEVELS,
  DATA_CATEGORIES,
  ENVIRONMENTS,
  EXTERNAL_EXPOSURES,
  HUMAN_OVERSIGHT,
  IMPACT_LEVELS,
  THIRD_PARTY_RELIANCE,
  type AssetProfile,
  type Person,
  type ProfileFormState,
} from "@/lib/governance-types";
import { humanize } from "@/lib/format";
import { saveProfile } from "./actions";

const CONTROL =
  "mt-1 block w-full rounded border border-line bg-surface px-2 py-1 text-ink aria-[invalid=true]:border-deny";

function Field({
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

type Option = { value: string; label: string };

function Select({
  label,
  name,
  value,
  options,
  error,
}: {
  label: string;
  name: string;
  value: string;
  options: readonly Option[];
  error?: string;
}) {
  return (
    <Field label={label} error={error}>
      {({ id, describedBy, invalid }) => (
        <select
          id={id}
          name={name}
          defaultValue={value}
          aria-describedby={describedBy}
          aria-invalid={invalid}
          className={CONTROL}
        >
          <option value="">Not stated</option>
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      )}
    </Field>
  );
}

const vocabulary = (values: readonly string[]): Option[] =>
  values.map((value) => ({ value, label: humanize(value) }));

function Input({
  label,
  name,
  value,
  error,
}: {
  label: string;
  name: string;
  value: string;
  error?: string;
}) {
  return (
    <Field label={label} error={error}>
      {({ id, describedBy, invalid }) => (
        <input
          id={id}
          name={name}
          type="text"
          defaultValue={value}
          maxLength={200}
          aria-describedby={describedBy}
          aria-invalid={invalid}
          className={CONTROL}
        />
      )}
    </Field>
  );
}

function TextArea({
  label,
  name,
  value,
  hint,
  error,
}: {
  label: string;
  name: string;
  value: string;
  hint?: string;
  error?: string;
}) {
  return (
    <Field label={label} error={error} hint={hint}>
      {({ id, describedBy, invalid }) => (
        <textarea
          id={id}
          name={name}
          rows={3}
          defaultValue={value}
          aria-describedby={describedBy}
          aria-invalid={invalid}
          className={CONTROL}
        />
      )}
    </Field>
  );
}

type ListField = "external_integrations" | "declared_tool_access" | "evidence_references";

export function ProfileForm({
  assetId,
  profile,
  people,
}: {
  assetId: string;
  profile: AssetProfile;
  people: Person[];
}) {
  const [state, action, pending] = useActionState<ProfileFormState, FormData>(saveProfile, {});
  const errors = state.fieldErrors ?? {};
  // A refused form keeps what was typed. Otherwise it starts from the stored profile.
  const text = (name: keyof AssetProfile): string => {
    const typed = state.values?.[name];
    if (typeof typed === "string") return typed;
    const stored = profile[name];
    return typeof stored === "string" ? stored : "";
  };
  const list = (name: ListField): string => {
    const typed = state.values?.[name];
    return typeof typed === "string" ? typed : (profile[name] ?? []).join("\n");
  };
  const typedCategories = state.values?.data_categories;
  const categories = Array.isArray(typedCategories)
    ? typedCategories
    : (profile.data_categories ?? []);
  const owners: Option[] = people.map((person) => ({ value: person.id, label: person.email }));

  return (
    <form action={action} aria-label="Edit profile" className="grid gap-3 p-3 md:grid-cols-2">
      <input type="hidden" name="asset_id" value={assetId} />
      <Select label="Asset type" name="asset_type" value={text("asset_type")}
        options={vocabulary(ASSET_TYPES)} error={errors.asset_type} />
      <Select label="Deployment environment" name="deployment_environment"
        value={text("deployment_environment")} options={vocabulary(ENVIRONMENTS)}
        error={errors.deployment_environment} />
      <Select label="Business owner" name="business_owner_id" value={text("business_owner_id")}
        options={owners} error={errors.business_owner_id} />
      <Select label="Technical owner" name="technical_owner_id"
        value={text("technical_owner_id")} options={owners} error={errors.technical_owner_id} />
      <TextArea label="Description" name="description" value={text("description")}
        error={errors.description} />
      <TextArea label="Business purpose" name="business_purpose" value={text("business_purpose")}
        error={errors.business_purpose} />
      <TextArea label="Intended use" name="intended_use" value={text("intended_use")}
        error={errors.intended_use} />
      <TextArea label="Prohibited use" name="prohibited_use" value={text("prohibited_use")}
        error={errors.prohibited_use} />
      <Input label="Responsible team" name="responsible_team" value={text("responsible_team")}
        error={errors.responsible_team} />
      <Input label="Model provider" name="model_provider" value={text("model_provider")}
        error={errors.model_provider} />
      <Input label="Model name" name="model_name" value={text("model_name")}
        error={errors.model_name} />
      <Input label="Model version" name="model_version" value={text("model_version")}
        error={errors.model_version} />
      <fieldset
        className="rounded border border-line p-2"
        aria-describedby={errors.data_categories ? "data-categories-error" : undefined}
      >
        <legend className="px-1 text-sm font-medium">Data categories</legend>
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          {DATA_CATEGORIES.map((value) => (
            <label key={value} className="flex items-center gap-1.5">
              <input
                type="checkbox"
                name="data_categories"
                value={value}
                defaultChecked={categories.includes(value)}
              />
              {humanize(value)}
            </label>
          ))}
        </div>
        {errors.data_categories && (
          <p id="data-categories-error" className="mt-1 text-xs text-deny">
            {errors.data_categories}
          </p>
        )}
      </fieldset>
      <Select label="External exposure" name="external_exposure"
        value={text("external_exposure")} options={vocabulary(EXTERNAL_EXPOSURES)}
        error={errors.external_exposure} />
      <Select label="Autonomy level" name="autonomy_level" value={text("autonomy_level")}
        options={vocabulary(AUTONOMY_LEVELS)} error={errors.autonomy_level} />
      <Select label="Human oversight" name="human_oversight" value={text("human_oversight")}
        options={vocabulary(HUMAN_OVERSIGHT)} error={errors.human_oversight} />
      <Select label="Impact level" name="impact_level" value={text("impact_level")}
        options={vocabulary(IMPACT_LEVELS)} error={errors.impact_level} />
      <Select label="Third-party reliance" name="third_party_reliance"
        value={text("third_party_reliance")} options={vocabulary(THIRD_PARTY_RELIANCE)}
        error={errors.third_party_reliance} />
      <TextArea label="External integrations" name="external_integrations"
        value={list("external_integrations")} hint="One per line."
        error={errors.external_integrations} />
      <TextArea label="Declared tool access" name="declared_tool_access"
        value={list("declared_tool_access")}
        hint="One per line. Used only when the asset has no agents. An asset with agents is scored on their actual grants."
        error={errors.declared_tool_access} />
      <TextArea label="Evidence references" name="evidence_references"
        value={list("evidence_references")} hint="One per line."
        error={errors.evidence_references} />

      <div className="md:col-span-2">
        <p className="mb-2 text-xs text-muted">
          Saving creates a new profile version. The asset then needs a new assessment, because the
          last one describes the previous profile.
        </p>
        <button
          type="submit"
          disabled={pending}
          className="rounded bg-accent px-3 py-1.5 font-medium text-accent-ink disabled:opacity-60"
        >
          {pending ? "Saving" : "Save profile"}
        </button>
        {state.error && (
          <p role="alert" className="mt-2 text-sm text-deny">
            {state.error}
          </p>
        )}
        {state.saved && (
          <p role="status" className="mt-2 text-sm text-allow">
            {state.saved}
          </p>
        )}
      </div>
    </form>
  );
}
