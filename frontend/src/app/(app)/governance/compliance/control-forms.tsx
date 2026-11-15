"use client";

import { useState } from "react";
import { type ActionState, ConfirmAction } from "@/components/confirm-action";
import { CONTROL, Field } from "@/components/form-field";
import { humanize } from "@/lib/format";
import { assessControl, verifyEvidence } from "./actions";

const ASSESSED = ["IMPLEMENTED", "PARTIALLY_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_APPLICABLE"];

export type EvidenceChoice = {
  id: string;
  description: string;
  verification: string;
};

const METHODS_BY_SOURCE: Record<string, string[]> = {
  internal_record: ["internal_record_checked"],
  inline: ["content_recomputed", "manual_attestation"],
  external_reference: ["content_recomputed", "manual_attestation"],
};

/**
 * Shown to holders of governance_reviewer. The API decides again on every request: a claim of
 * implementation without verified, linked evidence comes back as EVIDENCE_REQUIRED, in its words.
 */
export function AssessControl({
  controlId,
  identifier,
  evidence,
}: {
  controlId: string;
  identifier: string;
  evidence: EvidenceChoice[];
}) {
  return (
    <ConfirmAction
      trigger="Assess control"
      triggerLabel={`Assess control ${identifier}`}
      title={`Assess control ${identifier}`}
      confirmLabel="Record assessment"
      action={assessControl}
      fields={{ control_id: controlId }}
      extra={(state: ActionState) => (
        <div className="mb-3 space-y-3">
          <Field label="Status" error={state.fieldErrors?.status}>
            {({ id, describedBy, invalid }) => (
              <select
                id={id}
                name="status"
                defaultValue=""
                aria-invalid={invalid || undefined}
                aria-describedby={describedBy}
                className={CONTROL}
              >
                <option value="" disabled>
                  Choose a status
                </option>
                {ASSESSED.map((value) => (
                  <option key={value} value={value}>
                    {humanize(value)}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Field label="Note" hint="Recorded with the assessment." error={state.fieldErrors?.note}>
            {({ id, describedBy, invalid }) => (
              <textarea
                id={id}
                name="note"
                rows={3}
                maxLength={2000}
                aria-invalid={invalid || undefined}
                aria-describedby={describedBy}
                className={CONTROL}
              />
            )}
          </Field>
          <fieldset
            aria-describedby={`${controlId}-cited${state.fieldErrors?.evidence_ids ? ` ${controlId}-cited-error` : ""}`}
            aria-invalid={state.fieldErrors?.evidence_ids ? true : undefined}
          >
            <legend className="text-sm font-medium">Evidence cited</legend>
            <p id={`${controlId}-cited`} className="text-xs text-muted">
              Implemented and Partially implemented need at least one linked item that a reviewer
              has verified. Unverified or rejected evidence does not count.
            </p>
            {state.fieldErrors?.evidence_ids && (
              <p id={`${controlId}-cited-error`} className="text-xs text-deny">
                {state.fieldErrors.evidence_ids}
              </p>
            )}
            {evidence.length === 0 ? (
              <p className="text-sm text-muted">No evidence is linked to this control.</p>
            ) : (
              evidence.map((item) => (
                <label key={item.id} className="flex items-start gap-1.5 py-0.5 text-sm">
                  <input type="checkbox" name="evidence_ids" value={item.id} className="mt-1" />
                  <span>
                    {item.description}
                    <span className="text-xs text-muted"> ({humanize(item.verification)})</span>
                  </span>
                </label>
              ))
            )}
          </fieldset>
        </div>
      )}
    >
      <p>
        This records your assessment of the control for this organization. It is a person&apos;s
        judgment, not an audit result, and earlier assessments stay on record.
      </p>
    </ConfirmAction>
  );
}

function VerifyFields({ sourceType, state }: { sourceType: string; state: ActionState }) {
  const methods = METHODS_BY_SOURCE[sourceType] ?? ["manual_attestation"];
  const [method, setMethod] = useState(methods[0]);
  const errors = state.fieldErrors ?? {};
  return (
    <div className="mb-3 space-y-3">
      <fieldset>
        <legend className="text-sm font-medium">Outcome</legend>
        <div className="flex gap-4">
          <label className="flex items-center gap-1.5">
            <input type="radio" name="outcome" value="VERIFIED" defaultChecked />
            Verified
          </label>
          <label className="flex items-center gap-1.5">
            <input type="radio" name="outcome" value="REJECTED" />
            Rejected
          </label>
        </div>
      </fieldset>
      <Field
        label="Method"
        hint="The page shows this method beside the evidence, so an attestation is never taken for a recomputed hash."
        error={errors.method}
      >
        {({ id, describedBy, invalid }) => (
          <select
            id={id}
            name="method"
            value={method}
            onChange={(event) => setMethod(event.target.value)}
            aria-invalid={invalid || undefined}
            aria-describedby={describedBy}
            className={CONTROL}
          >
            {methods.map((value) => (
              <option key={value} value={value}>
                {humanize(value)}
              </option>
            ))}
          </select>
        )}
      </Field>
      {sourceType === "external_reference" && method === "content_recomputed" && (
        <Field
          label="Content to compare"
          hint="The API recomputes the hash from this text and compares it with the declared hash."
          error={errors.content}
        >
          {({ id, describedBy, invalid }) => (
            <textarea
              id={id}
              name="content"
              rows={4}
              aria-invalid={invalid || undefined}
              aria-describedby={describedBy}
              className={CONTROL}
            />
          )}
        </Field>
      )}
      <Field label="Note" hint="Recorded with the verification." error={errors.note}>
        {({ id, describedBy, invalid }) => (
          <textarea
            id={id}
            name="note"
            rows={3}
            maxLength={2000}
            aria-invalid={invalid || undefined}
            aria-describedby={describedBy}
            className={CONTROL}
          />
        )}
      </Field>
    </div>
  );
}

/** The submitter of evidence cannot verify it. The API says so, and the page repeats it. */
export function VerifyEvidence({
  evidenceId,
  controlId,
  description,
  sourceType,
}: {
  evidenceId: string;
  controlId: string;
  description: string;
  sourceType: string;
}) {
  return (
    <ConfirmAction
      trigger="Verify"
      triggerLabel={`Verify evidence: ${description}`}
      title={`Verify evidence: ${description}`}
      confirmLabel="Record verification"
      action={verifyEvidence}
      fields={{ evidence_id: evidenceId, control_id: controlId }}
      extra={(state: ActionState) => <VerifyFields sourceType={sourceType} state={state} />}
    >
      <p>
        This records a verification, or a rejection, with you as the reviewer. Only evidence whose
        latest verification is Verified counts toward a control.
      </p>
    </ConfirmAction>
  );
}
