"use client";

import { useEffect, useRef, useState } from "react";
import { type ActionState, ConfirmAction } from "@/components/confirm-action";
import { CONTROL, Field } from "@/components/form-field";
import { humanize } from "@/lib/format";
import {
  type Conditions,
  type DecisionFormState,
  RESOURCE_CLASSIFICATIONS,
} from "@/lib/governance-types";
import { approveReview, rejectReview, requestInformation } from "./actions";
import { ConditionsFields, type ConditionValues } from "./conditions-fields";

type Kind = "approve" | "approve_conditional" | "request_information" | "reject";

const KINDS: { value: Kind; label: string }[] = [
  { value: "approve", label: "Approve" },
  { value: "approve_conditional", label: "Approve with conditions" },
  { value: "request_information", label: "Request information" },
  { value: "reject", label: "Reject" },
];

type EvidenceChoice = { id: string; description: string; verification: string };

// The order a keyboard user would meet the fields, so focus goes to the first one that failed.
const FOCUS_ORDER = [
  "reason",
  "valid_until",
  "next_review_at",
  "denied_tools",
  "held_tools",
  "denied_actions",
  "max_resource_classification",
  "advisory_conditions",
  "evidence_ids",
];

const fromBound = (bound: Conditions | null): ConditionValues => ({
  denied_tools: (bound?.denied_tools ?? []).join("\n"),
  held_tools: (bound?.held_tools ?? []).join("\n"),
  denied_actions: (bound?.denied_actions ?? []).join("\n"),
  hold_all: bound?.hold_all ?? false,
  max_resource_classification: bound?.max_resource_classification ?? "",
  advisory_conditions: (bound?.advisory_conditions ?? []).join("\n"),
});

/**
 * The decision controls. They are shown to holders of governance_reviewer, and the API decides
 * again on every request: a refusal comes back as text and stays on the page.
 */
export function DecisionForm({
  reviewId,
  open,
  assetName,
  awaitingInformation,
  bound,
  evidence,
  needed,
  counted,
  alreadyVoted,
}: {
  reviewId: string;
  // False once a decision has closed the review. The form goes, and the outcome stays.
  open: boolean;
  assetName: string;
  awaitingInformation: boolean;
  // Conditions set by earlier votes. Every later approval has to carry exactly these.
  bound: Conditions | null;
  evidence: EvidenceChoice[];
  needed: number;
  counted: number | null;
  alreadyVoted: boolean;
}) {
  const [kind, setKind] = useState<Kind>(bound ? "approve_conditional" : "approve");
  const [reason, setReason] = useState("");
  const [validUntil, setValidUntil] = useState("");
  const [nextReview, setNextReview] = useState("");
  const [conditions, setConditions] = useState<ConditionValues>(fromBound(bound));
  const [cited, setCited] = useState<string[]>([]);
  const [result, setResult] = useState<DecisionFormState>({});
  const root = useRef<HTMLDivElement>(null);
  const alert = useRef<HTMLParagraphElement>(null);
  const errors = result.fieldErrors ?? {};
  const approving = kind === "approve" || kind === "approve_conditional";

  // After a failed submit, focus goes to the first field with an error, else to the message.
  useEffect(() => {
    if (!result.error) return;
    const failed = result.fieldErrors ?? {};
    const first = FOCUS_ORDER.find(
      (name) => failed[name] || (name === "denied_tools" && failed.conditions),
    );
    const target = first ? root.current?.querySelector<HTMLElement>(`[name="${first}"]`) : null;
    (target ?? alert.current)?.focus();
  }, [result]);

  // Double submission is stopped by the disabled confirm button, and by the API, which refuses
  // a second decision on a closed review or a second vote from the same person.
  const run =
    (action: (state: DecisionFormState, data: FormData) => Promise<DecisionFormState>) =>
    async (_: ActionState, data: FormData): Promise<ActionState> => {
      const outcome = await action({}, data);
      setResult(outcome);
      if (outcome.saved) setReason("");
      // The outcome, refusals included, is shown on the page, so the dialog always closes.
      return {};
    };

  const fields: Record<string, string> = {
    review_id: reviewId,
    reason,
    ...(approving
      ? {
          valid_until: validUntil,
          next_review_at: nextReview,
          evidence_ids: cited.join(","),
          conditional: kind === "approve_conditional" ? "1" : "0",
        }
      : {}),
    ...(kind === "approve_conditional"
      ? {
          denied_tools: conditions.denied_tools,
          held_tools: conditions.held_tools,
          denied_actions: conditions.denied_actions,
          hold_all: conditions.hold_all ? "on" : "",
          max_resource_classification: conditions.max_resource_classification,
          advisory_conditions: conditions.advisory_conditions,
        }
      : {}),
  };

  const standing =
    counted === null ? "approvals counted are not visible to this account" : `${counted} of ${needed} counted so far`;
  const final = counted !== null && counted + 1 >= needed;
  const approvalEffect = (
    <>
      <p>
        This records your approval of <strong>{assetName}</strong> ({standing}).{" "}
        {counted === null
          ? "Whether it completes the approval depends on the votes that still count."
          : final
            ? "It is the last approval needed, so it decides the review and the asset's approval takes effect."
            : "It is a vote. The review and the asset stay open until enough approvals count."}
      </p>
      <p>This cannot be undone.</p>
    </>
  );

  const outcome = result.saved && (
    <p role="status" className="text-sm">
      {result.saved}
    </p>
  );
  if (!open) {
    return (
      <div className="space-y-2 p-3">
        {outcome}
        <p className="text-muted">This review is closed. No further decision can be recorded on it.</p>
      </div>
    );
  }

  return (
    <div ref={root} className="space-y-4 p-3">
      {alreadyVoted && (
        <p className="text-sm text-muted">
          You have already voted on this review. The API will not count a second vote from you.
        </p>
      )}
      {awaitingInformation && (
        <p className="text-sm text-muted">
          Information has been requested, so the API refuses an approval until the submitter
          resubmits. You can still reject.
        </p>
      )}

      <fieldset>
        <legend className="mb-1 text-sm font-medium">Your decision</legend>
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          {KINDS.map((option) => (
            <label key={option.value} className="flex items-center gap-1.5">
              <input
                type="radio"
                name="kind"
                value={option.value}
                checked={kind === option.value}
                onChange={() => setKind(option.value)}
              />
              {option.label}
            </label>
          ))}
        </div>
      </fieldset>

      <Field
        label="Reason"
        hint="Recorded with the decision and shown in the history."
        error={errors.reason}
      >
        {({ id, describedBy, invalid }) => (
          <textarea
            id={id}
            name="reason"
            aria-invalid={invalid || undefined}
            aria-describedby={describedBy}
            rows={3}
            maxLength={2000}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            className={CONTROL}
          />
        )}
      </Field>

      {approving && (
        <>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label="Valid until (UTC)"
              hint="The approval ends here. In enforce mode the gateway denies after this time. In observe mode the expiry is recorded, not blocked."
              error={errors.valid_until}
            >
              {({ id, describedBy, invalid }) => (
                <input
                  id={id}
                  type="datetime-local"
                  name="valid_until"
                  aria-invalid={invalid || undefined}
                  aria-describedby={describedBy}
                  value={validUntil}
                  onChange={(event) => setValidUntil(event.target.value)}
                  className={CONTROL}
                />
              )}
            </Field>
            <Field
              label="Next review by (UTC)"
              hint="Must be in the future and no later than the end of the approval."
              error={errors.next_review_at}
            >
              {({ id, describedBy, invalid }) => (
                <input
                  id={id}
                  type="datetime-local"
                  name="next_review_at"
                  aria-invalid={invalid || undefined}
                  aria-describedby={describedBy}
                  value={nextReview}
                  onChange={(event) => setNextReview(event.target.value)}
                  className={CONTROL}
                />
              )}
            </Field>
          </div>

          {kind === "approve_conditional" && (
            <ConditionsFields
              values={conditions}
              onChange={setConditions}
              errors={errors}
              classifications={RESOURCE_CLASSIFICATIONS}
              bound={bound !== null}
            />
          )}

          {evidence.length > 0 && (
            <fieldset aria-describedby={errors.evidence_ids ? "decision-evidence-error" : undefined}>
              <legend className="mb-1 text-sm font-medium">
                Evidence this decision relies on (optional)
              </legend>
              <ul className="space-y-1">
                {evidence.map((item) => (
                  <li key={item.id}>
                    <label className="flex items-start gap-1.5">
                      <input
                        type="checkbox"
                        name="evidence_ids"
                        aria-invalid={errors.evidence_ids ? true : undefined}
                        checked={cited.includes(item.id)}
                        onChange={(event) =>
                          setCited((previous) =>
                            event.target.checked
                              ? [...previous, item.id]
                              : previous.filter((value) => value !== item.id),
                          )
                        }
                      />
                      <span>
                        {item.description}{" "}
                        <span className="text-xs text-muted">({humanize(item.verification)})</span>
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
              {errors.evidence_ids && (
                <p id="decision-evidence-error" className="mt-1 text-xs text-deny">
                  {errors.evidence_ids}
                </p>
              )}
            </fieldset>
          )}
        </>
      )}

      {outcome}
      {result.error && (
        <p
          ref={alert}
          id="decision-error"
          role="alert"
          tabIndex={-1}
          className="rounded border border-line p-2 text-sm text-deny"
        >
          {result.error}
        </p>
      )}

      <div className="flex flex-wrap gap-2">
        {kind === "approve" && (
          <ConfirmAction
            trigger="Approve"
            triggerLabel="Approve this review"
            title="Approve this review?"
            confirmLabel="Confirm approval"
            action={run(approveReview)}
            fields={fields}
          >
            {approvalEffect}
            <p>
              No conditions are recorded. Valid until {validUntil || "the date you enter"} (UTC).
            </p>
          </ConfirmAction>
        )}
        {kind === "approve_conditional" && (
          <ConfirmAction
            trigger="Approve with conditions"
            triggerLabel="Approve with conditions"
            title="Approve with conditions?"
            confirmLabel="Confirm conditional approval"
            action={run(approveReview)}
            fields={fields}
          >
            {approvalEffect}
            <p>
              The conditions you entered are recorded with it. The gateway enforces tool, action,
              hold, and classification conditions; advisory conditions are only shown to people.
            </p>
          </ConfirmAction>
        )}
        {kind === "request_information" && (
          <ConfirmAction
            trigger="Request information"
            triggerLabel="Request information from the submitter"
            title="Request information?"
            confirmLabel="Confirm request"
            action={run(requestInformation)}
            fields={fields}
          >
            <p>
              The review stays open but cannot be approved until the submitter resubmits. Your
              reason is recorded. This cannot be undone.
            </p>
          </ConfirmAction>
        )}
        {kind === "reject" && (
          <ConfirmAction
            trigger="Reject"
            triggerLabel="Reject this review"
            title="Reject this review?"
            confirmLabel="Confirm rejection"
            danger
            action={run(rejectReview)}
            fields={fields}
          >
            <p>
              One rejection decides the review, whatever votes came before. The asset becomes
              Rejected, and the gateway denies its agents&apos; actions until a later approval.
              This cannot be undone.
            </p>
          </ConfirmAction>
        )}
      </div>
    </div>
  );
}
