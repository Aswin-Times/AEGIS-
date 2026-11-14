"use client";

import { ConfirmAction } from "@/components/confirm-action";
import { activateVersion, approveVersion, deactivateVersion } from "./actions";

/**
 * Controls follow the role the API reports, and the API refuses anyone else. The author of a
 * version still sees Approve: the API says why it will not count.
 */
export function VersionActions({
  policyId,
  versionId,
  name,
  version,
  approved,
  active,
  canApprove,
  canActivate,
}: {
  policyId: string;
  versionId: string;
  name: string;
  version: number;
  approved: boolean;
  active: boolean;
  canApprove: boolean;
  canActivate: boolean;
}) {
  const fields = { policy_id: policyId, version_id: versionId };
  const subject = `${name} version ${version}`;
  return (
    <div className="flex flex-wrap gap-1">
      {canApprove && !approved && (
        <ConfirmAction
          trigger="Approve"
          triggerLabel={`Approve ${subject}`}
          title={`Approve ${subject}?`}
          confirmLabel="Confirm approval"
          action={approveVersion}
          fields={fields}
        >
          <p>
            You are recorded as the approver, and the version can no longer be approved by anyone
            else. It does not apply until an administrator activates it. A version cannot be
            edited, and the person who created it cannot approve it.
          </p>
        </ConfirmAction>
      )}
      {canActivate && approved && !active && (
        <ConfirmAction
          trigger="Activate"
          triggerLabel={`Activate ${subject}`}
          title={`Activate ${subject}?`}
          confirmLabel="Confirm activation"
          action={activateVersion}
          fields={fields}
        >
          <p>
            Once active, this version applies to new submissions it covers. Activating it does
            not deactivate an older version: where both apply, the most restrictive requirement
            wins.
          </p>
        </ConfirmAction>
      )}
      {canActivate && active && (
        <ConfirmAction
          trigger="Deactivate"
          triggerLabel={`Deactivate ${subject}`}
          title={`Deactivate ${subject}?`}
          confirmLabel="Confirm deactivation"
          danger
          action={deactivateVersion}
          fields={fields}
        >
          <p>
            New submissions stop using this version. Reviews already open keep the requirements
            frozen when they were submitted. The version itself is not changed, and it can be
            activated again.
          </p>
        </ConfirmAction>
      )}
    </div>
  );
}
