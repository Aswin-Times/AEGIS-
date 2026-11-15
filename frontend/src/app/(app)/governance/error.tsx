"use client";

import { AlertTriangle } from "lucide-react";

// Generic on purpose: production error boundaries receive a digest, not the ApiError. Pages render
// <PermissionDenied /> themselves when the API answers 403.
export default function GovernanceError({ reset }: { error: Error; reset: () => void }) {
  return (
    <div role="alert" className="rounded-md border border-line bg-surface p-6">
      <p className="flex items-center gap-2 font-medium">
        <AlertTriangle aria-hidden size={16} className="text-deny" />
        Governance records could not be loaded
      </p>
      <p className="mb-3 text-muted">
        The AEGIS API did not return them. Nothing is shown here rather than showing data that
        may be stale.
      </p>
      <button
        type="button"
        onClick={reset}
        className="rounded border border-line px-3 py-1.5 hover:bg-subtle"
      >
        Try again
      </button>
    </div>
  );
}
