import { Lock } from "lucide-react";

/** Rendered by pages that catch an ApiError with status 403, since error boundaries only get digests. */
export function PermissionDenied() {
  return (
    <div role="alert" className="rounded-md border border-line bg-surface p-6">
      <p className="flex items-center gap-2 font-medium">
        <Lock aria-hidden size={16} className="text-hold" />
        Your role cannot view this page
      </p>
      <p className="text-muted">
        The AEGIS API refused the request for your account. Nothing is shown here. An
        administrator can change your role or grant the permission this page needs.
      </p>
    </div>
  );
}
