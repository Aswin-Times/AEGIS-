import { Lock } from "lucide-react";
import type { ReactNode } from "react";

/**
 * Rendered by pages that catch an ApiError with status 403, since error boundaries only get digests.
 * A panel inside a readable page can say what it needs instead of using the page wording.
 */
export function PermissionDenied({
  title = "Your role cannot view this page",
  children,
}: {
  title?: string;
  children?: ReactNode;
}) {
  return (
    <div role="alert" className="rounded-md border border-line bg-surface p-6">
      <p className="flex items-center gap-2 font-medium">
        <Lock aria-hidden size={16} className="text-hold" />
        {title}
      </p>
      <p className="text-muted">
        {children ??
          "The AEGIS API refused the request for your account. Nothing is shown here. An administrator can change your role or grant the permission this page needs."}
      </p>
    </div>
  );
}
