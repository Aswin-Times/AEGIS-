import { AlertTriangle } from "lucide-react";

/** A refusal or failure from the API, shown in place of the records that could not be loaded. */
export function LoadFailure({ what, message }: { what: string; message: string }) {
  return (
    <div role="alert" className="rounded-md border border-line bg-surface p-6">
      <p className="flex items-center gap-2 font-medium">
        <AlertTriangle aria-hidden size={16} className="text-deny" />
        {what} could not be loaded
      </p>
      <p className="text-muted">{message}</p>
    </div>
  );
}
