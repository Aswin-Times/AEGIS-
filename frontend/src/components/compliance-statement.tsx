import { Info } from "lucide-react";

/** The API's statement that a mapping is not a certification, word for word. */
export function ComplianceStatement({ text }: { text: string }) {
  return (
    <aside
      role="note"
      aria-label="No certification statement"
      className="mb-4 flex items-start gap-2 rounded-md border border-line bg-subtle p-3"
    >
      <Info aria-hidden size={16} className="mt-0.5 shrink-0" />
      <p>{text}</p>
    </aside>
  );
}
