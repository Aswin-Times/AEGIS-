export function Tile({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <section aria-label={label} className="rounded-md border border-line bg-surface p-3">
      <h3 className="text-xs text-muted">{label}</h3>
      <strong className="block text-2xl font-semibold">{value}</strong>
      {note && <p className="text-xs text-muted">{note}</p>}
    </section>
  );
}
