export function formatTime(value: string | null | undefined): string {
  if (!value) return "None";
  return new Date(value).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function shortId(value: string | null | undefined): string {
  return value ? value.slice(0, 8) : "None";
}

export function pageOffset(raw: string | undefined): number {
  const parsed = Number(raw ?? 0);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : 0;
}

export function humanize(code: string): string {
  const text = code.replaceAll("_", " ").toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}
