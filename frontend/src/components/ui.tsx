import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Circle,
  Clock,
  FlaskConical,
  type LucideIcon,
  XCircle,
} from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

type Tone = "allow" | "deny" | "hold" | "neutral";

const TONE_CLASSES: Record<Tone, string> = {
  allow: "bg-allow-bg text-allow",
  deny: "bg-deny-bg text-deny",
  hold: "bg-hold-bg text-hold",
  neutral: "bg-neutral-bg text-neutral",
};

const STATUS: Record<string, { tone: Tone; icon: LucideIcon; label: string }> = {
  ALLOW: { tone: "allow", icon: CheckCircle2, label: "Allowed" },
  DENY: { tone: "deny", icon: Ban, label: "Denied" },
  REQUIRE_APPROVAL: { tone: "hold", icon: Clock, label: "Held for approval" },
  PENDING: { tone: "hold", icon: Clock, label: "Pending" },
  APPROVED: { tone: "allow", icon: CheckCircle2, label: "Approved" },
  REJECTED: { tone: "deny", icon: XCircle, label: "Rejected" },
  EXECUTED: { tone: "neutral", icon: CheckCircle2, label: "Executed" },
  CANCELLED: { tone: "neutral", icon: XCircle, label: "Cancelled" },
  STARTED: { tone: "hold", icon: Clock, label: "Started, no outcome" },
  SUCCEEDED: { tone: "allow", icon: CheckCircle2, label: "Succeeded" },
  FAILED: { tone: "deny", icon: XCircle, label: "Failed" },
  active: { tone: "allow", icon: CheckCircle2, label: "Active" },
  disabled: { tone: "deny", icon: Ban, label: "Disabled" },
  low: { tone: "neutral", icon: Circle, label: "Low" },
  medium: { tone: "hold", icon: AlertTriangle, label: "Medium" },
  high: { tone: "deny", icon: AlertTriangle, label: "High" },
  critical: { tone: "deny", icon: AlertTriangle, label: "Critical" },
  allow: { tone: "allow", icon: CheckCircle2, label: "Allow" },
  deny: { tone: "deny", icon: Ban, label: "Deny" },
  require_approval: { tone: "hold", icon: Clock, label: "Require approval" },
};

/** Status always pairs color with an icon and a word, so it never depends on color alone. */
export function StatusBadge({ value }: { value: string }) {
  const status = STATUS[value] ?? { tone: "neutral" as Tone, icon: Circle, label: value };
  const Icon = status.icon;
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-medium ${TONE_CLASSES[status.tone]}`}
    >
      <Icon aria-hidden size={12} />
      {status.label}
    </span>
  );
}

export function SyntheticBadge() {
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap rounded border border-line px-1.5 py-0.5 text-xs text-muted">
      <FlaskConical aria-hidden size={12} />
      Synthetic
    </span>
  );
}

export function PageHeader({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children?: ReactNode;
}) {
  return (
    <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-lg font-semibold">{title}</h1>
        {description && <p className="max-w-3xl text-muted">{description}</p>}
      </div>
      {children}
    </header>
  );
}

export function Panel({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="rounded-md border border-line bg-surface">
      {title && (
        <h2 className="border-b border-line px-3 py-2 text-sm font-semibold">{title}</h2>
      )}
      {children}
    </section>
  );
}

export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left">
        <thead>
          <tr className="border-b border-line text-xs text-muted">
            {head.map((label) => (
              <th key={label} scope="col" className="whitespace-nowrap px-3 py-2 font-medium">
                {label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-line">{children}</tbody>
      </table>
    </div>
  );
}

export function Cell({ children, mono }: { children: ReactNode; mono?: boolean }) {
  return (
    <td className={`px-3 py-2 align-top ${mono ? "whitespace-nowrap font-mono text-xs" : ""}`}>
      {children}
    </td>
  );
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="px-3 py-10 text-center">
      <p className="font-medium">{title}</p>
      <p className="text-muted">{detail}</p>
    </div>
  );
}

export function Pagination({
  basePath,
  total,
  limit,
  offset,
  params = {},
}: {
  basePath: string;
  total: number;
  limit: number;
  offset: number;
  params?: Record<string, string | undefined>;
}) {
  const href = (next: number) => {
    const search = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) if (value) search.set(key, value);
    if (next > 0) search.set("offset", String(next));
    const text = search.toString();
    return text ? `${basePath}?${text}` : basePath;
  };
  const end = Math.min(offset + limit, total);
  const linkClass = "rounded border border-line px-2 py-1 hover:bg-subtle";
  return (
    <nav
      aria-label="Pagination"
      className="flex items-center justify-between border-t border-line px-3 py-2 text-xs text-muted"
    >
      <span>{total === 0 ? "No records" : `${offset + 1} to ${end} of ${total}`}</span>
      <span className="flex gap-2">
        {offset > 0 && (
          <Link className={linkClass} href={href(Math.max(0, offset - limit))}>
            Previous
          </Link>
        )}
        {end < total && (
          <Link className={linkClass} href={href(offset + limit)}>
            Next
          </Link>
        )}
      </span>
    </nav>
  );
}

export function FilterLinks({
  basePath,
  name,
  current,
  options,
}: {
  basePath: string;
  name: string;
  current: string | undefined;
  options: { value: string | undefined; label: string }[];
}) {
  return (
    <nav aria-label="Filter" className="mb-3 flex flex-wrap gap-1">
      {options.map((option) => {
        const active = current === option.value;
        return (
          <Link
            key={option.label}
            href={option.value ? `${basePath}?${name}=${option.value}` : basePath}
            aria-current={active ? "true" : undefined}
            className={`rounded border px-2 py-1 text-xs ${
              active
                ? "border-accent bg-accent text-accent-ink"
                : "border-line bg-surface hover:bg-subtle"
            }`}
          >
            {option.label}
          </Link>
        );
      })}
    </nav>
  );
}
