"use client";

import {
  Activity,
  Bot,
  Boxes,
  ClipboardCheck,
  FileLock2,
  Gavel,
  LayoutDashboard,
  ScrollText,
  Siren,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const ITEMS = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/assets", label: "AI Assets", icon: Boxes },
  { href: "/agents", label: "Agent Registry", icon: Bot },
  { href: "/policies", label: "Policies", icon: FileLock2 },
  { href: "/incidents", label: "Incidents", icon: Siren },
  { href: "/events", label: "Security Events", icon: Activity },
  { href: "/decisions", label: "Policy Decisions", icon: Gavel },
  { href: "/approvals", label: "Approval Queue", icon: ClipboardCheck },
  { href: "/audit", label: "Audit Records", icon: ScrollText },
];

export function Sidebar() {
  const pathname = usePathname();
  return (
    <nav aria-label="Main" className="flex gap-1 overflow-x-auto p-2 md:flex-col">
      {ITEMS.map(({ href, label, icon: Icon }) => {
        const active = pathname === href || pathname.startsWith(`${href}/`);
        return (
          <Link
            key={href}
            href={href}
            aria-current={active ? "page" : undefined}
            className={`flex items-center gap-2 whitespace-nowrap rounded px-2 py-1.5 ${
              active ? "bg-subtle font-medium" : "text-muted hover:bg-subtle hover:text-ink"
            }`}
          >
            <Icon aria-hidden size={16} />
            {label}
          </Link>
        );
      })}
    </nav>
  );
}
