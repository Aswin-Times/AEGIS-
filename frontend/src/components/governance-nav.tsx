"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const ITEMS = [
  { href: "/governance", label: "Overview", exact: true },
  { href: "/governance/assets", label: "Inventory", exact: false },
];

export function GovernanceNav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Governance" className="mb-4 flex gap-1 overflow-x-auto border-b border-line">
      {ITEMS.map(({ href, label, exact }) => {
        const active = exact
          ? pathname === href
          : pathname === href || pathname.startsWith(`${href}/`);
        return (
          <Link
            key={href}
            href={href}
            aria-current={active ? "page" : undefined}
            className={`whitespace-nowrap border-b-2 px-3 py-1.5 ${
              active ? "border-accent font-medium" : "border-transparent text-muted hover:text-ink"
            }`}
          >
            {label}
          </Link>
        );
      })}
    </nav>
  );
}
