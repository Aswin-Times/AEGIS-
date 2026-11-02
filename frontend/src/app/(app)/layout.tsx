import { LogOut, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { Sidebar } from "@/components/sidebar";
import { signOut } from "@/app/login/actions";
import { api } from "@/lib/api";
import type { Me } from "@/lib/types";

export default async function AppLayout({ children }: { children: ReactNode }) {
  const me = await api<Me>("/auth/me");
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <aside className="shrink-0 border-b border-line bg-surface md:w-52 md:border-b-0 md:border-r">
        <div className="flex items-center gap-2 px-4 py-3 font-semibold">
          <ShieldCheck aria-hidden size={18} className="text-accent" />
          AEGIS
        </div>
        <Sidebar />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center justify-end gap-3 border-b border-line bg-surface px-4 py-2 text-xs text-muted">
          <span>
            {me.email} ({me.role})
          </span>
          <form action={signOut}>
            <button type="submit" className="flex items-center gap-1 hover:text-ink">
              <LogOut aria-hidden size={14} />
              Sign out
            </button>
          </form>
        </div>
        <main className="min-w-0 flex-1 p-4">{children}</main>
      </div>
    </div>
  );
}
