import type { ReactNode } from "react";
import { GovernanceNav } from "@/components/governance-nav";

export default function GovernanceLayout({ children }: { children: ReactNode }) {
  return (
    <>
      <GovernanceNav />
      {children}
    </>
  );
}
