import "server-only";

import { api } from "@/lib/api";
import type { Page } from "@/lib/types";

/** Every page of a list, 100 at a time. A page that stops at the first 100 would hide the rest. */
export async function allPages<P extends Page<unknown>>(path: string): Promise<P> {
  const first = await api<P>(`${path}${path.includes("?") ? "&" : "?"}limit=100`);
  const items = [...first.items];
  while (items.length < first.total && items.length % 100 === 0) {
    const more = await api<P>(
      `${path}${path.includes("?") ? "&" : "?"}limit=100&offset=${items.length}`,
    );
    if (more.items.length === 0) break;
    items.push(...more.items);
  }
  return { ...first, items };
}
