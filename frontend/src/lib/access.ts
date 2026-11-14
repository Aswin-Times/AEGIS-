import "server-only";

import { allPages } from "@/lib/all-pages";
import { ApiError, api } from "@/lib/api";
import { shortId } from "@/lib/format";
import type { Person } from "@/lib/governance-types";
import type { Me, Page } from "@/lib/types";

/**
 * Who the signed-in user is and who holds governance_reviewer, as the API reports it. Showing a
 * control from this is a convenience only: every action is authorized again by the API.
 * Only admins and reviewers may list people, so for anyone else the list is empty and the user is
 * not a holder.
 */
export async function loadAccess() {
  const me = await api<Me>("/auth/me");
  let people: Person[] = [];
  try {
    people = (await allPages<Page<Person>>("/governance/people")).items;
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 403)) throw error;
  }
  const emails = new Map(people.map((person) => [person.id, person.email]));
  return {
    me,
    admin: me.role === "admin",
    people,
    holders: people.filter((person) => person.reviewer_grant_id !== null),
    holder: people.some((person) => person.id === me.id && person.reviewer_grant_id !== null),
    /** An email where this account may see people, otherwise a short id. */
    label: (id: string | null | undefined) =>
      id ? (emails.get(id) ?? `User ${shortId(id)}`) : "None",
  };
}
