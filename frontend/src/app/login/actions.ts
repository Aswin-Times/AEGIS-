"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { api, ApiError, SESSION_COOKIE } from "@/lib/api";

// The form resets after each submission, so the fields worth keeping come back in the state.
export type SignInState = { error?: string; tenantSlug?: string; email?: string };

export async function signIn(_: SignInState, form: FormData): Promise<SignInState> {
  const tenantSlug = String(form.get("tenant_slug") ?? "");
  const email = String(form.get("email") ?? "");
  let result: { access_token: string; expires_in: number };
  try {
    result = await api("/auth/login", {
      method: "POST",
      authenticated: false,
      body: { tenant_slug: tenantSlug, email, password: String(form.get("password") ?? "") },
    });
  } catch (error) {
    if (error instanceof ApiError && error.status < 500) {
      return {
        error: "That sign-in did not work. Check the details and try again.",
        tenantSlug,
        email,
      };
    }
    return { error: "AEGIS is not reachable right now. Try again shortly.", tenantSlug, email };
  }

  (await cookies()).set(SESSION_COOKIE, result.access_token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: result.expires_in,
  });
  redirect("/overview");
}

export async function signOut(): Promise<void> {
  (await cookies()).delete(SESSION_COOKIE);
  redirect("/login");
}
