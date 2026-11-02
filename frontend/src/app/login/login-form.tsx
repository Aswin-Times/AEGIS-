"use client";

import { useActionState } from "react";
import { signIn } from "./actions";

const INPUT = "mt-1 w-full rounded border border-line bg-surface px-2 py-1.5";

export function LoginForm() {
  const [state, action, pending] = useActionState(signIn, {});
  return (
    <form action={action} className="space-y-3">
      <label className="block">
        Organization
        <input
          name="tenant_slug"
          required
          autoComplete="organization"
          defaultValue={state.tenantSlug}
          className={INPUT}
        />
      </label>
      <label className="block">
        Email
        <input
          name="email"
          type="email"
          required
          autoComplete="username"
          defaultValue={state.email}
          className={INPUT}
        />
      </label>
      <label className="block">
        Password
        <input
          name="password"
          type="password"
          required
          autoComplete="current-password"
          className={INPUT}
        />
      </label>
      {state.error && (
        <p role="alert" className="text-sm text-deny">
          {state.error}
        </p>
      )}
      <button
        type="submit"
        disabled={pending}
        className="w-full rounded bg-accent px-3 py-1.5 font-medium text-accent-ink disabled:opacity-60"
      >
        {pending ? "Signing in" : "Sign in"}
      </button>
    </form>
  );
}
