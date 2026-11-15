import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export const SESSION_COOKIE = "aegis_session";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    // For a malformed request, the locations of the fields the API rejected.
    readonly fields: string[] = [],
  ) {
    super(message);
  }
}

function baseUrl(): string {
  return process.env.AEGIS_API_URL ?? "http://127.0.0.1:8000";
}

type Options = { method?: string; body?: unknown; authenticated?: boolean };

/** Server-side API call. The token stays in an HttpOnly cookie, out of reach of page scripts. */
export async function api<T>(path: string, options: Options = {}): Promise<T> {
  const { method = "GET", body, authenticated = true } = options;
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (authenticated) {
    const token = (await cookies()).get(SESSION_COOKIE)?.value;
    if (!token) redirect("/login");
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${baseUrl()}/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });

  if (!response.ok) {
    if (response.status === 401 && authenticated) redirect("/login");
    const payload = await response.json().catch(() => null);
    throw new ApiError(
      response.status,
      payload?.error?.code ?? "UNKNOWN_ERROR",
      payload?.error?.message ?? "The request could not be completed.",
      Array.isArray(payload?.error?.fields) ? payload.error.fields.map(String) : [],
    );
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

export function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}
