import { expect, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

export const API = `${process.env.AEGIS_E2E_API_URL ?? "http://127.0.0.1:8000"}/api/v1`;

const demo = JSON.parse(
  readFileSync(path.join(__dirname, "../../backend/.dev/demo-credentials.json"), "utf-8"),
) as { tenant: string; password: string };

export const email = (role: string) => `${role}@synthetic.example.test`;

export async function headersFor(role: string) {
  const response = await fetch(`${API}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      tenant_slug: demo.tenant,
      email: email(role),
      password: demo.password,
    }),
  });
  expect(response.status).toBe(200);
  const { access_token: token } = (await response.json()) as { access_token: string };
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

export const adminHeaders = () => headersFor("admin");

export async function signIn(page: Page, role: string) {
  await page.goto("/login");
  await page.getByLabel("Organization").fill(demo.tenant);
  await page.getByLabel("Email").fill(email(role));
  await page.getByLabel("Password").fill(demo.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/overview$/);
}

/** A new synthetic agent, so each test starts with no incidents of its own. */
export async function newRestrictedAgent() {
  const headers = await adminHeaders();
  const post = async (url: string, body: object) => {
    const response = await fetch(`${API}${url}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    expect(response.status).toBeLessThan(300);
    return response.json();
  };
  const assets = await (await fetch(`${API}/assets`, { headers })).json();
  const name = `synthetic-e2e-${randomUUID().slice(0, 8)}`;
  const agent = await post("/agents", {
    asset_id: assets.items[0].id,
    name,
    owner: "Synthetic E2E",
  });
  const credential = await post(`/agents/${agent.id}/credentials`, {});
  const agentHeaders = {
    Authorization: `Bearer ${credential.key}`,
    "Content-Type": "application/json",
  };
  return {
    id: agent.id as string,
    name,
    headers,
    act: async (tool: string) => {
      const response = await fetch(`${API}/gateway/actions`, {
        method: "POST",
        headers: agentHeaders,
        body: JSON.stringify({
          idempotency_key: randomUUID(),
          tool,
          resource_id: null,
          params: {},
        }),
      });
      expect(response.status).toBe(200);
      return response.json();
    },
  };
}

/** Correlation runs in the API's background worker, so its result is awaited, not assumed. */
export async function waitForIncident(agentId: string, headers: Record<string, string>) {
  let found: { id: string; version: number } | undefined;
  await expect
    .poll(
      async () => {
        const page = await (
          await fetch(`${API}/incidents?rule_key=repeated_unauthorized_tools&limit=100`, {
            headers,
          })
        ).json();
        found = page.items.find((item: { agent_id: string }) => item.agent_id === agentId);
        return found !== undefined;
      },
      { timeout: 20_000, intervals: [250] },
    )
    .toBe(true);
  return found as { id: string; version: number };
}

export type Tenant = {
  slug: string;
  headers: (user: string) => Promise<Record<string, string>>;
  signIn: (page: Page, user: string) => Promise<void>;
};

/**
 * A synthetic tenant of its own with admin, admin2, reviewer, reviewer2, and viewer, so approval
 * tests never change the demo tenant. Tenants cannot be deleted, which is why it is created once
 * per spec file.
 */
export function newGovernanceTenant(): Tenant {
  const slug = `synthetic-approvals-${randomUUID().slice(0, 8)}`;
  const password = randomUUID();
  const python =
    process.platform === "win32"
      ? path.join(__dirname, "../../backend/.venv/Scripts/python.exe")
      : path.join(__dirname, "../../backend/.venv/bin/python");
  // The arguments hold the new password, so they are kept out of any error thrown here.
  try {
    execFileSync(python, [path.join(__dirname, "provision_governance_tenant.py"), slug, password], {
      stdio: "pipe",
    });
  } catch (error) {
    const stderr = String((error as { stderr?: Buffer }).stderr ?? "").trim();
    throw new Error(`Could not provision the approval tenant. ${stderr}`);
  }
  return {
    slug,
    headers: async (user) => {
      const response = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant_slug: slug, email: email(user), password }),
      });
      expect(response.status).toBe(200);
      const { access_token: token } = (await response.json()) as { access_token: string };
      return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
    },
    signIn: async (page, user) => {
      await page.context().clearCookies();
      await page.goto("/login");
      await page.getByLabel("Organization").fill(slug);
      await page.getByLabel("Email").fill(email(user));
      await page.getByLabel("Password").fill(password);
      await page.getByRole("button", { name: "Sign in" }).click();
      await expect(page).toHaveURL(/\/overview$/);
    },
  };
}
