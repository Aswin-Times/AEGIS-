import { expect, type Page, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";

// Full-stack tests: a real agent key, the real gateway, and the dashboard in a real browser.
const API = `${process.env.AEGIS_E2E_API_URL ?? "http://127.0.0.1:8000"}/api/v1`;
const demo = JSON.parse(
  readFileSync(path.join(__dirname, "../../backend/.dev/demo-credentials.json"), "utf-8"),
) as { tenant: string; password: string };

const email = (role: string) => `${role}@synthetic.example.test`;

async function adminHeaders() {
  const response = await fetch(`${API}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      tenant_slug: demo.tenant,
      email: email("admin"),
      password: demo.password,
    }),
  });
  expect(response.status).toBe(200);
  const { access_token: token } = (await response.json()) as { access_token: string };
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

async function demoAgent() {
  const headers = await adminHeaders();
  const agents = await (await fetch(`${API}/agents`, { headers })).json();
  const agent = agents.items.find(
    (item: { name: string }) => item.name === "synthetic-research-agent",
  );
  const credential = await (
    await fetch(`${API}/agents/${agent.id}/credentials`, {
      method: "POST",
      headers,
      body: "{}",
    })
  ).json();
  const resources = await (await fetch(`${API}/resources?limit=100`, { headers })).json();
  const resource = (name: string) =>
    resources.items.find((item: { name: string }) => item.name === name).id as string;
  const agentHeaders = {
    Authorization: `Bearer ${credential.key}`,
    "Content-Type": "application/json",
  };
  return {
    id: agent.id as string,
    resource,
    headers: agentHeaders,
    adminHeaders: headers,
    act: async (tool: string, resourceId: string | null, params: object = {}) => {
      const response = await fetch(`${API}/gateway/actions`, {
        method: "POST",
        headers: agentHeaders,
        body: JSON.stringify({
          idempotency_key: randomUUID(),
          tool,
          resource_id: resourceId,
          params,
        }),
      });
      expect(response.status).toBe(200);
      return response.json();
    },
    execute: (requestId: string) =>
      fetch(`${API}/gateway/actions/${requestId}/execute`, {
        method: "POST",
        headers: agentHeaders,
      }),
  };
}

async function signIn(page: Page, role: string) {
  await page.goto("/login");
  await page.getByLabel("Organization").fill(demo.tenant);
  await page.getByLabel("Email").fill(email(role));
  await page.getByLabel("Password").fill(demo.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/overview$/);
}

test("signed-out visitors are sent to sign in", async ({ page }) => {
  await page.goto("/audit");
  await expect(page).toHaveURL(/\/login$/);
});

test("a failed sign-in is generic and keeps the non-secret fields", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Organization").fill(demo.tenant);
  await page.getByLabel("Email").fill(email("reviewer"));
  await page.getByLabel("Password").fill("not-the-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("That sign-in did not work")).toBeVisible();
  await expect(page.getByLabel("Organization")).toHaveValue(demo.tenant);
  await expect(page.getByLabel("Email")).toHaveValue(email("reviewer"));
  await expect(page.getByLabel("Password")).toHaveValue("");
});

test("the session cookie cannot be read by page scripts", async ({ page, context }) => {
  await signIn(page, "viewer");
  const cookie = (await context.cookies()).find((item) => item.name === "aegis_session");
  expect(cookie?.httpOnly).toBe(true);
  expect(cookie?.sameSite).toBe("Lax");
  expect(await page.evaluate(() => document.cookie)).not.toContain("aegis_session");
});

test("the overview shows counts from stored records", async ({ page }) => {
  const headers = await adminHeaders();
  const overview = await (await fetch(`${API}/overview`, { headers })).json();
  await signIn(page, "viewer");
  const denied = page.getByRole("link", { name: /^Denied/ });
  await expect(denied).toContainText(String(overview.decisions.DENY));
  await expect(page.getByRole("link", { name: /^Audit events/ })).toBeVisible();
});

test("a denied action shows evidence that the tool did not run", async ({ page }) => {
  const agent = await demoAgent();
  const denied = await agent.act("lookup_customer", agent.resource("Synthetic Salary Table"));
  expect(denied.outcome).toBe("DENY");
  expect(denied.reason_code).toBe("TOOL_NOT_GRANTED");
  expect(denied.execution).toBeNull();

  await signIn(page, "viewer");
  await page.goto("/decisions?outcome=DENY");
  await expect(page.getByRole("cell", { name: "Tool did not run" }).first()).toBeVisible();

  await page.goto(`/decisions/${denied.decision_id}`);
  await expect(page.getByText("The tool did not run. No execution record exists")).toBeVisible();
  await expect(page.getByText("TOOL_NOT_GRANTED", { exact: true })).toBeVisible();
  await expect(page.getByText(denied.request_id)).toBeVisible();
});

test("a held action runs only after a reviewer approves it, and only once", async ({ page }) => {
  const agent = await demoAgent();
  const body = `Synthetic message ${randomUUID()}`;
  const held = await agent.act("send_message", agent.resource("Synthetic Partner Inbox"), { body });
  expect(held.outcome).toBe("REQUIRE_APPROVAL");
  expect(held.execution).toBeNull();
  expect((await agent.execute(held.request_id)).status).toBe(409);

  await signIn(page, "reviewer");
  await page.goto("/approvals?status=PENDING");
  const row = page.getByRole("row").filter({ hasText: body });
  await row.getByRole("button", { name: /^Approve/ }).click();

  const dialog = page.getByRole("dialog", { name: "Approve this exact action?" });
  await expect(dialog).toContainText(body);
  await expect(dialog).toContainText("Action hash");
  await dialog.getByRole("button", { name: "Approve action" }).click();
  await expect(page.getByRole("row").filter({ hasText: body })).toHaveCount(0);

  const executed = await agent.execute(held.request_id);
  expect(executed.status).toBe(200);
  const result = await executed.json();
  expect(result.execution.status).toBe("SUCCEEDED");
  expect(result.execution.result.simulated).toBe(true);
  expect((await agent.execute(held.request_id)).status).toBe(409);

  await page.goto("/events");
  await expect(page.getByRole("heading", { name: "Security Events" })).toBeVisible();
  await page.goto(`/decisions/${held.decision_id}`);
  await expect(page.getByText("An execution record exists for this request")).toBeVisible();
});

test("a rejected action never runs", async ({ page }) => {
  const agent = await demoAgent();
  const body = `Synthetic message ${randomUUID()}`;
  const held = await agent.act("send_message", agent.resource("Synthetic Partner Inbox"), { body });

  await signIn(page, "reviewer");
  await page.goto("/approvals?status=PENDING");
  await page
    .getByRole("row")
    .filter({ hasText: body })
    .getByRole("button", { name: /^Reject/ })
    .click();
  await page
    .getByRole("dialog", { name: "Reject this action?" })
    .getByRole("button", { name: "Reject action" })
    .click();
  await expect(page.getByRole("row").filter({ hasText: body })).toHaveCount(0);

  expect((await agent.execute(held.request_id)).status).toBe(409);
});

test("cancelling the confirmation changes nothing", async ({ page }) => {
  const agent = await demoAgent();
  const body = `Synthetic message ${randomUUID()}`;
  const held = await agent.act("send_message", agent.resource("Synthetic Partner Inbox"), { body });

  await signIn(page, "reviewer");
  await page.goto("/approvals?status=PENDING");
  const row = page.getByRole("row").filter({ hasText: body });
  await row.getByRole("button", { name: /^Approve/ }).click();
  await page
    .getByRole("dialog", { name: "Approve this exact action?" })
    .getByRole("button", { name: "Cancel" })
    .click();

  const approval = await (
    await fetch(`${API}/approvals/${held.approval_id}`, { headers: agent.adminHeaders })
  ).json();
  expect(approval.status).toBe("PENDING");
});

test("a viewer gets no decision or management controls", async ({ page }) => {
  const agent = await demoAgent();
  const body = `Synthetic message ${randomUUID()}`;
  await agent.act("send_message", agent.resource("Synthetic Partner Inbox"), { body });

  await signIn(page, "viewer");
  await page.goto("/approvals?status=PENDING");
  const row = page.getByRole("row").filter({ hasText: body });
  await expect(row).toContainText("Awaiting a reviewer");
  await expect(row.getByRole("button")).toHaveCount(0);

  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: "Audit Records" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Verify chain" })).toHaveCount(0);

  await page.goto("/agents");
  await expect(page.getByRole("heading", { name: "Agent Registry" })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Disable/ })).toHaveCount(0);
});

test("disabling an agent from the dashboard stops its actions", async ({ page }) => {
  const agent = await demoAgent();
  await signIn(page, "admin");
  try {
    await page.goto("/agents");
    await page.getByRole("button", { name: "Disable synthetic-research-agent" }).click();
    await page
      .getByRole("dialog", { name: "Disable synthetic-research-agent?" })
      .getByRole("button", { name: "Disable agent" })
      .click();
    await expect(
      page.getByRole("button", { name: "Enable synthetic-research-agent" }),
    ).toBeVisible();

    const denied = await agent.act("calculate", null, { operator: "add", a: 1, b: 2 });
    expect(denied.reason_code).toBe("AGENT_DISABLED");
    expect(denied.execution).toBeNull();
  } finally {
    await fetch(`${API}/agents/${agent.id}/status`, {
      method: "POST",
      headers: agent.adminHeaders,
      body: JSON.stringify({ status: "active" }),
    });
  }
});

test("audit verification reports on the real chain", async ({ page }) => {
  await signIn(page, "reviewer");
  await page.goto("/audit");
  await page.getByRole("button", { name: "Verify chain" }).click();
  await expect(page.getByRole("status")).toContainText(/Chain intact: \d+ events checked/);
  await expect(page.getByRole("row").nth(1)).toBeVisible();
});

test("the policies page shows the active version and its rules", async ({ page }) => {
  await signIn(page, "viewer");
  await page.goto("/policies");
  await expect(page.getByText("Active", { exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "hold-outbound" })).toBeVisible();
});

test("assets are labeled synthetic", async ({ page }) => {
  await signIn(page, "viewer");
  await page.goto("/assets");
  await expect(page.getByText("Synthetic", { exact: true }).first()).toBeVisible();
});

test("the layout works at phone width with no horizontal page scroll", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await signIn(page, "viewer");
  for (const path of [
    "/overview",
    "/incidents",
    "/events",
    "/decisions",
    "/approvals",
    "/audit",
    "/agents",
    "/policies",
  ]) {
    await page.goto(path);
    await expect(page.locator("main").first()).toBeVisible();
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow, path).toBeLessThanOrEqual(0);
  }
});
