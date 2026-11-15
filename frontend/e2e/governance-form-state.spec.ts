import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { API, newGovernanceTenant, type Tenant } from "./helpers";

// React resets a form after its action. These tests check that a refused submission keeps what a
// person chose, so sending it again cannot record something else, and that a form shows what is
// stored after a success. A synthetic tenant of its own keeps the demo tenant as it was.

type Headers = Record<string, string>;
let tenant: Tenant;
const tokens: Record<string, Headers> = {};
const ids: Record<string, string> = {};

async function call(method: string, path: string, user: string, body?: object) {
  return fetch(`${API}${path}`, {
    method,
    headers: tokens[user],
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function get<T = Record<string, unknown>>(path: string, user = "admin"): Promise<T> {
  const response = await call("GET", path, user);
  expect(response.status, await response.clone().text()).toBe(200);
  return response.json();
}

async function post<T = Record<string, unknown>>(path: string, body: object, user = "admin") {
  const response = await call("POST", path, user, body);
  expect(response.status, await response.clone().text()).toBeLessThan(300);
  return (await response.json()) as T;
}

test.beforeAll(async () => {
  tenant = newGovernanceTenant();
  for (const user of ["admin", "admin2", "reviewer"]) tokens[user] = await tenant.headers(user);
  const people = await get<{ items: { id: string; email: string }[] }>("/governance/people?limit=100");
  for (const user of ["admin", "admin2", "reviewer"]) {
    ids[user] = people.items.find((item) => item.email.startsWith(`${user}@`))!.id;
  }
  await post("/governance/role-grants", { user_id: ids.reviewer }, "admin");
  await post("/governance/role-grants", { user_id: ids.admin2 }, "admin");
});

async function newAsset() {
  return post<{ id: string }>("/assets", {
    name: `synthetic-form-state-${randomUUID().slice(0, 8)}`,
    owner: "Synthetic E2E",
    risk_classification: "low",
    intended_use: "Synthetic form state e2e",
    is_synthetic: true,
  });
}

/** A NIST control with one unverified inline evidence item linked to it, submitted by admin. */
async function controlWithEvidence() {
  const frameworks = await get<{ items: { id: string; key: string }[] }>("/governance/frameworks");
  const nist = frameworks.items.find((item) => item.key.startsWith("nist"))!;
  const controls = await get<{ items: { id: string; identifier: string }[] }>(
    `/governance/controls?framework_id=${nist.id}&limit=5`,
  );
  const control = controls.items[0]!;
  const asset = await newAsset();
  const description = `Synthetic form-state evidence ${randomUUID().slice(0, 8)}`;
  const evidence = await post<{ id: string }>("/governance/evidence", {
    asset_id: asset.id,
    category: "architecture_documentation",
    description,
    source: { source_type: "inline", content_text: `Synthetic text ${description}` },
    control_ids: [control.id],
  });
  return { control, evidence: { id: evidence.id, description } };
}

test("a refused verification keeps the chosen outcome, so a rejection stays a rejection", async ({
  page,
}) => {
  const { control, evidence } = await controlWithEvidence();
  await tenant.signIn(page, "reviewer");
  await page.goto(`/governance/compliance/controls/${control.id}`);
  await page.getByRole("button", { name: `Verify evidence: ${evidence.description}` }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("radio", { name: "Rejected" }).check();
  // No note, so the page refuses and nothing is sent.
  await dialog.getByRole("button", { name: "Record verification" }).click();
  await expect(dialog.getByLabel("Note")).toHaveAttribute("aria-invalid", "true");
  await expect(dialog.getByRole("radio", { name: "Rejected" })).toBeChecked();
  await expect(dialog.getByRole("radio", { name: "Verified" })).not.toBeChecked();

  await dialog.getByLabel("Note").fill("Synthetic rejection after a refused attempt");
  await dialog.getByRole("button", { name: "Record verification" }).click();
  await expect(dialog).toBeHidden();
  const stored = await get<{ current_verification: string; latest_verification: { outcome: string } }>(
    `/governance/evidence/${evidence.id}`,
  );
  expect(stored.latest_verification.outcome).toBe("REJECTED");
  expect(stored.current_verification).toBe("REJECTED");
});

test("a control assessment the API refuses keeps the status, note, and cited evidence", async ({
  page,
}) => {
  const { control, evidence } = await controlWithEvidence();
  await tenant.signIn(page, "reviewer");
  await page.goto(`/governance/compliance/controls/${control.id}`);
  await page.getByRole("button", { name: `Assess control ${control.identifier}` }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Status").selectOption("IMPLEMENTED");
  await dialog.getByLabel("Note").fill("Synthetic claim that is refused");
  await dialog.getByRole("checkbox", { name: evidence.description }).check();
  await dialog.getByRole("button", { name: "Record assessment" }).click();
  // The evidence is unverified, so the API refuses the claim.
  await expect(dialog.getByRole("alert")).toContainText("EVIDENCE_REQUIRED");
  await expect(dialog.getByLabel("Status")).toHaveValue("IMPLEMENTED");
  await expect(dialog.getByLabel("Note")).toHaveValue("Synthetic claim that is refused");
  await expect(dialog.getByRole("checkbox", { name: evidence.description })).toBeChecked();
});

test("a refused mode change keeps the reason that was typed", async ({ page }) => {
  const found = (await get<{ enforcement_mode: string }>("/governance/enforcement")).enforcement_mode;
  try {
    if (found !== "observe") await post("/governance/enforcement", { mode: "observe", reason: "Synthetic reset" });
    await tenant.signIn(page, "admin");
    await page.goto("/governance/enforcement");
    await page.getByRole("button", { name: "Switch to enforce mode" }).click();
    // Another administrator switches first, so this request is refused with a conflict.
    await post("/governance/enforcement", { mode: "enforce", reason: "Synthetic concurrent switch" }, "admin2");
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Reason").fill("Synthetic reason kept after a refusal");
    await dialog.getByRole("button", { name: "Confirm switch to enforce" }).click();
    await expect(dialog.getByRole("alert")).toContainText("ENFORCEMENT_MODE_UNCHANGED");
    await expect(dialog.getByLabel("Reason")).toHaveValue("Synthetic reason kept after a refusal");
  } finally {
    const now = (await get<{ enforcement_mode: string }>("/governance/enforcement")).enforcement_mode;
    if (now !== found) await post("/governance/enforcement", { mode: found, reason: "Synthetic restore" });
  }
});

test("after assigning, the reviewer picker shows the person now assigned", async ({ page }) => {
  const asset = await newAsset();
  await post(`/governance/assets/${asset.id}/profile`, {
    asset_type: "ai_application",
    data_categories: ["public"],
    external_exposure: "none",
    autonomy_level: "advisory",
    human_oversight: "in_the_loop",
    declared_tool_access: [],
    impact_level: "negligible",
    deployment_environment: "development",
    third_party_reliance: "none",
  });
  await post(`/governance/assets/${asset.id}/assess`, {});
  const review = await post<{ id: string }>(`/governance/assets/${asset.id}/submit`, {
    reason: "Synthetic submission for assignment",
  });

  await tenant.signIn(page, "reviewer");
  await page.goto(`/governance/approvals/${review.id}`);
  const picker = page.getByLabel("Assign reviewer");
  await picker.selectOption({ label: "admin2@synthetic.example.test" });
  await page.getByRole("button", { name: "Assign reviewer" }).click();
  await expect(page.getByRole("status")).toContainText("Reviewer assigned");
  expect((await get<{ assigned_reviewer: string }>(`/governance/approvals/${review.id}`)).assigned_reviewer).toBe(
    ids.admin2,
  );
  await expect(picker).toHaveValue(ids.admin2!);
});
