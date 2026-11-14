import { expect, type Page, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { adminHeaders, API, signIn } from "./helpers";

type Overview = {
  total_assets: number;
  by_assessed_risk: Record<string, number>;
  unassessed: number;
  awaiting_approval: number;
  conditionally_approved: number;
  suspended: number;
  overdue_reviews: number;
  outstanding_findings: number;
  evidence_verified: number;
  evidence_total: number;
  enforcement_mode: string;
};

async function overviewFromApi(): Promise<Overview> {
  const response = await fetch(`${API}/governance/overview`, { headers: await adminHeaders() });
  expect(response.status).toBe(200);
  return response.json();
}

async function newAsset(prefix: string, risk: string) {
  const name = `${prefix}-${risk}`;
  const response = await fetch(`${API}/assets`, {
    method: "POST",
    headers: await adminHeaders(),
    body: JSON.stringify({
      name,
      owner: "Synthetic E2E",
      risk_classification: risk,
      intended_use: "Synthetic governance e2e check",
      is_synthetic: true,
    }),
  });
  expect(response.status).toBe(201);
  return { name, id: ((await response.json()) as { id: string }).id };
}

const tile = (page: Page, name: string) => page.getByRole("region", { name, exact: true });

test("overview shows counts from the API and the enforcement mode", async ({ page }) => {
  // An asset that exists for this test, so the total is not merely whatever was already there.
  await newAsset(`synthetic-e2e-${randomUUID().slice(0, 8)}`, "high");
  const overview = await overviewFromApi();

  await signIn(page, "reviewer");
  await page.goto("/governance");
  await expect(page.getByRole("heading", { name: "Governance Center" })).toBeVisible();

  const expected: Record<string, string> = {
    "AI assets": String(overview.total_assets),
    Unassessed: String(overview.unassessed),
    "Awaiting approval": String(overview.awaiting_approval),
    "Conditionally approved": String(overview.conditionally_approved),
    Suspended: String(overview.suspended),
    "Reviews owed past date": String(overview.overdue_reviews),
    "Outstanding findings": String(overview.outstanding_findings),
    "Evidence verified": `${overview.evidence_verified} of ${overview.evidence_total}`,
  };
  for (const [name, value] of Object.entries(expected)) {
    await expect(tile(page, name).locator("strong")).toHaveText(value);
  }
  for (const level of ["LOW", "MEDIUM", "HIGH", "CRITICAL"]) {
    const label = level.charAt(0) + level.slice(1).toLowerCase();
    await expect(tile(page, `Assessed risk: ${label}`).locator("strong")).toHaveText(
      String(overview.by_assessed_risk[level]),
    );
  }

  // The overdue tile says what it counts, since it can overlap the awaiting-approval tile.
  await expect(tile(page, "Reviews owed past date")).toContainText("past their review date");
  const mode = page.getByRole("region", { name: "Enforcement mode", exact: true });
  await expect(mode).toContainText(overview.enforcement_mode === "enforce" ? "Enforce" : "Observe");
});

test("overview empty state on a tenant with no assets", async ({ page }) => {
  const slug = `synthetic-empty-${randomUUID().slice(0, 8)}`;
  const password = randomUUID();
  execFileSync(
    path.join(__dirname, "../../backend/.venv/Scripts/python.exe"),
    [path.join(__dirname, "provision_tenant.py"), slug, "admin@synthetic.example.test", password],
    { stdio: "pipe" },
  );

  await page.goto("/login");
  await page.getByLabel("Organization").fill(slug);
  await page.getByLabel("Email").fill("admin@synthetic.example.test");
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/overview$/);

  await page.goto("/governance");
  await expect(page.getByText("No AI assets to govern")).toBeVisible();
  await expect(tile(page, "AI assets").locator("strong")).toHaveText("0");
  await page.goto("/governance/assets");
  await expect(page.getByText("No AI assets match")).toBeVisible();
});

test("inventory shows a new asset as not governed, with declared risk labeled declared", async ({
  page,
}) => {
  const prefix = `synthetic-e2e-${randomUUID().slice(0, 8)}`;
  const asset = await newAsset(prefix, "critical");

  await signIn(page, "reviewer");
  await page.goto("/governance");
  await page.getByRole("link", { name: "Inventory", exact: true }).click();
  await expect(page).toHaveURL(/\/governance\/assets$/);
  await page.getByLabel("Search").fill(prefix);
  await page.getByRole("button", { name: "Apply filters" }).click();

  const row = page.getByRole("row").filter({ hasText: asset.name });
  await expect(row).toContainText("Not governed");
  await expect(row).toContainText("Declared");
  await expect(row).toContainText("Critical");
  await expect(row).toContainText("Synthetic");
  // No assessment exists, so no assessed level is claimed.
  await expect(row).toContainText("Not assessed");
  await expect(row).not.toContainText("Assessed Critical");
  await expect(row).not.toContainText("Low");
});

test("inventory search and filters narrow the list", async ({ page }) => {
  const prefix = `synthetic-e2e-${randomUUID().slice(0, 8)}`;
  const high = await newAsset(prefix, "high");
  const low = await newAsset(prefix, "low");

  await signIn(page, "reviewer");
  await page.goto("/governance/assets");
  await page.getByLabel("Search").fill(prefix);
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByRole("row").filter({ hasText: high.name })).toHaveCount(1);
  await expect(page.getByRole("row").filter({ hasText: low.name })).toHaveCount(1);

  await page.getByLabel("Declared risk").selectOption("high");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page).toHaveURL(/declared_risk=high/);
  await expect(page.getByRole("row").filter({ hasText: high.name })).toHaveCount(1);
  await expect(page.getByRole("row").filter({ hasText: low.name })).toHaveCount(0);

  // Neither asset has a governance state, so a status filter excludes both.
  await page.getByLabel("Governance status").selectOption("APPROVED");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByText("No AI assets match")).toBeVisible();
});
