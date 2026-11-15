import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { API, newGovernanceTenant, type Tenant } from "./helpers";

// Asset page actions an administrator takes more than once or in sequence, in a synthetic tenant
// of its own so the demo tenant is left as it was.

type Headers = Record<string, string>;
let tenant: Tenant;
let admin: Headers;

test.beforeAll(async () => {
  tenant = newGovernanceTenant();
  admin = await tenant.headers("admin");
});

async function call(method: string, path: string, headers: Headers, body?: object) {
  return fetch(`${API}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function newAsset() {
  const name = `synthetic-asset-actions-${randomUUID().slice(0, 8)}`;
  const response = await call("POST", "/assets", admin, {
    name,
    owner: "Synthetic E2E",
    risk_classification: "low",
    intended_use: "Synthetic asset action e2e",
    is_synthetic: true,
  });
  expect(response.status).toBe(201);
  return { name, id: ((await response.json()) as { id: string }).id };
}

type Detail = {
  governance_status: string | null;
  profile: { version: number; profile: Record<string, unknown> } | null;
};

async function detailOf(id: string): Promise<Detail> {
  const response = await call("GET", `/governance/assets/${id}`, admin);
  expect(response.status).toBe(200);
  return response.json();
}

const LOW_PROFILE = {
  asset_type: "ai_application",
  data_categories: ["public"],
  external_exposure: "none",
  autonomy_level: "advisory",
  declared_tool_access: [],
  human_oversight: "in_the_loop",
  impact_level: "negligible",
  deployment_environment: "development",
  third_party_reliance: "none",
};

test("a second profile save from the same page keeps the choices saved by the first", async ({
  page,
}) => {
  const asset = await newAsset();
  await tenant.signIn(page, "admin");
  await page.goto(`/governance/assets/${asset.id}`);
  await page.getByLabel("Business owner").selectOption({ label: "admin2@synthetic.example.test" });
  await page.getByLabel("Asset type").selectOption("autonomous_agent");
  await page.getByLabel("Autonomy level").selectOption("bounded");
  await page.getByRole("checkbox", { name: "Internal", exact: true }).check();
  await page.getByLabel("Business purpose").fill("Synthetic first purpose");
  await page.getByRole("button", { name: "Save profile" }).click();
  await expect(page.getByRole("status")).toContainText("Profile saved as version 1");
  const first = (await detailOf(asset.id)).profile!.profile;

  // The form now shows what was saved, so changing one field changes only that field.
  await expect(page.getByLabel("Business owner")).toHaveValue(String(first.business_owner_id));
  await expect(page.getByLabel("Asset type")).toHaveValue("autonomous_agent");
  await expect(page.getByLabel("Autonomy level")).toHaveValue("bounded");
  await expect(page.getByRole("checkbox", { name: "Internal", exact: true })).toBeChecked();
  await page.getByLabel("Business purpose").fill("Synthetic second purpose");
  await page.getByRole("button", { name: "Save profile" }).click();
  await expect(page.getByRole("status")).toContainText("Profile saved as version 2");

  const second = (await detailOf(asset.id)).profile!;
  expect(second.version).toBe(2);
  expect(second.profile).toEqual({ ...first, business_purpose: "Synthetic second purpose" });
});

test("a refused profile save keeps every choice that was made", async ({ page }) => {
  const asset = await newAsset();
  await tenant.signIn(page, "admin");
  await page.goto(`/governance/assets/${asset.id}`);
  const owner = page.getByLabel("Business owner");
  await owner.selectOption({ label: "admin2@synthetic.example.test" });
  const chosen = await owner.inputValue();
  await page.getByLabel("Asset type").selectOption("autonomous_agent");
  await page.getByRole("checkbox", { name: "Internal", exact: true }).check();
  // Over the 2000-character limit, so the save is refused and nothing is stored.
  await page.getByLabel("Business purpose").fill("x".repeat(2001));
  await page.getByRole("button", { name: "Save profile" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Some fields need attention" })).toBeVisible();
  await expect(page.getByLabel("Business purpose")).toHaveAttribute("aria-invalid", "true");
  expect((await detailOf(asset.id)).profile).toBeNull();

  await expect(owner).toHaveValue(chosen);
  await expect(page.getByLabel("Asset type")).toHaveValue("autonomous_agent");
  await expect(page.getByRole("checkbox", { name: "Internal", exact: true })).toBeChecked();
  await page.getByLabel("Business purpose").fill("Synthetic purpose after a refusal");
  await page.getByRole("button", { name: "Save profile" }).click();
  await expect(page.getByRole("status")).toContainText("Profile saved as version 1");
  expect((await detailOf(asset.id)).profile!.profile).toMatchObject({
    business_owner_id: chosen,
    asset_type: "autonomous_agent",
    data_categories: ["internal"],
    business_purpose: "Synthetic purpose after a refusal",
  });
});

/** An asset with a complete assessment, in ASSESSMENT_REQUIRED, made through the API. */
async function assessedAsset(profile: object = LOW_PROFILE) {
  const asset = await newAsset();
  expect((await call("POST", `/governance/assets/${asset.id}/profile`, admin, profile)).status).toBe(201);
  expect((await call("POST", `/governance/assets/${asset.id}/assess`, admin, {})).status).toBe(201);
  expect((await detailOf(asset.id)).governance_status).toBe("ASSESSMENT_REQUIRED");
  return asset;
}

test("an administrator submits an assessed asset for review from its page", async ({ page }) => {
  const asset = await newAsset();
  expect((await call("POST", `/governance/assets/${asset.id}/profile`, admin, LOW_PROFILE)).status).toBe(201);

  await tenant.signIn(page, "admin");
  await page.goto(`/governance/assets/${asset.id}`);
  // A draft has no assessment of its current profile yet, so nothing can be submitted.
  await expect(page.getByRole("button", { name: "Submit for review" })).toHaveCount(0);
  await page.getByRole("button", { name: "Run risk assessment" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Assessment recorded" })).toBeVisible();

  // Submitting cannot be withdrawn, so the form says so before it is sent.
  const submission = page.getByRole("region", { name: "Submission", exact: true });
  await expect(submission).toContainText("This cannot be undone");
  await expect(submission).toContainText("Under review");

  // A reason is required, and nothing is sent without one.
  await page.getByRole("button", { name: "Submit for review" }).click();
  await expect(page.getByLabel("Submission reason")).toHaveAttribute("aria-invalid", "true");
  expect((await detailOf(asset.id)).governance_status).toBe("ASSESSMENT_REQUIRED");

  await page.getByLabel("Submission reason").fill("Synthetic submission from the asset page");
  await page.getByRole("button", { name: "Submit for review" }).click();
  await expect(submission).toContainText("Submitted for review on");
  // A standing fact on the page, not an announcement.
  await expect(page.getByRole("status").filter({ hasText: "Submitted for review" })).toHaveCount(0);
  expect((await detailOf(asset.id)).governance_status).toBe("UNDER_REVIEW");
  const reviews = await (await call("GET", `/governance/approvals?asset_id=${asset.id}`, admin)).json();
  expect(reviews.items).toHaveLength(1);
  expect(reviews.items[0].status).toBe("OPEN");
  const history = await (await call("GET", `/governance/assets/${asset.id}/history`, admin)).json();
  const submit = history.items.find((item: { kind: string | null }) => item.kind === "SUBMIT");
  expect(submit.decision.reason).toBe("Synthetic submission from the asset page");
  // The page links to the review, and offers no second submission.
  await expect(page.getByRole("link", { name: "Open the review" })).toHaveAttribute(
    "href",
    `/governance/approvals/${reviews.items[0].id}`,
  );
  await expect(page.getByRole("button", { name: "Submit for review" })).toHaveCount(0);
});

test("only administrators see the submission section, and the API refuses others", async ({ page }) => {
  const asset = await assessedAsset();
  // An administrator sees it on this asset, so its absence below is about the role.
  await tenant.signIn(page, "admin");
  await page.goto(`/governance/assets/${asset.id}`);
  await expect(page.getByRole("region", { name: "Submission", exact: true })).toBeVisible();

  for (const user of ["reviewer", "viewer"]) {
    await tenant.signIn(page, user);
    await page.goto(`/governance/assets/${asset.id}`);
    await expect(page.getByRole("heading", { name: asset.name })).toBeVisible();
    await expect(page.getByRole("region", { name: "Submission", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Submit for review" })).toHaveCount(0);
    const refused = await call("POST", `/governance/assets/${asset.id}/submit`, await tenant.headers(user), {
      reason: "Synthetic refused submission",
    });
    expect(refused.status).toBe(403);
  }
  expect((await detailOf(asset.id)).governance_status).toBe("ASSESSMENT_REQUIRED");
});

test("a submission the API refuses shows its words and changes nothing", async ({ page }) => {
  // An incomplete assessment still moves the asset to ASSESSMENT_REQUIRED, but cannot be submitted.
  const asset = await assessedAsset({ autonomy_level: "advisory" });
  const before = await (await call("GET", `/governance/assets/${asset.id}/history`, admin)).json();
  const probe = await call("POST", `/governance/assets/${asset.id}/submit`, admin, { reason: "Probe" });
  expect(probe.status).toBe(409);
  const expected = ((await probe.json()) as { error: { code: string; message: string } }).error;
  expect(expected.code).toBe("ASSESSMENT_NOT_CURRENT");

  await tenant.signIn(page, "admin");
  await page.goto(`/governance/assets/${asset.id}`);
  await page.getByLabel("Submission reason").fill("Synthetic submission that is refused");
  await page.getByRole("button", { name: "Submit for review" }).click();
  await expect(page.getByRole("alert").filter({ hasText: expected.message })).toBeVisible();
  // The reason that was typed is still there to send again.
  await expect(page.getByLabel("Submission reason")).toHaveValue("Synthetic submission that is refused");
  expect((await detailOf(asset.id)).governance_status).toBe("ASSESSMENT_REQUIRED");
  const after = await (await call("GET", `/governance/assets/${asset.id}/history`, admin)).json();
  expect(after.total).toBe(before.total);
});
