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
  profile: { version: number; profile: Record<string, unknown> } | null;
};

async function detailOf(id: string): Promise<Detail> {
  const response = await call("GET", `/governance/assets/${id}`, admin);
  expect(response.status).toBe(200);
  return response.json();
}

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
