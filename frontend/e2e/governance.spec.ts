import { expect, type Page, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { adminHeaders, API, headersFor, signIn, waitForIncident } from "./helpers";

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
  // Decisions a person made apply in both modes, so neither note may say checks never block.
  await expect(mode).toContainText("Decisions a person made");
  await expect(mode).not.toContainText("They do not block actions");
});

test("overview empty state on a tenant with no assets", async ({ page }) => {
  const slug = `synthetic-empty-${randomUUID().slice(0, 8)}`;
  const password = randomUUID();
  const python =
    process.platform === "win32"
      ? path.join(__dirname, "../../backend/.venv/Scripts/python.exe")
      : path.join(__dirname, "../../backend/.venv/bin/python");
  // The helper prints only an exception type, and the arguments (which hold the new password) are
  // kept out of any error thrown here.
  try {
    execFileSync(
      python,
      [path.join(__dirname, "provision_tenant.py"), slug, "admin@synthetic.example.test", password],
      { stdio: "pipe" },
    );
  } catch (error) {
    const stderr = String((error as { stderr?: Buffer }).stderr ?? "").trim();
    throw new Error(`Could not provision the empty tenant. ${stderr}`);
  }

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

// Asset details and risk

type Headers = Record<string, string>;

async function post<T = Record<string, unknown>>(path: string, body: object, headers?: Headers) {
  const response = await fetch(`${API}${path}`, {
    method: "POST",
    headers: headers ?? (await adminHeaders()),
    body: JSON.stringify(body),
  });
  expect(response.status, await response.clone().text()).toBeLessThan(300);
  return (await response.json()) as T;
}

async function get<T = Record<string, unknown>>(path: string): Promise<T> {
  const response = await fetch(`${API}${path}`, { headers: await adminHeaders() });
  expect(response.status).toBe(200);
  return response.json();
}

// Every input low, so a test changes only what it is about.
const LOW_PROFILE = {
  asset_type: "ai_application",
  description: "Synthetic e2e asset",
  data_categories: ["public"],
  external_exposure: "none",
  autonomy_level: "advisory",
  human_oversight: "in_the_loop",
  declared_tool_access: [],
  impact_level: "negligible",
  deployment_environment: "development",
  third_party_reliance: "none",
};

const profilePath = (id: string) => `/governance/assets/${id}/profile`;
const region = (page: Page, name: string) => page.getByRole("region", { name, exact: true });
const titleCase = (level: string) => level.charAt(0) + level.slice(1).toLowerCase();

type Stored = {
  status: string;
  risk_level: string | null;
  score: number | null;
  methodology_version_id: string;
  result: {
    missing: string[];
    floor_applied: string | null;
    mitigations: string[];
    factors: { label: string; level: number; weight: number; contribution: number }[];
  };
};

type Methodology = {
  id: string;
  version: number;
  created_by: string | null;
  document: {
    factors: { id: string; label: string; weight: number }[];
    floors: { id: string; description: string }[];
    provenance_note: string;
  };
};

async function methodologyOf(id: string): Promise<Methodology> {
  const page = await get<{ items: Methodology[] }>("/governance/methodologies?limit=100");
  const found = page.items.find((item) => item.id === id);
  expect(found).toBeDefined();
  return found as Methodology;
}

// A precondition, so a test that needs a reviewer does not grant the role as a hidden side effect.
async function ensureReviewerGrant(admin: Headers) {
  const people = await get<{
    items: { id: string; email: string; reviewer_grant_id: string | null }[];
  }>("/governance/people?limit=100");
  const person = people.items.find((item) => item.email.startsWith("reviewer@"))!;
  if (!person.reviewer_grant_id) await post("/governance/role-grants", { user_id: person.id }, admin);
}

test("admin saves a profile with owners picked from real users", async ({ page }) => {
  const asset = await newAsset(`synthetic-e2e-${randomUUID().slice(0, 8)}`, "medium");
  const people = await get<{ items: { id: string; email: string }[] }>("/governance/people");
  const business = people.items.find((person) => person.email.startsWith("reviewer@"))!;
  const technical = people.items.find((person) => person.email.startsWith("admin@"))!;

  await signIn(page, "admin");
  await page.goto(`/governance/assets/${asset.id}`);
  await expect(page.getByRole("heading", { name: asset.name })).toBeVisible();

  // Owners are a pick from the organization's users, not free text.
  const businessOwner = page.getByLabel("Business owner");
  await expect(businessOwner).toHaveJSProperty("tagName", "SELECT");
  const offered = await businessOwner.locator("option").allTextContents();
  for (const person of people.items) expect(offered).toContain(person.email);
  expect(offered).toHaveLength(people.items.length + 1);

  await businessOwner.selectOption({ label: business.email });
  await page.getByLabel("Technical owner").selectOption({ label: technical.email });
  await page
    .getByLabel("Description", { exact: true })
    .fill("Synthetic profile saved from the form");
  await page.getByLabel("Asset type").selectOption("autonomous_agent");
  await page.getByLabel("Autonomy level").selectOption("bounded");
  await page.getByRole("checkbox", { name: "Regulated" }).check();
  await page.getByRole("button", { name: "Save profile" }).click();
  await expect(page.getByRole("status")).toContainText("Profile saved");

  const detail = await get<{ profile: { version: number; profile: Record<string, unknown> } }>(
    `/governance/assets/${asset.id}`,
  );
  expect(detail.profile.version).toBe(1);
  expect(detail.profile.profile).toMatchObject({
    business_owner_id: business.id,
    technical_owner_id: technical.id,
    description: "Synthetic profile saved from the form",
    asset_type: "autonomous_agent",
    autonomy_level: "bounded",
    data_categories: ["regulated"],
  });
  await expect(page.getByRole("status")).toContainText(`version ${detail.profile.version}`);
});

test("incomplete assessment shows what is missing and no risk level", async ({ page }) => {
  const asset = await newAsset(`synthetic-e2e-${randomUUID().slice(0, 8)}`, "low");
  await post(profilePath(asset.id), { autonomy_level: "advisory" });

  await signIn(page, "admin");
  await page.goto(`/governance/assets/${asset.id}`);
  await page.getByRole("button", { name: "Run risk assessment" }).click();
  await expect(page.getByRole("status")).toContainText("Assessment recorded");
  await page.getByRole("link", { name: "View risk assessment" }).click();
  await expect(page).toHaveURL(/\/risk$/);

  const risk = await get<{ assessment: Stored }>(
    `/governance/assets/${asset.id}/risk`,
  );
  expect(risk.assessment.status).toBe("INCOMPLETE");
  expect(risk.assessment.risk_level).toBeNull();
  const missing: string[] = risk.assessment.result.missing;
  expect(missing.length).toBeGreaterThan(0);
  const methodology = await methodologyOf(risk.assessment.methodology_version_id);

  const result = region(page, "Result");
  await expect(result).toContainText("Incomplete");
  await expect(result).toContainText("No risk level");
  for (const level of ["Low", "Medium", "High", "Critical"]) {
    await expect(result.getByText(level, { exact: true })).toHaveCount(0);
  }
  await expect(result.getByText("Assessed", { exact: true })).toHaveCount(0);

  const inputs = region(page, "Missing inputs");
  await expect(inputs.getByRole("listitem")).toHaveCount(missing.length);
  for (const id of missing) {
    const label = methodology.document.factors.find((factor) => factor.id === id)!.label;
    await expect(inputs).toContainText(label);
  }
});

test("complete assessment shows every factor, score, floor, and mitigations", async ({ page }) => {
  const asset = await newAsset(`synthetic-e2e-${randomUUID().slice(0, 8)}`, "low");
  // Bounded autonomy with regulated data scores MEDIUM, and the floor raises it to HIGH.
  await post(profilePath(asset.id), {
    ...LOW_PROFILE,
    autonomy_level: "bounded",
    data_categories: ["regulated"],
  });
  await post(`/governance/assets/${asset.id}/assess`, {});

  const { assessment } = await get<{ assessment: Stored }>(
    `/governance/assets/${asset.id}/risk`,
  );
  expect(assessment.status).toBe("COMPLETE");
  const result = assessment.result;
  expect(result.floor_applied).not.toBeNull();
  const methodology = await methodologyOf(assessment.methodology_version_id);

  await signIn(page, "reviewer");
  await page.goto(`/governance/assets/${asset.id}/risk`);

  const summary = region(page, "Result");
  await expect(summary).toContainText("Assessed");
  await expect(summary).toContainText(titleCase(assessment.risk_level!));
  await expect(summary).toContainText(String(assessment.score));

  const factors = region(page, "Factors");
  for (const factor of result.factors) {
    const row = factors.getByRole("row").filter({ hasText: factor.label });
    await expect(row).toHaveCount(1);
    const cells = row.getByRole("cell");
    await expect(cells.nth(2)).toHaveText(String(factor.level));
    await expect(cells.nth(3)).toHaveText(String(factor.weight));
    await expect(cells.nth(4)).toHaveText(String(factor.contribution));
  }
  await expect(factors.getByRole("row")).toHaveCount(result.factors.length + 1);

  const floor = methodology.document.floors.find((item) => item.id === result.floor_applied)!;
  await expect(region(page, "Floors")).toContainText(floor.description);
  for (const text of result.mitigations as string[]) {
    await expect(region(page, "Mitigations")).toContainText(text);
  }
  await expect(region(page, "Missing inputs")).toHaveCount(0);
});

test("risk page states the weights are engineering judgment", async ({ page }) => {
  const scored = await newAsset(`synthetic-e2e-${randomUUID().slice(0, 8)}`, "low");
  await post(profilePath(scored.id), LOW_PROFILE);
  await post(`/governance/assets/${scored.id}/assess`, {});
  const { assessment } = await get<{ assessment: Stored }>(
    `/governance/assets/${scored.id}/risk`,
  );
  const methodology = await methodologyOf(assessment.methodology_version_id);
  const unassessed = await newAsset(`synthetic-e2e-${randomUUID().slice(0, 8)}`, "low");

  await signIn(page, "viewer");
  await page.goto(`/governance/assets/${scored.id}/risk`);
  const box = region(page, "Methodology");
  await expect(box).toContainText("engineering judgment");
  await expect(box).toContainText("not values taken from any standard");
  await expect(box).toContainText(`Version ${methodology.version}`);
  await expect(box).toContainText(methodology.document.provenance_note);
  if (methodology.created_by === null) await expect(box).toContainText("Built-in");

  // With no assessment there is no level, and the statement is still there.
  await page.goto(`/governance/assets/${unassessed.id}/risk`);
  await expect(page.getByText("This asset has not been assessed")).toBeVisible();
  await expect(region(page, "Methodology")).toContainText("engineering judgment");
  await expect(page.getByText("Assessed", { exact: true })).toHaveCount(0);
});

test("asset page shows policies, history, evidence, mappings, and related incidents", async ({
  page,
}) => {
  const admin = await adminHeaders();
  const reviewer = await headersFor("reviewer");
  await ensureReviewerGrant(admin);

  // A policy for a narrow kind of asset, so other assets in this organization are not affected.
  const policyName = `synthetic-e2e-policy-${randomUUID().slice(0, 8)}`;
  const policy = await post<{ id: string }>("/governance/policies", {
    name: policyName,
    category: "general",
  });
  const version = await post<{ id: string; version: number }>(
    `/governance/policies/${policy.id}/versions`,
    {
      document: {
        description: "Synthetic e2e policy",
        severity: "medium",
        applicability: {
          asset_types: ["model_provider"],
          environments: ["development"],
          data_categories: ["public"],
        },
        controls: { required_human_oversight: ["in_the_loop"] },
      },
      effective_from: new Date(Date.now() - 3_600_000).toISOString(),
    },
  );
  const versionPath = `/governance/policies/${policy.id}/versions/${version.id}`;
  await post(`${versionPath}/approve`, {}, reviewer);
  await post(`${versionPath}/activate`, {}, admin);
  try {

    const asset = await newAsset(`synthetic-e2e-${randomUUID().slice(0, 8)}`, "medium");
    await post(profilePath(asset.id), { ...LOW_PROFILE, asset_type: "model_provider" });
    const agent = await post<{ id: string }>("/agents", {
      asset_id: asset.id,
      name: `synthetic-e2e-agent-${randomUUID().slice(0, 8)}`,
      owner: "Synthetic E2E",
    });
    const credential = await post<{ key: string }>(`/agents/${agent.id}/credentials`, {});
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await fetch(`${API}/gateway/actions`, {
        method: "POST",
        headers: { Authorization: `Bearer ${credential.key}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          idempotency_key: randomUUID(),
          tool: "run_shell_command",
          resource_id: null,
          params: {},
        }),
      });
      expect(response.status).toBe(200);
    }
    await waitForIncident(agent.id, admin);
    await post(`/governance/assets/${asset.id}/assess`, {});
    const review = await post<{ required_controls: { applicable_version_ids: string[] } }>(
      `/governance/assets/${asset.id}/submit`,
      { reason: "Synthetic e2e submission" },
    );
    expect(review.required_controls.applicable_version_ids).toContain(version.id);

    // An attestation, so the page must not present it as a recomputed hash.
    const controls = await get<{ items: { id: string; identifier: string }[]; statement: string }>(
      "/governance/controls?limit=1",
    );
    const control = controls.items[0]!;
    const evidence = await post<{ id: string }>("/governance/evidence", {
      asset_id: asset.id,
      category: "model_evaluation",
      description: `Synthetic e2e evidence ${randomUUID().slice(0, 8)}`,
      source: {
        source_type: "external_reference",
        source_uri: "https://example.test/synthetic-evaluation",
        content_sha256: "a".repeat(64),
      },
      control_ids: [control.id],
    });
    await post(
      `/governance/evidence/${evidence.id}/verify`,
      { outcome: "VERIFIED", method: "manual_attestation", note: "Synthetic attestation" },
      reviewer,
    );

    const history = await get<{ items: { seq: number; type: string }[] }>(
      `/governance/assets/${asset.id}/history`,
    );
    const evidenceList = await get<{ items: { description: string }[] }>(
      `/governance/evidence?asset_id=${asset.id}`,
    );
    const incidents = await get<{ items: { id: string; title: string }[] }>(
      `/incidents?asset_id=${asset.id}`,
    );
    const frameworks = await get<{ items: { name: string; library_status: string }[] }>(
      "/governance/frameworks",
    );

    await signIn(page, "reviewer");
    await page.goto(`/governance/assets/${asset.id}`);

    const policies = region(page, "Policies");
    await expect(policies).toContainText(policyName);
    await expect(policies).toContainText(`Version ${version.version}`);
    await expect(policies).toContainText("required_human_oversight");

    const rows = region(page, "History").getByRole("row");
    await expect(rows).toHaveCount(history.items.length + 1);
    for (const [index, entry] of history.items.entries()) {
      // The audit sequence is the order, so the rows must follow the API's order.
      await expect(rows.nth(index + 1).getByRole("cell").first()).toHaveText(String(entry.seq));
    }

    const proof = region(page, "Evidence");
    await expect(proof).toContainText(evidenceList.items[0]!.description);
    await expect(proof).toContainText("Verified");
    await expect(proof).toContainText("Manual attestation");
    await expect(proof).toContainText("Nothing was recomputed");
    await expect(proof).not.toContainText("Hash recomputed");

    const mappings = region(page, "Control mappings");
    await expect(mappings).toContainText(control.identifier);
    await expect(mappings).toContainText(controls.statement);
    for (const framework of frameworks.items) {
      await expect(mappings).toContainText(framework.name);
    }
    await expect(mappings).toContainText("Not loaded");

    const related = region(page, "Related incidents");
    expect(incidents.items.length).toBeGreaterThan(0);
    for (const incident of incidents.items) {
      await expect(related.getByRole("link", { name: incident.title })).toHaveAttribute(
        "href",
        `/incidents/${incident.id}`,
      );
    }
  } finally {
    // The policy would otherwise stay active for every later submission in this organization.
    await post(`${versionPath}/deactivate`, {}, admin);
    const policies = await get<{ items: { id: string; versions: { id: string; active: boolean }[] }[] }>(
      "/governance/policies?limit=100",
    );
    const stored = policies.items.find((item) => item.id === policy.id)!;
    expect(stored.versions.find((item) => item.id === version.id)!.active).toBe(false);
  }
});

test("viewer sees no edit controls and a direct mutation is refused", async ({ page }) => {
  const asset = await newAsset(`synthetic-e2e-${randomUUID().slice(0, 8)}`, "medium");
  await post(profilePath(asset.id), { ...LOW_PROFILE, description: "Synthetic viewer check" });

  await signIn(page, "viewer");
  await page.goto(`/governance/assets/${asset.id}`);
  await expect(page.getByRole("heading", { name: asset.name })).toBeVisible();
  await expect(page.getByText("Synthetic viewer check")).toBeVisible();
  await expect(page.getByRole("button", { name: "Save profile" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Run risk assessment" })).toHaveCount(0);
  await expect(page.getByLabel("Business owner")).toHaveCount(0);
  await expect(page.getByRole("textbox")).toHaveCount(0);

  // The page hides the controls, and the API refuses the request in any case.
  const viewer = await headersFor("viewer");
  for (const [path, body] of [
    [profilePath(asset.id), { description: "Changed by a viewer" }],
    [`/governance/assets/${asset.id}/assess`, {}],
  ] as const) {
    const response = await fetch(`${API}${path}`, {
      method: "POST",
      headers: viewer,
      body: JSON.stringify(body),
    });
    expect(response.status).toBe(403);
  }
  const detail = await get<{ profile: { version: number; profile: { description: string } } }>(
    `/governance/assets/${asset.id}`,
  );
  expect(detail.profile.version).toBe(1);
  expect(detail.profile.profile.description).toBe("Synthetic viewer check");
});

test("a profile change after an assessment is flagged as needing reassessment", async ({
  page,
}) => {
  const asset = await newAsset(`synthetic-e2e-${randomUUID().slice(0, 8)}`, "low");
  await post(profilePath(asset.id), LOW_PROFILE);
  await post(`/governance/assets/${asset.id}/assess`, {});
  await post(profilePath(asset.id), { ...LOW_PROFILE, description: "Changed after assessment" });

  const detail = await get<{ profile: { version: number } }>(`/governance/assets/${asset.id}`);
  expect(detail.profile.version).toBe(2);
  const note = "Assessed against profile version 1; the current profile is version 2; reassessment needed";

  // Every role sees it, on both pages.
  for (const role of ["viewer", "admin"]) {
    await signIn(page, role);
    for (const suffix of ["", "/risk"]) {
      await page.goto(`/governance/assets/${asset.id}${suffix}`);
      await expect(region(page, "Summary")).toContainText(note);
    }
    await expect(region(page, "Result")).toContainText(note);
    await page.context().clearCookies();
  }

  // A fresh assessment of the current profile clears the note.
  await post(`/governance/assets/${asset.id}/assess`, {});
  await signIn(page, "viewer");
  await page.goto(`/governance/assets/${asset.id}/risk`);
  await expect(page.getByText("reassessment needed")).toHaveCount(0);
});
