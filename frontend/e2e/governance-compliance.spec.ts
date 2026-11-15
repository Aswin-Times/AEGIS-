import { expect, type Page, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { API, newGovernanceTenant, type Tenant } from "./helpers";

// Everything here runs in a synthetic tenant of its own, so the demo tenant (and its enforcement
// mode) is left as it was. Holders of governance_reviewer: reviewer, admin, admin2. Not holders:
// reviewer2 (role reviewer) and viewer. admin submits evidence and assets, so admin is the
// submitter whenever a test needs a refusal for a submitter.

type Headers = Record<string, string>;
let tenant: Tenant;
const tokens: Record<string, Headers> = {};

test.beforeAll(async () => {
  tenant = newGovernanceTenant();
  for (const user of ["admin", "admin2", "reviewer", "reviewer2", "viewer"]) {
    tokens[user] = await tenant.headers(user);
  }
  const people = await get<{ items: { id: string; email: string }[] }>("/governance/people", "admin");
  const idOf = (name: string) => people.items.find((item) => item.email.startsWith(`${name}@`))!.id;
  // Nobody can grant the role to themselves, so each admin is granted by the other.
  await post("/governance/role-grants", { user_id: idOf("reviewer") }, "admin");
  await post("/governance/role-grants", { user_id: idOf("admin2") }, "admin");
  await post("/governance/role-grants", { user_id: idOf("admin") }, "admin2");
});

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

/** The status, error code, and message of a refused request: what the page must repeat. */
async function refusal(path: string, body: object, user: string) {
  const response = await call("POST", path, user, body);
  const payload = (await response.json()) as { error: { code: string; message: string } };
  return { status: response.status, ...payload.error };
}

type Framework = {
  id: string;
  key: string;
  version: string;
  name: string;
  library_status: string;
  control_count: number;
  source_control_count: number | null;
  coverage: string;
  status_counts: Record<string, number>;
};
type Control = { id: string; identifier: string; name: string; current_status: string; framework_key: string };
type Compliance<T> = { items: T[]; statement: string };

const frameworks = () => get<Compliance<Framework>>("/governance/frameworks");
const nist = async () => (await frameworks()).items.find((item) => item.key.startsWith("nist"))!;
const iso = async () => (await frameworks()).items.find((item) => item.key.startsWith("iso"))!;

async function firstControl(): Promise<Control> {
  const framework = await nist();
  const page = await get<Compliance<Control>>(`/governance/controls?framework_id=${framework.id}&limit=5`);
  return page.items[0]!;
}

const region = (page: Page, name: string) => page.getByRole("region", { name, exact: true });
const statement = (page: Page) => page.getByRole("note", { name: "No certification statement" });
const alertWith = (page: Page, text: string | RegExp) =>
  page.getByRole("alert").filter({ hasText: text });

async function newAsset() {
  const name = `synthetic-compliance-${randomUUID().slice(0, 8)}`;
  const asset = await post<{ id: string }>("/assets", {
    name,
    owner: "Synthetic E2E",
    risk_classification: "medium",
    intended_use: "Synthetic compliance e2e check",
    is_synthetic: true,
  });
  return { name, id: asset.id };
}

/**
 * Evidence for a control, submitted by admin (so admin is the submitter). Inline text is always
 * recomputed when verified, whatever the method, so an external reference is the way to get a
 * verification that is only an attestation.
 */
async function newEvidence(controlId: string, kind: "inline" | "external" = "inline") {
  const asset = await newAsset();
  const description = `Synthetic evidence ${randomUUID().slice(0, 8)}`;
  const source =
    kind === "inline"
      ? { source_type: "inline", content_text: `Synthetic text ${description}` }
      : {
          source_type: "external_reference",
          source_uri: "https://example.test/synthetic-evidence",
          content_sha256: "a".repeat(64),
        };
  const evidence = await post<{ id: string }>("/governance/evidence", {
    asset_id: asset.id,
    category: "architecture_documentation",
    description,
    source,
    control_ids: [controlId],
  });
  return { id: evidence.id, description, asset };
}

const LOW_PROFILE = {
  asset_type: "ai_application",
  description: "Synthetic compliance e2e asset",
  data_categories: ["public"],
  external_exposure: "none",
  autonomy_level: "advisory",
  human_oversight: "in_the_loop",
  declared_tool_access: [],
  impact_level: "negligible",
  deployment_environment: "development",
  third_party_reliance: "none",
};

async function submitted() {
  const asset = await newAsset();
  await post(`/governance/assets/${asset.id}/profile`, LOW_PROFILE);
  await post(`/governance/assets/${asset.id}/assess`, {});
  const review = await post<{ id: string }>(`/governance/assets/${asset.id}/submit`, {
    reason: "Synthetic submission for compliance e2e",
  });
  return { ...asset, reviewId: review.id };
}

/** An approved asset whose next review falls `reviewInMs` from now. */
async function approved(reviewInMs: number) {
  const { reviewId, ...asset } = await submitted();
  await post(
    `/governance/approvals/${reviewId}/approve`,
    {
      reason: "Synthetic approval for review e2e",
      valid_until: new Date(Date.now() + 86_400_000 * 200).toISOString(),
      next_review_at: new Date(Date.now() + reviewInMs).toISOString(),
    },
    "reviewer",
  );
  return asset;
}

const utc = (iso: string) => new Date(iso).toISOString().replace("T", " ").slice(0, 19) + " UTC";

// Compliance

test("compliance shows the API's no-certification statement on every state", async ({ page }) => {
  const { statement: expected } = await frameworks();
  const framework = await nist();
  const unused = Object.entries(framework.status_counts).find(([, count]) => count === 0)?.[0]
    ?? "NOT_IMPLEMENTED";
  const control = await firstControl();

  for (const user of ["reviewer", "viewer"]) {
    await tenant.signIn(page, user);
    for (const path of [
      "/governance/compliance",
      `/governance/compliance?framework=${framework.id}`,
      // Empty: no stored control has this status.
      `/governance/compliance?framework=${framework.id}&status=${unused}`,
      `/governance/compliance/controls/${control.id}`,
    ]) {
      await page.goto(path);
      await expect(statement(page), path).toHaveText(expected);
    }
  }

  // Error: the API refuses a framework that is not an id, and the page says so, statement included.
  await page.goto("/governance/compliance?framework=not-an-id");
  await expect(alertWith(page, "could not be loaded")).toBeVisible();
  await expect(statement(page)).toHaveText(expected);
  await page.goto(`/governance/compliance?framework=${framework.id}&status=${unused}`);
  await expect(page.getByText("No controls match")).toBeVisible();
});

test("ISO shows the library as not loaded, with zero controls", async ({ page }) => {
  const framework = await iso();
  expect(framework.library_status).toBe("NOT_LOADED");
  expect(framework.control_count).toBe(0);

  await tenant.signIn(page, "viewer");
  await page.goto("/governance/compliance");
  const card = region(page, framework.name);
  await expect(card).toContainText("Not loaded");
  await expect(card).toContainText("0 controls");
  await expect(card).toContainText(framework.coverage);
  await expect(card.getByRole("link", { name: /View controls/ })).toHaveCount(0);
  await expect(card).not.toContainText("%");

  await page.goto(`/governance/compliance?framework=${framework.id}`);
  await expect(page.getByText("No controls are loaded for this framework")).toBeVisible();
  await expect(page.getByRole("table")).toHaveCount(0);
});

test("NIST shows its shipped count against the source count, and never a percentage", async ({
  page,
}) => {
  const framework = await nist();
  expect(framework.library_status).toBe("LOADED_PARTIAL");
  expect(framework.source_control_count).not.toBeNull();

  await tenant.signIn(page, "viewer");
  await page.goto("/governance/compliance");
  const card = region(page, framework.name);
  await expect(card).toContainText("Partial library");
  await expect(card).toContainText(
    `${framework.control_count} of ${framework.source_control_count} subcategories`,
  );
  await expect(card).toContainText(framework.coverage);
  // Status counts are the stored rows' own counts.
  for (const [status, count] of Object.entries(framework.status_counts)) {
    const label = status.charAt(0) + status.slice(1).toLowerCase().replaceAll("_", " ");
    await expect(
      card.locator("dl > div").filter({ has: page.locator("dt", { hasText: new RegExp(`^${label}$`) }) })
        .locator("dd"),
    ).toHaveText(String(count));
  }
  await expect(page.locator("body")).not.toContainText("%");
  await expect(page.locator("body")).not.toContainText(/\bcompliant\b/i);
  await expect(page.locator("body")).not.toContainText("fully loaded");
});

test("evidence shows its verification method, and only verified evidence counts", async ({
  page,
}) => {
  const control = await firstControl();
  const evidence = await newEvidence(control.id, "external");
  const claim = {
    status: "IMPLEMENTED",
    note: "Synthetic claim before any verification",
    evidence_ids: [evidence.id],
  };
  const refused = await refusal(`/governance/controls/${control.id}/assess`, claim, "reviewer");
  expect(refused).toMatchObject({ status: 409, code: "EVIDENCE_REQUIRED" });

  await tenant.signIn(page, "reviewer");
  await page.goto(`/governance/compliance/controls/${control.id}`);
  await expect(page.getByRole("heading", { level: 1 })).toContainText(control.identifier);
  const status = region(page, "Status");
  await expect(status).toContainText("Not assessed");
  const linked = region(page, "Linked evidence");
  const row = linked.getByRole("row").filter({ hasText: evidence.description });
  await expect(row).toContainText("Unverified");
  await expect(row).toContainText("Not checked");
  await expect(linked).toContainText("does not count");
  await expect(status).toContainText("1 linked");
  await expect(status).toContainText("0 verified");

  // A claim without verified evidence is refused by the API, and its words are shown.
  await page.getByRole("button", { name: `Assess control ${control.identifier}` }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Status").selectOption("IMPLEMENTED");
  await dialog.getByLabel("Note").fill(claim.note);
  await dialog.getByRole("checkbox", { name: evidence.description }).check();
  await dialog.getByRole("button", { name: "Record assessment" }).click();
  await expect(dialog.getByRole("alert")).toContainText(refused.message);
  await expect(dialog.getByRole("alert")).toContainText("EVIDENCE_REQUIRED");
  await dialog.getByRole("button", { name: "Cancel" }).click();

  // A reviewer who did not submit it verifies it by attestation, and the page says what that means.
  await page.getByRole("button", { name: `Verify evidence: ${evidence.description}` }).click();
  await dialog.getByLabel("Method").selectOption({ label: "Manual attestation" });
  await dialog.getByLabel("Note").fill("Synthetic attestation by a reviewer");
  await dialog.getByRole("button", { name: "Record verification" }).click();
  await expect(dialog).toBeHidden();
  await expect(row).toContainText("Verified");
  await expect(row).toContainText("Method: Manual attestation");
  await expect(row).toContainText("Nothing was recomputed");
  await expect(row).not.toContainText("hash was recomputed");
  await expect(row).toContainText("declared hash");
  const stored = await get<{
    latest_verification: { method: string; scope: string; outcome: string };
  }>(`/governance/evidence/${evidence.id}`);
  expect(stored.latest_verification).toMatchObject({
    method: "manual_attestation",
    scope: "attestation_only",
    outcome: "VERIFIED",
  });
  await expect(status).toContainText("1 verified");
  // Verifying is not assessing.
  await expect(status).toContainText("Not assessed");

  await page.getByRole("button", { name: `Assess control ${control.identifier}` }).click();
  await dialog.getByLabel("Status").selectOption("PARTIALLY_IMPLEMENTED");
  await dialog.getByLabel("Note").fill("Synthetic partial assessment");
  await dialog.getByRole("checkbox", { name: evidence.description }).check();
  await dialog.getByRole("button", { name: "Record assessment" }).click();
  await expect(dialog).toBeHidden();
  const after = (await get<Compliance<Control>>(`/governance/controls?framework_id=${(await nist()).id}&limit=5`))
    .items.find((item) => item.id === control.id)!;
  expect(after.current_status).toBe("PARTIALLY_IMPLEMENTED");
  await expect(status).toContainText("Partially implemented");
  await expect(status).toContainText("Synthetic partial assessment");

  // Another reviewer rejects the evidence: it stops counting, and the status says so plainly.
  await post(
    `/governance/evidence/${evidence.id}/verify`,
    { outcome: "REJECTED", method: "manual_attestation", note: "Synthetic rejection" },
    "admin2",
  );
  await page.reload();
  const reasserted = (await get<Compliance<Control>>(`/governance/controls?framework_id=${(await nist()).id}&limit=5`))
    .items.find((item) => item.id === control.id)!;
  expect(reasserted.current_status).toBe("EVIDENCE_REQUIRED");
  await expect(status).toContainText("Evidence required");
  await expect(status).toContainText("not counted");
  await expect(row).toContainText("Rejected");
  await expect(status).toContainText("0 verified");

  await page.goto(`/governance/compliance?framework=${(await nist()).id}`);
  await expect(page.getByRole("row").filter({ hasText: control.identifier }).first()).toContainText(
    "Evidence required",
  );
});

test("a submitter cannot verify their own evidence, and the page shows the API's refusal", async ({
  page,
}) => {
  const control = await firstControl();
  const evidence = await newEvidence(control.id);
  const body = { outcome: "VERIFIED", method: "manual_attestation", note: "Synthetic self-check" };
  const refused = await refusal(`/governance/evidence/${evidence.id}/verify`, body, "admin");
  expect(refused).toMatchObject({ status: 403, code: "SELF_VERIFICATION_REFUSED" });

  await tenant.signIn(page, "admin");
  await page.goto(`/governance/compliance/controls/${control.id}`);
  await page.getByRole("button", { name: `Verify evidence: ${evidence.description}` }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Method").selectOption({ label: "Manual attestation" });
  // A missing note is a field error, tied to the field.
  await dialog.getByRole("button", { name: "Record verification" }).click();
  const note = dialog.getByLabel("Note");
  await expect(note).toHaveAttribute("aria-invalid", "true");
  await expect(note).toHaveAccessibleDescription(/reason|note/i);
  await note.fill(body.note);
  await dialog.getByRole("button", { name: "Record verification" }).click();
  await expect(dialog.getByRole("alert")).toContainText(refused.message);
  const stored = await get<{ current_verification: string }>(`/governance/evidence/${evidence.id}`);
  expect(stored.current_verification).toBe("UNVERIFIED");
});

test("others see no assessing or verifying controls, and the API refuses their attempts", async ({
  page,
}) => {
  const control = await firstControl();
  const evidence = await newEvidence(control.id);
  const assess = { status: "NOT_IMPLEMENTED", note: "Synthetic attempt", evidence_ids: [] };
  const verify = { outcome: "VERIFIED", method: "manual_attestation", note: "Synthetic attempt" };

  for (const user of ["viewer", "reviewer2"]) {
    await tenant.signIn(page, user);
    await page.goto(`/governance/compliance/controls/${control.id}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.getByRole("button", { name: /Assess control|Verify evidence/ })).toHaveCount(0);
    await expect(page.getByText("needs the governance reviewer role")).toBeVisible();
    expect((await refusal(`/governance/controls/${control.id}/assess`, assess, user)).status).toBe(403);
    expect((await refusal(`/governance/evidence/${evidence.id}/verify`, verify, user)).status).toBe(403);
  }
  const stored = await get<{ current_verification: string }>(`/governance/evidence/${evidence.id}`);
  expect(stored.current_verification).toBe("UNVERIFIED");
});

// Reviews

test("review center shows upcoming, overdue, and reassessment requests from stored rows", async ({
  page,
}) => {
  const upcoming = await approved(10 * 86_400_000);
  const later = await approved(60 * 86_400_000);
  const owed = await approved(5_000);
  const reassess = await approved(20 * 86_400_000);
  await post(`/governance/assets/${reassess.id}/reassess`, { reason: "Synthetic reassessment request" });

  type Due = { asset_id: string; name: string; governance_status: string; next_review_at: string; overdue: boolean };
  // Dates cannot be set in the past, so the near one is awaited until the API itself reports it past.
  await expect
    .poll(async () => {
      const due = await get<{ items: Due[] }>("/governance/reviews/due?limit=100");
      return due.items.find((item) => item.asset_id === owed.id)?.overdue;
    }, { timeout: 20_000, intervals: [500] })
    .toBe(true);
  const due = await get<{ items: Due[]; total: number }>("/governance/reviews/due?limit=100");
  const dueRow = (asset: { id: string }) => due.items.find((item) => item.asset_id === asset.id)!;

  await tenant.signIn(page, "reviewer");
  await page.goto("/governance/reviews");
  await expect(page.getByRole("heading", { level: 1, name: "Review center" })).toBeVisible();

  const overdueCount = due.items.filter((item) => item.overdue).length;
  await expect(region(page, "Reviews owed past date").locator("strong")).toHaveText(String(overdueCount));
  await expect(region(page, "Upcoming").locator("strong")).toHaveText(
    String(due.items.filter((item) => !item.overdue).length),
  );
  // The overdue count says what it counts, since it can overlap the awaiting-approval count.
  await expect(region(page, "Reviews owed past date")).toContainText("reassessment required");
  await expect(region(page, "Reviews owed past date")).toContainText("under review");
  await expect(region(page, "Reviews owed past date")).toContainText("Awaiting approval");

  const soon = region(page, "Upcoming reviews").getByRole("row").filter({ hasText: upcoming.name });
  await expect(soon).toContainText(utc(dueRow(upcoming).next_review_at));
  await expect(soon).toContainText("Approved");
  // Outside the default 30 day window, so not listed there.
  await expect(region(page, "Upcoming reviews").getByRole("row").filter({ hasText: later.name })).toHaveCount(0);

  const past = region(page, "Past their review date").getByRole("row").filter({ hasText: owed.name });
  await expect(past).toContainText(utc(dueRow(owed).next_review_at));

  const requests = region(page, "Reassessment requests").getByRole("row").filter({ hasText: reassess.name });
  await expect(requests).toContainText("Reassessment required");

  await page.goto("/governance/reviews?window=90");
  const wider = region(page, "Upcoming reviews").getByRole("row").filter({ hasText: later.name });
  await expect(wider).toContainText("Approved");
});

test("reviews show their empty and error states", async ({ page }) => {
  const empty = newGovernanceTenant();
  await empty.signIn(page, "viewer");
  await page.goto("/governance/reviews");
  await expect(page.getByText("No reviews are due")).toBeVisible();
  await expect(region(page, "Reviews owed past date").locator("strong")).toHaveText("0");
  await expect(region(page, "Reassessment requested").locator("strong")).toHaveText("0");
  await expect(page.getByText("No reassessment requests")).toBeVisible();

  await page.goto("/governance/compliance?status=NOT_IMPLEMENTED");
  await expect(statement(page)).toBeVisible();
  await expect(page.getByText("No controls match")).toBeVisible();

  await page.goto("/governance/reviews?window=not-a-number");
  await expect(alertWith(page, "could not be loaded")).toBeVisible();
});

// Enforcement

type Preflight = {
  would_deny: number;
  would_hold: number;
  assets_checked: number;
  items: { asset_id: string; name: string; verdict: string; reason_code: string; governance_status: string | null }[];
};

async function modeOf(): Promise<string> {
  return (await get<{ enforcement_mode: string }>("/governance/enforcement")).enforcement_mode;
}

/** Puts the mode back as it was found, so one test's change is never another's starting point. */
async function restore(found: string) {
  if ((await modeOf()) !== found) {
    await post("/governance/enforcement", { mode: found, reason: "Synthetic e2e restores the mode" });
  }
}

test("enforcement lists the preflight from stored rows and states what it does not do", async ({
  page,
}) => {
  const ungoverned = await newAsset();
  const preflight = await get<Preflight>("/governance/enforcement/preflight");
  const found = await modeOf();
  expect(preflight.items.map((item) => item.asset_id)).toContain(ungoverned.id);

  await tenant.signIn(page, "viewer");
  await page.goto("/governance/enforcement");
  await expect(page.getByRole("heading", { level: 1, name: "Enforcement" })).toBeVisible();
  const mode = region(page, "Enforcement mode");
  await expect(mode).toContainText(found === "enforce" ? "Enforce" : "Observe");
  if (found === "observe") {
    await expect(mode).toContainText("Decisions a person made");
    await expect(mode).toContainText("recorded");
  }
  const list = region(page, "What enforce mode would block");
  await expect(list).toContainText("changes nothing");
  await expect(list.getByRole("row").filter({ hasText: ungoverned.name })).toContainText("Not governed");
  await expect(list.getByRole("row").filter({ hasText: ungoverned.name })).toContainText(
    preflight.items.find((item) => item.asset_id === ungoverned.id)!.reason_code,
  );
  await expect(region(page, "Would deny").locator("strong")).toHaveText(String(preflight.would_deny));
  await expect(region(page, "Would hold").locator("strong")).toHaveText(String(preflight.would_hold));
  // A viewer gets no control, and the API refuses a direct attempt.
  await expect(page.getByRole("button", { name: /Switch to/ })).toHaveCount(0);
  const refused = await refusal(
    "/governance/enforcement",
    { mode: found === "enforce" ? "observe" : "enforce", reason: "Synthetic attempt" },
    "viewer",
  );
  expect(refused.status).toBe(403);
  expect((await refusal("/governance/enforcement", { mode: "enforce", reason: "x" }, "reviewer")).status).toBe(403);
  expect(await modeOf()).toBe(found);
});

test("an administrator changes the mode with a reason, after confirming", async ({ page }) => {
  const found = await modeOf();
  try {
    await restore("observe");
    await tenant.signIn(page, "admin");
    await page.goto("/governance/enforcement");
    await page.getByRole("button", { name: "Switch to enforce mode" }).click();
    const dialog = page.getByRole("dialog");
    // The dialog says what will happen, and wording stays within spec 11.
    await expect(dialog).toContainText("no approval in force is denied");
    await expect(dialog).toContainText("Decisions a person made");

    // A reason is required, and the field says so.
    await dialog.getByRole("button", { name: "Confirm switch to enforce" }).click();
    const reason = dialog.getByLabel("Reason");
    await expect(reason).toHaveAttribute("aria-invalid", "true");
    await expect(reason).toHaveAccessibleDescription(/reason/i);
    expect(await modeOf()).toBe("observe");

    await reason.fill("Synthetic e2e switch to enforce");
    await dialog.getByRole("button", { name: "Confirm switch to enforce" }).click();
    await expect(dialog).toBeHidden();
    expect(await modeOf()).toBe("enforce");
    const mode = region(page, "Enforcement mode");
    await expect(mode).toContainText("Enforce");
    await expect(mode).toContainText("no approval in force");
    await expect(page.getByRole("button", { name: "Switch to observe mode" })).toBeVisible();
  } finally {
    await restore(found);
  }
});

test("setting the mode it already has shows the API's conflict", async ({ page }) => {
  const found = await modeOf();
  try {
    await restore("observe");
    await tenant.signIn(page, "admin");
    await page.goto("/governance/enforcement");
    await page.getByRole("button", { name: "Switch to enforce mode" }).click();
    // Another administrator switches it while this dialog is open.
    await post("/governance/enforcement", { mode: "enforce", reason: "Synthetic concurrent switch" }, "admin2");
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Reason").fill("Synthetic e2e stale switch");
    await dialog.getByRole("button", { name: "Confirm switch to enforce" }).click();
    await expect(dialog.getByRole("alert")).toContainText("The enforcement mode is already enforce.");
    await expect(dialog.getByRole("alert")).toContainText("ENFORCEMENT_MODE_UNCHANGED");
  } finally {
    await restore(found);
  }
});

// Phone width

test("all governance views fit a 375 pixel screen without page scroll", async ({ page }) => {
  const control = await firstControl();
  const withReview = await submitted();
  const evidence = await newEvidence(control.id);
  await page.setViewportSize({ width: 375, height: 812 });
  await tenant.signIn(page, "admin");
  const paths = [
    "/governance",
    "/governance/assets",
    `/governance/assets/${withReview.id}`,
    `/governance/assets/${withReview.id}/risk`,
    `/governance/assets/${evidence.asset.id}`,
    "/governance/approvals",
    `/governance/approvals/${withReview.reviewId}`,
    "/governance/policies",
    "/governance/compliance",
    `/governance/compliance?framework=${(await nist()).id}`,
    `/governance/compliance/controls/${control.id}`,
    "/governance/reviews",
    "/governance/enforcement",
  ];
  for (const path of paths) {
    await page.goto(path);
    // A route that does not exist renders a 404 heading, which would pass the width check.
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.getByRole("heading", { level: 1 })).not.toHaveText("404");
    const widths = await page.evaluate(() => ({
      scroll: document.documentElement.scrollWidth,
      client: document.documentElement.clientWidth,
    }));
    expect(widths.scroll, path).toBe(widths.client);
  }
});
