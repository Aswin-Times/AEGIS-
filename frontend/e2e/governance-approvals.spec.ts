import { expect, type Locator, type Page, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { API, newGovernanceTenant, type Tenant } from "./helpers";

// Everything here runs in a synthetic tenant of its own, so the demo tenant is left as it was.
// Holders of governance_reviewer: reviewer, admin, admin2. Not holders: reviewer2, viewer.
// admin submits, so admin is the submitter whenever a test needs a self-approval refusal.

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

/** The error code and message of a refused request, which is what the page must repeat. */
async function refusal(path: string, body: object, user: string) {
  const response = await call("POST", path, user, body);
  const payload = (await response.json()) as { error: { code: string; message: string } };
  return { status: response.status, ...payload.error };
}

const LOW_PROFILE = {
  asset_type: "ai_application",
  description: "Synthetic approval e2e asset",
  data_categories: ["public"],
  external_exposure: "none",
  autonomy_level: "advisory",
  human_oversight: "in_the_loop",
  declared_tool_access: [],
  impact_level: "negligible",
  deployment_environment: "development",
  third_party_reliance: "none",
};

type Review = {
  id: string;
  asset_id: string;
  status: string;
  required_approvers: number;
  assigned_reviewer: string | null;
  assessment_id: string;
  profile_version_id: string;
  required_controls: {
    self_approval_permitted: boolean;
    owner_approval_permitted: boolean;
    required_controls: { control: string; value: unknown }[];
    applicable_version_ids: string[];
  };
  findings: { control: string; severity: string; message: string }[];
};

/** A synthetic asset with a complete assessment and a submitted review, by admin. */
async function submitted(profile: object = LOW_PROFILE) {
  const name = `synthetic-approval-${randomUUID().slice(0, 8)}`;
  const asset = await post<{ id: string }>("/assets", {
    name,
    owner: "Synthetic E2E",
    risk_classification: "medium",
    intended_use: "Synthetic approval e2e check",
    is_synthetic: true,
  });
  await post(`/governance/assets/${asset.id}/profile`, profile);
  await post(`/governance/assets/${asset.id}/assess`, {});
  const review = await post<Review>(`/governance/assets/${asset.id}/submit`, {
    reason: "Synthetic submission for approval e2e",
  });
  return { name, assetId: asset.id, review };
}

type PolicyVersion = { id: string; version: number; approved: boolean; active: boolean };

/** A narrow policy that applies only to a model_provider asset in development with public data. */
async function activePolicy(controls: object, user = "admin") {
  const name = `synthetic-approval-policy-${randomUUID().slice(0, 8)}`;
  const policy = await post<{ id: string }>("/governance/policies", { name, category: "general" }, user);
  const version = await post<PolicyVersion>(
    `/governance/policies/${policy.id}/versions`,
    {
      document: {
        description: "Synthetic approval e2e policy",
        severity: "medium",
        applicability: {
          asset_types: ["model_provider"],
          environments: ["development"],
          data_categories: ["public"],
        },
        controls,
      },
      effective_from: new Date(Date.now() - 3_600_000).toISOString(),
    },
    user,
  );
  const path = `/governance/policies/${policy.id}/versions/${version.id}`;
  await post(`${path}/approve`, {}, "reviewer");
  await post(`${path}/activate`, {}, "admin");
  return {
    name,
    policyId: policy.id,
    versionId: version.id,
    // Runs in a finally block, so the policy never applies to a later submission.
    deactivate: async () => {
      const response = await call("POST", `${path}/deactivate`, "admin", {});
      expect([200, 409]).toContain(response.status);
    },
  };
}

const PROVIDER_PROFILE = { ...LOW_PROFILE, asset_type: "model_provider" };
const region = (page: Page, name: string) => page.getByRole("region", { name, exact: true });
const future = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 16);

/** The text of every element a field's aria-describedby points at. */
async function describedText(page: Page, field: Locator) {
  const ids = ((await field.getAttribute("aria-describedby")) ?? "").split(" ").filter(Boolean);
  const texts = await Promise.all(ids.map((id) => page.locator(`[id="${id}"]`).innerText()));
  return texts.join(" ");
}

async function open(page: Page, user: string, reviewId: string) {
  await tenant.signIn(page, user);
  await page.goto(`/governance/approvals/${reviewId}`);
}

async function confirm(page: Page, trigger: string, confirmLabel: string) {
  await page.getByRole("button", { name: trigger, exact: true }).click();
  await page.getByRole("button", { name: confirmLabel, exact: true }).click();
}

async function fillApproval(page: Page, reason: string) {
  await page.getByLabel("Reason", { exact: true }).fill(reason);
  await page.getByLabel("Valid until (UTC)").fill(future(300));
  await page.getByLabel("Next review by (UTC)").fill(future(150));
}

test("pending submission shows assessment, frozen controls, findings, and evidence with method", async ({
  page,
}) => {
  const policy = await activePolicy({
    required_human_oversight: ["in_the_loop"],
    minimum_approvers: 1,
  });
  try {
    const { name, assetId, review } = await submitted({
      ...PROVIDER_PROFILE,
      human_oversight: "after_the_fact",
    });
    expect(review.findings.length).toBeGreaterThan(0);
    const evidence = await post<{ id: string; description: string }>("/governance/evidence", {
      asset_id: assetId,
      category: "model_evaluation",
      description: `Synthetic approval evidence ${randomUUID().slice(0, 8)}`,
      source: {
        source_type: "external_reference",
        source_uri: "https://example.test/synthetic-evaluation",
        content_sha256: "b".repeat(64),
      },
    });
    await post(
      `/governance/evidence/${evidence.id}/verify`,
      { outcome: "VERIFIED", method: "manual_attestation", note: "Synthetic attestation" },
      "reviewer",
    );
    const assessments = await get<{
      items: { id: string; risk_level: string; score: number; status: string }[];
    }>(`/governance/assets/${assetId}/assessments`);
    const frozen = assessments.items.find((item) => item.id === review.assessment_id)!;

    await open(page, "reviewer", review.id);
    await expect(page.getByRole("heading", { name })).toBeVisible();

    const summary = region(page, "Review summary");
    await expect(summary).toContainText("Awaiting decision");
    await expect(summary).toContainText("Approvals needed 1");
    await expect(summary).toContainText("Approvals counted 0 of 1");
    // The flags are the ones frozen at submission, and silence means refusal.
    await expect(summary).toContainText("Self-approval by the submitter Not permitted");
    await expect(summary).toContainText("Approval by an asset owner Not permitted");

    const assessment = region(page, "Frozen assessment");
    await expect(assessment).toContainText(frozen.status === "COMPLETE" ? "Complete" : "Incomplete");
    await expect(assessment).toContainText(frozen.risk_level.charAt(0) + frozen.risk_level.slice(1).toLowerCase());
    await expect(assessment).toContainText(String(frozen.score));
    await expect(region(page, "Frozen profile")).toContainText("After the fact");

    const controls = region(page, "Required controls");
    await expect(controls).toContainText(policy.name);
    for (const item of review.required_controls.required_controls) {
      await expect(controls).toContainText(item.control);
    }
    const findings = region(page, "Findings");
    for (const finding of review.findings) await expect(findings).toContainText(finding.message);

    const proof = region(page, "Evidence");
    await expect(proof).toContainText(evidence.description);
    await expect(proof).toContainText("Manual attestation");
    await expect(proof).toContainText("Nothing was recomputed");
    await expect(proof).not.toContainText("Hash recomputed");
  } finally {
    await policy.deactivate();
  }
});

test("reviewer approves with dates, and history shows the decision", async ({ page }) => {
  const { assetId, review } = await submitted();
  await open(page, "reviewer", review.id);

  // Expiry is enforced only in enforce mode, so the hint names both modes.
  const dates = page.getByText("In enforce mode the gateway denies after this time");
  await expect(dates).toContainText("In observe mode the expiry is recorded, not blocked");
  await fillApproval(page, "Synthetic approval reason");
  await confirm(page, "Approve this review", "Confirm approval");
  await expect(page.getByRole("status")).toContainText("Decision recorded");

  const history = await get<{
    items: { type: string; decision: { kind: string; reason: string; valid_until: string } | null }[];
  }>(`/governance/assets/${assetId}/history`);
  const approval = history.items.find((item) => item.decision?.kind === "APPROVE")!;
  expect(approval.decision!.reason).toBe("Synthetic approval reason");
  expect(approval.decision!.valid_until).toMatch(/^\d{4}-\d\d-\d\dT.*(Z|\+00:00)$/);

  const detail = await get<{ governance_status: string }>(`/governance/assets/${assetId}`);
  expect(detail.governance_status).toBe("APPROVED");
  const log = region(page, "Decision history");
  await expect(log).toContainText("Approve");
  await expect(log).toContainText("Synthetic approval reason");
  await expect(region(page, "Review summary")).toContainText("Decided");
  // A decided review offers no further decision.
  await expect(page.getByRole("button", { name: "Approve this review", exact: true })).toHaveCount(0);
});

test("conditional approval requires conditions, and labels advisory ones not enforced", async ({
  page,
}) => {
  const { assetId, review } = await submitted();
  await open(page, "reviewer", review.id);

  await page.getByRole("radio", { name: "Approve with conditions" }).check();
  await fillApproval(page, "Synthetic conditional approval");
  await confirm(page, "Approve with conditions", "Confirm conditional approval");

  // Nothing was sent to the API as a decision, and the field says why.
  const conditions = page.getByLabel("Denied tools");
  await expect(page.getByText("Add at least one condition")).toBeVisible();
  await expect(conditions).toHaveAttribute("aria-invalid", "true");
  expect(await describedText(page, conditions)).toContain("Add at least one condition");
  await expect(page.getByLabel("Hold every action for approval")).toHaveAttribute("aria-invalid", "true");
  const before = await get<{ items: { kind: string | null }[] }>(`/governance/assets/${assetId}/history`);
  expect(before.items.filter((item) => item.kind === "APPROVE_CONDITIONAL")).toHaveLength(0);
  const after = await get<Review>(`/governance/approvals/${review.id}`);
  expect(after.status).toBe("OPEN");

  await conditions.fill("send_message");
  await page.getByLabel("Advisory conditions").fill("Review the outputs weekly");
  await confirm(page, "Approve with conditions", "Confirm conditional approval");
  await expect(page.getByRole("status")).toContainText("Decision recorded");

  const detail = await get<{ governance_status: string }>(`/governance/assets/${assetId}`);
  expect(detail.governance_status).toBe("CONDITIONALLY_APPROVED");
  const bound = region(page, "Conditions on this review");
  await expect(bound).toContainText("send_message");
  await expect(bound).toContainText("Enforced by the gateway");
  await expect(bound).toContainText("Review the outputs weekly");
  await expect(bound).toContainText("Advisory, not enforced");
});

test("conditions of an earlier vote are shown and bind the next approval", async ({ page }) => {
  const policy = await activePolicy({ minimum_approvers: 2 });
  try {
    const { review } = await submitted(PROVIDER_PROFILE);
    expect(review.required_approvers).toBe(2);
    const conditions = { denied_tools: ["send_message"], advisory_conditions: ["Weekly output review"] };
    await post(
      `/governance/approvals/${review.id}/approve`,
      {
        reason: "First vote, with conditions",
        valid_until: new Date(Date.now() + 300 * 86_400_000).toISOString(),
        next_review_at: new Date(Date.now() + 150 * 86_400_000).toISOString(),
        conditions,
      },
      "reviewer",
    );

    await open(page, "admin2", review.id);
    await expect(region(page, "Review summary")).toContainText("Approvals counted 1 of 2");
    const bound = region(page, "Conditions on this review");
    await expect(bound).toContainText("send_message");
    await expect(bound).toContainText("Enforced by the gateway");
    await expect(bound).toContainText("Weekly output review");
    await expect(bound).toContainText("Advisory, not enforced");

    // Conditions of every vote bind every later approval, so an approval without them is refused,
    // and the page repeats the API's own message.
    await page.getByRole("radio", { name: "Approve", exact: true }).check();
    await fillApproval(page, "Second vote, without conditions");
    await confirm(page, "Approve this review", "Confirm approval");
    const expected = await refusal(
      `/governance/approvals/${review.id}/approve`,
      {
        reason: "Second vote, without conditions",
        valid_until: new Date(Date.now() + 300 * 86_400_000).toISOString(),
        next_review_at: new Date(Date.now() + 150 * 86_400_000).toISOString(),
      },
      "admin2",
    );
    expect(expected).toMatchObject({ status: 409, code: "CONDITIONS_MISMATCH" });
    await expect(page.getByRole("alert").filter({ hasText: expected.message })).toBeVisible();

    // The conditional form starts from the bound conditions, so the same ones can be carried.
    await page.getByRole("radio", { name: "Approve with conditions" }).check();
    await expect(page.getByLabel("Denied tools")).toHaveValue("send_message");
    await expect(page.getByLabel("Advisory conditions")).toHaveValue("Weekly output review");
    await confirm(page, "Approve with conditions", "Confirm conditional approval");
    await expect(page.getByRole("status")).toContainText("Decision recorded");
    const stored = await get<Review>(`/governance/approvals/${review.id}`);
    expect(stored.status).toBe("DECIDED");
  } finally {
    await policy.deactivate();
  }
});

test("reject and request information record a reason", async ({ page }) => {
  const rejected = await submitted();
  const asked = await submitted();

  await open(page, "reviewer", rejected.review.id);
  await page.getByRole("radio", { name: "Reject", exact: true }).check();
  // A reason is required, and its field says so.
  await confirm(page, "Reject this review", "Confirm rejection");
  const reason = page.getByLabel("Reason", { exact: true });
  await expect(reason).toHaveAttribute("aria-invalid", "true");
  expect(await describedText(page, reason)).toContain("Give a reason");
  expect((await get<Review>(`/governance/approvals/${rejected.review.id}`)).status).toBe("OPEN");

  await reason.fill("Synthetic rejection reason");
  await confirm(page, "Reject this review", "Confirm rejection");
  await expect(page.getByRole("status")).toContainText("Decision recorded");
  expect((await get<Review>(`/governance/approvals/${rejected.review.id}`)).status).toBe("DECIDED");
  expect((await get<{ governance_status: string }>(`/governance/assets/${rejected.assetId}`)).governance_status).toBe(
    "REJECTED",
  );
  await expect(region(page, "Decision history")).toContainText("Synthetic rejection reason");

  await page.goto(`/governance/approvals/${asked.review.id}`);
  await page.getByRole("radio", { name: "Request information" }).check();
  await confirm(page, "Request information from the submitter", "Confirm request");
  await expect(page.getByLabel("Reason", { exact: true })).toHaveAttribute("aria-invalid", "true");
  await page.getByLabel("Reason", { exact: true }).fill("Synthetic question for the submitter");
  await confirm(page, "Request information from the submitter", "Confirm request");
  await expect(page.getByRole("status")).toContainText("Decision recorded");
  expect((await get<Review>(`/governance/approvals/${asked.review.id}`)).status).toBe("INFO_REQUESTED");
  await expect(region(page, "Review summary")).toContainText("Information requested");
  await expect(region(page, "Decision history")).toContainText("Synthetic question for the submitter");
});

test("a double click on confirm records one decision", async ({ page }) => {
  const { assetId, review } = await submitted();
  await open(page, "reviewer", review.id);
  await page.getByRole("radio", { name: "Reject", exact: true }).check();
  await page.getByLabel("Reason", { exact: true }).fill("Synthetic rejection, confirmed twice");
  await page.getByRole("button", { name: "Reject this review", exact: true }).click();
  await page.getByRole("button", { name: "Confirm rejection", exact: true }).dblclick();
  await expect(page.getByRole("status")).toContainText("Decision recorded");
  // A second request would have been refused and shown as an alert.
  await expect(page.locator("#decision-error")).toHaveCount(0);
  const history = await get<{ items: { kind: string | null }[] }>(
    `/governance/assets/${assetId}/history`,
  );
  expect(history.items.filter((item) => item.kind === "REJECT")).toHaveLength(1);
});

test("submitter sees the self-approval refusal message", async ({ page }) => {
  const { review } = await submitted();
  // admin holds the role and submitted, so the control is shown and the API refuses.
  await open(page, "admin", review.id);
  await fillApproval(page, "Synthetic self-approval attempt");
  await confirm(page, "Approve this review", "Confirm approval");

  const expected = await refusal(
    `/governance/approvals/${review.id}/approve`,
    {
      reason: "x",
      valid_until: new Date(Date.now() + 300 * 86_400_000).toISOString(),
      next_review_at: new Date(Date.now() + 150 * 86_400_000).toISOString(),
    },
    "admin",
  );
  expect(expected).toMatchObject({ status: 403, code: "SELF_APPROVAL_REFUSED" });
  await expect(page.getByRole("alert").filter({ hasText: expected.message })).toBeVisible();
  expect((await get<Review>(`/governance/approvals/${review.id}`)).status).toBe("OPEN");
  const decisions = await get<{ items: { type: string; kind: string | null }[] }>(
    `/governance/assets/${review.asset_id}/history`,
  );
  expect(decisions.items.filter((item) => item.kind === "APPROVE")).toHaveLength(0);
});

test("user without the governance role sees permission denied and no decision controls", async ({
  page,
}) => {
  const { review } = await submitted();
  for (const user of ["reviewer2", "viewer"]) {
    await open(page, user, review.id);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    // The record can be read, and the decision cannot be made.
    await expect(region(page, "Review summary")).toBeVisible();
    await expect(page.getByRole("alert").filter({ hasText: "governance reviewer role" })).toBeVisible();
    for (const label of ["Approve this review", "Reject this review"]) {
      await expect(page.getByRole("button", { name: label })).toHaveCount(0);
    }
    await expect(page.getByLabel("Reason", { exact: true })).toHaveCount(0);

    // The API refuses in any case.
    for (const action of ["approve", "reject", "request-information"]) {
      const response = await call("POST", `/governance/approvals/${review.id}/${action}`, user, {
        reason: "Synthetic refused decision",
        valid_until: new Date(Date.now() + 300 * 86_400_000).toISOString(),
        next_review_at: new Date(Date.now() + 150 * 86_400_000).toISOString(),
      });
      expect(response.status).toBe(403);
    }
  }
  expect((await get<Review>(`/governance/approvals/${review.id}`)).status).toBe("OPEN");
});

test("a profile change after submission shows the not-current refusal", async ({ page }) => {
  const { assetId, review } = await submitted();
  await post(`/governance/assets/${assetId}/profile`, {
    ...LOW_PROFILE,
    description: "Changed after submission",
  });

  await open(page, "reviewer", review.id);
  // The frozen state is shown as frozen, with what changed since.
  await expect(region(page, "Frozen profile")).toContainText("profile has changed since");
  // A refused review is resubmitted only after information is requested, or rejected.
  await expect(region(page, "Frozen profile")).toContainText("request information");
  await fillApproval(page, "Synthetic approval of a stale review");
  await confirm(page, "Approve this review", "Confirm approval");
  const expected = await refusal(
    `/governance/approvals/${review.id}/approve`,
    {
      reason: "x",
      valid_until: new Date(Date.now() + 300 * 86_400_000).toISOString(),
      next_review_at: new Date(Date.now() + 150 * 86_400_000).toISOString(),
    },
    "reviewer",
  );
  expect(expected).toMatchObject({ status: 409, code: "ASSESSMENT_NOT_CURRENT" });
  await expect(page.getByRole("alert").filter({ hasText: expected.message })).toBeVisible();
  expect((await get<Review>(`/governance/approvals/${review.id}`)).status).toBe("OPEN");
});

test("a reviewer can assign another reviewer, and the list shows the queue", async ({ page }) => {
  const { name, review } = await submitted();
  const people = await get<{ items: { id: string; email: string }[] }>("/governance/people");
  const admin2 = people.items.find((item) => item.email.startsWith("admin2@"))!;

  await open(page, "reviewer", review.id);
  await page.getByLabel("Assign reviewer").selectOption({ label: admin2.email });
  await page.getByRole("button", { name: "Assign reviewer" }).click();
  await expect(page.getByRole("status")).toContainText("Reviewer assigned");
  expect((await get<Review>(`/governance/approvals/${review.id}`)).assigned_reviewer).toBe(admin2.id);

  // Only the assigned reviewer can decide, and the API says so.
  const refused = await refusal(`/governance/approvals/${review.id}/reject`, { reason: "x" }, "reviewer");
  expect(refused.code).toBe("NOT_ASSIGNED_REVIEWER");

  await page.goto("/governance/approvals");
  const row = page.getByRole("row").filter({ hasText: name });
  await expect(row).toContainText("Awaiting decision");
  await expect(row).toContainText(admin2.email);
  await row.getByRole("link", { name }).click();
  await expect(page).toHaveURL(new RegExp(`/governance/approvals/${review.id}$`));
});

test("approval list filters by status", async ({ page }) => {
  const open1 = await submitted();
  await tenant.signIn(page, "viewer");
  await page.goto("/governance/approvals?status=OPEN");
  await expect(page.getByRole("row").filter({ hasText: open1.name })).toHaveCount(1);
  await page.goto("/governance/approvals?status=DECIDED");
  await expect(page.getByRole("row").filter({ hasText: open1.name })).toHaveCount(0);
});

test("policy library shows versions, status, applicability, and approver", async ({ page }) => {
  const draftName = `synthetic-approval-draft-${randomUUID().slice(0, 8)}`;
  let policy: Awaited<ReturnType<typeof activePolicy>> | undefined;
  try {
    policy = await activePolicy({ required_human_oversight: ["in_the_loop"] });
    const draft = await post<{ id: string }>("/governance/policies", { name: draftName, category: "general" });
    await post(`/governance/policies/${draft.id}/versions`, {
      document: { description: "Synthetic draft", severity: "low" },
      effective_from: new Date(Date.now() - 3_600_000).toISOString(),
    });
    const people = await get<{ items: { id: string; email: string }[] }>("/governance/people");
    const reviewer = people.items.find((item) => item.email.startsWith("reviewer@"))!;

    // reviewer2 may list people but holds no role, so it sees emails and no controls.
    await tenant.signIn(page, "reviewer2");
    await page.goto("/governance/policies");
    const active = page.getByRole("row").filter({ hasText: policy!.name });
    await expect(active).toContainText("Version 1");
    await expect(active).toContainText("Active");
    await expect(active).toContainText("Model provider");
    await expect(active).toContainText("Development");
    await expect(active).toContainText("Public");
    await expect(active).toContainText(reviewer.email);
    await expect(page.getByRole("button", { name: /^(Approve|Activate|Deactivate) / })).toHaveCount(0);

    const drafted = page.getByRole("row").filter({ hasText: draftName });
    await expect(drafted).toContainText("Draft");
    await expect(drafted).toContainText("Not approved");
    await expect(drafted).toContainText("Applies to every asset");
    await expect(page.getByText("not a statement that any asset complies")).toBeVisible();
    // Active means switched on, and a version applies only from its effective date.
    await expect(page.getByText("applies only from its effective date")).toBeVisible();

    // A viewer reads the library too, and has no controls either.
    await tenant.signIn(page, "viewer");
    await page.goto("/governance/policies");
    await expect(page.getByRole("row").filter({ hasText: policy!.name })).toContainText("Active");
    await expect(page.getByRole("button", { name: /^(Approve|Activate|Deactivate) / })).toHaveCount(0);
  } finally {
    await policy?.deactivate();
  }
});

test("author cannot approve their own policy version", async ({ page }) => {
  // admin holds the role and authors the version, so the control is shown and the API refuses.
  const name = `synthetic-approval-own-${randomUUID().slice(0, 8)}`;
  const policy = await post<{ id: string }>("/governance/policies", { name, category: "general" });
  const version = await post<PolicyVersion>(`/governance/policies/${policy.id}/versions`, {
    document: { description: "Synthetic own policy", severity: "low" },
    effective_from: new Date(Date.now() - 3_600_000).toISOString(),
  });
  const versionPath = `/governance/policies/${policy.id}/versions/${version.id}`;
  try {
    await tenant.signIn(page, "admin");
    await page.goto("/governance/policies");
    await page.getByRole("button", { name: `Approve ${name} version 1`, exact: true }).click();
    await page.getByRole("button", { name: "Confirm approval", exact: true }).click();

    const expected = await refusal(`${versionPath}/approve`, {}, "admin");
    expect(expected).toMatchObject({ status: 403, code: "SELF_APPROVAL_REFUSED" });
    await expect(page.getByRole("alert").filter({ hasText: expected.message })).toBeVisible();
    const stored = await get<{ items: { id: string; versions: PolicyVersion[] }[] }>(
      "/governance/policies?limit=100",
    );
    expect(stored.items.find((item) => item.id === policy.id)!.versions[0]!.approved).toBe(false);

    // Another holder approves, and an admin activates and deactivates.
    await tenant.signIn(page, "reviewer");
    await page.goto("/governance/policies");
    const row = page.getByRole("row").filter({ hasText: name });
    await page.getByRole("button", { name: `Approve ${name} version 1`, exact: true }).click();
    await page.getByRole("button", { name: "Confirm approval", exact: true }).click();
    await expect(row).toContainText("Approved, not active");
    await expect(row).toContainText("reviewer@");
    // Only an admin changes what applies.
    await expect(page.getByRole("button", { name: `Activate ${name} version 1` })).toHaveCount(0);

    await tenant.signIn(page, "admin");
    await page.goto("/governance/policies");
    await page.getByRole("button", { name: `Activate ${name} version 1`, exact: true }).click();
    await expect(page.getByRole("dialog")).toContainText("only from its effective date");
    await page.getByRole("button", { name: "Confirm activation", exact: true }).click();
    await expect(row).toContainText("Active");
    await page.getByRole("button", { name: `Deactivate ${name} version 1`, exact: true }).click();
    await page.getByRole("button", { name: "Confirm deactivation", exact: true }).click();
    await expect(row).toContainText("Approved, not active");
  } finally {
    const response = await call("POST", `${versionPath}/deactivate`, "admin", {});
    expect([200, 409]).toContain(response.status);
  }
});

test("review and policy pages fit a 375 pixel screen", async ({ page }) => {
  const { review } = await submitted();
  await page.setViewportSize({ width: 375, height: 812 });
  await tenant.signIn(page, "reviewer");
  for (const path of [`/governance/approvals/${review.id}`, "/governance/approvals", "/governance/policies"]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    const widths = await page.evaluate(() => ({
      scroll: document.documentElement.scrollWidth,
      client: document.documentElement.clientWidth,
    }));
    expect(widths.scroll, path).toBe(widths.client);
  }
});
