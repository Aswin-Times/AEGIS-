import { expect, type Page, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { API, newGovernanceTenant, type Tenant } from "./helpers";

// The governance workflow end to end (spec section 1, Success), in a synthetic tenant of its own so
// the demo tenant is left as it was. Registering the agent and adding evidence are API-only, as in
// the product; owners, purpose, assessment, submission, review, and the decision are made in the
// browser; the gateway is called with the agent's real key; and the history is read on the page.
// People: admin submits, reviewer (granted governance_reviewer by admin) decides, admin2 and
// reviewer2 own the asset and hold no grant, and viewer reads the history.

type Headers = Record<string, string>;
let tenant: Tenant;
const tokens: Record<string, Headers> = {};
const ids: Record<string, string> = {};

async function call(method: string, path: string, user: string, body?: object, headers?: Headers) {
  return fetch(`${API}${path}`, {
    method,
    headers: headers ?? tokens[user],
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
  for (const user of ["admin", "admin2", "reviewer", "reviewer2", "viewer"]) {
    tokens[user] = await tenant.headers(user);
  }
  const people = await get<{ items: { id: string; email: string }[] }>("/governance/people?limit=100");
  for (const user of ["admin", "admin2", "reviewer", "reviewer2"]) {
    ids[user] = people.items.find((item) => item.email.startsWith(`${user}@`))!.id;
  }
  await post("/governance/role-grants", { user_id: ids.reviewer }, "admin");
  // A runtime policy that allows everything, so only governance can deny an action here.
  const runtime = await post<{ id: string }>("/policies", { name: "synthetic-allow-all" });
  const version = await post<{ id: string }>(`/policies/${runtime.id}/versions`, {
    document: { rules: [{ id: "allow", effect: "allow", match: {}, reason_code: "ALLOWED_BY_RULE" }] },
  });
  await post(`/policies/${runtime.id}/activate`, { version_id: version.id });
});

const region = (page: Page, name: string) => page.getByRole("region", { name, exact: true });
const future = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 16);

type Action = {
  outcome: string;
  reason_code: string;
  execution: { status: string; result: Record<string, unknown> | null } | null;
};

type HistoryEntry = {
  seq: number;
  type: string;
  kind: string | null;
  decision: { reason: string; evidence_ids: string[]; policy_version_ids: string[] } | null;
};

test("an agent goes from registration to an enforced, suspended, and traceable decision", async ({
  page,
}) => {
  // 1. Register an agent with real grants and a real key (API-only, as in the product).
  const name = `synthetic-workflow-${randomUUID().slice(0, 8)}`;
  const asset = await post<{ id: string }>("/assets", {
    name,
    owner: "Synthetic E2E",
    risk_classification: "medium",
    intended_use: "Synthetic workflow e2e",
    is_synthetic: true,
  });
  const agent = await post<{ id: string }>("/agents", {
    asset_id: asset.id,
    name: `${name}-agent`,
    owner: "Synthetic E2E",
  });
  const document = await post<{ id: string }>("/resources", {
    kind: "document",
    name: `${name}-document`,
    classification: "internal",
    content: { synthetic: true },
    is_synthetic: true,
  });
  await post(`/agents/${agent.id}/tool-grants`, { tool: "calculate" });
  await post(`/agents/${agent.id}/tool-grants`, { tool: "read_document" });
  await post(`/agents/${agent.id}/resource-grants`, { resource_id: document.id });
  const credential = await post<{ key: string }>(`/agents/${agent.id}/credentials`, {});
  const agentHeaders = { Authorization: `Bearer ${credential.key}`, "Content-Type": "application/json" };
  const act = async (tool: string, resourceId: string | null, params: object) => {
    const response = await call("POST", "/gateway/actions", "agent", {
      idempotency_key: randomUUID(),
      tool,
      resource_id: resourceId,
      params,
    }, agentHeaders);
    expect(response.status, await response.clone().text()).toBe(200);
    return (await response.json()) as Action;
  };

  // A policy for this kind of asset only, so the review has frozen controls and a finding.
  const policyName = `synthetic-workflow-policy-${randomUUID().slice(0, 8)}`;
  const policy = await post<{ id: string }>("/governance/policies", { name: policyName, category: "general" });
  const policyVersion = await post<{ id: string }>(`/governance/policies/${policy.id}/versions`, {
    document: {
      description: "Synthetic workflow policy",
      severity: "high",
      applicability: { asset_types: ["autonomous_agent"], environments: ["production_internal"] },
      controls: {
        required_owners: ["business", "technical"],
        required_evidence_categories: ["security_evaluation"],
        required_human_oversight: ["in_the_loop"],
      },
    },
    effective_from: new Date(Date.now() - 3_600_000).toISOString(),
  });
  const policyPath = `/governance/policies/${policy.id}/versions/${policyVersion.id}`;
  await post(`${policyPath}/approve`, {}, "reviewer");
  await post(`${policyPath}/activate`, {}, "admin");

  try {
    // 2. Owners, picked from real users in the browser.
    await tenant.signIn(page, "admin");
    await page.goto(`/governance/assets/${asset.id}`);
    await expect(page.getByRole("heading", { name })).toBeVisible();
    await page.getByLabel("Business owner").selectOption({ label: "admin2@synthetic.example.test" });
    await page.getByLabel("Technical owner").selectOption({ label: "reviewer2@synthetic.example.test" });
    await page.getByRole("button", { name: "Save profile" }).click();
    await expect(page.getByRole("status")).toContainText("Profile saved as version 1");
    type Detail = {
      governance_status: string | null;
      business_owner: { id: string } | null;
      technical_owner: { id: string } | null;
      profile: { id: string; version: number; profile: Record<string, unknown> } | null;
    };
    let detail = await get<Detail>(`/governance/assets/${asset.id}`);
    expect(detail.business_owner?.id).toBe(ids.admin2);
    expect(detail.technical_owner?.id).toBe(ids.reviewer2);
    expect(detail.governance_status).toBe("DRAFT");

    // 3. Purpose, permitted and prohibited use, and every risk factor.
    await page.getByLabel("Asset type").selectOption("autonomous_agent");
    await page.getByLabel("Deployment environment").selectOption("production_internal");
    await page.getByLabel("Business purpose").fill("Answer synthetic internal questions for staff");
    await page.getByLabel("Intended use").fill("Internal document lookups and arithmetic");
    await page.getByLabel("Prohibited use").fill("Sending messages outside the organization");
    await page.getByRole("checkbox", { name: "Internal", exact: true }).check();
    await page.getByLabel("External exposure").selectOption("internal_users");
    await page.getByLabel("Autonomy level").selectOption("supervised");
    await page.getByLabel("Human oversight").selectOption("on_the_loop");
    await page.getByLabel("Impact level").selectOption("minor");
    await page.getByLabel("Third-party reliance").selectOption("vetted");
    await page.getByRole("button", { name: "Save profile" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Profile saved as version 2" })).toBeVisible();
    detail = await get<Detail>(`/governance/assets/${asset.id}`);
    expect(detail.profile?.version).toBe(2);
    expect(detail.profile?.profile).toMatchObject({
      business_owner_id: ids.admin2,
      technical_owner_id: ids.reviewer2,
      business_purpose: "Answer synthetic internal questions for staff",
      intended_use: "Internal document lookups and arithmetic",
      prohibited_use: "Sending messages outside the organization",
    });

    // 4. A complete assessment, which recomputes to its stored result.
    await page.getByRole("button", { name: "Run risk assessment" }).click();
    await expect(
      page.getByRole("status").filter({ hasText: "Assessment recorded. It is complete." }),
    ).toBeVisible();
    const risk = await get<{
      assessment: { id: string; score: number; risk_level: string; input: Record<string, unknown> };
      recomputed_matches: boolean;
    }>(`/governance/assets/${asset.id}/risk`);
    expect(risk.recomputed_matches).toBe(true);
    // Tool access comes from the real grants: compute and an internal read, level 2.
    expect(risk.assessment.input).toMatchObject({ tool_access_source: "grants", tool_access_level: 2 });
    expect([risk.assessment.score, risk.assessment.risk_level]).toEqual([160, "MEDIUM"]);

    // Evidence for the required category: added by the admin and verified by the reviewer through
    // the API, since adding evidence has no form in the dashboard.
    const evidenceDescription = `Synthetic security evaluation ${randomUUID().slice(0, 8)}`;
    const evidence = await post<{ id: string }>("/governance/evidence", {
      asset_id: asset.id,
      category: "security_evaluation",
      description: evidenceDescription,
      source: { source_type: "inline", content_text: "Synthetic evaluation: no transmit tools." },
    });
    await post(
      `/governance/evidence/${evidence.id}/verify`,
      { outcome: "VERIFIED", method: "content_recomputed", note: "Recomputed the stored hash" },
      "reviewer",
    );

    // 5 and 6. Submission in the browser, with the required controls frozen on the review.
    await page.reload();
    await page.getByLabel("Submission reason").fill("Ready for review: synthetic workflow");
    await page.getByRole("button", { name: "Submit for review" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Submitted for review" })).toBeVisible();
    type Review = {
      id: string;
      status: string;
      submitted_by: string;
      assessment_id: string;
      required_controls: { applicable_version_ids: string[]; required_controls: { control: string }[] };
      findings: { control: string; message: string }[];
    };
    const reviews = await get<{ items: Review[] }>(`/governance/approvals?asset_id=${asset.id}`);
    expect(reviews.items).toHaveLength(1);
    const review = reviews.items[0]!;
    expect([review.status, review.submitted_by, review.assessment_id]).toEqual([
      "OPEN",
      ids.admin,
      risk.assessment.id,
    ]);
    expect(review.required_controls.applicable_version_ids).toEqual([policyVersion.id]);
    expect(review.findings.map((item) => item.control)).toEqual(["required_human_oversight"]);
    expect((await get<Detail>(`/governance/assets/${asset.id}`)).governance_status).toBe("UNDER_REVIEW");
    await expect(region(page, "Policies")).toContainText(policyName);

    // 7. The reviewer reads the frozen assessment, controls, findings, and verified evidence.
    await tenant.signIn(page, "reviewer");
    await page.goto(`/governance/approvals/${review.id}`);
    await expect(page.getByRole("heading", { name })).toBeVisible();
    const assessment = region(page, "Frozen assessment");
    await expect(assessment).toContainText("Complete");
    await expect(assessment).toContainText("Medium");
    await expect(assessment).toContainText("160");
    const controls = region(page, "Required controls");
    await expect(controls).toContainText(policyName);
    for (const item of review.required_controls.required_controls) {
      await expect(controls).toContainText(item.control);
    }
    await expect(region(page, "Findings")).toContainText(review.findings[0]!.message);
    const proof = region(page, "Evidence");
    await expect(proof).toContainText(evidenceDescription);
    await expect(proof).toContainText("Verified");
    await expect(proof).toContainText("The hash was recomputed from the content and matched.");

    // 8. Conditional approval, denying document reads and citing the evidence.
    await page.getByRole("radio", { name: "Approve with conditions" }).check();
    await page.getByLabel("Reason", { exact: true }).fill("Adequate, with document reads denied");
    await page.getByLabel("Valid until (UTC)").fill(future(30));
    await page.getByLabel("Next review by (UTC)").fill(future(15));
    await page.getByLabel("Denied tools").fill("read_document");
    await page.getByRole("checkbox", { name: new RegExp(evidenceDescription) }).check();
    await page.getByRole("button", { name: "Approve with conditions", exact: true }).click();
    await page.getByRole("button", { name: "Confirm conditional approval", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("Decision recorded");
    expect((await get<Detail>(`/governance/assets/${asset.id}`)).governance_status).toBe(
      "CONDITIONALLY_APPROVED",
    );

    // 10. Enforce mode, through the real gateway with the agent's key.
    expect((await get<{ enforcement_mode: string }>("/governance/enforcement")).enforcement_mode).toBe("observe");
    await post("/governance/enforcement", { mode: "enforce", reason: "Synthetic workflow e2e" });
    try {
      const allowed = await act("calculate", null, { operator: "add", a: 2, b: 3 });
      expect([allowed.outcome, allowed.execution?.status]).toEqual(["ALLOW", "SUCCEEDED"]);
      expect(allowed.execution?.result).toEqual({ value: 5 });
      const denied = await act("read_document", document.id, {});
      expect([denied.outcome, denied.reason_code]).toEqual(["DENY", "GOVERNANCE_CONDITION_DENIED"]);
      expect(denied.execution).toBeNull();

      // 11. A suspension by the reviewer, and the same agent is denied.
      await post(`/governance/assets/${asset.id}/suspend`, { reason: "Synthetic suspension" }, "reviewer");
      const blocked = await act("calculate", null, { operator: "add", a: 2, b: 3 });
      expect([blocked.outcome, blocked.reason_code]).toEqual(["DENY", "GOVERNANCE_BLOCKED"]);
      expect(blocked.execution).toBeNull();
    } finally {
      await post("/governance/enforcement", { mode: "observe", reason: "Restore after workflow e2e" });
    }

    // 12. The history in the dashboard, in audit order, matching the API.
    const history = await get<{ items: HistoryEntry[]; total: number }>(
      `/governance/assets/${asset.id}/history?limit=100`,
    );
    expect(history.total).toBe(history.items.length);
    expect(history.items.map((entry) => entry.kind ?? entry.type)).toEqual([
      "profile_version",
      "profile_version",
      "assessment",
      "SUBMIT",
      "APPROVE_CONDITIONAL",
      "SUSPEND",
    ]);
    const approval = history.items.find((entry) => entry.kind === "APPROVE_CONDITIONAL")!;
    expect(approval.decision!.evidence_ids).toEqual([evidence.id]);
    expect(approval.decision!.policy_version_ids).toEqual([policyVersion.id]);

    await tenant.signIn(page, "viewer");
    await page.goto(`/governance/assets/${asset.id}`);
    const rows = region(page, "History").getByRole("row");
    await expect(rows).toHaveCount(history.items.length + 1);
    for (const [index, entry] of history.items.entries()) {
      const row = rows.nth(index + 1);
      await expect(row.getByRole("cell").first()).toHaveText(String(entry.seq));
      if (entry.decision) await expect(row).toContainText(entry.decision.reason);
    }
    await expect(rows.nth(4)).toContainText("Decision: Submit");
    await expect(rows.nth(5)).toContainText("Decision: Approve conditional");
    await expect(rows.nth(6)).toContainText("Decision: Suspend");
  } finally {
    const response = await call("POST", `${policyPath}/deactivate`, "admin", {});
    expect([200, 409]).toContain(response.status);
  }
});
