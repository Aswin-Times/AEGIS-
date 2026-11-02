import { expect, test } from "@playwright/test";
import { API, newRestrictedAgent, signIn, waitForIncident } from "./helpers";

// The complete workflow, through the real gateway, the real correlation worker, and a real browser.
test("repeated unauthorized actions reach the dashboard as an evidenced incident", async ({
  page,
}) => {
  const agent = await newRestrictedAgent();
  const denials = [
    await agent.act("run_shell_command"),
    await agent.act("run_shell_command"),
    await agent.act("run_shell_command"),
  ];
  for (const denial of denials) {
    expect(denial.outcome).toBe("DENY");
    expect(denial.execution).toBeNull();
  }

  const incident = await waitForIncident(agent.id, agent.headers);

  await signIn(page, "reviewer");
  await page.goto("/incidents");
  const row = page.getByRole("row").filter({ hasText: agent.name });
  await expect(row).toContainText("Repeated unauthorized tool attempts");
  await expect(row).toContainText("Open");
  await expect(row).toContainText("High");
  await row.getByRole("link", { name: incident.id.slice(0, 8) }).click();

  await expect(page).toHaveURL(new RegExp(`/incidents/${incident.id}$`));
  await expect(page.getByRole("heading", { name: "Repeated unauthorized tool attempts" })).toBeVisible();
  await expect(page.getByText("repeated_unauthorized_tools v1", { exact: true })).toBeVisible();

  const timeline = page.getByRole("region", { name: "Evidence timeline" });
  await expect(timeline.getByText("gateway.action_denied").first()).toBeVisible();
  await expect(timeline.getByText("UNKNOWN_TOOL (run_shell_command)").first()).toBeVisible();
  await expect(timeline.getByText("incident.created")).toBeVisible();

  // No findings exist until someone asks for them.
  await expect(page.getByText("No investigation has been run")).toBeVisible();
  await page.getByRole("button", { name: "Run investigation" }).click();

  const facts = page.getByRole("region", { name: "Verified facts" });
  await expect(facts).toContainText("verified security events are linked");
  await expect(facts).toContainText("No execution record exists for 3 denied requests");
  await expect(page.getByRole("region", { name: "Rule result" })).toContainText(
    "requires at least 3 matching events",
  );
  await expect(page.getByRole("region", { name: "What the records cannot show" })).toContainText(
    "do not show why",
  );
  await expect(page.getByRole("region", { name: "Recommended actions" })).toContainText(
    "AEGIS does not do this automatically",
  );
  const hypotheses = page.getByRole("region", { name: "AI hypotheses" });
  await expect(hypotheses).toContainText("No AI provider is configured");

  // An evidence reference leads to the authorized record it cites.
  await facts.getByRole("link", { name: /policy decision/ }).first().click();
  await expect(page).toHaveURL(/\/evidence\/policy_decision\//);
  await expect(page.getByText("UNKNOWN_TOOL")).toBeVisible();
  await expect(page.getByText("DENY")).toBeVisible();
});

test("the lifecycle is controlled, recorded, and refuses stale changes", async ({ page }) => {
  const agent = await newRestrictedAgent();
  for (let i = 0; i < 3; i += 1) await agent.act("run_shell_command");
  const incident = await waitForIncident(agent.id, agent.headers);

  await signIn(page, "reviewer");
  await page.goto(`/incidents/${incident.id}`);
  await expect(page.getByRole("button", { name: "Close incident" })).toHaveCount(0);

  await page.getByRole("button", { name: "Acknowledge" }).click();
  await page
    .getByRole("dialog", { name: "Acknowledge this incident?" })
    .getByRole("button", { name: "Acknowledge incident" })
    .click();
  await expect(page.getByTestId("incident-status")).toHaveText("Acknowledged");
  const history = page.getByRole("region", { name: "State changes" });
  await expect(history).toContainText("reviewer@synthetic.example.test");

  // Resolving needs a stated reason, and the browser form enforces it before the API does.
  await page.getByRole("button", { name: "Resolve" }).click();
  const resolve = page.getByRole("dialog", { name: "Resolve this incident?" });
  await resolve.getByLabel("Reason").fill("Synthetic: grants reviewed");
  await resolve.getByRole("button", { name: "Resolve incident" }).click();
  await expect(page.getByTestId("incident-status")).toHaveText("Resolved");
  await expect(history).toContainText("Synthetic: grants reviewed");

  // A change made elsewhere after this page loaded is refused, and says so.
  const stale = await (
    await fetch(`${API}/incidents/${incident.id}/close`, {
      method: "POST",
      headers: agent.headers,
      body: JSON.stringify({ expected_version: incident.version, reason: "stale" }),
    })
  ).json();
  expect(stale.error.code).toBe("INCIDENT_VERSION_CONFLICT");
});

test("security events show their agent, decision, and incident", async ({ page }) => {
  const agent = await newRestrictedAgent();
  let denial;
  for (let i = 0; i < 3; i += 1) denial = await agent.act("run_shell_command");
  const incident = await waitForIncident(agent.id, agent.headers);

  await signIn(page, "viewer");
  await page.goto(`/events?agent_id=${agent.id}`);
  await expect(page.getByRole("heading", { name: "Security Events" })).toBeVisible();
  const rows = page.getByRole("row").filter({ hasText: "gateway.action_denied" });
  await expect(rows).toHaveCount(3);
  await expect(rows.first()).toContainText(agent.name);
  await expect(rows.first()).toContainText("High");
  await expect(rows.first()).toContainText("run_shell_command");
  await expect(rows.first().getByRole("link", { name: incident.id.slice(0, 8) })).toHaveAttribute(
    "href",
    `/incidents/${incident.id}`,
  );
  await page.goto(`/decisions/${denial.decision_id}`);
  await expect(page.getByText("The tool did not run")).toBeVisible();
});

test("a viewer can read an incident but gets no controls", async ({ page }) => {
  const agent = await newRestrictedAgent();
  for (let i = 0; i < 3; i += 1) await agent.act("run_shell_command");
  const incident = await waitForIncident(agent.id, agent.headers);

  await signIn(page, "viewer");
  await page.goto(`/incidents/${incident.id}`);
  await expect(page.getByRole("heading", { name: "Repeated unauthorized tool attempts" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Evidence timeline" })).toBeVisible();
  for (const name of ["Acknowledge", "Investigate", "Resolve", "Run investigation"]) {
    await expect(page.getByRole("button", { name })).toHaveCount(0);
  }
});

test("queue filters and empty states come from the API", async ({ page }) => {
  await signIn(page, "viewer");
  await page.goto("/incidents?severity=critical");
  await expect(page.getByText("No matching incidents")).toBeVisible();
});

test("an unknown incident or evidence record shows not found", async ({ page }) => {
  await signIn(page, "viewer");
  const missing = "00000000-0000-4000-8000-000000000000";
  // Pages stream, so the status is sent before the lookup finishes. The content is what matters.
  await page.goto(`/incidents/${missing}`);
  await expect(page.getByText("This page could not be found")).toBeVisible();
  await page.goto(`/evidence/security_event/${missing}`);
  await expect(page.getByText("This page could not be found")).toBeVisible();
});

test("the overview reports incidents and any correlation backlog from stored records", async ({
  page,
}) => {
  const headers = (await newRestrictedAgent()).headers;
  // The worker may still be correlating earlier tests' events, so wait for it to settle.
  let overview = { active_incidents: -1, pending_correlation: -1 };
  await expect
    .poll(
      async () => {
        overview = await (await fetch(`${API}/overview`, { headers })).json();
        return overview.pending_correlation;
      },
      { timeout: 20_000, intervals: [250] },
    )
    .toBe(0);
  await signIn(page, "viewer");
  await expect(page.getByRole("link", { name: /^Active incidents/ })).toContainText(
    String(overview.active_incidents),
  );
});
