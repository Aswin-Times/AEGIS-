import { defineConfig } from "@playwright/test";

// Runs against the live local stack (see README). Set AEGIS_E2E_CHANNEL="" to use Playwright's
// own Chromium, for example in CI after `npx playwright install chromium`.
const channel = process.env.AEGIS_E2E_CHANNEL ?? "msedge";

export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  fullyParallel: false,
  reporter: "list",
  timeout: 60_000,
  use: {
    baseURL: process.env.AEGIS_E2E_BASE_URL ?? "http://127.0.0.1:3000",
    ...(channel ? { channel } : {}),
    trace: "off",
  },
});
