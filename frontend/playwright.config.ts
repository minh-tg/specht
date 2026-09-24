import { defineConfig, devices } from "@playwright/test";

// The smoke suite drives the shipped artifact: the Go server with the
// embedded React build (scripts/e2e-ui.sh boots it). E2E_BASE_URL lets the
// script point Playwright at its ephemeral port; CHROMIUM_BIN lets NixOS
// (and other FHS-less hosts) substitute a system Chromium for the bundled
// download.
const baseURL = process.env.E2E_BASE_URL ?? "http://127.0.0.1:18081";

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
    ...(process.env.CHROMIUM_BIN
      ? { launchOptions: { executablePath: process.env.CHROMIUM_BIN } }
      : {}),
  },
});
