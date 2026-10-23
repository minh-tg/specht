import { defineConfig } from "@playwright/test";

const base = process.env.SITE_BASE || "/";
const prefix = base.endsWith("/") ? base : `${base}/`;
const baseURL = `http://127.0.0.1:4327${prefix}`;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  workers: 2,
  retries: 0,
  reporter: "list",
  use: {
    baseURL,
    trace: "retain-on-failure",
    launchOptions: process.env.CHROMIUM_BIN ? { executablePath: process.env.CHROMIUM_BIN } : {},
  },
  webServer: {
    command: "pnpm preview --ignore-lock --host 127.0.0.1 --port 4327",
    url: baseURL,
    reuseExistingServer: false,
  },
  projects: [
    { name: "desktop", use: { viewport: { width: 1440, height: 1000 } } },
    {
      name: "plain-360",
      use: { viewport: { width: 360, height: 800 }, isMobile: false, hasTouch: false },
    },
  ],
});
