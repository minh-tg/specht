import { defineConfig } from "@playwright/test";
const base = process.env.DEMO_BASE || "/demo/";
export default defineConfig({
  testDir: "./demo-tests",
  fullyParallel: true,
  workers: 2,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: `http://127.0.0.1:4328${base}`,
    trace: "retain-on-failure",
    launchOptions: process.env.CHROMIUM_BIN ? { executablePath: process.env.CHROMIUM_BIN } : {},
  },
  webServer: {
    command:
      "pnpm exec vite preview --config vite.demo.config.ts --host 127.0.0.1 --port 4328 --strictPort",
    url: `http://127.0.0.1:4328${base}`,
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
