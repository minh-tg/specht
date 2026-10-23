import { expect, test } from "@playwright/test";
import snapshot from "../src/demo/snapshot.json" with { type: "json" };

test("an existing session is neither read nor replaced by the demo", async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.setItem("specht.session", "pre-existing-session-marker");
    window.__demoCredentialAccess = 0;
    const read = Storage.prototype.getItem;
    const write = Storage.prototype.setItem;
    Storage.prototype.getItem = function(key) {
      if (key === "specht.session") window.__demoCredentialAccess++;
      return read.call(this, key);
    };
    Storage.prototype.setItem = function(key, value) {
      if (key === "specht.session") window.__demoCredentialAccess++;
      return write.call(this, key, value);
    };
  });
  await page.goto("./");
  await expect(page.getByRole("link", { name: "SQL injection in user query", exact: true }))
    .toBeVisible();
  expect(await page.evaluate(() => window.__demoCredentialAccess)).toBe(0);
  expect(await page.evaluate(() => sessionStorage.getItem("specht.session"))).toBe(
    "pre-existing-session-marker",
  );
});

test("CSP independently blocks an accidental live API request", async ({ browser, baseURL, page }) => {
  const probe = await browser.newPage({ viewport: page.viewportSize()! });
  let reached = false;
  try {
    await probe.route("**/api/v1/demo-probe", (route) => {
      reached = true;
      return route.fulfill({ json: { unexpected: true } });
    });
    await probe.goto(new URL("./", baseURL).href);
    const outcome = await probe.evaluate(() =>
      fetch("/api/v1/demo-probe").then(() => "allowed", () => "blocked")
    );
    expect(outcome).toBe("blocked");
    expect(reached).toBe(false);
  } finally {
    await probe.close();
  }
});

test("waiver audit history can be inspected without management actions", async ({ page }) => {
  await page.goto(`./#/${snapshot.slug}/waivers`);
  await page.getByRole("button", { name: /^History of/ }).click();
  await expect(page.getByText("Requested", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /Approve|Reject|Withdraw|Delete/ })).toHaveCount(0);
});

test("live monitoring is explicitly unavailable instead of pretending to scan", async ({ page }) => {
  await page.goto(`./#/${snapshot.slug}/changes/${snapshot.commit}`);
  await page.getByRole("button", { name: "Wait for a new report", exact: true }).click();
  await expect(
    page.getByRole("status").filter({
      hasText: "Live report monitoring is unavailable in this fixed sample.",
    }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Wait for a new report", exact: true }))
    .toBeVisible();
});
