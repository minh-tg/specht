import { expect, type Page, test } from "@playwright/test";
import axe from "axe-core";
import snapshot from "../src/demo/snapshot.json" with { type: "json" };

declare global {
  interface Window {
    axe: typeof axe;
    __demoCredentialAccess: number;
  }
}

const requests = new WeakMap<Page, string[]>();
test.beforeEach(async ({ page }) => {
  const calls: string[] = [];
  requests.set(page, calls);
  page.on("websocket", (socket) => calls.push(socket.url()));
  page.on("request", (request) => {
    if (
      ["fetch", "xhr", "websocket"].includes(request.resourceType())
      || new URL(request.url()).pathname.startsWith("/api/")
    ) calls.push(request.url());
  });
});
test.afterEach(async ({ page }) => expect(requests.get(page)).toEqual([]));

const project = `/${snapshot.slug}`;
for (
  const [name, path] of [
    ["findings", `${project}/findings`],
    ["blocked change", `${project}/changes/${snapshot.commit}`],
    ["reports", `${project}/reports`],
    ["waiver history", `${project}/waivers`],
  ] as const
) {
  for (const theme of ["light", "dark"] as const) {
    test(`${name} ${theme} uses real UI, fits and passes axe without an API`, async ({ page }) => {
      await page.goto(`./#${path}`);
      await expect(page.getByText("Read-only demo · Sample data", { exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      if (theme === "light") {
        await page.getByRole("button", { name: "Dark theme", exact: true }).click();
      }
      await expect(page.getByRole("button", { name: "Dark theme", exact: true })).toHaveAttribute(
        "aria-pressed",
        String(theme === "dark"),
      );
      await expect(page.getByText(/Could not load|Couldn't load|Loading findings|Loading reports/))
        .toHaveCount(0);
      await page.evaluate(() => document.fonts.ready);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
        page.viewportSize()!.width,
      );
      const axeURL = new URL("test-axe.js", page.url()).href.split("#")[0];
      await page.route(
        axeURL,
        (route) => route.fulfill({ contentType: "text/javascript", body: axe.source }),
      );
      await page.addScriptTag({ url: axeURL });
      const errors = await page.evaluate(async () =>
        (await window.axe.run(document, {
          runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"] },
        })).violations.map((v) => ({ id: v.id, targets: v.nodes.map((n) => n.target) }))
      );
      expect(errors).toEqual([]);
    });
  }
}

test("browse a finding and retain deep links on refresh", async ({ page }) => {
  await page.goto("./");
  const link = page.getByRole("link", { name: "SQL injection in user query", exact: true });
  await link.click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("SQL injection in user query");
  await page.reload();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("SQL injection in user query");
  await expect(page.getByRole("button", { name: /Request waiver|Save triage|Delete/ })).toHaveCount(
    0,
  );
});

test("the blocked change retains the introduced finding and existing debt", async ({ page }) => {
  await page.goto(`./#${project}/changes/${snapshot.commit}`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("1 finding blocks this change.");
  await expect(page.getByRole("heading", { name: /SQL injection in user query/, level: 3 }))
    .toBeVisible();
  await page.getByText(/1 other finding blocks this project/).click();
  await expect(page.getByText("Hardcoded credentials in app config", { exact: true }))
    .toBeVisible();
});

test("configuration and uploads have an explicit unavailable state", async ({ page }) => {
  await page.goto(`./#${project}/reports/upload`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Not included in this demo");
  await page.getByRole("link", { name: "Back to sample findings" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(snapshot.slug);
});

test("no session or service worker is created", async ({ page }) => {
  await page.goto("./");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem("specht.session"))).toBeNull();
  expect(
    await page.evaluate(() => navigator.serviceWorker.getRegistrations().then((r) => r.length)),
  ).toBe(0);
  await expect(page.locator("meta[http-equiv=\"Content-Security-Policy\"]")).toHaveAttribute(
    "content",
    /connect-src 'none'/,
  );
});
