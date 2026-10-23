import { expect, test } from "@playwright/test";
import axe from "axe-core";

declare global {
  interface Window {
    axe: typeof axe;
  }
}

const routes = [
  "",
  "docs/getting-started/",
  "docs/scanners/",
  "docs/ci-gates/",
  "docs/triage-and-waivers/",
  "docs/self-hosting/",
];

for (const theme of ["light", "dark"] as const) {
  for (const route of routes) {
    test(`${theme}: ${route || "homepage"} fits and passes axe`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      await page.addInitScript((value) => localStorage.setItem("starlight-theme", value), theme);
      await page.goto(`./${route}`);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      await page.evaluate(() => document.fonts.ready);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
        page.viewportSize()!.width,
      );
      for (const image of await page.locator("img").all()) {
        await image.scrollIntoViewIfNeeded();
        await expect
          .poll(() => image.evaluate((el) => (el as HTMLImageElement).naturalWidth))
          .toBeGreaterThan(0);
      }
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.addScriptTag({ content: axe.source });
      const violations = await page.evaluate(async () => {
        const results = await window.axe.run(document, {
          runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"] },
        });
        return results.violations.map(({ id, nodes }) => ({
          id,
          targets: nodes.map((node) => node.target),
        }));
      });
      expect(violations).toEqual([]);
    });
  }
}

test("homepage navigation works without JavaScript", async ({ browser, baseURL, page }) => {
  const plain = await browser.newPage({ javaScriptEnabled: false, viewport: page.viewportSize()! });
  try {
    await plain.goto(new URL("./", baseURL).href);
    await expect(plain.getByRole("heading", { name: /Know what blocks/ })).toBeVisible();
    await plain.getByRole("link", { name: "Evaluate locally", exact: false }).last().click();
    await expect(
      plain.getByRole("heading", { level: 1, name: "Evaluate Specht locally" }),
    ).toBeVisible();
  } finally {
    await plain.close();
  }
});

test("reduced motion disables animations and smooth scrolling", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("./");
  expect(await page.evaluate(() => getComputedStyle(document.documentElement).scrollBehavior)).toBe(
    "auto",
  );
  expect(await page.evaluate(() => document.getAnimations().length)).toBe(0);
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#main$/);
});

test("internal links and fragments resolve within the configured base", async ({
  page,
  request,
  baseURL,
}) => {
  const checked = new Map<string, Set<string>>();
  for (const route of routes) {
    await page.goto(`./${route}`);
    const links = await page
      .locator("a[href]")
      .evaluateAll((anchors) => anchors.map((anchor) => (anchor as HTMLAnchorElement).href));
    for (const href of links) {
      const url = new URL(href);
      if (url.origin !== new URL(baseURL!).origin) continue;
      expect(url.pathname.startsWith(new URL(baseURL!).pathname), href).toBeTruthy();
      const key = `${url.origin}${url.pathname}${url.search}`;
      let ids = checked.get(key);
      if (!ids) {
        const response = await request.get(key);
        expect(response.ok(), key).toBeTruthy();
        if ((response.headers()["content-type"] || "").includes("text/html")) {
          const html = await response.text();
          ids = new Set(
            await page.evaluate(
              (content) =>
                Array.from(
                  new DOMParser().parseFromString(content, "text/html").querySelectorAll("[id]"),
                  (element) => element.id,
                ),
              html,
            ),
          );
        } else {
          ids = new Set();
        }
        checked.set(key, ids);
      }
      if (url.hash) expect(ids.has(decodeURIComponent(url.hash.slice(1))), href).toBeTruthy();
    }
  }
});

test("homepage uses local assets and contains honest preview guidance", async ({
  page,
  baseURL,
}, info) => {
  const external: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).origin !== new URL(baseURL!).origin) external.push(request.url());
  });
  await page.goto("./");
  await expect(page.getByText("Experimental preview.", { exact: true })).toBeVisible();
  await expect(page.getByText(/No tagged release yet/)).toBeVisible();
  await page.locator(".site-footer").scrollIntoViewIfNeeded();
  expect(await page.locator("img").count()).toBe(2);
  for (const image of await page.locator("img").all()) {
    await image.scrollIntoViewIfNeeded();
    await expect
      .poll(() => image.evaluate((el) => (el as HTMLImageElement).naturalWidth))
      .toBeGreaterThan(0);
  }
  expect(external).toEqual([]);
  await page.screenshot({
    path: info.outputPath("homepage.png"),
    fullPage: true,
    animations: "disabled",
  });
});
