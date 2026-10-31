/// <reference lib="dom" />
import type { Page } from "@playwright/test";
import { expect, test } from "@playwright/test";
import axe from "axe-core";
import { apiToken, FIXTURE_HIGH, ingestFixture, seedProject, uiLogin, uniq } from "./helpers";

// The phone pass: the four pages a signed-in admin reaches most often, audited at 360x740.
// Each page must pass axe-core on the WCAG 2.2 A and AA rules and must not scroll sideways.
// The axe runner and the rule set match frontend/e2e/a11y.spec.ts.

const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function settle(page: Page): Promise<void> {
  await page.evaluate(async () => {
    for (let attempt = 0; attempt < 10; attempt += 1) {
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const running = document.getAnimations();
      if (running.length === 0) return;
      await Promise.all(running.map((animation) => animation.finished.catch(() => undefined)));
    }
  });
}

async function auditPhone(page: Page, name: string): Promise<void> {
  await page.waitForLoadState("networkidle");
  await settle(page);

  const widths = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    viewport: window.innerWidth,
  }));
  expect(
    widths.scroll,
    `${name} scrolls sideways: content is ${widths.scroll}px wide in a ${widths.viewport}px viewport`,
  ).toBeLessThanOrEqual(widths.viewport);

  // Evaluated through the devtools protocol, which the page CSP does not govern.
  await page.evaluate(axe.source);
  const result = await page.evaluate(
    async (tags) => {
      const api = (window as unknown as { axe: typeof axe; }).axe;
      return await api.run(document, { runOnly: { type: "tag", values: tags } });
    },
    WCAG_TAGS,
  );
  const report = result.violations
    .map((v) =>
      `${v.id} (${v.impact ?? "unknown"}): ${
        v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(", ")
      }`
    )
    .join("\n");
  expect(result.violations, `${name} has axe violations:\n${report}`).toEqual([]);
}

test("the projects list fits a 360px phone and passes axe", async ({ page, request }) => {
  const token = await apiToken(request);
  await seedProject(request, token, uniq("mobile-list"));
  await uiLogin(page);
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
  await auditPhone(page, "projects list");
});

test("the findings list fits a 360px phone and passes axe", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("mobile-findings");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await uiLogin(page);
  await page.goto(`/${slug}/findings`);
  await expect(page.locator("tbody tr").first()).toBeVisible();
  const search = page.getByRole("searchbox", { name: "Search findings" });
  await expect(search).toBeVisible();
  expect(await page.evaluate(() => matchMedia("(pointer: coarse)").matches)).toBe(true);
  expect((await search.boundingBox())!.height).toBeGreaterThanOrEqual(44);
  await auditPhone(page, "findings list");
});

test("a finding detail fits a 360px phone and passes axe", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("mobile-detail");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await uiLogin(page);
  await page.goto(`/${slug}/findings`);
  await page.locator("a[href*=\"/findings/\"]").first().click();
  await expect(page.getByRole("group", { name: "What is this finding?" })).toBeVisible();
  await auditPhone(page, "finding detail");
});

test("the project access page fits a 360px phone and passes axe", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("mobile-access");
  await seedProject(request, token, slug);
  await uiLogin(page);
  await page.goto(`/${slug}/access`);
  await expect(page.getByRole("heading", { name: /Direct Members/ })).toBeVisible();
  await auditPhone(page, "project access");
  const configuration = page.getByRole("button", { name: /^Configuration/ });
  await configuration.click();
  await expect(page.getByRole("menuitem", { name: "Access & Members" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  await auditPhone(page, "project configuration menu");
  await page.keyboard.press("Escape");
  await expect(configuration).toBeFocused();
});
