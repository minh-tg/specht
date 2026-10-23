import { expect, test } from "@playwright/test";
import axe from "axe-core";

test("product views support click and keyboard selection without changing focus unexpectedly", async ({
  page,
}) => {
  await page.goto("./");
  const change = page.getByRole("tab", { name: "CI decision" });
  const findings = page.getByRole("tab", { name: "Finding triage" });
  await expect(change).toHaveAttribute("aria-selected", "true");
  await findings.click();
  await expect(page.getByRole("tabpanel", { name: "Finding triage" })).toBeVisible();
  await expect(page.getByRole("tabpanel", { name: "CI decision" })).not.toBeVisible();
  await findings.press("ArrowRight");
  await expect(change).toBeFocused();
  await expect(change).toHaveAttribute("aria-selected", "true");
  await change.press("End");
  await expect(findings).toBeFocused();
  await findings.press("Home");
  await expect(change).toBeFocused();
});

test("full-size viewer is keyboard reachable, passes axe and restores focus", async ({ page }) => {
  await page.goto("./");
  await page.getByRole("tab", { name: "Finding triage" }).click();
  const opener = page.getByRole("link", { name: "Open full-size Specht findings screenshot" });
  await opener.focus();
  await opener.press("Enter");
  const dialog = page.getByRole("dialog", { name: "Product screenshot · Sample data" });
  await expect(dialog).toBeVisible();
  const region = dialog.getByRole("region", { name: "Full-size screenshot" });
  await expect(region).toHaveAttribute("tabindex", "0");
  await expect
    .poll(() => dialog.locator("img").evaluate((image) => (image as HTMLImageElement).naturalWidth))
    .toBe(1440);
  await page.addScriptTag({ content: axe.source });
  expect(
    await page.evaluate(async () =>
      (
        await window.axe.run(document, {
          runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"] },
        })
      ).violations.map((v) => v.id),
    ),
  ).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(opener).toBeFocused();
  await opener.click();
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await expect(opener).toBeFocused();
});

test("both screenshots remain accessible without JavaScript", async ({
  browser,
  page,
  baseURL,
}) => {
  const plain = await browser.newPage({ javaScriptEnabled: false, viewport: page.viewportSize()! });
  try {
    await plain.goto(new URL("./", baseURL).href);
    await expect(plain.locator('[role="tablist"]')).toBeHidden();
    await expect(plain.locator("[data-product-image]")).toHaveCount(2);
    for (const image of await plain.locator("[data-product-image]").all())
      await expect(image).toBeVisible();
    await expect(
      plain.getByRole("link", { name: "Open full-size Specht findings screenshot" }),
    ).toHaveAttribute("href", /images\/findings\.webp$/);
  } finally {
    await plain.close();
  }
});

test("useful product content starts within the first desktop viewport", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("./");
  await page.evaluate(() => document.fonts.ready);
  const box = await page.locator(".product-frame").first().boundingBox();
  expect(box!.y).toBeLessThan(520);
});
