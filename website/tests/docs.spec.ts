import { expect, test } from "@playwright/test";
import axe from "axe-core";

test("docs search returns real pages and Escape restores focus", async ({ page }) => {
  await page.goto("./docs/getting-started/");
  const opener = page.getByRole("button", { name: "Search docs", exact: true });
  await opener.click();
  const dialog = page.getByRole("dialog", { name: "Search docs" });
  await expect(dialog).toBeVisible();
  await dialog.locator("input").fill("fingerprint");
  const result = dialog.locator('a[href*="/docs/self-hosting/"]').first();
  await expect(result).toBeVisible();
  await page.addScriptTag({ content: axe.source });
  const violations = await page.evaluate(async () => {
    const result = await window.axe.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"] },
    });
    return result.violations.map((violation) => violation.id);
  });
  expect(violations).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(opener).toBeFocused();
  await opener.click();
  await dialog.locator("input").fill("fingerprint");
  await result.click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Self-hosting responsibilities");
});

test("docs sidebar navigation remains usable on narrow screens", async ({ page }, info) => {
  await page.goto("./docs/getting-started/");
  const menu = page.getByRole("button", { name: "Menu", exact: true });
  if (info.project.name === "plain-360") {
    await menu.click();
    await expect(page.locator("#starlight__sidebar:popover-open")).toHaveCount(1);
  }
  await page.getByRole("link", { name: "Scanner reports", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Scanner reports");
  if (info.project.name === "plain-360")
    await expect(page.locator("#starlight__sidebar:popover-open")).toHaveCount(0);
});

test("code copy preserves commands when narrow blocks wrap", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("./docs/getting-started/");
  await page.locator(".expressive-code").first().getByRole("button", { name: /Copy/ }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied.trim()).toBe(
    "git clone https://github.com/minh-tg/specht.git\ncd specht\ncp deploy/.env.prod.example deploy/.env.prod",
  );
});
