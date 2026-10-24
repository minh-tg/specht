import { expect, test } from "@playwright/test";

test("documentation code stays keyboard reachable without JavaScript", async ({
  browser,
  baseURL,
  page,
}) => {
  const plain = await browser.newPage({ javaScriptEnabled: false, viewport: page.viewportSize()! });
  try {
    await plain.goto(new URL("docs/getting-started/", baseURL).href);
    const code = plain.locator(".expressive-code pre").first();
    await expect(code).toHaveAttribute("tabindex", "0");
    await plain.keyboard.press("Tab");
    await code.focus();
    await expect(code).toBeFocused();
    await expect(code).toHaveCSS("outline-style", "solid");
    expect(await plain.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
      page.viewportSize()!.width,
    );
  } finally {
    await plain.close();
  }
});

test("missing pages return 404 and link back within the site base", async ({ page, baseURL }) => {
  const response = await page.goto("./not-a-real-page/");
  expect(response?.status()).toBe(404);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Page not found");
  const home = page.getByRole("link", { name: "Go to the product homepage", exact: true });
  await expect(home).toHaveAttribute("href", new URL(baseURL!).pathname);
  await home.click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(/Know what blocks/);
});

test("the homepage does not simulate live processing with decorative motion", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.goto("./");
  await expect(page.locator(".hero-aside")).toHaveCount(0);
  expect(await page.evaluate(() => document.getAnimations().length)).toBe(0);
});

test("homepage controls are not horizontally clipped", async ({ page }) => {
  await page.goto("./");
  await page.evaluate(() => document.fonts.ready);
  const width = page.viewportSize()!.width;
  for (const anchor of await page
    .locator(".site-header a:visible, .site-header select:visible, .hero-actions a, .site-footer a")
    .all()) {
    const box = await anchor.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(width);
  }
});
