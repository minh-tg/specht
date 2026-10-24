import { expect, test } from "@playwright/test";

const canvas = { light: "rgb(244, 242, 236)", dark: "rgb(25, 24, 23)" };
for (const theme of ["light", "dark"] as const) {
  const opposite = theme === "light" ? "dark" : "light";

  test(`homepage follows ${theme} system preference until a choice is saved`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: theme });
    await page.goto("./");
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    await expect(page.locator("html")).toHaveCSS("background-color", canvas[theme]);
    await expect(page.getByRole("combobox", { name: "Color theme" })).toHaveValue("auto");
    await page.emulateMedia({ colorScheme: opposite });
    await expect(page.locator("html")).toHaveAttribute("data-theme", opposite);
    await expect(page.locator("html")).toHaveCSS("background-color", canvas[opposite]);
  });

  test(`saved ${theme} homepage preference overrides the system`, async ({ page }) => {
    await page.addInitScript((value) => localStorage.setItem("starlight-theme", value), theme);
    await page.emulateMedia({ colorScheme: opposite });
    await page.goto("./");
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    await expect(page.getByRole("combobox", { name: "Color theme" })).toHaveValue(theme);
    await page.emulateMedia({ colorScheme: theme });
    await page.emulateMedia({ colorScheme: opposite });
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
  });

  test(`homepage keeps the ${theme} system theme without JavaScript`, async ({
    browser,
    baseURL,
    page,
  }) => {
    const plain = await browser.newPage({
      javaScriptEnabled: false,
      colorScheme: theme,
      viewport: page.viewportSize()!,
    });
    try {
      await plain.goto(baseURL!);
      await expect(plain.locator("html")).toHaveCSS("background-color", canvas[theme]);
      await expect(plain.getByRole("heading", { level: 1 })).toBeVisible();
      await expect(plain.getByRole("combobox", { name: "Color theme" })).toHaveCount(0);
    } finally {
      await plain.close();
    }
  });
}

test("homepage theme choice works by keyboard and stays in sync with docs", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("./");
  const picker = page.getByRole("combobox", { name: "Color theme" });
  await picker.focus();
  await picker.press("ArrowDown");
  await expect(picker).toHaveValue("light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(picker).toBeFocused();
  await page.reload();
  await expect(picker).toHaveValue("light");
  await page
    .getByRole("navigation", { name: "Main navigation" })
    .getByRole("link", { name: "Docs", exact: true })
    .click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  const menu = page.getByRole("button", { name: "Menu", exact: true });
  const mobileMenu = await menu.isVisible();
  if (mobileMenu) await menu.click();
  await page.getByRole("combobox", { name: "Select theme" }).selectOption("dark");
  if (mobileMenu) await page.keyboard.press("Escape");
  await page.getByRole("banner").getByRole("link", { name: "Specht", exact: true }).click();
  await expect(picker).toHaveValue("dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.emulateMedia({ colorScheme: "light" });
  await picker.selectOption("auto");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator("html")).toHaveCSS("background-color", canvas.light);
});

test("homepage theme choice fits a 320px viewport", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto("./");
  const picker = page.getByRole("combobox", { name: "Color theme" });
  await expect(picker).toBeVisible();
  await expect(picker).toHaveCSS("font-size", "16px");
  const box = (await picker.boundingBox())!;
  expect(box.height).toBeGreaterThanOrEqual(44);
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(320);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});

test("homepage theme controls still work when preference storage is blocked", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.addInitScript(() => {
    Object.defineProperty(window, "localStorage", {
      get() {
        throw new DOMException("Storage denied", "SecurityError");
      },
    });
  });
  await page.emulateMedia({ colorScheme: "light" });
  await page.goto("./");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.getByRole("combobox", { name: "Color theme" }).selectOption("dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.emulateMedia({ colorScheme: "dark" });
  await page.emulateMedia({ colorScheme: "light" });
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  expect(errors).toEqual([]);
});
