import { expect, test } from "@playwright/test";

test("visitors without JavaScript get a documentation path instead of a blank demo", async ({ browser, page, baseURL }) => {
  const plain = await browser.newPage({ javaScriptEnabled: false, viewport: page.viewportSize()! });
  try {
    await plain.goto(new URL("./", baseURL).href);
    await expect(plain.getByText(/This demo requires JavaScript/)).toBeVisible();
    await expect(plain.getByRole("link", { name: "Read the installation guide" })).toHaveAttribute(
      "href",
      "../docs/getting-started/",
    );
    await expect(plain.getByRole("link", { name: "return to the product site" })).toHaveAttribute(
      "href",
      "../",
    );
  } finally {
    await plain.close();
  }
});
