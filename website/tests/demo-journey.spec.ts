import { expect, test } from "@playwright/test";

test("the product site opens a working read-only demo and returns within its base", async ({
  page,
  baseURL,
}) => {
  const api: string[] = [];
  page.on("websocket", (socket) => api.push(socket.url()));
  page.on("request", (request) => {
    if (
      ["fetch", "xhr", "websocket"].includes(request.resourceType()) ||
      new URL(request.url()).pathname.startsWith("/api/")
    )
      api.push(request.url());
  });
  await page.goto("./");
  await page.getByRole("link", { name: "Try the demo", exact: true }).click();
  await expect(page.getByText("Read-only demo · Sample data", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "SQL injection in user query", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("SQL injection in user query");
  await page.reload();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("SQL injection in user query");
  await page
    .getByRole("navigation", { name: "Demo navigation" })
    .getByRole("link", { name: "Blocked change", exact: true })
    .click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("1 finding blocks this change.");
  await page
    .getByRole("navigation", { name: "Demo navigation" })
    .getByRole("link", { name: "Waiver history", exact: true })
    .click();
  await page.getByRole("button", { name: /^History of/ }).click();
  await expect(page.getByText("Requested", { exact: true })).toBeVisible();
  await page
    .getByRole("navigation", { name: "Demo navigation" })
    .getByRole("link", { name: "Reports", exact: true })
    .click();
  await expect(
    page.getByText("Uploads require a local installation.", { exact: false }),
  ).toBeVisible();
  await expect(page.getByRole("link", { name: /^Upload (a )?report$/ })).toHaveCount(0);
  await page.getByRole("link", { name: "Evaluate locally", exact: true }).click();
  await expect(
    page.getByRole("heading", { level: 1, name: "Evaluate Specht locally" }),
  ).toBeVisible();
  expect(new URL(page.url()).pathname).toBe(new URL("docs/getting-started/", baseURL!).pathname);
  await page.goBack();
  await expect(page.getByText("Read-only demo · Sample data", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Back to product", exact: true }).click();
  await expect(page.getByRole("heading", { name: /Know what blocks/ })).toBeVisible();
  expect(new URL(page.url()).pathname).toBe(new URL(baseURL!).pathname);
  expect(api).toEqual([]);
});
