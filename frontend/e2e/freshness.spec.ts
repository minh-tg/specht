import { expect, test } from "@playwright/test";
import { apiToken, FIXTURE_HIGH, ingestFixture, seedProject, uiLogin, uniq } from "./helpers";

test("a fresh browser response does not make old completed evidence look newly scanned", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("report-freshness");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  const response = await request.get(`/api/v1/projects/${slug}/stats`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(response.ok()).toBeTruthy();
  const stats = await response.json();
  // This field must come from the real server, not a browser history-page walk.
  expect(stats.latest_completed_report.id).toBe(stats.latest_report.id);
  const oldCompletion = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const oldReceipt = new Date(Date.parse(oldCompletion) - 2 * 60 * 1000).toISOString();
  const failedReceipt = new Date(Date.now() - 60 * 1000).toISOString();
  await page.route(`**/api/v1/projects/${slug}/stats`, async (route) => {
    await route.fulfill({
      json: {
        ...stats,
        report_count: 2,
        latest_completed_report: {
          ...stats.latest_completed_report,
          created_at: oldReceipt,
          completed_at: oldCompletion,
        },
        latest_report: {
          ...stats.latest_report,
          id: "99999999-9999-4999-8999-999999999999",
          status: "failed",
          created_at: failedReceipt,
          completed_at: failedReceipt,
        },
      },
    });
  });
  await uiLogin(page);
  await page.goto(`/${slug}/findings`);
  const completed = page.getByText(/Latest completed report/);
  const attempt = page.getByText(/Latest attempt/);
  await expect(completed.locator("time")).toHaveAttribute("datetime", oldCompletion);
  await expect(attempt).toContainText("Failed");
  await expect(attempt.locator("time")).toHaveAttribute("datetime", failedReceipt);
  await expect(page.getByText(/^Page data fetched/)).toBeVisible();
  const refreshedStats = page.waitForResponse((r) =>
    new URL(r.url()).pathname === `/api/v1/projects/${slug}/stats`
  );
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await refreshedStats;
  await expect(completed.locator("time")).toHaveAttribute("datetime", oldCompletion);
  await expect(attempt.locator("time")).toHaveAttribute("datetime", failedReceipt);
});
