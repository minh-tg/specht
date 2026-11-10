import { expect, test } from "@playwright/test";
import {
  apiToken,
  BASE_SHA,
  CHANGE_SHA,
  FIXTURE_GITLEAKS,
  FIXTURE_HIGH,
  FIXTURE_HIGH_MEDIUM,
  FIXTURE_HIGH_NEW,
  ingestFixture,
  seedProject,
  uiLogin,
  uniq,
} from "./helpers";

test("CI explanations retain the project-wide scope and tightened floor", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("gate-scope");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH_MEDIUM, { commit_sha: BASE_SHA });
  await ingestFixture(request, token, slug, FIXTURE_HIGH, {
    commit_sha: CHANGE_SHA,
    base_revision: BASE_SHA,
  });
  const response = await request.get(`/api/v1/projects/${slug}/reports?commit=${CHANGE_SHA}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(response.ok()).toBeTruthy();
  const reports = await response.json() as Array<{ id: string; }>;
  await uiLogin(page);
  const link = `/${slug}/changes/${CHANGE_SHA}?report=${reports[0].id}&severity=medium`;
  await page.goto(`${link}&scope=project`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "2 findings block this project.",
  );
  await expect(page.getByRole("region", { name: "Findings blocking this project" })).toBeVisible();
  await page.goto(`${link}&scope=introduced`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "Nothing new in this commit blocks this change.",
  );
});

test("every scanner's check link shows the same verdict for the commit", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("gate-commit");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH, { commit_sha: BASE_SHA });
  const change = { commit_sha: CHANGE_SHA, base_revision: BASE_SHA, branch: "feat/two-scanners" };
  await ingestFixture(request, token, slug, FIXTURE_HIGH_NEW, change);
  await ingestFixture(request, token, slug, FIXTURE_GITLEAKS, { ...change, scanner: "gitleaks" });

  const auth = { headers: { Authorization: `Bearer ${token}` } };
  const reports = await (await request.get(
    `/api/v1/projects/${slug}/reports?commit=${CHANGE_SHA}`,
    auth,
  )).json() as Array<{ id: string; tool_name: string; }>;
  expect(reports).toHaveLength(2);
  const commitGate = await (await request.get(
    `/api/v1/projects/${slug}/gate?introduced_only=true&commit=${CHANGE_SHA}`,
    auth,
  )).json() as { blocking_count: number; };
  // Each step alone blocks on fewer: the page must add them up whichever link was followed.
  for (const report of reports) {
    const own = await (await request.get(
      `/api/v1/projects/${slug}/gate?introduced_only=true&report_id=${report.id}`,
      auth,
    )).json() as { blocking_count: number; };
    expect(own.blocking_count).toBeGreaterThan(0);
    expect(own.blocking_count).toBeLessThan(commitGate.blocking_count);
  }

  await uiLogin(page);
  const headline = `${commitGate.blocking_count} findings block this change.`;
  for (const report of reports) {
    await page.goto(`/${slug}/changes/${CHANGE_SHA}?report=${report.id}&scope=introduced`);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(headline);
    await expect(page.getByText(/^Scanned by .+ and .+,/)).toBeVisible();
  }
  await page.goto(`/${slug}/changes/${CHANGE_SHA.slice(0, 7)}`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(headline);
});
