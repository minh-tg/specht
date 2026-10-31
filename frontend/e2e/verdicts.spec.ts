import { expect, test } from "@playwright/test";
import {
  apiToken,
  BASE_SHA,
  CHANGE_SHA,
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
    "Nothing first seen in this commit blocks this change.",
  );
});

test("an exact check link keeps its report after another scan of the same commit", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("gate-exact");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH, { commit_sha: BASE_SHA });
  await ingestFixture(request, token, slug, FIXTURE_HIGH, {
    commit_sha: CHANGE_SHA,
    base_revision: BASE_SHA,
  });
  const response = await request.get(`/api/v1/projects/${slug}/reports?commit=${CHANGE_SHA}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(response.ok()).toBeTruthy();
  const reports = await response.json() as Array<{ id: string; }>;
  await ingestFixture(request, token, slug, FIXTURE_HIGH_NEW, {
    commit_sha: CHANGE_SHA,
    base_revision: BASE_SHA,
  });
  await uiLogin(page);
  await page.goto(`/${slug}/changes/${CHANGE_SHA}`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("1 finding blocks this change.");
  await page.goto(`/${slug}/changes/${CHANGE_SHA}?report=${reports[0].id}&scope=introduced`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "Nothing first seen in this commit blocks this change.",
  );
});
