import type { APIRequestContext, Page } from "@playwright/test";
import { expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";

// Shared by the browser suites. The script bootstraps an admin account (two-phase ADMIN_EMAILS);
// these defaults mirror it, and E2E_UI_ADMIN_* overrides keep both sides in sync.

export const ADMIN_EMAIL = process.env.E2E_UI_ADMIN_EMAIL ?? "journey-admin@specht.local";
export const ADMIN_PASSWORD = process.env.E2E_UI_ADMIN_PASSWORD ?? "journey-admin-123";

// Playwright runs with frontend/ as cwd; the fixtures live in the repo's
// e2e/testdata next to the Go suite.
export const FIXTURE_HIGH = path.resolve(process.cwd(), "../e2e/testdata/high.sarif.json");
export const FIXTURE_MEDIUM = path.resolve(process.cwd(), "../e2e/testdata/medium.sarif.json");
export const FIXTURE_HIGH_MEDIUM = path.resolve(
  process.cwd(),
  "../e2e/testdata/high-medium.sarif.json",
);
export const FIXTURE_HIGH_NEW = path.resolve(process.cwd(), "../e2e/testdata/high-new.sarif.json");

// A baseline scan and the pull-request scan that adds one blocking finding on top of it.
export const BASE_SHA = "1111111111111111111111111111111111111111";
export const CHANGE_SHA = "2222222222222222222222222222222222222222";

export function uniq(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

export async function apiToken(request: APIRequestContext): Promise<string> {
  const res = await request.post("/api/v1/auth/login", {
    data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
  const body = await res.json();
  return body.token as string;
}

export async function seedProject(
  request: APIRequestContext,
  token: string,
  slug: string,
): Promise<void> {
  const res = await request.post("/api/v1/projects", {
    headers: { Authorization: `Bearer ${token}` },
    data: { name: slug, slug },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
}

export async function ingestFixture(
  request: APIRequestContext,
  token: string,
  slug: string,
  fixturePath: string,
  extra: Record<string, unknown> = {},
): Promise<void> {
  const res = await request.post("/api/v1/reports", {
    headers: { Authorization: `Bearer ${token}` },
    data: {
      project: slug,
      scanner: "sarif",
      raw_data: JSON.parse(readFileSync(fixturePath, "utf8")),
      ...extra,
    },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
}

export async function uiLogin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.fill("#login-email", ADMIN_EMAIL);
  await page.fill("#login-password", ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/$/);
}
