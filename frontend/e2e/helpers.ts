import type { APIRequestContext, Locator, Page } from "@playwright/test";
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
export const FIXTURE_GITLEAKS = path.resolve(process.cwd(), "../e2e/testdata/gitleaks.json");
export const FIXTURE_NUCLEI = path.resolve(process.cwd(), "../e2e/testdata/nuclei.jsonl");
export const FIXTURE_GOSEC_JSON = path.resolve(
  process.cwd(),
  "../internal/parser/testdata/foreign/gosec.json",
);
export const FIXTURE_HIGH_NEW = path.resolve(process.cwd(), "../e2e/testdata/high-new.sarif.json");

// A baseline scan and the pull-request scan that adds one blocking finding on top of it.
export const BASE_SHA = "1111111111111111111111111111111111111111";
export const CHANGE_SHA = "2222222222222222222222222222222222222222";

/** Opens a dropdown (the Base UI Select) and picks the option with this visible label. */
export async function chooseOption(
  page: Page,
  control: Locator,
  label: string | RegExp,
): Promise<void> {
  await control.click();
  await page.getByRole("option", { name: label, exact: true }).click();
}

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

/** Signs the page in as any account, for the journeys that need a non-admin person. */
export async function uiLoginAs(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/login");
  await page.fill("#login-email", email);
  await page.fill("#login-password", password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/$/);
}

/** Registers a new account through the API and returns its credentials. */
export async function registerPerson(
  request: APIRequestContext,
  prefix: string,
): Promise<{ email: string; password: string; }> {
  const email = `${uniq(prefix)}@example.com`;
  const password = "journey-person-123";
  const res = await request.post("/api/v1/auth/register", { data: { email, password } });
  expect(res.ok(), await res.text()).toBeTruthy();
  return { email, password };
}

/** Files a waiver request for the project's first finding and returns that request's id. */
export async function requestWaiver(
  request: APIRequestContext,
  token: string,
  slug: string,
  reason: string,
): Promise<string> {
  const headers = { Authorization: `Bearer ${token}` };
  const list = await request.get(`/api/v1/projects/${slug}/findings`, { headers });
  expect(list.ok(), await list.text()).toBeTruthy();
  const findings = (await list.json()) as Array<{ id: string; }>;
  expect(findings.length).toBeGreaterThan(0);
  const res = await request.post(`/api/v1/projects/${slug}/waivers/requests`, {
    headers,
    data: {
      target_ids: [findings[0]!.id],
      reason,
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
  return (await res.json()).id as string;
}
