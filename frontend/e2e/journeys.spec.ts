import type { APIRequestContext } from "@playwright/test";
import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";

// Browser journeys for the pages the COMP suites cannot prove: the seven
// COMP-only entries BP-63..BP-69 against the shipped artifact. The script
// bootstraps an admin account (two-phase ADMIN_EMAILS) — these defaults
// mirror it; E2E_UI_ADMIN_* overrides keep both sides in sync.

const ADMIN_EMAIL = process.env.E2E_UI_ADMIN_EMAIL ?? "journey-admin@specht.local";
const ADMIN_PASSWORD = process.env.E2E_UI_ADMIN_PASSWORD ?? "journey-admin-123";

// Playwright runs with frontend/ as cwd; the fixtures live in the repo's
// e2e/testdata next to the Go suite.
const FIXTURE_HIGH = path.resolve(process.cwd(), "../e2e/testdata/high.sarif.json");
const FIXTURE_MEDIUM = path.resolve(process.cwd(), "../e2e/testdata/medium.sarif.json");

const HIGH_TITLE = "Hardcoded credentials in app config";

function uniq(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

async function apiToken(request: APIRequestContext): Promise<string> {
  const res = await request.post("/api/v1/auth/login", {
    data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
  const body = await res.json();
  return body.token as string;
}

async function seedProject(request: APIRequestContext, token: string, slug: string): Promise<void> {
  const res = await request.post("/api/v1/projects", {
    headers: { Authorization: `Bearer ${token}` },
    data: { name: slug, slug },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
}

async function ingestFixture(
  request: APIRequestContext,
  token: string,
  slug: string,
  fixturePath: string,
): Promise<void> {
  const res = await request.post("/api/v1/reports", {
    headers: { Authorization: `Bearer ${token}` },
    data: {
      project: slug,
      scanner: "sarif",
      raw_data: JSON.parse(readFileSync(fixturePath, "utf8")),
    },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
}

async function uiLogin(page: import("@playwright/test").Page): Promise<void> {
  await page.goto("/login");
  await page.fill("#login-email", ADMIN_EMAIL);
  await page.fill("#login-password", ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/$/);
}

test("BP-63: findings dashboard filters live rows", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("bp63");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await ingestFixture(request, token, slug, FIXTURE_MEDIUM);

  // The browser needs its own session — API seeding does not authenticate
  // the page.
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  const rows = page.locator("tbody tr");
  await expect(rows).toHaveCount(2);

  await page.getByLabel("Filter by severity").selectOption("high");
  await expect(rows).toHaveCount(1);
  await expect(page.getByText(HIGH_TITLE)).toBeVisible();

  await page.getByLabel("Filter by severity").selectOption("");
  await expect(rows).toHaveCount(2);
});

test("BP-64: finding detail triage applies states and enforces reasons", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("bp64");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await page.locator("tbody tr").filter({ hasText: HIGH_TITLE }).click();
  await expect(page).toHaveURL(new RegExp(`/${slug}/findings/`));
  await expect(page.getByRole("heading", { name: "Triage" })).toBeVisible();

  const triageSelect = page.locator("select:has(option[value=\"exploitable\"])");
  const apply = page.getByRole("button", { name: "Apply" });

  // The reason-required branch: Apply stays disabled until the reason
  // exists, then applies and reports the gate effect.
  await triageSelect.selectOption("false_positive");
  await expect(apply).toBeDisabled();
  await page.getByPlaceholder("Reason").fill("browser journey: not reachable in our build");
  await expect(apply).toBeEnabled();
  await apply.click();
  await expect(page.getByText(/Triage saved \(effect:/)).toBeVisible();

  // A reason-free state applies directly and sticks: after a reload the
  // dashboard's analysis column shows it (the detail form is an action
  // picker, not a state display).
  await triageSelect.selectOption("exploitable");
  await apply.click();
  await expect(page.getByText(/Triage saved \(effect:/)).toBeVisible();
  await page.goto(`/${slug}/findings`);
  await expect(
    page.locator("tbody tr").filter({ hasText: HIGH_TITLE }),
  ).toContainText("Confirmed");
});

test("BP-65: report history lists both ingested reports", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("bp65");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await ingestFixture(request, token, slug, FIXTURE_MEDIUM);
  await uiLogin(page);

  await page.goto(`/${slug}/reports`);
  await expect(page.getByText("completed", { exact: true })).toHaveCount(2);
  await expect(page.getByText("No reports yet")).toHaveCount(0);
});

test("BP-66: manual ingest uploads a scan file", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("bp66");
  await seedProject(request, token, slug);
  await uiLogin(page);

  await page.goto("/ingest");
  await page.getByLabel("Project").selectOption(slug);
  await page.getByLabel("Scanner").selectOption("sarif");
  await page.setInputFiles("#ingest-file", FIXTURE_HIGH);
  await expect(page.getByText("high.sarif.json loaded")).toBeVisible();

  await page.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByText(/Report submitted\. ID:/)).toBeVisible();

  // The upload really landed: the finding is listed.
  await page.goto(`/${slug}/findings`);
  await expect(page.locator("tbody tr")).toHaveCount(1);
});

test("BP-67: API keys create with one-time reveal and revoke", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("bp67");
  await seedProject(request, token, slug);
  await uiLogin(page);

  await page.goto("/api-keys");
  await page.getByLabel("Project").selectOption(slug);
  await page.fill("#apikeys-name", "journey-key");
  await page.getByRole("button", { name: "Create" }).click();

  await expect(page.getByText("This key will not be shown again")).toBeVisible();
  await expect(page.locator("code").filter({ hasText: /^vuln_/ })).toBeVisible();

  await page.getByRole("button", { name: "Dismiss" }).click();
  await page.getByRole("button", { name: "Revoke" }).click();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText("No API keys yet")).toBeVisible();
});

test("BP-68: logout and session expiry both return to sign in", async ({ page }) => {
  await uiLogin(page);
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();

  await page.getByRole("button", { name: "Logout" }).click();
  await expect(page).toHaveURL(/\/login/);

  // Session expiry: the stored session vanishes and the guard bounces the
  // next navigation instead of rendering a stale shell.
  await uiLogin(page);
  // String form: the e2e tsconfig has no DOM lib, and this is exactly what
  // an expired session looks like — the key disappears from tab storage.
  await page.evaluate("sessionStorage.removeItem('specht.session')");
  await page.reload();
  await expect(page).toHaveURL(/\/login/);
});

test("BP-69: sso hash token installs a session and junk is rejected", async ({ page, request }) => {
  const token = await apiToken(request);

  // A well-formed token in the fragment installs the session…
  await page.goto(`/#sso_token=${encodeURIComponent(token)}`);
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();

  // …and an unusable fragment never installs one. A hash-only goto is a
  // same-document navigation (the in-memory session would survive), so
  // step through a real path change: the app boots fresh, finds no usable
  // token, and the guard sends it to sign in.
  await page.evaluate("sessionStorage.removeItem('specht.session')");
  await page.goto("/login");
  await expect(page).toHaveURL(/\/login/);
  await page.goto("/#sso_token=not-a-jwt");
  await expect(page).toHaveURL(/\/login/);
});
