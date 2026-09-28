import { expect, test } from "@playwright/test";

// Browser smoke for the auth journey against the real artifact: Go server
// with the embedded React build, real PostgreSQL, real API. Complements the
// Go e2e suite (HTTP/exit-code contracts) by covering what only a browser
// can: routing guards, form flows, redirects, and session restore.

test("anonymous visitors are sent to sign in", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login\?redirect=%2F/);
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});

test("register, sign in, and land on the projects dashboard", async ({ page }) => {
  const email = `smoke-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;
  const password = "smoke-password-123";

  await page.goto("/register");
  await expect(page.getByRole("heading", { name: "Create account" })).toBeVisible();
  await page.fill("#reg-email", email);
  await page.fill("#reg-password", password);
  await page.getByRole("button", { name: "Create account" }).click();
  // Registration hands off to the sign-in screen, never straight in.
  await expect(page).toHaveURL(/\/login/);

  await page.fill("#login-email", email);
  await page.fill("#login-password", password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();

  // The session survives a reload (stored session restore).
  await page.reload();
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
});

test("a rejected password shows the inline error", async ({ page }) => {
  await page.goto("/login");
  await page.fill("#login-email", "nobody@example.com");
  await page.fill("#login-password", "definitely-wrong-1");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByText("Invalid email or password")).toBeVisible();
  await expect(page).toHaveURL(/\/login/);
});

test("the sign-in page offers the SSO entry point", async ({ page }) => {
  // SSO is opt-in server-side; without an IdP the entry point is unreachable,
  // so this pins the link contract only: it points at the real login route and
  // does not post a form. The working redirect-from-IdP flow stays COMP-only
  // (sso.test.ts) until the suite runs against an SSO-enabled server.
  await page.goto("/login");

  const link = page.getByRole("link", { name: /sign in with sso/i });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute("href", "/api/v1/auth/sso/login");
});
