import { expect, test } from "@playwright/test";
import {
  apiToken,
  BASE_SHA,
  CHANGE_SHA,
  FIXTURE_HIGH,
  FIXTURE_HIGH_MEDIUM,
  FIXTURE_HIGH_NEW,
  FIXTURE_MEDIUM,
  ingestFixture,
  seedProject,
  uiLogin,
  uniq,
} from "./helpers";

// Browser journeys for the pages the COMP suites cannot prove, against the shipped artifact.
// The admin account and the seeding helpers are shared with the other browser suites in ./helpers.

const NEW_TITLE = "SQL injection in user query";
const HIGH_TITLE = "Hardcoded credentials in app config";

test("findings dashboard filters live rows", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("findings-filter");
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

test("finding detail triage applies states and enforces reasons", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("finding-detail");
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
  // Wait for the PATCH itself: the first confirmation is still on screen, so
  // asserting on its text would let the reload cut the second save short.
  await triageSelect.selectOption("exploitable");
  const saved = page.waitForResponse((res) => res.request().method() === "PATCH" && res.ok());
  await apply.click();
  await saved;
  await page.goto(`/${slug}/findings`);
  await expect(
    page.locator("tbody tr").filter({ hasText: HIGH_TITLE }),
  ).toContainText("Exploitable");
});

test("report history lists both ingested reports", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("report-history");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await ingestFixture(request, token, slug, FIXTURE_MEDIUM);
  await uiLogin(page);

  await page.goto(`/${slug}/reports`);
  await expect(page.getByText("Completed", { exact: true })).toHaveCount(2);
  await expect(page.getByText("No reports yet")).toHaveCount(0);
});

test("manual ingest uploads a scan file", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("manual-ingest");
  await seedProject(request, token, slug);
  await uiLogin(page);

  await page.goto(`/${slug}/reports/upload`);
  await page.getByLabel("Scanner").selectOption("sarif");
  await page.setInputFiles("#ingest-file", FIXTURE_HIGH);
  await expect(page.getByText("high.sarif.json loaded")).toBeVisible();

  await page.getByRole("button", { name: "Upload" }).click();
  // Other status regions exist on the page (the route announcer), so pick the card by its content.
  const resultCard = page.getByRole("status").filter({
    has: page.getByRole("link", { name: "View findings" }),
  });
  await expect(resultCard).toContainText(/finding/);
  await expect(page.getByRole("link", { name: "View findings" })).toBeVisible();

  // The upload really landed: the finding is listed.
  await page.goto(`/${slug}/findings`);
  await expect(page.locator("tbody tr")).toHaveCount(1);
});

test("API keys create with one-time reveal and revoke", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("api-keys");
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

test("logout and session expiry both return to sign in", async ({ page }) => {
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

test("sso hash token installs a session only for a login started here, and junk is rejected", async ({ page, request }) => {
  const token = await apiToken(request);

  // A well-formed token in the fragment installs the session when this browser
  // started an SSO login (pressing "Sign in with SSO" leaves this marker)…
  await page.goto("/login");
  await page.evaluate("localStorage.setItem('specht.sso_attempt', String(Date.now()))");
  await page.goto(`/#sso_token=${encodeURIComponent(token)}`);
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();

  // …but the same token in a link nobody here asked for is ignored, so a crafted
  // link cannot sign the visitor into someone else's account.
  await page.evaluate("sessionStorage.removeItem('specht.session')");
  await page.goto("/login");
  await page.goto(`/#sso_token=${encodeURIComponent(token)}`);
  await expect(page).toHaveURL(/\/login/);

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

test("an admin creates a project and follows the guided CI setup", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("guided-setup");
  await uiLogin(page);

  await page.goto("/");
  // A fresh instance has no projects, so the dashboard shows the empty-state
  // link instead of the "New project" action; both point at the same route.
  await page.getByRole("link", { name: /^(New project|Create your first project)$/ }).click();
  await expect(page).toHaveURL(/\/projects\/new$/);
  await page.getByLabel("Name").fill(slug);
  await expect(page.getByLabel("Slug")).toHaveValue(slug);
  await page.getByRole("button", { name: "Create project" }).click();

  await expect(page).toHaveURL(new RegExp(`/${slug}/setup$`));
  await expect(page.getByRole("heading", { name: `Set up CI for ${slug}` })).toBeVisible();

  // The key is shown once; the pipeline snippets only reference the secret.
  await page.getByRole("button", { name: "Create key" }).click();
  await expect(page.locator("code").filter({ hasText: /^vuln_/ })).toBeVisible();
  await expect(page.getByText("Copy it now. It will not be shown again.")).toBeVisible();

  const githubSnippet = page.locator("pre").first();
  await expect(githubSnippet).toContainText("uses: minh-tg/specht@vX.Y.Z");
  await expect(githubSnippet).not.toContainText("go run");
  await expect(githubSnippet).not.toContainText("jq");
  await expect(githubSnippet).toContainText(`project: "${slug}"`);
  // The dev build has no release tag to pin, so the page says what to replace.
  await expect(page.getByText(/development build/)).toBeVisible();

  // The page notices the first report arriving without a reload.
  await expect(page.getByText("Waiting for the first report...")).toBeVisible();
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await expect(page.getByText(/First report received: 1 finding\./)).toBeVisible({
    timeout: 15_000,
  });
});

test("the project header gives an honest verdict and links severity counts to the list", async ({ page, request }) => {
  const token = await apiToken(request);
  const blocked = uniq("verdict-blocked");
  const passing = uniq("verdict-passing");
  const empty = uniq("verdict-empty");
  for (const slug of [blocked, passing, empty]) await seedProject(request, token, slug);
  await ingestFixture(request, token, blocked, FIXTURE_HIGH);
  await ingestFixture(request, token, passing, FIXTURE_MEDIUM);
  await uiLogin(page);

  await page.goto(`/${blocked}/findings`);
  await expect(page.getByRole("heading", { level: 1, name: blocked })).toBeVisible();
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();
  await expect(page.getByText("1 finding blocks this project")).toBeVisible();
  await expect(page.getByText(/Floor: /)).toBeVisible();
  await page.getByRole("link", { name: "1 high finding" }).click();
  await expect(page).toHaveURL(/severity=high/);
  await expect(page.getByLabel("Filter by severity")).toHaveValue("high");

  await page.goto(`/${passing}/findings`);
  await expect(page.getByText("PASSING", { exact: true })).toBeVisible();
  await expect(page.getByText("Nothing blocks this project")).toBeVisible();

  // A project that was never scanned must not read as passing.
  await page.goto(`/${empty}/findings`);
  await expect(page.getByText("NO SCANS", { exact: true })).toBeVisible();
  await expect(page.getByText("PASSING", { exact: true })).toHaveCount(0);
});

test("unknown URLs show a not-found page and a bare project URL opens its findings", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("bare-url");
  await seedProject(request, token, slug);
  await uiLogin(page);

  await page.goto("/definitely/not/a/page");
  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await page.getByRole("link", { name: "Back to projects" }).click();
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();

  await page.goto(`/${slug}`);
  await expect(page).toHaveURL(new RegExp(`/${slug}/findings$`));
});

test("the theme choice persists across reloads", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light" });
  await page.goto("/login");
  const html = page.locator("html");
  await expect(html).not.toHaveClass(/dark/);

  await page.getByRole("button", { name: /^Theme: system/ }).click();
  await page.getByRole("button", { name: /^Theme: light/ }).click();
  await expect(html).toHaveClass(/dark/);

  await page.reload();
  await expect(html).toHaveClass(/dark/);
  await expect(page.getByRole("button", { name: "Theme: dark (click to change)" })).toBeVisible();

  await page.getByRole("button", { name: /^Theme: dark/ }).click();
  await expect(html).not.toHaveClass(/dark/);
});

test("back to findings returns to the filtered list the finding was opened from", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("back-filter");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await ingestFixture(request, token, slug, FIXTURE_MEDIUM);
  await uiLogin(page);

  await page.goto(`/${slug}/findings?severity=high`);
  await page.getByRole("link", { name: HIGH_TITLE }).click();
  await expect(page).toHaveURL(new RegExp(`/${slug}/findings/`));

  await page.getByRole("link", { name: "← Back to findings" }).click();
  await expect(page).toHaveURL(new RegExp(`/${slug}/findings\\?severity=high$`));
  await expect(page.getByLabel("Filter by severity")).toHaveValue("high");
});

test("keyboard users can skip the navigation", async ({ page }) => {
  await page.goto("/login");
  await page.keyboard.press("Tab");

  const skip = page.getByRole("link", { name: "Skip to main content" });
  await expect(skip).toBeFocused();
  await expect(skip).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.locator("main#main-content")).toBeFocused();
});

test("triaging the only blocker flips the project verdict to passing", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("verdict-flip");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: HIGH_TITLE }).click();
  await expect(page.locator("span", { hasText: /^Blocks gate$/ })).toBeVisible();

  await page.locator("select:has(option[value=\"false_positive\"])").selectOption("false_positive");
  await page.getByPlaceholder("Reason").fill("e2e: test credential, not a real secret");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText(/Triage saved \(effect:/)).toBeVisible();

  await page.getByRole("link", { name: "← Back to findings" }).click();
  await expect(page.getByText("PASSING", { exact: true })).toBeVisible();
  await expect(page.getByText("Nothing blocks this project")).toBeVisible();
});

test("marking the only blocker not reachable flips the project verdict to passing", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("reachability-flip");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: HIGH_TITLE }).click();

  const assess = page.getByRole("button", { name: "Assess" });
  await expect(assess).toBeDisabled();
  await page.getByLabel("Reachability assessment").selectOption("not_reachable");
  await page.getByLabel("Evidence").fill("e2e: the vulnerable code path is never called");
  await expect(assess).toBeEnabled();
  await assess.click();

  // The assessment is saved, shown as the latest one, and the gate follows.
  await expect(page.getByText("Reachability saved")).toBeVisible();
  await expect(page.getByText(/Latest:\s*Not Reachable/)).toBeVisible();

  await page.getByRole("link", { name: "← Back to findings" }).click();
  await expect(page.getByText("PASSING", { exact: true })).toBeVisible();
  await expect(page.getByText("Nothing blocks this project")).toBeVisible();
});

test("a CI link opens the change view with only what the change introduced", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("change-view");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH_MEDIUM, { commit_sha: BASE_SHA });
  await ingestFixture(request, token, slug, FIXTURE_HIGH_NEW, {
    commit_sha: CHANGE_SHA,
    base_revision: BASE_SHA,
    gate_introduced_only: true,
  });
  await uiLogin(page);

  // The CI check links by commit; a 7-character prefix is enough.
  await page.goto(`/${slug}/changes/${CHANGE_SHA.slice(0, 7)}`);
  await expect(page.getByRole("heading", { name: "Change 2222222" })).toBeVisible();
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();
  await expect(page.getByText("1 finding blocks this change")).toBeVisible();

  // Only the introduced finding is listed as a blocker; the baseline debt is folded away.
  const introduced = page.getByRole("region", { name: "Findings introduced by this change" });
  await expect(introduced.getByRole("link", { name: NEW_TITLE })).toBeVisible();
  await expect(introduced.getByRole("link", { name: HIGH_TITLE })).toHaveCount(0);

  await page.getByText(/1 other finding blocks this project/).click();
  await expect(page.getByRole("link", { name: HIGH_TITLE })).toBeVisible();

  // Deciding is one click away.
  await introduced.getByRole("link", { name: NEW_TITLE }).click();
  await expect(page).toHaveURL(new RegExp(`/${slug}/findings/`));
  await expect(page.getByRole("heading", { name: "Triage" })).toBeVisible();
});

test("a commit with no scan says so instead of failing", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("change-none");
  await seedProject(request, token, slug);
  await uiLogin(page);

  await page.goto(`/${slug}/changes/deadbee`);
  await expect(page.getByText("No scan found for commit deadbee")).toBeVisible();
  await expect(page.getByRole("link", { name: "Upload a report" })).toBeVisible();
});
