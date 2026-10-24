import { expect, type Locator, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import {
  apiToken,
  BASE_SHA,
  CHANGE_SHA,
  chooseOption,
  FIXTURE_GITLEAKS,
  FIXTURE_GOSEC_JSON,
  FIXTURE_GRYPE_MULTI_CVSS,
  FIXTURE_HIGH,
  FIXTURE_HIGH_MEDIUM,
  FIXTURE_HIGH_NEW,
  FIXTURE_MEDIUM,
  FIXTURE_NUCLEI,
  FIXTURE_TRIVY_MULTI_SOURCE,
  ingestFixture,
  registerPerson,
  requestWaiver,
  seedProject,
  uiLogin,
  uiLoginAs,
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

  const highChip = page.getByRole("button", { name: /^High/ });
  await highChip.click();
  await expect(highChip).toHaveAttribute("aria-pressed", "true");
  await expect(rows).toHaveCount(1);
  await expect(page.getByText(HIGH_TITLE)).toBeVisible();

  await highChip.click();
  await expect(highChip).toHaveAttribute("aria-pressed", "false");
  await expect(rows).toHaveCount(2);
});

test("quick views match open triage counters and clear previous filters", async ({ page, request }) => {
  const token = await apiToken(request);
  const headers = { Authorization: `Bearer ${token}` };
  const slug = uniq("quick-views");
  await seedProject(request, token, slug);
  const raw = JSON.parse(
    readFileSync(new URL("../../e2e/testdata/trivy-alpine-scan.json", import.meta.url), "utf8"),
  ) as {
    Results: Array<{ Vulnerabilities: Array<{ Severity: string; }>; }>;
  };
  const ingest = async () => {
    const response = await request.post("/api/v1/reports", {
      headers,
      data: { project: slug, scanner: "trivy", branch: "main", scan_mode: "full", raw_data: raw },
    });
    expect(response.ok(), await response.text()).toBeTruthy();
  };
  await ingest();
  const list = await request.get(`/api/v1/projects/${slug}/findings`, { headers });
  expect(list.ok()).toBeTruthy();
  const findings = await list.json() as Array<{ id: string; current_severity: string; }>;
  const high = findings.find((finding) => finding.current_severity === "high")!;
  const low = findings.find((finding) => finding.current_severity === "low")!;
  const triage = await request.patch(`/api/v1/findings/${high.id}`, {
    headers,
    data: { analysis_state: "in_triage" },
  });
  expect(triage.ok(), await triage.text()).toBeTruthy();

  await uiLogin(page);
  await page.goto(`/${slug}/findings?q=no-match&status=fixed&offset=40`);
  await page.getByRole("link", { name: "Needs triage 2", exact: true }).click();
  const titles = page.locator("tbody tr a[href*=\"/findings/\"]");
  await expect(titles).toHaveCount(2);
  await expect(page.getByLabel("Filter by status")).toHaveText("Open or reopened");
  await expect(page.getByLabel("Filter by triage state")).toHaveText("Needs triage");
  expect(new URL(page.url()).searchParams.has("q")).toBe(false);
  expect(new URL(page.url()).searchParams.has("offset")).toBe(false);
  const highRow = page.locator("tbody tr").filter({
    has: page.locator(`a[href="/${slug}/findings/${high.id}"]`),
  });
  const lowRow = page.locator("tbody tr").filter({
    has: page.locator(`a[href="/${slug}/findings/${low.id}"]`),
  });
  await expect(highRow.getByText("Blocks gate", { exact: true })).toBeVisible();
  await expect(highRow.locator("td").first()).toHaveCSS("box-shadow", /inset/);
  await expect(lowRow.getByText("Blocks gate", { exact: true })).toHaveCount(0);
  await expect(lowRow.locator("td").first()).toHaveCSS("box-shadow", "none");

  await page.getByRole("link", { name: "Open critical/high", exact: true }).click();
  await expect(titles).toHaveCount(1);
  await expect(titles.first()).toHaveAttribute("href", `/${slug}/findings/${high.id}`);

  // A complete scan closes the high finding while preserving its triage state.
  // It must no longer inflate the counter or remain in the linked view.
  raw.Results[0].Vulnerabilities = raw.Results[0].Vulnerabilities.filter((v) =>
    v.Severity === "LOW"
  );
  await ingest();
  await page.reload();
  await page.getByRole("link", { name: "Needs triage 1", exact: true }).click();
  await expect(titles).toHaveCount(1);
  await expect(titles.first()).toHaveAttribute("href", `/${slug}/findings/${low.id}`);
});

test("the findings list searches, filters by triage state and sorts on the server", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("findings-server");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH_MEDIUM);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  const titles = page.locator("tbody tr a[href*=\"/findings/\"]");
  await expect(titles).toHaveCount(2);
  // Worst first by default.
  await expect(titles.first()).toHaveText("Hardcoded credentials in app config");

  // A search narrows the whole list, and it is in the URL, so the page can be shared.
  await page.getByRole("searchbox", { name: "Search findings" }).fill("urllib3");
  await expect(titles).toHaveCount(1);
  await expect(titles.first()).toHaveText("Outdated dependency urllib3");
  await expect(page).toHaveURL(/q=urllib3/);

  // Reloading restores it from the URL.
  await page.reload();
  await expect(page.getByRole("searchbox", { name: "Search findings" })).toHaveValue("urllib3");
  await expect(titles).toHaveCount(1);

  await page.getByRole("searchbox", { name: "Search findings" }).fill("");
  await expect(titles).toHaveCount(2);

  // Nothing is triaged yet, so "needs triage" keeps both, and "exploitable" keeps none.
  await chooseOption(page, page.getByLabel("Filter by triage state"), "Needs triage");
  await expect(titles).toHaveCount(2);
  await chooseOption(page, page.getByLabel("Filter by triage state"), "Exploitable");
  await expect(page.getByText("No findings match these filters.")).toBeVisible();
  await page.getByRole("button", { name: "Clear filters" }).click();
  await expect(titles).toHaveCount(2);

  // Sorting by title reorders the server's answer, and the choice stays in the URL.
  await page.getByRole("button", { name: /^Finding/ }).click();
  await expect(page).toHaveURL(/sort=title/);
  await expect(titles.first()).toHaveText("Hardcoded credentials in app config");
  await page.getByRole("button", { name: /^Finding/ }).click();
  await expect(page).toHaveURL(/dir=desc/);
  await expect(titles.first()).toHaveText("Outdated dependency urllib3");
});

test("selecting findings in the list triages them together", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("findings-bulk");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH_MEDIUM);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await page.getByRole("checkbox", { name: "Select all findings on this page" }).check();
  const bar = page.getByRole("region", { name: "Bulk actions" });
  await expect(bar).toContainText("2 selected");

  await bar.getByRole("button", { name: "Triage…" }).click();
  const dialog = page.getByRole("dialog", { name: "Triage 2 findings" });
  await chooseOption(page, dialog.getByRole("combobox", { name: "Decision" }), "Exploitable");
  await dialog.getByRole("button", { name: "Apply to 2 findings" }).click();

  await expect(page.getByText("Triage saved for 2 findings")).toBeVisible();
  await expect(bar).toHaveCount(0);
  const states = page.locator("tbody tr td:nth-child(5)");
  await expect(states.first()).toContainText("Exploitable");
  await expect(states.nth(1)).toContainText("Exploitable");

  // j and k move the cursor and x selects the row under it.
  await page.locator("tbody tr").first().focus();
  await page.keyboard.press("j");
  await page.keyboard.press("x");
  await expect(page.locator("tbody input[type=checkbox]").nth(1)).toBeChecked();
  await expect(bar).toContainText("1 selected");
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

  const triageSelect = page.getByLabel("Triage action");
  const apply = page.getByRole("button", { name: "Apply" });

  // The reason-required branch: Apply stays disabled until the reason
  // exists, then applies and reports the gate effect.
  await chooseOption(page, triageSelect, "False positive");
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
  await chooseOption(page, triageSelect, "Exploitable");
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
  await chooseOption(page, page.getByLabel("Scanner"), /^SARIF/);
  await page.setInputFiles("#ingest-file", FIXTURE_HIGH);
  await expect(page.getByTestId("file-dropzone").getByText("high.sarif.json")).toBeVisible();

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
  await chooseOption(page, page.getByLabel("Project"), slug);
  await page.fill("#apikeys-name", "journey-key");
  await page.getByRole("button", { name: "Create" }).click();

  await expect(page.getByText("This key will not be shown again")).toBeVisible();
  await expect(page.locator("code").filter({ hasText: /^vuln_/ })).toBeVisible();

  await page.getByRole("button", { name: "Dismiss" }).click();
  await page.getByRole("button", { name: "Revoke" }).click();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText("No API keys yet")).toBeVisible();
});

test("a person renames themselves on the profile page and it sticks", async ({ page }) => {
  await uiLogin(page);

  await page.goto("/profile");
  const field = page.getByLabel("Display name");
  await expect(field).toBeVisible();
  const original = await field.inputValue();
  try {
    await field.fill("Journey Tester");
    await page.getByRole("button", { name: "Save name" }).click();
    await expect(page.getByRole("button", { name: "Save name" })).toBeDisabled();

    await page.reload();
    await expect(page.getByLabel("Display name")).toHaveValue("Journey Tester");
  } finally {
    // The account is shared with other journeys: leave it as it was found.
    await page.getByLabel("Display name").fill(original);
    await page.getByRole("button", { name: "Save name" }).click();
  }
});

test("a mismatched new password is caught on the page before anything is sent", async ({ page }) => {
  await uiLogin(page);

  await page.goto("/profile");
  await page.getByLabel("Current password").fill("whatever-it-is-now");
  await page.getByLabel("New password", { exact: true }).fill("a-brand-new-password-1");
  await page.getByLabel("Confirm new password").fill("a-different-password-2");
  await page.getByRole("button", { name: "Change password" }).click();

  await expect(page.getByText("The two passwords do not match.")).toBeVisible();
});

test("logout and session expiry both return to sign in", async ({ page }) => {
  await uiLogin(page);
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();

  await page.getByRole("button", { name: /^Account menu/ }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
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

test("a session token in the URL fragment never signs the visitor in", async ({ page, request }) => {
  const token = await apiToken(request);

  // The server no longer sends a token in the fragment, and accepting one
  // would let a crafted link sign the visitor into someone else's account.
  // That holds even while this browser has an SSO login pending (pressing
  // "Sign in with SSO" leaves this marker).
  await page.goto("/login");
  await page.evaluate("localStorage.setItem('specht.sso_attempt', String(Date.now()))");
  await page.goto(`/#sso_token=${encodeURIComponent(token)}`);
  await expect(page).toHaveURL(/\/login/);

  // And without a pending login, or with a junk value, the result is the same.
  await page.evaluate("sessionStorage.removeItem('specht.session')");
  await page.goto("/login");
  await page.goto(`/#sso_token=${encodeURIComponent(token)}`);
  await expect(page).toHaveURL(/\/login/);
  await page.goto("/login");
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
  await page.getByRole("button", { name: "Create a key for this pipeline" }).click();
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
  await expect(page.getByRole("button", { name: /^High/ })).toHaveAttribute("aria-pressed", "true");

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
  await expect(page.getByRole("button", { name: "Theme: dark. Switch to system" })).toBeVisible();

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
  await expect(page.getByRole("button", { name: /^High/ })).toHaveAttribute("aria-pressed", "true");
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

test("a bare ? opens the shortcut sheet until the single-key switch is turned off", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("single-key");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await uiLogin(page);
  await page.goto(`/${slug}/findings`);
  await expect(page.getByRole("link", { name: HIGH_TITLE })).toBeVisible();

  await page.keyboard.press("?");
  const sheet = page.getByRole("dialog", { name: "Keyboard shortcuts" });
  await expect(sheet).toBeVisible();
  await expect(sheet.locator("kbd", { hasText: /^J$/ })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(sheet).toBeHidden();

  await page.getByRole("button", { name: /^Account menu/ }).click();
  const item = page.getByRole("menuitemcheckbox", { name: "Single-key shortcuts" });
  await expect(item).toHaveAttribute("aria-checked", "true");
  await item.click();
  await expect(item).toHaveAttribute("aria-checked", "false");
  await page.keyboard.press("Escape");

  // The choice is kept per browser, so it survives a reload.
  await page.reload();
  await expect(page.getByRole("link", { name: HIGH_TITLE })).toBeVisible();
  await page.keyboard.press("?");
  await expect(sheet).toBeHidden();

  // Ctrl+/ still works, and the sheet no longer lists the single keys.
  await page.keyboard.press("Control+/");
  await expect(sheet).toBeVisible();
  await expect(sheet.locator("kbd", { hasText: /^J$/ })).toHaveCount(0);
  await expect(sheet).toContainText("Single-key shortcuts are off");
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
  await expect(page.getByRole("region", { name: "Why this blocks" })).toBeVisible();

  await chooseOption(page, page.getByLabel("Triage action"), "False positive");
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
  await chooseOption(page, page.getByLabel("Reachability assessment"), "Not Reachable");
  await page.getByLabel("Evidence", { exact: true }).fill(
    "e2e: the vulnerable code path is never called",
  );
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
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("1 finding blocks this change.");

  // Only the introduced finding is listed as a blocker; the baseline debt is folded away.
  const introduced = page.getByRole("region", { name: "Findings introduced by this change" });
  await expect(introduced.getByRole("button", { name: NEW_TITLE, exact: true })).toBeVisible();
  await expect(introduced.getByRole("button", { name: HIGH_TITLE, exact: true })).toHaveCount(0);

  await page.getByText(/1 other finding blocks this project/).click();
  await expect(page.getByRole("link", { name: HIGH_TITLE })).toBeVisible();

  // Ticking a fix tracks progress and leaves the verdict alone: only a scan changes it.
  await expect(page.getByText("0 of 1 handled")).toBeVisible();
  await introduced.getByRole("checkbox", { name: `I've done this: ${NEW_TITLE}` }).check();
  await expect(page.getByText("1 of 1 handled")).toBeVisible();
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();
  await expect(page.getByText("Waiting for the next scan")).toBeVisible();
  await introduced.getByRole("checkbox", { name: `I've done this: ${NEW_TITLE}` }).uncheck();

  // Deciding is one click away.
  await introduced.getByRole("link", { name: "Open the full finding" }).click();
  await expect(page).toHaveURL(new RegExp(`/${slug}/findings/`));
  await expect(page.getByRole("heading", { name: "Triage" })).toBeVisible();
});

test("a change view with long fix text keeps titles readable and does not scroll sideways", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("change-long-fix");
  await seedProject(request, token, slug);
  // A secret scanner's fix sentence is long; it used to push the title down to one letter per line.
  const res = await request.post("/api/v1/reports", {
    headers: { Authorization: `Bearer ${token}` },
    data: {
      project: slug,
      scanner: "gitleaks",
      commit_sha: CHANGE_SHA,
      raw_data: JSON.parse(readFileSync(FIXTURE_GITLEAKS, "utf8")),
    },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
  await uiLogin(page);

  await page.goto(`/${slug}/changes/${CHANGE_SHA.slice(0, 7)}`);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("block this change");
  const entry = page.getByRole("region", { name: "Findings introduced by this change" })
    .getByRole("button").first();
  await expect(entry).toBeVisible();
  const name = (await entry.getAttribute("aria-label")) ?? "";
  const box = await entry.getByText(name, { exact: true }).boundingBox();
  expect(box?.width ?? 0, "the title keeps room to read").toBeGreaterThan(120);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    "the page does not scroll sideways",
  ).toBe(true);
});

test("the pages load without a Content-Security-Policy violation", async ({ page }) => {
  const violations: string[] = [];
  page.on("console", (message) => {
    if (/Content Security Policy|violates the following/i.test(message.text())) {
      violations.push(message.text().slice(0, 160));
    }
  });
  for (const path of ["/login", "/register", "/invite/not-a-link"]) {
    await page.goto(path, { waitUntil: "networkidle" });
  }
  await uiLogin(page);
  await page.goto("/", { waitUntil: "networkidle" });
  expect(violations, "a font or script was blocked by the CSP").toEqual([]);
});

test("the navigation fits a 360px screen without cutting or wrapping a link", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 740 });
  await uiLogin(page);
  await page.goto("/", { waitUntil: "networkidle" });

  const nav = page.getByRole("navigation", { name: "Main" });
  const trigger = nav.getByRole("button", { name: /^Account menu/ });
  const items = [
    ["Account menu", trigger],
    ["Projects", nav.getByRole("link", { name: "Projects", exact: true })],
    ["Teams", nav.getByRole("link", { name: "Teams", exact: true })],
    ["API keys", nav.getByRole("link", { name: "API keys", exact: true })],
    ["Admin", nav.getByRole("link", { name: "Admin", exact: true })],
  ] as const;
  for (const [name, item] of items) {
    await expect(item).toBeVisible();
    const box = await item.boundingBox();
    expect(box, name).not.toBeNull();
    expect(box!.x + box!.width, `${name} stays inside the screen`).toBeLessThanOrEqual(360);
    expect(box!.height, `${name} stays on one line`).toBeLessThan(40);
  }
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    "the page does not scroll sideways",
  ).toBe(true);

  // From sm up the account menu is the last item of the row.
  await page.setViewportSize({ width: 1024, height: 740 });
  const adminBox = await items[4][1].boundingBox();
  const triggerBox = await trigger.boundingBox();
  expect(triggerBox!.x, "the account menu sits right of Admin").toBeGreaterThan(adminBox!.x);
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

test("an admin invites a teammate by link, the teammate joins, and the link works once", async ({ page, request, browser }) => {
  const token = await apiToken(request);
  const slug = uniq("invite");
  await seedProject(request, token, slug);
  await uiLogin(page);

  await page.goto(`/${slug}/access`);
  await page.getByRole("button", { name: "Invite people" }).click();
  await page.getByRole("button", { name: "Create link" }).click();
  const link = (await page.getByTestId("invite-link").textContent()) ?? "";
  expect(link).toContain("/invite/");
  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByRole("list", { name: "Pending invites" })).toContainText(
    "Anyone with the link",
  );

  // The newcomer opens the link in a browser with no session.
  const guestContext = await browser.newContext();
  const guest = await guestContext.newPage();
  await guest.goto(link);
  await expect(guest.getByRole("heading", { name: `Join ${slug}` })).toBeVisible();
  await guest.getByLabel("Email").fill(`${uniq("guest")}@example.com`);
  await guest.getByLabel("Choose a password").fill("short");
  await expect(guest.getByRole("list", { name: "Requirements" })).toContainText(
    "At least 8 characters (not met)",
  );
  await guest.getByLabel("Choose a password").fill("correct-horse-battery");
  await expect(guest.getByRole("list", { name: "Requirements" })).toContainText(
    "At least 8 characters (met)",
  );
  await guest.getByRole("button", { name: "Create account and join" }).click();
  await expect(guest).toHaveURL(new RegExp(`/${slug}/`));

  // The link is single use.
  await guest.goto(link);
  await expect(guest.getByRole("heading", { name: "This invite link does not work" }))
    .toBeVisible();
  await guestContext.close();

  await page.reload();
  await expect(page.getByText("No open invites.")).toBeVisible();
});

test("an admin overrides the severity floor and the project verdict follows", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("policy-floor");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: /^Configuration/ }).click();
  await page.getByRole("menuitem", { name: "Policy", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/${slug}/policy$`));
  const floor = page.getByRole("group", { name: "Severity floor" });
  await expect(floor).toContainText("Default");
  await expect(floor).toContainText("High");

  // A high finding no longer blocks once the floor sits at critical.
  await page.getByRole("button", { name: "Override Severity floor" }).click();
  await chooseOption(page, page.getByRole("combobox", { name: "Severity floor" }), "Critical");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(floor).toContainText("Override");
  await expect(floor).toContainText("Critical");
  await expect(page.getByText("PASSING", { exact: true })).toBeVisible();

  // The override survives a reload, and taking it back restores the verdict.
  await page.reload();
  await expect(floor).toContainText("Override");
  await page.getByRole("button", { name: "Remove override for Severity floor" }).click();
  await expect(floor).toContainText("Default");
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();
});

test("a manager approves a waiver request, the verdict passes, and revoking it blocks again", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("waivers");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await requestWaiver(request, token, slug, "Not reachable from the public API.");
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();

  await page.getByRole("link", { name: "Waivers", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/${slug}/waivers$`));
  await expect(page.getByRole("tab", { name: "Waiting 1" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByText("Not reachable from the public API.")).toBeVisible();

  // Rejecting needs a note; approving does not.
  await page.getByRole("button", { name: /^Reject / }).click();
  await expect(page.getByRole("dialog", { name: "Reject this waiver?" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reject", exact: true })).toBeDisabled();
  await page.keyboard.press("Escape");

  await page.getByRole("button", { name: /^Approve / }).click();
  await page.getByLabel(/^Note/).fill("Fine until the image bump.");
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Waiting 0" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "In force 1" })).toBeVisible();
  await expect(page.getByText("PASSING", { exact: true })).toBeVisible();

  await page.getByRole("tab", { name: "In force 1" }).click();
  await expect(page).toHaveURL(/state=in_force/);
  await expect(page.getByText("Fine until the image bump.")).toBeVisible();
  await page.getByRole("button", { name: /^Revoke / }).click();
  await expect(page.getByRole("tab", { name: "In force 0" })).toBeVisible();
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();

  await page.getByRole("tab", { name: "Closed 1" }).click();
  await expect(page.getByText(/^Revoked by /)).toBeVisible();
});

test("the insights page counts only open findings and shows what blocks the gate", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("insights");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH_MEDIUM);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await page.getByRole("link", { name: "Insights", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/${slug}/insights$`));
  const stat = (label: string) =>
    page.getByText(label, { exact: true }).locator("xpath=preceding-sibling::div[1]");
  await expect(stat("open findings")).toHaveText("2");
  await expect(stat("block the gate now")).toHaveText("1");

  const severity = page.getByRole("list", { name: "Open findings by severity" });
  await expect(severity.getByRole("listitem").nth(1)).toContainText("High");
  await expect(severity.getByRole("listitem").nth(1)).toContainText("1, 1 block the gate");
  await expect(severity.getByRole("listitem").nth(2)).toContainText("Medium");

  const states = page.getByRole("list", { name: "Open findings by triage state" });
  await expect(states.getByRole("listitem")).toHaveText(["Not triaged2"]);

  // Both findings are new, so none is past its fix date and the age chart puts them under 7 days.
  const ages = page.getByRole("list", { name: "Open findings by age" });
  await expect(ages.getByRole("listitem").first()).toContainText("Under 7 days");
  await expect(ages.getByRole("listitem").first()).toContainText("2");
  await expect(page.getByRole("heading", { name: "Past their fix date" })).toHaveCount(0);
});

test("a project admin switches the watcher off and sets how often it polls", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("watcher");
  await seedProject(request, token, slug);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await page.getByRole("button", { name: /^Configuration/ }).click();
  await page.getByRole("menuitem", { name: "Watcher", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/${slug}/watcher$`));
  const watch = page.getByRole("switch", { name: "Watch this project" });
  const interval = page.getByRole("combobox", { name: "Interval" });
  await expect(watch).toHaveAttribute("aria-checked", "true");
  await expect(interval).toContainText("every hour");

  // A new interval is saved at once, survives a reload, and can be taken back.
  await chooseOption(page, interval, "every 6 hours");
  await expect(page.getByRole("button", { name: "Reset to every hour" })).toBeVisible();
  await page.reload();
  await expect(interval).toContainText("every 6 hours");
  await page.getByRole("button", { name: "Reset to every hour" }).click();
  await expect(interval).toContainText("every hour");
  await expect(page.getByRole("button", { name: /^Reset/ })).toHaveCount(0);

  // Switching a project off reads as off, not as a fault, and stays off.
  await watch.click();
  await expect(watch).toHaveAttribute("aria-checked", "false");
  await expect(page.getByText("Off for this project")).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
  await page.reload();
  await expect(page.getByRole("switch", { name: "Watch this project" })).toHaveAttribute(
    "aria-checked",
    "false",
  );
  await expect(page.getByText("Off for this project")).toBeVisible();
});

test("a global admin manages accounts and sees the server's totals", async ({ page, request }) => {
  const email = `admin-journey-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;
  const registered = await request.post("/api/v1/auth/register", {
    data: { email, password: "journey-person-123" },
  });
  expect(registered.ok(), await registered.text()).toBeTruthy();
  await uiLogin(page);

  await page.goto("/");
  await page.getByRole("link", { name: "Admin", exact: true }).click();
  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.getByRole("heading", { name: "Admin", level: 1 })).toBeVisible();
  const total = (label: string) =>
    page.getByText(label, { exact: true }).locator("xpath=preceding-sibling::div[1]");
  await expect(total("projects")).not.toHaveText("0");
  await expect(total("people")).not.toHaveText("0");

  // You cannot change or deactivate yourself.
  const you = page.getByRole("listitem").filter({ hasText: "(you)" });
  await expect(you).toContainText("That is you");
  await expect(you.getByRole("combobox")).toBeDisabled();

  await page.getByRole("searchbox", { name: "Find a person by email" }).fill(email);
  const people = page.getByRole("list", { name: "People" });
  await expect(people.getByRole("listitem")).toHaveCount(1);
  const row = people.getByRole("listitem").first();
  await expect(row).toContainText("Active");

  // A role change takes effect at once and can be undone.
  await chooseOption(page, page.getByRole("combobox", { name: `Role of ${email}` }), "Admin");
  await expect(page.getByText("Role changed")).toBeVisible();
  await page.reload();
  await page.getByRole("searchbox", { name: "Find a person by email" }).fill(email);
  await expect(page.getByRole("combobox", { name: `Role of ${email}` })).toContainText("Admin");
  await chooseOption(page, page.getByRole("combobox", { name: `Role of ${email}` }), "User");
  await expect(page.getByRole("combobox", { name: `Role of ${email}` })).toContainText("User");

  // Deactivating asks first, then ends the account; reactivating does not ask.
  await page.getByRole("button", { name: `Deactivate ${email}` }).click();
  const dialog = page.getByRole("alertdialog", { name: `Deactivate ${email}?` });
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(row).toContainText("Active");
  await page.getByRole("button", { name: `Deactivate ${email}` }).click();
  await dialog.getByRole("button", { name: "Deactivate" }).click();
  await expect(row).toContainText("Deactivated");
  await page.getByRole("button", { name: `Reactivate ${email}` }).click();
  await expect(row).toContainText("Active");
  await expect(row).not.toContainText("Deactivated");

  // A fresh server has no report old enough to remove, so the button has nothing to do.
  await expect(page.getByText("Nothing to remove")).toBeVisible();
  await expect(page.getByRole("button", { name: "Remove them…" })).toBeDisabled();
});

test("an admin hands a locked-out person a reset link that works once", async ({ page, request, browser }) => {
  const email = `reset-journey-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;
  const registered = await request.post("/api/v1/auth/register", {
    data: { email, password: "forgotten-password-1" },
  });
  expect(registered.ok(), await registered.text()).toBeTruthy();
  await uiLogin(page);

  await page.goto("/admin");
  await page.getByRole("searchbox", { name: "Find a person by email" }).fill(email);
  await page.getByRole("button", { name: `Reset password for ${email}` }).click();
  const dialog = page.getByRole("dialog", { name: `Send this link to ${email}` });
  const link = (await dialog.getByTestId("reset-link").textContent()) ?? "";
  expect(link).toContain("/reset/");
  await dialog.getByRole("button", { name: "Done" }).click();

  // The person opens the link in a browser with no session.
  const guestContext = await browser.newContext();
  const guest = await guestContext.newPage();
  await guest.goto(link);
  await expect(guest.getByRole("heading", { name: "Choose a new password" })).toBeVisible();
  await guest.getByLabel("New password", { exact: true }).fill("a-new-password-for-me");
  await guest.getByLabel("Confirm new password").fill("a-new-password-for-me");
  await guest.getByRole("button", { name: "Set password" }).click();
  await expect(guest.getByRole("heading", { name: "Password changed" })).toBeVisible();

  // The new password signs in; the link does not work a second time.
  await guest.getByRole("link", { name: "Go to sign in" }).click();
  await guest.getByLabel("Email").fill(email);
  await guest.getByLabel("Password").fill("a-new-password-for-me");
  await guest.getByRole("button", { name: "Sign in" }).click();
  await expect(guest).toHaveURL(/\/$/);
  await guest.goto(link);
  await guest.getByLabel("New password", { exact: true }).fill("another-password-again");
  await guest.getByLabel("Confirm new password").fill("another-password-again");
  await guest.getByRole("button", { name: "Set password" }).click();
  await expect(guest.getByRole("heading", { name: "This reset link does not work" })).toBeVisible();
  await guestContext.close();
});

test("the command palette jumps between pages from the keyboard", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("palette");
  const other = uniq("palette-other");
  await seedProject(request, token, slug);
  await seedProject(request, token, other);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  const search = page.getByRole("searchbox", { name: "Search findings" });
  await expect(search).toBeVisible();
  await search.focus();
  await page.keyboard.press("Control+k");
  const input = page.getByRole("combobox", { name: "Search commands" });
  await expect(input).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(search).toBeFocused();
  await page.keyboard.press("Control+k");
  await expect(input).toBeFocused();

  // A page of this project, found by a word and reached with Enter.
  await input.fill("policy");
  await expect(page.getByRole("option").first()).toContainText("Policy");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/${slug}/policy$`));
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator("main#main-content")).toBeFocused();

  // Another project, picked with the arrow keys and Enter.
  await page.keyboard.press("Control+k");
  await page.getByRole("combobox", { name: "Search commands" }).fill(other);
  await expect(page.getByRole("option")).toHaveCount(1);
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/${other}/findings$`));

  // Pages of a project are offered only inside one; Escape closes without going anywhere.
  await page.goto("/teams");
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("group", { name: "This project" })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page).toHaveURL(/\/teams$/);

  // Dismissal returns to the opener; a nested shortcut sheet keeps its own focus.
  const opener = page.getByRole("button", { name: "Open command palette" });
  await opener.focus();
  await opener.press("Enter");
  await expect(page.getByRole("dialog", { name: "Command palette" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(opener).toBeFocused();
  await page.keyboard.press("Control+k");
  await input.fill("shortcuts");
  await page.keyboard.press("Enter");
  const sheet = page.getByRole("dialog", { name: "Keyboard shortcuts", exact: true });
  await expect(sheet).toBeVisible();
  await expect(sheet).toContainText("Keys marked with a place only work while focus is there.");
  expect(await sheet.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(opener).toBeFocused();

  // A navigation command must leave focus at the new page, not the persistent header button.
  await opener.click();
  await input.fill("all projects");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator("main#main-content")).toBeFocused();
});

test("a global admin creates a team, rosters a person and deletes the team", async ({ page, request }) => {
  const member = await registerPerson(request, "team-member");
  const teamName = uniq("Team Journey");
  await uiLogin(page);

  await page.goto("/teams");
  await page.getByRole("button", { name: "+ Create Team" }).click();
  const create = page.getByRole("dialog", { name: "Create Company Team" });
  await create.getByLabel("Team Name").fill(teamName);
  await create.getByRole("button", { name: "Create Team" }).click();
  await expect(create).toHaveCount(0);

  const card = page.locator(".bg-card").filter({
    has: page.getByRole("heading", { name: teamName, exact: true }),
  });
  // The creator is granted team admin on create, so the roster starts with one person.
  await expect(card).toContainText("1 members");
  await card.getByRole("button", { name: "Manage Roster" }).click();

  const roster = page.getByRole("dialog", { name: `${teamName} members` });
  await roster.getByLabel("Email address").fill(member.email);
  await roster.getByRole("button", { name: "Add", exact: true }).click();
  const list = roster.getByRole("list");
  await expect(list.getByRole("listitem").filter({ hasText: member.email })).toHaveCount(1);

  await list.getByRole("listitem").filter({ hasText: member.email })
    .getByRole("button", { name: "Remove" }).click();
  await expect(list.getByRole("listitem").filter({ hasText: member.email })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(roster).toHaveCount(0);
  await expect(card).toContainText("1 members");

  await card.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("alertdialog", { name: `Delete ${teamName}?` })
    .getByRole("button", { name: "Delete team" }).click();
  await expect(page.getByRole("heading", { name: teamName, exact: true })).toHaveCount(0);
});

test("a person who is not a global admin cannot reach admin tools", async ({ page, request }) => {
  const person = await registerPerson(request, "forbidden-person");
  await uiLoginAs(page, person.email, person.password);

  await page.goto("/admin");
  await expect(page.getByText("Only global admins can see this page.")).toBeVisible();
  await expect(page.getByRole("list", { name: "People" })).toHaveCount(0);

  await page.goto("/teams");
  await expect(page.getByRole("heading", { name: "Company Teams" })).toBeVisible();
  await expect(page.getByText("Global Admin required to create teams")).toBeVisible();
  await expect(page.getByRole("button", { name: "+ Create Team" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create First Team" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Manage Roster" })).toHaveCount(0);
});

test("manual ingest takes line-based Nuclei output", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("jsonl-ingest");
  await seedProject(request, token, slug);
  await uiLogin(page);

  await page.goto(`/${slug}/reports/upload`);
  await chooseOption(page, page.getByLabel("Scanner"), /^Nuclei/);
  await page.setInputFiles("#ingest-file", FIXTURE_NUCLEI);
  await expect(page.getByTestId("file-dropzone").getByText("nuclei.jsonl")).toBeVisible();

  await page.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByRole("link", { name: "View findings" })).toBeVisible();

  await page.goto(`/${slug}/findings`);
  await expect(page.locator("tbody tr").first()).toBeVisible();
});

test("a project admin classifies an environment and a later scan leaves it alone", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("environment");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH, {
    environment: "production",
    commit_sha: BASE_SHA,
  });
  await uiLogin(page);

  await page.goto(`/${slug}/insights`);
  const environments = page.getByRole("list", { name: "Environments" });
  await expect(environments.getByRole("listitem")).toContainText("production");
  await expect(environments.getByRole("listitem")).toContainText("Internal");

  await page.getByRole("button", { name: "Edit production" }).click();
  const dialog = page.getByRole("dialog", { name: "Classify production" });
  await chooseOption(page, dialog.getByLabel("Tier"), "Staging");
  await dialog.getByLabel("Reachable from the internet").check();
  await chooseOption(page, dialog.getByLabel("Data sensitivity"), "Restricted");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog).toBeHidden();
  await expect(environments.getByRole("listitem")).toContainText("Internet facing");
  await expect(environments.getByRole("listitem")).toContainText("restricted");

  // A later scan of the same environment does not undo it.
  await ingestFixture(request, token, slug, FIXTURE_MEDIUM, {
    environment: "production",
    commit_sha: CHANGE_SHA,
  });
  await page.reload();
  await expect(environments.getByRole("listitem")).toContainText("staging");
  await expect(environments.getByRole("listitem")).toContainText("Internet facing");
  await expect(environments.getByRole("listitem")).toContainText("restricted");
});

test("a file uploaded under the wrong scanner is refused with what to do", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("wrong-scanner");
  await seedProject(request, token, slug);
  await uiLogin(page);

  await page.goto(`/${slug}/reports/upload`);
  await chooseOption(page, page.getByLabel("Scanner"), /^Trivy/);
  await page.setInputFiles("#ingest-file", FIXTURE_GOSEC_JSON);
  await page.getByRole("button", { name: "Upload" }).click();

  await expect(page.getByRole("alert")).toContainText("The file is not trivy output");
  await expect(page.getByRole("alert")).toContainText(
    "Check that you chose the scanner that wrote it",
  );

  // Nothing was recorded.
  await page.goto(`/${slug}/reports`);
  await expect(page.getByText("gosec")).toHaveCount(0);
  await page.goto(`/${slug}/findings`);
  await expect(page.locator("tbody tr")).toHaveCount(0);
});

test("the upload page says how to produce the chosen scanner's file and takes .sarif", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("format-help");
  await seedProject(request, token, slug);
  await uiLogin(page);

  await page.goto(`/${slug}/reports/upload`);
  await chooseOption(page, page.getByLabel("Scanner"), /^Semgrep/);
  const help = page.getByRole("region", { name: /semgrep/i });
  await expect(help).toContainText("semgrep scan --json");
  await expect(help).toContainText("semgrep scan --sarif");
  await expect(help).toContainText("Checked with Semgrep");
  await expect(page.getByText("Takes .json, .sarif")).toBeVisible();

  // The usual extension for SARIF is .sarif, which the page used to refuse.
  await chooseOption(page, page.getByLabel("Scanner"), /^SARIF/);
  await page.setInputFiles("#ingest-file", {
    name: "results.sarif",
    mimeType: "application/json",
    buffer: readFileSync(FIXTURE_HIGH),
  });
  await expect(page.getByTestId("file-dropzone").getByText("results.sarif")).toBeVisible();
  await page.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByRole("link", { name: "View findings" })).toBeVisible();
});

/**
 * Presses Alt+T, Sonner's key for the notification list, then Tab to the toast and Tab again to
 * the button in it: the list takes focus first, then the toast, then its Undo button.
 */
async function focusUndoWithKeyboard(page: import("@playwright/test").Page): Promise<void> {
  await page.keyboard.press("Alt+t");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Undo" })).toBeFocused();
}

test("a keyboard user undoes a triage change from the notification", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("undo-triage");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await page.locator("tbody tr").filter({ hasText: HIGH_TITLE }).click();
  const decide = page.getByRole("heading", { level: 2, name: "Decide" }).locator("..");
  await expect(decide).toContainText("Currently: Not triaged");

  await chooseOption(page, page.getByLabel("Triage action"), "Exploitable");
  await page.getByRole("button", { name: "Apply" }).click();
  // The chosen state shows at once and the page claims nothing about the gate until it refetched.
  await expect(decide).toContainText("Currently: Exploitable");
  await expect(page.getByText(/Triage saved \(effect:/)).toBeVisible();

  await focusUndoWithKeyboard(page);
  await page.keyboard.press("Enter");
  await expect(page.getByText("Triage restored to Not triaged")).toBeVisible();
  await expect(decide).toContainText("Currently: Not triaged");
  // Focus went back to a real control, not to the page body.
  await expect.poll(() => page.evaluate(() => document.activeElement?.tagName)).not.toBe("BODY");

  // The history is honest: the change and its reversal are two events.
  const findingId = new URL(page.url()).pathname.split("/").pop();
  const events = await request.get(`/api/v1/findings/${findingId}/events`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(events.ok(), await events.text()).toBeTruthy();
  const changes = ((await events.json()) as Array<{ event_type: string; }>)
    .filter((event) => event.event_type === "analysis_changed");
  expect(changes.length).toBeGreaterThanOrEqual(2);
});

test("Undo puts a triage back to a state that needed a reason, with its reason and expiry", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("undo-reason");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await page.locator("tbody tr").filter({ hasText: HIGH_TITLE }).click();
  const findingId = new URL(page.url()).pathname.split("/").pop();
  const auth = { Authorization: `Bearer ${token}` };

  // Accept the risk through the API, so the only notification on the page is the one under test.
  const expiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const accepted = await request.patch(`/api/v1/findings/${findingId}`, {
    headers: auth,
    data: {
      analysis_state: "accepted_risk",
      reason: "covered by the WAF rule",
      analysis_expires_at: expiry,
    },
  });
  expect(accepted.ok(), await accepted.text()).toBeTruthy();
  await page.reload();
  const decide = page.getByRole("heading", { level: 2, name: "Decide" }).locator("..");
  await expect(decide).toContainText("Currently: Accepted risk");
  await expect(decide).toContainText("Reason: covered by the WAF rule");

  await chooseOption(page, page.getByLabel("Triage action"), "Exploitable");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(decide).toContainText("Currently: Exploitable");
  await expect(page.getByText(/Triage saved \(effect:/)).toBeVisible();
  await expect(decide).not.toContainText("Reason:");

  await focusUndoWithKeyboard(page);
  await page.keyboard.press("Enter");
  await expect(page.getByText("Triage restored to Accepted risk")).toBeVisible();
  await expect(decide).toContainText("Currently: Accepted risk");
  await expect(decide).toContainText("Reason: covered by the WAF rule");
  await expect(decide).toContainText("Expires");

  // The server put the whole decision back, and the history names the event it reversed.
  const finding = await request.get(`/api/v1/findings/${findingId}`, { headers: auth });
  const restored = (await finding.json()) as {
    analysis_state: string;
    analysis_reason?: string;
    analysis_expires_at?: string;
    manual_override: boolean;
  };
  expect(restored.analysis_state).toBe("accepted_risk");
  expect(restored.analysis_reason).toBe("covered by the WAF rule");
  expect(new Date(restored.analysis_expires_at ?? "").getTime()).toBe(new Date(expiry).getTime());
  expect(restored.manual_override).toBe(true);
  const events = await request.get(`/api/v1/findings/${findingId}/events`, { headers: auth });
  const undone = ((await events.json()) as Array<{ event_type: string; changes?: string; }>)
    .filter((event) => event.event_type === "analysis_changed" && event.changes)
    .map((event) =>
      JSON.parse(Buffer.from(event.changes ?? "", "base64").toString()) as { undo_of?: string; }
    )
    .filter((changes) => changes.undo_of);
  expect(undone).toHaveLength(1);
});

test("a keyboard user undoes revoking a waiver from the notification", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("undo-waiver");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  await requestWaiver(request, token, slug, "Not reachable from the public API.");
  await uiLogin(page);

  await page.goto(`/${slug}/waivers`);
  await page.getByRole("button", { name: /^Approve / }).click();
  await page.getByLabel(/^Note/).fill("Fine until the image bump.");
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(page.getByRole("tab", { name: "In force 1" })).toBeVisible();

  await page.getByRole("tab", { name: "In force 1" }).click();
  await page.getByRole("button", { name: /^Revoke / }).click();
  await expect(page.getByRole("tab", { name: "In force 0" })).toBeVisible();
  await expect(page.getByText("Waiver revoked")).toBeVisible();

  await focusUndoWithKeyboard(page);
  await page.keyboard.press("Enter");
  await expect(page.getByText("Waiver back in force")).toBeVisible();
  await expect(page.getByRole("tab", { name: "In force 1" })).toBeVisible();
});

test("a manager restores a revoked waiver, and an expired one offers Edit expiry instead", async ({ page, request }) => {
  const token = await apiToken(request);
  const headers = { Authorization: `Bearer ${token}` };
  const slug = uniq("restore-waiver");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH);
  const requestId = await requestWaiver(request, token, slug, "Not reachable from the public API.");
  const approved = await request.post(`/api/v1/projects/${slug}/waivers/${requestId}/approve`, {
    headers,
    data: { note: "Fine until the image bump." },
  });
  expect(approved.ok(), await approved.text()).toBeTruthy();

  // A waiver whose expiry already passed. Whether or not the sweeper has switched it off yet, it
  // sits in the Closed list as expired and cannot be restored.
  const list = await request.get(`/api/v1/projects/${slug}/findings`, { headers });
  const findingId = ((await list.json()) as Array<{ id: string; }>)[0]!.id;
  const lapsed = await request.post(`/api/v1/projects/${slug}/waivers`, {
    headers,
    data: {
      name: "Old exception",
      target_ids: [findingId],
      expires_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    },
  });
  expect(lapsed.ok(), await lapsed.text()).toBeTruthy();
  await uiLogin(page);

  await page.goto(`/${slug}/waivers?state=in_force`);
  await expect(page.getByRole("tab", { name: "In force 1" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await page.getByRole("button", { name: /^Revoke / }).click();
  await expect(page.getByText("Waiver revoked")).toBeVisible();
  await expect(page.getByRole("tab", { name: "In force 0" })).toBeVisible();

  await page.getByRole("tab", { name: "Closed 2" }).click();
  await expect(page.getByText("Expired", { exact: true })).toBeVisible();
  // Only the revoked waiver can be restored; the expired one can have its expiry edited.
  await expect(page.getByRole("button", { name: /^Restore / })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Restore Old exception" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Edit expiry of Old exception" })).toBeVisible();

  await page.getByRole("button", { name: /^Restore / }).click();
  await expect(page.getByText("Waiver restored")).toBeVisible();
  await expect(page.getByRole("tab", { name: "In force 1" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Closed 1" })).toBeVisible();
  await expect(page.getByRole("tabpanel")).toBeFocused();

  // The restored waiver counts at the gate again.
  await page.goto(`/${slug}/findings`);
  await expect(page.getByText("PASSING", { exact: true })).toBeVisible();

  await page.goto(`/${slug}/waivers?state=closed`);
  await page.getByRole("button", { name: "Edit expiry of Old exception" }).click();
  await expect(page.getByRole("dialog", { name: "Edit waiver" })).toBeVisible();
});

test("removing a member asks first, and Undo from the notification grants the role again", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("undo-member");
  await seedProject(request, token, slug);
  const person = await registerPerson(request, "undo-member");
  const grant = await request.post(`/api/v1/projects/${slug}/members`, {
    headers: { Authorization: `Bearer ${token}` },
    data: { email: person.email, role: "manager" },
  });
  expect(grant.ok(), await grant.text()).toBeTruthy();
  await uiLogin(page);

  await page.goto(`/${slug}/access`);
  const row = page.getByRole("listitem").filter({ hasText: person.email });
  await row.getByRole("button", { name: "Remove" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Remove" }).click();
  await expect(page.getByText("Member removed")).toBeVisible();
  await expect(row).toHaveCount(0);

  await focusUndoWithKeyboard(page);
  await page.keyboard.press("Enter");
  await expect(page.getByText("Member restored")).toBeVisible();
  const restored = page.getByRole("listitem").filter({ hasText: person.email });
  await expect(restored).toContainText("manager");
});

test("Back from a finding returns the findings list to where it was scrolled", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("scroll-back");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH_MEDIUM);
  await uiLogin(page);

  await page.setViewportSize({ width: 1024, height: 600 });
  await page.goto(`/${slug}/findings`);
  await expect(page.locator("tbody tr").first()).toBeVisible();

  // The fixture has two findings, so make the page tall enough to scroll well past the first row.
  // The style survives the in-app navigation and Back, which do not reload the document.
  await page.addStyleTag({ content: "main { padding-bottom: 3000px; }" });
  const leftAt = 400;
  await page.evaluate((y) => window.scrollTo(0, y), leftAt);
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(leftAt);

  // Click without letting Playwright scroll the link into view first: the link is above the window
  // at this offset, and the point is to leave from exactly this position.
  await page.getByRole("link", { name: HIGH_TITLE }).dispatchEvent("click");
  await expect(page).toHaveURL(/\/findings\/[0-9a-f-]+$/);
  await page.goBack();

  await expect(page.getByRole("link", { name: HIGH_TITLE })).toBeAttached();
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThanOrEqual(leftAt - 2);
  expect(await page.evaluate(() => window.scrollY)).toBeLessThanOrEqual(leftAt + 2);
});

test("a new visit to the findings list starts at the top", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("scroll-top");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH_MEDIUM);
  await uiLogin(page);

  await page.setViewportSize({ width: 1024, height: 200 });
  await page.goto(`/${slug}/findings`);
  await expect(page.locator("tbody tr").first()).toBeVisible();
  await page.evaluate(() => window.scrollTo(0, 80));
  await page.getByRole("link", { name: HIGH_TITLE }).click();
  await expect(page).toHaveURL(/\/findings\/[0-9a-f-]+$/);

  // The "Back to findings" link is a new history entry, not the browser's Back.
  await page.getByRole("link", { name: /Back to findings/ }).click();
  await expect(page.locator("tbody tr").first()).toBeVisible();
  expect(await page.evaluate(() => window.scrollY)).toBe(0);
});

/** The value beside a term in a description list: what a screen reader reads after the name. */
function valueBeside(scope: Locator, term: string) {
  return scope.locator("dt", { hasText: new RegExp(`^${term}$`) }).locator(
    "xpath=following-sibling::dd[1]",
  );
}

test("the finding page lists the CVE evaluation in plain words and says where each part came from", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("cve-details");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_TRIVY_MULTI_SOURCE, { scanner: "trivy" });
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  // The list shows the advisory title; the CVE identifier appears on the finding page.
  await page.getByRole("link", { name: "libexample: cross-site scripting" }).click();
  await expect(page).toHaveURL(/\/findings\/[0-9a-f-]+$/);

  // Folded to a summary that names the source of the score, behind a disclosure button.
  const section = page.getByRole("region", { name: "CVE details" });
  await expect(section.getByText("CVE-2024-4444")).toBeVisible();
  await expect(section.getByText(/\(v3\.1, scan report\)/)).toBeVisible();
  const toggle = section.getByRole("button", { name: "Show the full CVE breakdown" });
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await toggle.focus();
  await page.keyboard.press("Enter");
  await expect(
    section.getByRole("button", { name: "Hide the full CVE breakdown" }),
  ).toHaveAttribute("aria-expanded", "true");

  // Every version the report carried, each with its band as a word and its metrics as label-value pairs.
  for (const version of ["2.0", "3.0", "3.1", "4.0"]) {
    await expect(
      section.getByRole("article", { name: `CVSS ${version}` }).first(),
    ).toBeVisible();
  }
  const v2 = section.getByRole("article", { name: "CVSS 2.0" });
  await expect(valueBeside(v2, "Access Complexity")).toHaveText("Medium");
  await expect(valueBeside(v2, "Authentication")).toHaveText("None");
  await expect(v2.getByText("Medium", { exact: true }).first()).toBeVisible();

  const v4 = section.getByRole("article", { name: "CVSS 4.0" });
  await expect(valueBeside(v4, "Attack Requirements")).toHaveText("None");
  await expect(valueBeside(v4, "User Interaction")).toHaveText("Passive");
  await expect(v4.getByText("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"))
    .toBeVisible();
  await expect(v4.getByRole("button", { name: "Copy CVSS 4.0 vector" })).toBeVisible();

  const v30 = section.getByRole("article", { name: "CVSS 3.0" });
  await expect(valueBeside(v30, "Scope")).toHaveText("Changed");
  await expect(valueBeside(v30, "Attack Vector")).toHaveText("Network");

  // The scanner said it, and the page says so.
  await expect(v4.getByText(/^From the scan report \(trivy, /)).toBeVisible();

  // CWE identifiers link to MITRE and open in a new tab.
  const cwe = section.getByRole("link", { name: /^CWE-79/ });
  await expect(cwe).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/79.html");
  await expect(cwe).toHaveAttribute("target", "_blank");
  await expect(cwe).toHaveAttribute("rel", "noopener noreferrer");

  // No provider is configured in this run, and the page says what that means.
  await expect(section.getByText(/No external provider is configured/)).toBeVisible();
});

test("a finding whose scan report carries several CVSS vectors lists them without scrolling a phone sideways", async ({ page, request }) => {
  const token = await apiToken(request);
  const slug = uniq("cve-details-phone");
  await seedProject(request, token, slug);
  await ingestFixture(request, token, slug, FIXTURE_GRYPE_MULTI_CVSS, { scanner: "grype" });
  await uiLogin(page);

  await page.setViewportSize({ width: 360, height: 740 });
  await page.goto(`/${slug}/findings`);
  await page.getByRole("link", { name: /^CVE-2024-1111 in/ }).first().click();
  await expect(page).toHaveURL(/\/findings\/[0-9a-f-]+$/);

  const section = page.getByRole("region", { name: "CVE details" });
  await section.getByRole("button", { name: "Show the full CVE breakdown" }).click();
  await expect(section.getByRole("article", { name: "CVSS 4.0" })).toBeVisible();
  await expect(section.getByText(/scored by nvd@nist\.gov:primary/).first()).toBeVisible();
  await expect(section.getByText(/scored by security-advisories@github\.com:secondary/).first())
    .toBeVisible();

  const overflow = await page.evaluate(() =>
    document.documentElement.scrollWidth - document.documentElement.clientWidth
  );
  expect(overflow).toBeLessThanOrEqual(0);
});
