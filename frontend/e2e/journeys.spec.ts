import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import {
  apiToken,
  BASE_SHA,
  CHANGE_SHA,
  chooseOption,
  FIXTURE_GITLEAKS,
  FIXTURE_GOSEC_JSON,
  FIXTURE_HIGH,
  FIXTURE_HIGH_MEDIUM,
  FIXTURE_HIGH_NEW,
  FIXTURE_MEDIUM,
  FIXTURE_NUCLEI,
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

  await page.getByRole("button", { name: "Sign out" }).click();
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
  for (const name of ["Profile", "Teams", "API keys", "Admin", "Sign out"]) {
    const item = nav.getByText(name, { exact: true });
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

  await page.getByRole("link", { name: "Policy", exact: true }).click();
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
  await page.getByRole("link", { name: "Watcher", exact: true }).click();
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
  await uiLogin(page);

  await page.goto(`/${slug}/findings`);
  await page.keyboard.press("Control+k");
  const input = page.getByRole("combobox", { name: "Search commands" });
  await expect(input).toBeFocused();

  // A page of this project, found by a word and reached with Enter.
  await input.fill("policy");
  await expect(page.getByRole("option").first()).toContainText("Policy");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/${slug}/policy$`));
  await expect(page.getByRole("dialog")).toHaveCount(0);

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

  // The button opens it too.
  await page.getByRole("button", { name: "Open command palette" }).click();
  await expect(page.getByRole("dialog", { name: "Command palette" })).toBeVisible();
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
  await expect(page.getByText("nuclei.jsonl loaded")).toBeVisible();

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
  await expect(page.getByText("results.sarif loaded")).toBeVisible();
  await page.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByRole("link", { name: "View findings" })).toBeVisible();
});
