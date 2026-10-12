import { expect, test } from "@playwright/test";
import {
  apiToken,
  BASE_SHA,
  CHANGE_SHA,
  chooseOption,
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
  await chooseOption(page, page.getByLabel("Scanner"), /^sarif/);
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
  await expect(page.locator("span", { hasText: /^Blocks gate$/ })).toBeVisible();

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
