/// <reference lib="dom" />
import type { Page } from "@playwright/test";
import { expect, test } from "@playwright/test";
import axe from "axe-core";
import {
  apiToken,
  BASE_SHA,
  CHANGE_SHA,
  FIXTURE_HIGH_MEDIUM,
  FIXTURE_HIGH_NEW,
  ingestFixture,
  registerPerson,
  requestWaiver,
  seedProject,
  uiLogin,
  uniq,
} from "./helpers";

// The accessibility baseline: every page passes axe-core with no WCAG 2.2 A or AA violations,
// in the light and the dark theme. Real data is seeded so the pages are audited with content
// (a blocked change, findings, reports) and not only their empty states.

const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

interface Finding {
  readonly page: string;
  readonly theme: string;
  readonly rule: string;
  readonly impact: string;
  readonly nodes: readonly string[];
}

const findings: Finding[] = [];
let audits = 0;

/**
 * Entrance animations (dialogs, tooltips, toasts) blend colours while they run, so audit the
 * settled state. Two frames let a transition that starts on the next render begin before the
 * wait; the loop then repeats until nothing is running.
 */
async function settle(page: Page): Promise<void> {
  const stuck = await page.evaluate(async () => {
    // A looping animation (a skeleton pulse, a spinner) never finishes, so each wait is capped and
    // the test fails naming what is still running instead of using up the whole test timeout.
    const deadline = Date.now() + 5_000;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const running = document.getAnimations();
      if (running.length === 0) return [];
      const left = deadline - Date.now();
      if (left <= 0) break;
      await Promise.race([
        Promise.all(running.map((animation) => animation.finished.catch(() => undefined))),
        new Promise((resolve) => setTimeout(resolve, left)),
      ]);
    }
    return document.getAnimations().map((animation) => {
      const target = (animation.effect as KeyframeEffect | null)?.target;
      const name = animation instanceof CSSAnimation
        ? animation.animationName
        : animation instanceof CSSTransition
        ? `transition ${animation.transitionProperty}`
        : animation.id || "script animation";
      const where = target
        ? `${target.tagName.toLowerCase()}.${[...target.classList].join(".")}`
        : "no target";
      const iterations = animation.effect?.getTiming().iterations;
      return `${name} on ${where} (iterations ${String(iterations)})`;
    });
  });
  expect(stuck, "animations still running when the page should be settled").toEqual([]);
}

async function audit(page: Page, name: string): Promise<void> {
  await page.waitForLoadState("networkidle");
  // Previous interactions can leave a target cut by the viewport edge and
  // sticky header. Start document scans at the top so axe measures the whole
  // target, rather than its scroll-dependent visible fragment.
  await page.evaluate(() => window.scrollTo({ top: 0, left: 0, behavior: "instant" }));
  await settle(page);
  // Evaluated through the devtools protocol, which the page CSP does not
  // govern; an inline <script> tag would be blocked by script-src 'self'.
  await page.evaluate(axe.source);
  for (const theme of ["light", "dark"] as const) {
    await page.evaluate(
      (t) => document.documentElement.classList.toggle("dark", t === "dark"),
      theme,
    );
    await settle(page);
    const result = await page.evaluate(
      async (tags) => {
        const api = (window as unknown as { axe: typeof axe; }).axe;
        return await api.run(document, { runOnly: { type: "tag", values: tags } });
      },
      WCAG_TAGS,
    );
    audits += 1;
    for (const violation of result.violations) {
      findings.push({
        page: name,
        theme,
        rule: violation.id,
        impact: violation.impact ?? "unknown",
        nodes: violation.nodes.slice(0, 3).map((n) =>
          `${n.target.join(" ")}: ${n.any[0]?.message ?? n.failureSummary ?? ""}`.slice(0, 160)
        ),
      });
    }
  }
}

test("every page passes axe in the light and the dark theme", async ({ page, request }) => {
  test.setTimeout(120_000);
  const token = await apiToken(request);
  const slug = uniq("a11y");
  const emptySlug = uniq("a11y-empty");
  await seedProject(request, token, slug);
  await seedProject(request, token, emptySlug);
  await ingestFixture(request, token, slug, FIXTURE_HIGH_MEDIUM, { commit_sha: BASE_SHA });
  await ingestFixture(request, token, slug, FIXTURE_HIGH_NEW, {
    commit_sha: CHANGE_SHA,
    base_revision: BASE_SHA,
    gate_introduced_only: true,
  });

  // Signed-out pages first.
  await page.goto("/login");
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  await audit(page, "/login");
  await page.goto("/register");
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "/register");

  // First run: the page exists only on a server with no account, so the answer is staged. The
  // password rules appear with the first character; audit them showing.
  await page.route("**/api/v1/capabilities", (route) =>
    route.fulfill({
      json: {
        registration: { enabled: true },
        sso: { enabled: false },
        setup: { required: true },
        version: "dev",
        commit: "none",
      },
    }));
  await page.goto("/setup");
  await expect(page.getByRole("heading", { name: "Set up Specht" })).toBeVisible();
  await audit(page, "/setup");
  await page.getByLabel("Password").fill("abc");
  await expect(page.getByRole("list", { name: "Requirements" })).toBeVisible();
  await audit(page, "/setup with password rules showing");
  await page.unroute("**/api/v1/capabilities");

  // An invitation, as the person who opens the link sees it, and a link that no longer works.
  const invited = await request.post(`/api/v1/projects/${slug}/invites`, {
    headers: { Authorization: `Bearer ${token}` },
    data: { role: "manager" },
  });
  expect(invited.ok(), await invited.text()).toBeTruthy();
  await page.goto((await invited.json()).link as string);
  await expect(page.getByRole("heading", { name: `Join ${slug}` })).toBeVisible();
  await audit(page, "/invite/:token");
  await page.goto("/reset/not-a-real-link");
  await expect(page.getByRole("heading", { name: "Choose a new password" })).toBeVisible();
  await audit(page, "/reset/:token");
  await page.goto("/invite/not-a-real-link");
  await expect(page.getByRole("heading", { name: "This invite link does not work" })).toBeVisible();
  await audit(page, "/invite/:token (not valid)");

  await uiLogin(page);
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
  await audit(page, "/ (projects)");

  await page.goto(`/${slug}/findings`);
  await expect(page.getByRole("grid").or(page.locator("table")).first()).toBeVisible();
  await audit(page, "findings list");

  // An open explanation is part of the page too: audit it with the tooltip showing. The button's
  // accessible description must carry the explanation, so a screen reader announces the answer.
  const tip = page.getByRole("button", { name: "What is Severity floor?" });
  await expect(tip).toHaveAccessibleDescription(/lowest severity that can block the gate/);
  await tip.hover();
  await expect(page.getByText(/lowest severity that can block the gate/)).toBeVisible();
  await audit(page, "findings list with a tooltip open");
  await page.mouse.move(0, 0);

  // The dropdown popup is a portal outside the page tree: audit it open as well.
  await page.getByLabel("Filter by triage state").click();
  await expect(page.getByRole("option", { name: "All triage states", exact: true })).toBeVisible();
  await audit(page, "findings list with a dropdown open");
  await page.keyboard.press("Escape");

  // A selection raises the bulk bar; audit it, and the dialog it opens.
  await page.getByRole("checkbox", { name: "Select all findings on this page" }).check();
  await expect(page.getByRole("region", { name: "Bulk actions" })).toBeVisible();
  await audit(page, "findings list with a selection");
  await page.getByRole("button", { name: "Triage…" }).click();
  await expect(page.getByRole("dialog", { name: /^Triage \d+ findings?$/ })).toBeVisible();
  await audit(page, "bulk triage dialog");
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Clear" }).click();

  await page.locator("a[href*=\"/findings/\"]").first().click();
  await expect(page.getByRole("group", { name: "What is this finding?" })).toBeVisible();
  await page.getByRole("radio", { name: /^Not a problem/ }).check();
  await page.getByRole("radio", { name: /^The code is not affected/ }).check();
  await audit(page, "finding detail with a decision picked");

  // A success toast is page content for as long as it shows. A real issue that is reachable keeps
  // the change blocked.
  await page.getByRole("radio", { name: /^Real issue/ }).check();
  await page.getByRole("radio", { name: "Yes", exact: true }).check();
  await page.getByRole("button", { name: "Save decision" }).click();
  await expect(page.getByText("Reachability saved", { exact: true })).toBeVisible();
  await audit(page, "finding detail with a success toast");
  // Decide-first: the decision leads the page, so its Save shows without scrolling. With a reason
  // field open the button can sit across the fold on a 720 px desktop, so this asks for any part.
  // The numbers go to the CI log, so a failure says how far below the fold the button sits.
  console.log("Save decision box", {
    box: await page.getByRole("button", { name: "Save decision" }).boundingBox(),
    viewport: page.viewportSize(),
    scrollY: await page.evaluate(() => window.scrollY),
  });
  await expect(page.getByRole("button", { name: "Save decision" })).toBeInViewport();

  await page.goto(`/${slug}/reports`);
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "reports");

  await page.goto(`/${slug}/changes/${CHANGE_SHA.slice(0, 7)}`);
  await expect(page.getByText("BLOCKED", { exact: true })).toBeVisible();
  await audit(page, "change view (blocked)");

  await page.goto(`/${slug}/changes/deadbee`);
  await expect(page.getByText("No scan found for commit deadbee")).toBeVisible();
  await audit(page, "change view (no scan)");

  await page.goto(`/${slug}/setup`);
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "project setup");

  await page.goto(`/${slug}/reports/upload`);
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "upload report");

  await page.goto("/projects/new");
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "new project");

  await page.goto("/api-keys");
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "api keys");

  await page.goto("/profile");
  await expect(page.getByRole("heading", { name: "Your profile" })).toBeVisible();
  await audit(page, "profile");
  // The password rules appear once typing starts; audit that state too.
  await page.getByLabel("New password", { exact: true }).fill("abc");
  await expect(page.getByRole("list", { name: "Requirements" })).toBeVisible();
  await audit(page, "profile with password rules");

  await page.goto(`/${emptySlug}/findings`);
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "empty project");

  await page.goto("/no-such-project/findings");
  await expect(page.getByRole("heading").first()).toBeVisible();
  await audit(page, "project not found");

  // Dialogs are page content while open: audit each one with its focus trap active.
  await page.goto(`/${slug}/access`);
  await expect(page.getByRole("heading", { name: /Direct Members/ })).toBeVisible();
  await audit(page, "project access");
  // The invite dialog, then the step that shows the link once.
  await page.getByRole("button", { name: "Invite people" }).click();
  await expect(page.getByRole("dialog", { name: "Invite someone to this project" })).toBeVisible();
  await audit(page, "invite dialog");
  await page.getByRole("button", { name: "Create link" }).click();
  await expect(page.getByRole("dialog", { name: "Send this link" })).toBeVisible();
  await audit(page, "invite link shown once");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  // The only admin cannot be removed: hovering the disabled control explains why.
  await page.locator("span[tabindex=\"0\"]").first().hover();
  await expect(
    page.locator("[data-slot=\"tooltip-content\"]", {
      hasText: "Cannot remove the last project admin",
    }),
  ).toBeVisible();
  await audit(page, "project access with a disabled reason shown");
  await page.mouse.move(0, 0);
  await page.getByRole("button", { name: "+ Add Member" }).click();
  await expect(page.getByRole("dialog", { name: "Add Direct Member" })).toBeVisible();
  await audit(page, "add member dialog");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);

  await page.getByRole("button", { name: "+ Link Team" }).click();
  await expect(page.getByRole("dialog", { name: "Link Company Team" })).toBeVisible();
  await audit(page, "link team dialog");
  await page.keyboard.press("Escape");

  // The policy page, and its editor for one setting.
  await page.goto(`/${slug}/policy`);
  await expect(page.getByRole("heading", { name: "Policy", exact: true })).toBeVisible();
  await audit(page, "project policy");
  await page.getByRole("button", { name: "Override Severity floor" }).click();
  await expect(page.getByRole("combobox", { name: "Severity floor" })).toBeVisible();
  await audit(page, "project policy while overriding a setting");

  // Waivers: the waiting list with a request in it, the decision dialog, and the other lists.
  await requestWaiver(request, token, slug, "Not reachable from the public API.");
  await page.goto(`/${slug}/waivers`);
  await expect(page.getByRole("tab", { name: "Waiting 1" })).toBeVisible();
  await audit(page, "project waivers");
  await page.getByRole("button", { name: /^Approve / }).click();
  await expect(page.getByRole("dialog", { name: "Approve this waiver?" })).toBeVisible();
  await audit(page, "waiver decision dialog");
  await page.keyboard.press("Escape");
  await page.getByRole("tab", { name: "In force 0" }).click();
  await expect(page.getByText("No waiver is letting a finding through.")).toBeVisible();
  await audit(page, "project waivers, empty list");

  await page.goto(`/${slug}/insights`);
  await expect(page.getByRole("list", { name: "Open findings by severity" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Where it runs" })).toBeVisible();
  await audit(page, "project insights");

  await page.goto(`/${slug}/watcher`);
  await expect(page.getByRole("switch", { name: "Watch this project" })).toBeVisible();
  await audit(page, "project watcher");

  await page.goto(`/${slug}/settings`);
  await expect(page.getByRole("button", { name: "Save" })).toBeVisible();
  await audit(page, "project settings");

  // Admin: the page, and the confirmation that ends an account. The test makes its own second
  // person, so a Deactivate button exists even when no other spec has registered anyone yet.
  await registerPerson(request, "a11y-person");
  await page.goto("/admin");
  await expect(page.getByRole("list", { name: "People" })).toBeVisible();
  await expect(page.getByText("Nothing to remove")).toBeVisible();
  await audit(page, "admin");
  await page.getByRole("button", { name: /^Deactivate / }).first().click();
  await expect(page.getByRole("alertdialog")).toBeVisible();
  await audit(page, "admin deactivate confirmation");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("alertdialog")).toHaveCount(0);

  // The command palette, open over a project page with a query typed.
  await page.goto(`/${slug}/findings`);
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("dialog", { name: "Command palette" })).toBeVisible();
  await audit(page, "command palette");
  await page.getByRole("combobox", { name: "Search commands" }).fill("zzzzqq");
  await expect(page.getByText("Nothing matches")).toBeVisible();
  await audit(page, "command palette with no match");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);

  await page.goto("/teams");
  await page.getByRole("button", { name: "+ Create Team" }).click();
  await expect(page.getByRole("dialog", { name: "Create Company Team" })).toBeVisible();
  await audit(page, "create team dialog");
  await page.keyboard.press("Escape");

  const report = findings
    .map((f) => `[${f.theme}] ${f.page}: ${f.rule} (${f.impact})\n    ${f.nodes.join("\n    ")}`)
    .join("\n");
  expect(findings, `axe found violations in ${audits} audits:\n${report}`).toEqual([]);
  expect(audits).toBeGreaterThanOrEqual(40);
});
