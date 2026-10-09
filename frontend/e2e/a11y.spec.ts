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
  await page.evaluate(async () => {
    for (let attempt = 0; attempt < 10; attempt += 1) {
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const running = document.getAnimations();
      if (running.length === 0) return;
      await Promise.all(running.map((animation) => animation.finished.catch(() => undefined)));
    }
  });
}

async function audit(page: Page, name: string): Promise<void> {
  await page.waitForLoadState("networkidle");
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

  await page.locator("a[href*=\"/findings/\"]").first().click();
  await expect(page.getByRole("heading", { name: "Triage" })).toBeVisible();
  await page.getByLabel("Triage action").selectOption("not_affected");
  await audit(page, "finding detail with a triage hint");

  // A success toast is page content for as long as it shows. "reachable" keeps the change blocked.
  await page.getByLabel("Reachability assessment").selectOption("reachable");
  await page.getByRole("button", { name: "Assess" }).click();
  await expect(page.getByText("Reachability saved")).toBeVisible();
  await audit(page, "finding detail with a success toast");

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
