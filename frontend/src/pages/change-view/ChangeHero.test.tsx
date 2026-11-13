import { formatClockTime } from "@/lib/format";
import type { PolicyEffective, Report } from "@/types/api";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ChangeHero } from "./ChangeHero";

const report = {
  id: "r1",
  created_at: "2026-10-30T10:00:00Z",
  status: "completed",
  branch: "main",
} as unknown as Report;
const policy = {
  severity_floor: "high",
  severity_source: "default",
} as unknown as PolicyEffective;

describe("ChangeHero passing copy", () => {
  it("says nothing is left blocking, without claiming the scan found nothing", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        state="passing"
        blockers={0}
        existing={0}
        waived={0}
        policy={policy}
      />,
    );

    expect(
      screen.getByText(
        "No new finding at High or above is left blocking this change in the scan of abcdef1. Nothing to do here.",
      ),
    ).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/found no new finding/);
  });

  it("stays true when waivers made the pass, and names the waived count", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        state="passing"
        blockers={0}
        existing={0}
        waived={2}
        policy={policy}
      />,
    );

    expect(
      screen.getByText(
        "No new finding at High or above is left blocking this change in the scan of abcdef1. The 2 waived findings do not count. Nothing to do here.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("2 waived")).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/found no new finding/);
  });

  it("uses the singular for one waived finding", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        state="passing"
        blockers={0}
        existing={0}
        waived={1}
        policy={policy}
      />,
    );

    expect(screen.getByText(/The 1 waived finding does not count\./)).toBeInTheDocument();
  });

  it("never says the change blocks the merge or is green", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        state="passing"
        blockers={0}
        existing={0}
        waived={2}
        policy={policy}
      />,
    );

    expect(document.body).not.toHaveTextContent(/blocks the merge|\bgreen\b/i);
  });
});

describe("ChangeHero narrow screens", () => {
  it("lets a long branch name wrap so a phone does not scroll sideways", () => {
    const branch = `dependabot/npm_and_yarn/${"a".repeat(60)}`;
    render(
      <ChangeHero
        commit="abcdef1234"
        report={{ ...report, branch }}
        state="passing"
        blockers={0}
        existing={0}
        waived={0}
        policy={policy}
      />,
    );

    expect(screen.getByText(branch)).toHaveClass("min-w-0", "[overflow-wrap:anywhere]");
  });
});

describe("ChangeHero unblocked and unconfirmed copy", () => {
  it("says the unblocked verdict is worked out now, not recorded at upload", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        state="unblocked"
        blockers={0}
        existing={0}
        waived={0}
        policy={policy}
      />,
    );

    expect(screen.getByText(/Specht works out this verdict now/)).toBeInTheDocument();
    expect(screen.getByText(/does not update; re-run the job if it still shows failed/))
      .toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(
      /recorded this verdict|when the scan uploaded|reflects it as of then/,
    );
    expect(document.body).not.toHaveTextContent(/blocks the merge|\bgreen\b/i);
  });

  it("says the unconfirmed verdict counts only what this commit introduced", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        state="unconfirmed"
        blockers={0}
        existing={0}
        waived={0}
        earlierOpen={2}
        policy={policy}
      />,
    );

    expect(
      screen.getByText(
        "This verdict counts only the findings this commit introduced. The findings below blocked the earlier commit and are still open.",
      ),
    ).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/did not examine|recorded as passing/);
  });
});

describe("ChangeHero project gate beside an older report", () => {
  const at = "2026-11-07T14:05:00Z";

  it("says the project gate is as of now, with the time, and not the state at the commit", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        state="blocked"
        blockers={2}
        existing={0}
        waived={0}
        policy={policy}
        projectWide
        gateAsOf={at}
      />,
    );

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      `2 findings block this project as of now, ${formatClockTime(at)}.`,
    );
    expect(screen.getByText(formatClockTime(at))).toHaveAttribute("datetime", at);
    expect(
      screen.getByText(
        "A newer report exists on main, so this is the project gate now, not the state at abcdef1.",
      ),
    ).toBeInTheDocument();
  });

  it("names a passing project gate as of now too", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        state="passing"
        blockers={0}
        existing={0}
        waived={0}
        policy={policy}
        projectWide
        gateAsOf={at}
      />,
    );

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      `Project gate passed as of now, ${formatClockTime(at)}.`,
    );
  });

  it("leaves a change-scoped verdict alone, since it is not the project gate", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        state="blocked"
        blockers={1}
        existing={0}
        waived={0}
        policy={policy}
        gateAsOf={at}
      />,
    );

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "1 finding blocks this change.",
    );
    expect(document.body).not.toHaveTextContent(/as of now|A newer report/);
  });
});

describe("ChangeHero links back to the code", () => {
  const sha = "9fceb02d0ae598e95dc970b74767f19372d61af8";
  function renderWith(extra: Partial<Report>) {
    render(
      <ChangeHero
        commit={sha}
        report={{ ...report, commit_sha: sha, ...extra } as Report}
        state="passing"
        blockers={0}
        existing={0}
        waived={0}
        policy={policy}
      />,
    );
  }

  it("links the pull request and the CI run the report names", () => {
    renderWith({
      repository_url: "https://github.com/acme/shop",
      pull_request_number: 123,
      pull_request_title: "Bump lodash",
      ci_run_url: "https://github.com/acme/shop/actions/runs/42",
    });

    const pr = screen.getByRole("link", { name: /#123 Bump lodash/ });
    expect(pr).toHaveAttribute("href", "https://github.com/acme/shop/pull/123");
    expect(pr).toHaveAttribute("target", "_blank");
    expect(pr).toHaveAttribute("rel", "noreferrer");
    expect(screen.getByRole("link", { name: "CI run" })).toHaveAttribute(
      "href",
      "https://github.com/acme/shop/actions/runs/42",
    );
  });

  it("names a GitLab merge request with !", () => {
    renderWith({ repository_url: "https://gitlab.com/acme/shop", pull_request_number: 15 });
    expect(screen.getByRole("link", { name: "!15" })).toHaveAttribute(
      "href",
      "https://gitlab.com/acme/shop/-/merge_requests/15",
    );
  });

  it("shows no link when the report names nothing, or a host Specht cannot link", () => {
    renderWith({ repository_url: "https://bitbucket.org/acme/shop", pull_request_number: 7 });
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});

describe("ChangeHero across scanners", () => {
  const scan = (tool: string, created: string) =>
    ({ ...report, id: tool, tool_name: tool, created_at: created }) as unknown as Report;

  it("names every scanner the verdict counts and the time of the last report", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        scans={[
          scan("gitleaks", "2026-10-30T10:00:00Z"),
          scan("semgrep", "2026-10-30T10:02:00Z"),
          scan("trivy", "2026-10-30T10:01:00Z"),
        ]}
        state="blocked"
        blockers={9}
        existing={0}
        waived={0}
        policy={policy}
      />,
    );

    expect(screen.getByText(/^Scanned by gitleaks, semgrep and trivy,/)).toBeInTheDocument();
    expect(screen.getByText(/^last report/).querySelector("time")).toHaveAttribute(
      "datetime",
      "2026-10-30T10:02:00Z",
    );
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "9 findings block this change.",
    );
  });

  it("does not call a commit done while a scanner is still running or failed", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        scans={[scan("trivy", "2026-10-30T10:01:00Z")]}
        outstanding={{ running: ["semgrep"], failed: ["gitleaks", "checkov"] }}
        state="incomplete"
        blockers={0}
        existing={0}
        waived={0}
        policy={policy}
      />,
    );

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "Nothing blocks this change so far.",
    );
    expect(
      screen.getByText("The verdict is not final until every scanner of abcdef1 has reported."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Still scanning abcdef1: semgrep. More findings may block it."),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "The gitleaks and checkov scans of abcdef1 failed, so their findings are not counted. Re-run those jobs.",
      ),
    ).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/Nothing to do here/);
  });

  it("names a running scanner beside a blocked verdict too", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={report}
        scans={[scan("trivy", "2026-10-30T10:01:00Z")]}
        outstanding={{ running: ["semgrep", "gitleaks"], failed: [] }}
        state="blocked"
        blockers={7}
        existing={0}
        waived={0}
        policy={policy}
      />,
    );

    expect(
      screen.getByText(
        "Still scanning abcdef1: semgrep and gitleaks. More findings may block it.",
      ),
    ).toBeInTheDocument();
  });
});
