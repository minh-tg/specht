import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { CveDetail } from "@/types/cve";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { completeReport, cvss, NVD, providerFilled, REPORT, V31_VECTOR } from "./cveDetailFixtures";
import { CveDetails } from "./CveDetails";

function serve(response: Response | (() => Response)) {
  globalThis.fetch = vi.fn().mockImplementation(async () =>
    typeof response === "function" ? response() : response
  );
}

function renderSection() {
  const client = createTestQueryClient();
  const view = render(
    <QueryClientProvider client={client}>
      <CveDetails findingId="f1" />
    </QueryClientProvider>,
  );
  return { client, ...view };
}

async function openBreakdown(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: /show the full cve breakdown/i }));
}

/** The `<dt>` with this exact text inside a container. A `dt` has no accessible name of its own. */
function termIn(scope: HTMLElement, text: string): HTMLElement {
  return within(scope).getByText(text, { selector: "dt" });
}

/** The value a term is paired with in a description list: what a screen reader reads after it. */
function valueOf(term: HTMLElement): string {
  return term.nextElementSibling?.textContent ?? "";
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("CveDetails states", () => {
  it("renders nothing for a finding without a CVE and reports no error", async () => {
    serve(jsonResponse({ error: { code: "not_cve", message: "No CVE" } }, 404));
    const { container, client } = renderSection();
    // Wait for the 404 to land in the cache, so the empty page is the answer and not the loading state.
    await vi.waitFor(() =>
      expect(client.getQueryState(["finding-cve", "f1"])?.status).toBe("error")
    );
    await act(async () => {});
    expect(container).toBeEmptyDOMElement();
    expect(screen.queryByText(/not available/i)).not.toBeInTheDocument();
  });

  it("shows a small note, not a failure, when the read fails", async () => {
    serve(jsonResponse({ error: { code: "cve_detail_failed", message: "boom" } }, 500));
    renderSection();
    expect(await screen.findByText("CVE details are not available right now.")).toBeVisible();
    expect(screen.getByRole("heading", { name: "CVE details" })).toBeVisible();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("treats an unknown 404 as an error note, not as a finding without a CVE", async () => {
    serve(jsonResponse({ error: { code: "not_found", message: "finding not found" } }, 404));
    renderSection();
    expect(await screen.findByText("CVE details are not available right now.")).toBeVisible();
  });
});

describe("CveDetails summary and disclosure", () => {
  it("starts folded to a one-line summary of the highest CVSS, EPSS and KEV", async () => {
    serve(jsonResponse(completeReport()));
    renderSection();
    const section = await screen.findByRole("region", { name: "CVE details" });
    expect(within(section).getByText("CVE-2024-3094")).toBeVisible();
    expect(within(section).getByText("10.0")).toBeVisible();
    expect(within(section).getByText("Critical")).toBeVisible();
    expect(within(section).getByText("(v3.1, scan report)")).toBeVisible();
    expect(within(section).getByText("EPSS 0.04%")).toBeVisible();
    expect(within(section).getByText("Known exploited")).toBeVisible();
    expect(screen.queryByRole("heading", { name: "CVSS 3.1" })).not.toBeInTheDocument();
  });

  it("opens and closes the breakdown with a keyboard-operable button", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    const button = await screen.findByRole("button", { name: /show the full cve breakdown/i });
    expect(button).toHaveAttribute("aria-expanded", "false");
    button.focus();
    await user.keyboard("{Enter}");
    const open = screen.getByRole("button", { name: /hide the full cve breakdown/i });
    expect(open).toHaveAttribute("aria-expanded", "true");
    expect(document.getElementById(open.getAttribute("aria-controls")!)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "CVSS 3.1" })).toBeVisible();
    await user.keyboard(" ");
    expect(screen.queryByRole("heading", { name: "CVSS 3.1" })).not.toBeInTheDocument();
  });

  it("attributes the summary score to a provider when only a provider supplied it", async () => {
    serve(jsonResponse(providerFilled()));
    renderSection();
    expect(await screen.findByText("(v3.1, NVD)")).toBeVisible();
    expect(screen.queryByText(/scan report/)).not.toBeInTheDocument();
  });
});

describe("CveDetails CVSS breakdown", () => {
  it("lists every version with its score and the band as a word", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    for (const version of ["2.0", "3.0", "3.1", "4.0"]) {
      const card = screen.getByRole("article", { name: `CVSS ${version}` });
      expect(within(card).getByText(/Base score/)).toBeVisible();
    }
    const v31 = screen.getByRole("article", { name: "CVSS 3.1" });
    expect(within(v31).getByText("10.0")).toBeVisible();
    expect(within(v31).getByText("Critical")).toBeVisible();
    const v2 = screen.getByRole("article", { name: "CVSS 2.0" });
    expect(within(v2).getByText("7.5")).toBeVisible();
    expect(within(v2).getByText("High")).toBeVisible();
  });

  it("announces each metric as a name and value pair in plain language", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const v31 = screen.getByRole("article", { name: "CVSS 3.1" });
    const pairs: Array<[string, string]> = [
      ["Attack Vector", "Network"],
      ["Attack Complexity", "Low"],
      ["Privileges Required", "None"],
      ["User Interaction", "None"],
      ["Scope", "Changed"],
      ["Confidentiality", "High"],
      ["Integrity", "High"],
      ["Availability", "High"],
    ];
    for (const [name, value] of pairs) {
      const term = termIn(v31, name);
      expect(valueOf(term)).toBe(value);
    }
    expect(within(v31).getByRole("region", { name: "Exploitability metrics" })).toBeVisible();
    expect(within(v31).getByRole("region", { name: "Scope metrics" })).toBeVisible();
    expect(within(v31).getByRole("region", { name: "Impact metrics" })).toBeVisible();
  });

  it("names the v2 and v4.0 metrics by their specification names", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const v2 = screen.getByRole("article", { name: "CVSS 2.0" });
    expect(valueOf(termIn(v2, "Authentication"))).toBe("None");
    expect(valueOf(termIn(v2, "Confidentiality Impact"))).toBe(
      "Partial",
    );
    const v4 = screen.getByRole("article", { name: "CVSS 4.0" });
    expect(valueOf(termIn(v4, "Attack Requirements"))).toBe("None");
    expect(valueOf(termIn(v4, "Exploit Maturity"))).toBe("Attacked");
    expect(valueOf(termIn(v4, "Automatable"))).toBe("Yes");
    for (const group of ["Threat", "Environmental", "Supplemental"]) {
      expect(within(v4).getByRole("region", { name: `${group} metrics` })).toBeVisible();
    }
  });

  it("shows the vector string with a copy button", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const v31 = screen.getByRole("article", { name: "CVSS 3.1" });
    expect(within(v31).getByText(V31_VECTOR)).toBeVisible();
    expect(within(v31).getByRole("button", { name: "Copy CVSS 3.1 vector" })).toBeVisible();
  });

  it("shows an unknown metric key or value as the raw code and does not crash", async () => {
    const detail = completeReport();
    detail.cvss = [
      cvss("3.1", V31_VECTOR, 10, "critical", REPORT, {
        metrics: [
          { group: "base", key: "AV", value: "Z" },
          { group: "base", key: "QQ", value: "9" },
        ],
      }),
    ];
    serve(jsonResponse(detail));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const card = screen.getByRole("article", { name: "CVSS 3.1" });
    expect(valueOf(termIn(card, "Attack Vector"))).toBe("Z");
    expect(valueOf(termIn(card, "QQ"))).toBe("9");
  });

  it("says plainly when the scanner's score differs from the vector's", async () => {
    const detail = completeReport();
    detail.cvss = [cvss("3.1", V31_VECTOR, 10, "critical", REPORT, { reported_score: 9.8 })];
    serve(jsonResponse(detail));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    expect(
      screen.getByText("The scanner (grype) reported 9.8; the vector computes to 10.0."),
    ).toBeVisible();
  });

  it("names the provider, not the scanner, when a provider's score differs", async () => {
    const detail = providerFilled();
    detail.cvss = [cvss("3.1", V31_VECTOR, 10, "critical", NVD, { reported_score: 9.8 })];
    serve(jsonResponse(detail));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    expect(screen.getByText("NVD reported 9.8; the vector computes to 10.0.")).toBeVisible();
    expect(screen.queryByText(/scanner/i)).not.toBeInTheDocument();
  });

  it("explains a vector that did not parse and still shows what the source reported", async () => {
    const detail = completeReport();
    detail.cvss = [
      cvss("3.1", "CVSS:3.1/AV:N/BROKEN", 7.5, "high", REPORT, {
        base_score: null,
        valid: false,
        metrics: [],
      }),
    ];
    serve(jsonResponse(detail));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const card = screen.getByRole("article", { name: "CVSS 3.1" });
    expect(within(card).getByText(/could not be read/)).toBeVisible();
    expect(within(card).getByText("7.5")).toBeVisible();
    expect(within(card).getByText("High")).toBeVisible();
    expect(card.querySelector("dt")).toBeNull();
  });
});

describe("CveDetails provenance", () => {
  it("says a report's values came from the scan report, with the scanner and day", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const v31 = screen.getByRole("article", { name: "CVSS 3.1" });
    expect(within(v31).getByText(/^From the scan report \(grype, /)).toBeVisible();
  });

  it("says a provider's values came from that provider, never from the scanner", async () => {
    serve(jsonResponse(providerFilled()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const v31 = screen.getByRole("article", { name: "CVSS 3.1" });
    expect(within(v31).getByText(/^From NVD, fetched .* ago$/)).toBeVisible();
    expect(screen.queryByText(/From the scan report/)).not.toBeInTheDocument();
  });

  it("shows the scoring party the source names", async () => {
    const detail = completeReport();
    detail.cvss = [cvss("3.1", V31_VECTOR, 10, "critical", { ...REPORT, detail: "nvd:primary" })];
    serve(jsonResponse(detail));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    expect(screen.getByText(/scored by nvd:primary/)).toBeVisible();
  });

  it("says where a watcher value came from", async () => {
    const detail = completeReport();
    detail.cvss = [
      cvss("3.1", V31_VECTOR, 10, "critical", { kind: "watcher", tool: "cve_watcher" }),
    ];
    serve(jsonResponse(detail));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    expect(screen.getByText("From the CVE watcher")).toBeVisible();
  });
});

describe("CveDetails exploitation, weaknesses, dates and references", () => {
  it("shows EPSS as a percentage with percentile and date, and the KEV facts", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const epss = termIn(document.body, "EPSS");
    expect(valueOf(epss)).toContain("0.04% chance of exploitation in the next 30 days");
    expect(valueOf(epss)).toContain("percentile 12.0%");
    expect(valueOf(epss)).toContain("From the EPSS feed");
    expect(valueOf(epss)).toMatch(/scored .*14.*2026|scored .*2026.*14/);
    const kev = valueOf(termIn(document.body, "Known exploited"));
    expect(kev).toContain("Listed in the CISA KEV catalog");
    expect(kev).toMatch(/added .*Apr.*2024/);
    expect(kev).toMatch(/due .*Apr.*2024/);
    expect(kev).toContain("ransomware use: Unknown");
    expect(kev).toContain("From the CISA KEV feed");
  });

  it("says when there is no EPSS score and the CVE is not in the KEV data", async () => {
    const detail = completeReport();
    detail.epss = null;
    detail.kev = null;
    serve(jsonResponse(detail));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    expect(valueOf(termIn(document.body, "EPSS"))).toBe("No score available");
    expect(valueOf(termIn(document.body, "Known exploited"))).toBe(
      "Not listed in the KEV data this server holds",
    );
  });

  it("links CWE identifiers to MITRE in a new tab without opener access", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const link = screen.getByRole("link", { name: /^CWE-506/ });
    expect(link).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/506.html");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("lists only https references, in a new tab without opener access", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const link = screen.getByRole("link", { name: /example\.org\/advisory\/1/ });
    expect(link).toHaveAttribute("href", "https://example.org/advisory/1");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(screen.queryByRole("link", { name: /not-https/ })).not.toBeInTheDocument();
  });

  it("shows the published date with its source", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const published = termIn(document.body, "Published");
    expect(valueOf(published)).toMatch(/Mar.*2024/);
    expect(valueOf(published)).toContain("From the scan report");
    expect(within(document.body).queryByText("Last modified", { selector: "dt" })).not
      .toBeInTheDocument();
  });
});

describe("CveDetails providers line and pending", () => {
  it("says no provider is configured when every provider is disabled", async () => {
    const detail = completeReport();
    detail.providers = detail.providers.map((p) => ({ ...p, status: "disabled" as const }));
    serve(jsonResponse(detail));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    expect(screen.getByText(/No external provider is configured/)).toBeVisible();
  });

  it("states each provider's status in words, including skipped for a complete report", async () => {
    serve(jsonResponse(completeReport()));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const line = screen.getByText(/External providers:/);
    expect(line).toHaveTextContent("NVD not asked, nothing more was needed");
    expect(line).toHaveTextContent("VulnCheck not configured");
    expect(line).toHaveTextContent("OSV not configured");
  });

  it("states found, no record, error and pending in words", async () => {
    const detail = providerFilled();
    detail.providers = [
      { name: "nvd", status: "found", fetched_at: "2026-10-15T10:00:00Z" },
      { name: "vulncheck", status: "not_found" },
      { name: "osv", status: "error" },
    ];
    serve(jsonResponse(detail));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    const line = screen.getByText(/External providers:/);
    expect(line).toHaveTextContent("NVD found, fetched");
    expect(line).toHaveTextContent("VulnCheck no record");
    expect(line).toHaveTextContent("OSV failed, will retry later");
  });

  it("shows a short note while a lookup is pending and drops it when the answer arrives", async () => {
    const pending: CveDetail = { ...completeReport(), pending: true, cvss: [] };
    serve(jsonResponse(pending));
    const { client } = renderSection();
    expect(await screen.findByText("Looking up more details.")).toBeVisible();
    expect(screen.getByText("No CVSS vector known")).toBeVisible();

    await act(async () => {
      client.setQueryData(["finding-cve", "f1"], providerFilled());
    });
    expect(await screen.findByText("(v3.1, NVD)")).toBeVisible();
    expect(screen.queryByText("Looking up more details.")).not.toBeInTheDocument();
  });

  it("explains a pending lookup inside the opened breakdown too", async () => {
    serve(jsonResponse({ ...completeReport(), pending: true, cvss: [] }));
    const user = userEvent.setup();
    renderSection();
    await openBreakdown(user);
    expect(screen.getByText(/Looking up more details from external providers/)).toBeVisible();
    expect(screen.getByText(/No CVSS vector is known for this CVE/)).toBeVisible();
  });
});
