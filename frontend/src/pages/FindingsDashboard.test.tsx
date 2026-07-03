import { render, screen } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { MemoryRouter, Route, Routes } from "react-router-dom"
import { vi } from "vitest"
import { FindingsDashboard } from "./FindingsDashboard"

beforeEach(() => {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () =>
      Promise.resolve([
        {
          id: "f1",
          project_id: "p1",
          current_title: "Test Vuln",
          current_severity: "high",
          triage_status: "open",
          finding_kind: "sca",
          last_seen_at: "2025-01-01T00:00:00Z",
          first_seen_at: "2025-01-01T00:00:00Z",
          current_description: null,
          current_remediation: null,
          current_cvss: null,
          cve_id: null,
          created_at: "2025-01-01T00:00:00Z",
          updated_at: "2025-01-01T00:00:00Z",
        },
      ]),
  } as Response)
})

function renderWithProviders(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/test-project/findings"]}>
        <Routes>
          <Route path="/:slug/findings" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe("FindingsDashboard", () => {
  it("shows loading state initially", () => {
    renderWithProviders(<FindingsDashboard />)
    const skeletons = document.querySelectorAll(".animate-pulse")
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it("renders findings after loading", async () => {
    renderWithProviders(<FindingsDashboard />)
    const title = await screen.findByText("Test Vuln")
    expect(title).toBeInTheDocument()
    expect(screen.getByText("sca")).toBeInTheDocument()
  })
})
