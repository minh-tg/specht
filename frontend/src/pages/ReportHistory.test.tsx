import { render, screen } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { MemoryRouter, Route, Routes } from "react-router-dom"
import { vi } from "vitest"
import { ReportHistory } from "./ReportHistory"

beforeEach(() => {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: () =>
      Promise.resolve([
        {
          id: "r1",
          project_id: "p1",
          tool_name: "trivy",
          status: "completed",
          scan_target: "repo/foo",
          total_findings: 5,
          created_at: "2025-01-01T00:00:00Z",
          updated_at: "2025-01-01T00:00:00Z",
        },
        {
          id: "r2",
          project_id: "p1",
          tool_name: "osv-scanner",
          status: "processing",
          scan_target: null,
          total_findings: null,
          created_at: "2025-01-02T00:00:00Z",
          updated_at: "2025-01-02T00:00:00Z",
        },
      ]),
  } as Response)
})

function renderWithProviders(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/test-project/reports"]}>
        <Routes>
          <Route path="/:slug/reports" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe("ReportHistory", () => {
  it("shows loading state initially", () => {
    renderWithProviders(<ReportHistory />)
    const skeletons = document.querySelectorAll(".animate-pulse")
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it("renders reports after loading", async () => {
    renderWithProviders(<ReportHistory />)
    expect(await screen.findByText("trivy")).toBeInTheDocument()
    expect(screen.getByText("osv-scanner")).toBeInTheDocument()
    expect(screen.getByText("5 findings")).toBeInTheDocument()
    expect(screen.getByText("repo/foo")).toBeInTheDocument()
  })
})
