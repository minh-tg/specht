import { render, screen } from "@testing-library/react"
import { SeverityBadge } from "./severity-badge"

describe("SeverityBadge", () => {
  it("renders the severity text", () => {
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText("critical")).toBeInTheDocument()
  })

  it("handles case-insensitive matching", () => {
    render(<SeverityBadge severity="HIGH" />)
    expect(screen.getByText("HIGH")).toBeInTheDocument()
  })

  it("falls back to low styling for unknown severities", () => {
    render(<SeverityBadge severity="unknown" />)
    expect(screen.getByText("unknown")).toBeInTheDocument()
  })
})
