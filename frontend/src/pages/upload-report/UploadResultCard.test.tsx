import type { IngestResponse } from "@/types/api";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { UploadResultCard } from "./UploadResultCard";

const REPLAY_NOTE = "This exact report was already ingested for this commit; showing its result.";

function renderCard(result: IngestResponse) {
  return render(
    <MemoryRouter>
      <UploadResultCard result={result} slug="alpha" onReset={vi.fn()} />
    </MemoryRouter>,
  );
}

const base: IngestResponse = {
  report_id: "r1",
  total_findings: 3,
  threshold_breached: false,
  replayed: false,
};

describe("UploadResultCard", () => {
  it("hides the replay note for a fresh ingest", () => {
    renderCard(base);

    expect(screen.queryByText(REPLAY_NOTE)).toBeNull();
    expect(screen.getByText(/3 findings? found/)).toBeInTheDocument();
  });

  it("shows the replay note when the server answered with the stored report", () => {
    renderCard({ ...base, replayed: true });

    expect(screen.getByText(REPLAY_NOTE)).toBeInTheDocument();
  });
});
