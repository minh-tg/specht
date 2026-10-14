import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { NotFound } from "./NotFound";

describe("NotFound", () => {
  it("states that the page is missing", () => {
    render(
      <MemoryRouter initialEntries={["/nowhere"]}>
        <NotFound />
      </MemoryRouter>,
    );

    expect(screen.getByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });

  it("links back to the home page", () => {
    render(
      <MemoryRouter initialEntries={["/nowhere"]}>
        <NotFound />
      </MemoryRouter>,
    );

    expect(screen.getByRole("link", { name: "Back to projects" })).toHaveAttribute("href", "/");
  });
});
