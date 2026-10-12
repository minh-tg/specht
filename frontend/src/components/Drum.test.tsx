import { render } from "@testing-library/react";
import { Drum } from "./Drum";

describe("Drum", () => {
  it("is three dots hidden from assistive technology", () => {
    const { container } = render(<Drum />);
    const drum = container.firstElementChild;
    expect(drum).toHaveAttribute("aria-hidden", "true");
    expect(drum?.querySelectorAll("i")).toHaveLength(3);
  });

  it("takes extra classes", () => {
    const { container } = render(<Drum className="text-foreground" />);
    expect(container.firstElementChild).toHaveClass("drum", "text-foreground");
  });
});
