import { resetSoundForTests, SOUND_STORAGE_KEY } from "@/lib/sound";
import { Menu } from "@base-ui/react/menu";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SoundSetting } from "./SoundSetting";

const created = vi.hoisted(() => ({ count: 0, oscillators: 0 }));

class FakeContext {
  state = "running";
  currentTime = 0;
  destination = {};
  constructor() {
    created.count += 1;
  }
  resume = () => Promise.resolve();
  addEventListener() {}
  createGain() {
    return {
      gain: {
        value: 0,
        setValueAtTime() {},
        linearRampToValueAtTime() {},
        exponentialRampToValueAtTime() {},
      },
      connect() {},
    };
  }
  createOscillator() {
    created.oscillators += 1;
    return { type: "", frequency: { value: 0 }, connect() {}, start() {}, stop() {} };
  }
}

function renderOpenMenu() {
  return render(
    <Menu.Root open>
      <Menu.Portal>
        <Menu.Positioner>
          <Menu.Popup>
            <SoundSetting />
          </Menu.Popup>
        </Menu.Positioner>
      </Menu.Portal>
    </Menu.Root>,
  );
}

beforeEach(() => {
  created.count = 0;
  created.oscillators = 0;
  window.localStorage.clear();
  resetSoundForTests();
  vi.stubGlobal("AudioContext", FakeContext);
  Object.defineProperty(document, "hidden", { configurable: true, value: false });
});

describe("SoundSetting", () => {
  it("is unchecked by default and builds no audio context", () => {
    renderOpenMenu();
    expect(screen.getByRole("menuitemcheckbox", { name: "Sound effects" }))
      .toHaveAttribute("aria-checked", "false");
    expect(created.count).toBe(0);
  });

  it("switching on stores the choice, creates the context in the click and plays a preview", async () => {
    renderOpenMenu();
    await userEvent.click(screen.getByRole("menuitemcheckbox", { name: "Sound effects" }));

    expect(window.localStorage.getItem(SOUND_STORAGE_KEY)).toBe("on");
    expect(screen.getByRole("menuitemcheckbox", { name: "Sound effects" }))
      .toHaveAttribute("aria-checked", "true");
    expect(created.count).toBe(1);
    await vi.waitFor(() => expect(created.oscillators).toBeGreaterThan(0));
  });

  it("switching off stores the choice and plays nothing", async () => {
    window.localStorage.setItem(SOUND_STORAGE_KEY, "on");
    renderOpenMenu();
    await userEvent.click(screen.getByRole("menuitemcheckbox", { name: "Sound effects" }));

    expect(window.localStorage.getItem(SOUND_STORAGE_KEY)).toBe("off");
    expect(created.oscillators).toBe(0);
  });
});
