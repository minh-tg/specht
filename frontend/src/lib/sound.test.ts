import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type Cue,
  isSoundEnabled,
  playCue,
  previewCue,
  resetSoundForTests,
  setSoundEnabled,
  SOUND_STORAGE_KEY,
  unlockAudio,
  useSoundEnabled,
} from "./sound";

interface FakeOsc {
  type: string;
  frequency: { value: number; };
  connect: () => void;
  start: (t: number) => void;
  stop: (t: number) => void;
  startedAt?: number;
  stoppedAt?: number;
}

const made = vi.hoisted(() => ({ contexts: [] as unknown[] }));

class FakeContext {
  state = "suspended";
  currentTime = 0;
  destination = {};
  oscillators: FakeOsc[] = [];
  peaks: number[] = [];
  resume = vi.fn(() => {
    this.state = "running";
    return Promise.resolve();
  });
  listeners: Record<string, () => void> = {};
  constructor() {
    made.contexts.push(this);
  }
  addEventListener(type: string, fn: () => void) {
    this.listeners[type] = fn;
  }
  createGain() {
    const peaks = this.peaks;
    return {
      gain: {
        value: 0,
        setValueAtTime: () => {},
        linearRampToValueAtTime: (v: number) => peaks.push(v),
        exponentialRampToValueAtTime: vi.fn(),
      },
      connect: () => {},
    };
  }
  createOscillator() {
    const osc: FakeOsc = {
      type: "",
      frequency: { value: 0 },
      connect: () => {},
      start: (t) => {
        osc.startedAt = t;
      },
      stop: (t) => {
        osc.stoppedAt = t;
      },
    };
    this.oscillators.push(osc);
    return osc;
  }
}

function lastContext(): FakeContext {
  return made.contexts.at(-1) as FakeContext;
}

function gesture(type = "click") {
  window.dispatchEvent(new Event(type));
}

beforeEach(() => {
  made.contexts.length = 0;
  window.localStorage.clear();
  resetSoundForTests();
  vi.stubGlobal("AudioContext", FakeContext);
  Object.defineProperty(document, "hidden", { configurable: true, value: false });
  vi.useFakeTimers({ toFake: ["Date"] });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("preference", () => {
  it("is off by default", () => {
    expect(isSoundEnabled()).toBe(false);
  });

  it("persists and reads back", () => {
    setSoundEnabled(true);
    expect(window.localStorage.getItem(SOUND_STORAGE_KEY)).toBe("on");
    expect(isSoundEnabled()).toBe(true);
    setSoundEnabled(false);
    expect(window.localStorage.getItem(SOUND_STORAGE_KEY)).toBe("off");
  });

  it("keeps the choice in memory when storage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(isSoundEnabled()).toBe(false);
    expect(() => setSoundEnabled(true)).not.toThrow();
    expect(isSoundEnabled()).toBe(true);
  });

  it("follows another tab through the storage event", () => {
    const { result } = renderHook(() => useSoundEnabled());
    expect(result.current).toBe(false);
    act(() => {
      window.localStorage.setItem(SOUND_STORAGE_KEY, "on");
      window.dispatchEvent(new StorageEvent("storage", { key: SOUND_STORAGE_KEY }));
    });
    expect(result.current).toBe(true);
  });

  it("ignores an unrelated stored value", () => {
    window.localStorage.setItem(SOUND_STORAGE_KEY, "loud");
    expect(isSoundEnabled()).toBe(false);
  });
});

describe("with the setting off", () => {
  it("never constructs an AudioContext, even after gestures and cue requests", () => {
    gesture("click");
    gesture("keydown");
    playCue("accepted");
    expect(made.contexts).toHaveLength(0);
  });

  it("attaches no gesture listener", () => {
    const add = vi.spyOn(window, "addEventListener");
    setSoundEnabled(false);
    expect(add.mock.calls.filter(([t]) => ["keydown", "pointerup", "click"].includes(t as string)))
      .toHaveLength(0);
  });
});

describe("with the setting on", () => {
  beforeEach(() => setSoundEnabled(true));

  it("creates no context until a gesture", () => {
    expect(made.contexts).toHaveLength(0);
    playCue("accepted");
    expect(made.contexts).toHaveLength(0);
  });

  it.each(["keydown", "pointerup", "click"])("unlocks on %s", async (type) => {
    gesture(type);
    expect(made.contexts).toHaveLength(1);
    expect(lastContext().resume).toHaveBeenCalled();
    await Promise.resolve();
    playCue("copied");
    expect(lastContext().oscillators).toHaveLength(1);
  });

  it("does not unlock on pointerdown", () => {
    gesture("pointerdown");
    expect(made.contexts).toHaveLength(0);
  });

  it("stays silent while the context is not running", () => {
    gesture("click");
    lastContext().state = "interrupted";
    playCue("accepted");
    expect(lastContext().oscillators).toHaveLength(0);
  });

  it("re-arms the listeners after the context is interrupted", async () => {
    gesture("click");
    await Promise.resolve();
    expect(lastContext().state).toBe("running");
    lastContext().state = "interrupted";
    lastContext().listeners.statechange();
    lastContext().resume.mockClear();
    gesture("click");
    expect(lastContext().resume).toHaveBeenCalled();
  });

  it("detaches the listeners once the context runs", async () => {
    gesture("click");
    await Promise.resolve();
    lastContext().listeners.statechange();
    gesture("click");
    expect(lastContext().resume).toHaveBeenCalledTimes(1);
  });

  it("is silent while the page is hidden", async () => {
    gesture("click");
    await Promise.resolve();
    Object.defineProperty(document, "hidden", { configurable: true, value: true });
    playCue("accepted");
    expect(lastContext().oscillators).toHaveLength(0);
  });

  it("is silent after the setting is switched off", async () => {
    gesture("click");
    await Promise.resolve();
    setSoundEnabled(false);
    playCue("accepted");
    expect(lastContext().oscillators).toHaveLength(0);
  });

  it("throttles the same cue but not a different one", async () => {
    gesture("click");
    await Promise.resolve();
    playCue("accepted");
    playCue("accepted");
    expect(lastContext().oscillators).toHaveLength(2);
    playCue("copied");
    expect(lastContext().oscillators).toHaveLength(3);
    vi.setSystemTime(Date.now() + 200);
    playCue("accepted");
    expect(lastContext().oscillators).toHaveLength(5);
  });

  const lengths: Array<[Cue, number]> = [
    ["accepted", 2],
    ["pass", 2],
    ["block", 1],
    ["copied", 1],
    ["error", 2],
  ];
  it.each(lengths)("%s uses %i notes, ends within 200ms and stays quiet", async (cue, notes) => {
    gesture("click");
    await Promise.resolve();
    playCue(cue);
    const ctx = lastContext();
    expect(ctx.oscillators).toHaveLength(notes);
    for (const osc of ctx.oscillators) {
      expect(["sine", "triangle"]).toContain(osc.type);
      expect(osc.stoppedAt!).toBeLessThanOrEqual(0.2);
    }
    expect(Math.max(...ctx.peaks)).toBeLessThanOrEqual(1);
  });

  it("previews after resume settles when the context starts suspended", async () => {
    previewCue("accepted");
    await Promise.resolve();
    await Promise.resolve();
    expect(lastContext().oscillators).toHaveLength(2);
  });

  it("never throws when the context fails to construct", () => {
    vi.stubGlobal(
      "AudioContext",
      class {
        constructor() {
          throw new Error("no audio");
        }
      },
    );
    expect(() => gesture("click")).not.toThrow();
    expect(() => playCue("error")).not.toThrow();
  });

  it("never throws when resume rejects", async () => {
    vi.stubGlobal(
      "AudioContext",
      class extends FakeContext {
        resume = vi.fn(() => Promise.reject(new Error("blocked")));
      },
    );
    gesture("click");
    await Promise.resolve();
    expect(() => playCue("pass")).not.toThrow();
  });

  it("degrades to silence when AudioContext is missing", () => {
    vi.stubGlobal("AudioContext", undefined);
    expect(() => unlockAudio()).not.toThrow();
    expect(() => playCue("accepted")).not.toThrow();
  });
});
