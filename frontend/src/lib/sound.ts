import { useSyncExternalStore } from "react";

export type Cue = "accepted" | "pass" | "block" | "copied" | "error";

export const SOUND_STORAGE_KEY = "specht.sound";

interface Note {
  readonly freq: number;
  /** Seconds after the cue starts. */
  readonly at: number;
  readonly dur: number;
  /** Share of the master gain, 0 to 1. */
  readonly level: number;
  readonly wave: "sine" | "triangle";
}

/** Every cue ends within 200ms. Sine and triangle only, so nothing reads as a buzzer. */
const CUES: Readonly<Record<Cue, readonly Note[]>> = {
  accepted: [
    { freq: 523.25, at: 0, dur: 0.07, level: 1, wave: "sine" },
    { freq: 783.99, at: 0.07, dur: 0.08, level: 1, wave: "sine" },
  ],
  pass: [
    { freq: 523.25, at: 0, dur: 0.18, level: 0.5, wave: "sine" },
    { freq: 659.25, at: 0, dur: 0.18, level: 0.5, wave: "sine" },
  ],
  block: [{ freq: 196, at: 0, dur: 0.16, level: 1, wave: "triangle" }],
  copied: [{ freq: 1200, at: 0, dur: 0.03, level: 0.6, wave: "sine" }],
  error: [
    { freq: 293.66, at: 0, dur: 0.09, level: 1, wave: "triangle" },
    { freq: 196, at: 0.09, dur: 0.09, level: 1, wave: "triangle" },
  ],
};

/** Peak of the master gain. Cues are feedback, not content. */
const MASTER_PEAK = 0.08;
const FLOOR = 0.0001;
const ATTACK = 0.005;
/** The same cue twice within this window plays once (a burst of toasts, a double click). */
const THROTTLE_MS = 150;

const GESTURES = ["keydown", "pointerup", "click"] as const;

type AudioContextCtor = new() => AudioContext;

function contextCtor(): AudioContextCtor | undefined {
  if (typeof window === "undefined") return undefined;
  const w = window as unknown as {
    AudioContext?: AudioContextCtor;
    webkitAudioContext?: AudioContextCtor;
  };
  return w.AudioContext ?? w.webkitAudioContext;
}

// Storage can be blocked, so the choice also lives in memory for this page view.
let memory: boolean | null = null;
const listeners = new Set<() => void>();

function readEnabled(): boolean {
  try {
    const stored = window.localStorage.getItem(SOUND_STORAGE_KEY);
    if (stored === "on") return true;
    if (stored === "off") return false;
    return memory ?? false;
  } catch {
    return memory ?? false;
  }
}

export function isSoundEnabled(): boolean {
  return readEnabled();
}

let ctx: AudioContext | null = null;
let master: GainNode | null = null;
let armed = false;
const lastPlayed = new Map<Cue, number>();

function notify() {
  syncGestureListeners();
  for (const listener of listeners) listener();
}

export function setSoundEnabled(on: boolean): void {
  memory = on;
  try {
    window.localStorage.setItem(SOUND_STORAGE_KEY, on ? "on" : "off");
  } catch {
    // The choice then only lasts for this page view.
  }
  notify();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  const onStorage = (event: StorageEvent) => {
    if (event.key === null || event.key === SOUND_STORAGE_KEY) {
      memory = null;
      notify();
    }
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

/** The sound preference, shared by every caller and followed across tabs. */
export function useSoundEnabled(): boolean {
  return useSyncExternalStore(subscribe, readEnabled, () => false);
}

function ensureContext(): AudioContext | null {
  if (ctx) return ctx;
  const Ctor = contextCtor();
  if (!Ctor) return null;
  try {
    ctx = new Ctor();
    master = ctx.createGain();
    master.gain.value = MASTER_PEAK;
    master.connect(ctx.destination);
    ctx.addEventListener?.("statechange", syncGestureListeners);
  } catch {
    ctx = null;
    master = null;
  }
  return ctx;
}

function resume() {
  try {
    void ctx?.resume()?.catch(() => undefined);
  } catch {
    // A failed resume leaves the context silent.
  }
}

function onGesture() {
  if (!readEnabled()) return;
  if (ensureContext() && ctx?.state !== "running") resume();
  syncGestureListeners();
}

/**
 * The unlock listeners stay attached only while sound is on and the context is not running. Safari
 * moves a context to "interrupted" after backgrounding, which re-arms them.
 */
function syncGestureListeners() {
  if (typeof window === "undefined") return;
  const want = readEnabled() && ctx?.state !== "running";
  if (want === armed) return;
  armed = want;
  for (const type of GESTURES) {
    if (want) window.addEventListener(type, onGesture, { capture: true, passive: true });
    else window.removeEventListener(type, onGesture, { capture: true });
  }
}

/**
 * Creates and resumes the context. Call it synchronously from a user gesture, such as the click
 * that switches the setting on, so the browser allows audio afterwards.
 */
export function unlockAudio(): void {
  if (!ensureContext()) return;
  if (ctx?.state !== "running") resume();
  syncGestureListeners();
}

/** Plays a cue if sound is on, the page is visible and the audio context is running. Never throws. */
export function playCue(cue: Cue): void {
  try {
    if (!readEnabled() || document.hidden) return;
    if (!ctx || ctx.state !== "running" || !master) return;
    const now = Date.now();
    const last = lastPlayed.get(cue);
    if (last !== undefined && now - last < THROTTLE_MS) return;
    lastPlayed.set(cue, now);

    const t0 = ctx.currentTime;
    for (const note of CUES[cue]) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = note.wave;
      osc.frequency.value = note.freq;
      const start = t0 + note.at;
      const end = start + note.dur;
      gain.gain.setValueAtTime(FLOOR, start);
      gain.gain.linearRampToValueAtTime(note.level, start + ATTACK);
      gain.gain.exponentialRampToValueAtTime(FLOOR, end);
      osc.connect(gain);
      gain.connect(master);
      osc.start(start);
      osc.stop(end + 0.01);
    }
  } catch {
    // Sound is a bonus; any failure degrades to silence.
  }
}

/** Plays a cue straight after a gesture, for the setting's preview. */
export function previewCue(cue: Cue): void {
  unlockAudio();
  if (ctx?.state === "running") {
    playCue(cue);
    return;
  }
  // A context created a moment ago can still be suspended; play once resume settles.
  try {
    void ctx?.resume()?.then(() => playCue(cue), () => undefined);
  } catch {
    // Silent.
  }
}

/** Test helper: forget the context, memory choice and throttle state. */
export function resetSoundForTests(): void {
  for (const type of GESTURES) window.removeEventListener(type, onGesture, { capture: true });
  armed = false;
  ctx = null;
  master = null;
  memory = null;
  lastPlayed.clear();
}

// Arm the unlock listeners at load when the person already opted in on an earlier visit.
syncGestureListeners();
