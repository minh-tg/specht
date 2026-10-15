import type { ZxcvbnFactory } from "@zxcvbn-ts/core";

let engine: Promise<ZxcvbnFactory> | null = null;

/**
 * Loads the estimator and its dictionaries on first use. They are a few hundred kilobytes, so they
 * live in their own chunks and stay out of the main bundle until a password field needs them.
 */
export function loadStrengthEngine(): Promise<ZxcvbnFactory> {
  engine ??= Promise.all([
    import("@zxcvbn-ts/core"),
    import("@zxcvbn-ts/language-common"),
    import("@zxcvbn-ts/language-en"),
  ]).then(([core, common, en]) =>
    new core.ZxcvbnFactory({
      dictionary: { ...common.dictionary, ...en.dictionary },
      graphs: common.adjacencyGraphs,
      translations: en.translations,
    })
  ).catch((err: unknown) => {
    // A failed chunk load may be a blip; let the next field try again.
    engine = null;
    throw err;
  });
  return engine;
}
