// Regenerates examples/ci/github-actions.yml and examples/ci/gitlab-ci.yml
// from the snippet source, so the setup page and the checked-in examples can
// never describe different pipelines.
//
// Run with:
//
//   pnpm --dir frontend ci:examples
//
// The vitest drift test in src/lib/ciExamples.test.ts fails when the files on
// disk differ from this output.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CI_EXAMPLES } from "./ciExamples.ts";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

for (const { path, content } of CI_EXAMPLES) {
  const target = join(repoRoot, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
  console.log(`wrote ${path}`);
}
