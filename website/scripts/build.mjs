import { cp, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const website = fileURLToPath(new URL("../", import.meta.url));
const frontend = fileURLToPath(new URL("../../frontend/", import.meta.url));
const base = process.env.SITE_BASE || "/";
if (
  !base.startsWith("/") ||
  base.startsWith("//") ||
  /[?#\\]/.test(base) ||
  base.split("/").includes("..")
) {
  throw new Error("SITE_BASE must be an absolute URL path without a query or parent segments");
}
const prefix = `${base.replace(/\/+$/, "")}/`;
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
function run(args, cwd, env = process.env) {
  const result = spawnSync(pnpm, args, {
    cwd,
    env,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
run(["build:demo"], frontend, { ...process.env, DEMO_BASE: `${prefix}demo/` });
const target = new URL("../public/demo/", import.meta.url);
await rm(target, { recursive: true, force: true });
await cp(new URL("../../frontend/demo-dist/", import.meta.url), target, { recursive: true });
run(["exec", "astro", "sync", "--force"], website);
run(["exec", "astro", "build"], website);
