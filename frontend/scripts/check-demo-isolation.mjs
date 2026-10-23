import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";

async function scripts(directory) {
  let code = "";
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = new URL(entry.name + (entry.isDirectory() ? "/" : ""), directory);
    if (entry.isDirectory()) code += await scripts(path);
    else if (entry.name.endsWith(".js")) code += await readFile(path, "utf8");
  }
  return code;
}
const production = await scripts(new URL("../dist/", import.meta.url));
const demo = await scripts(new URL("../demo-dist/", import.meta.url));
for (const marker of ["demo_read_only", "demo_unavailable", "observer@specht.example"]) {
  assert(!production.includes(marker), `Demo marker leaked into production: ${marker}`);
  assert(demo.includes(marker), `Demo artifact is missing its isolated sample: ${marker}`);
}
for (const endpoint of ["/api/v1/auth/login", "/api/v1/auth/refresh"]) {
  assert(production.includes(endpoint), `Production authentication is missing: ${endpoint}`);
  assert(
    !demo.includes(endpoint),
    `A production authentication client leaked into the demo: ${endpoint}`,
  );
}
assert(!demo.includes("session-refresh.js"), "Demo must not rotate real browser sessions");
console.log("Production auth retained; demo entry, fixtures and transport are isolated");
