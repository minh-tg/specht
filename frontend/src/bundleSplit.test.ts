import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";
import { type Expression, parseSync, Visitor } from "oxc-parser";
import { describe, expect, it } from "vitest";

/**
 * The strength estimator and its dictionaries are about 1.6 MB, so they must stay in their own
 * chunks. A static import of `@zxcvbn-ts/*` anywhere in the app pulls them into the main bundle,
 * and nothing else fails when that happens. The check parses every source file and reports each
 * import, re-export or dynamic import of those packages that is not a type-only import, outside
 * the one file that loads them on demand.
 */
const moduleUrl = import.meta.url;
const srcDir = fileURLToPath(new URL("./", moduleUrl));
const PACKAGE_PREFIX = "@zxcvbn-ts/";
const ENGINE_FILE = "components/PasswordStrengthEngine.ts";

function sourceFiles(dir: string, relative = ""): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isDirectory()) return sourceFiles(`${dir}${entry.name}/`, path);
    return /\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name) ? [path] : [];
  });
}

/** The value of a string literal or a template without substitutions, otherwise null. */
function stringValue(node: Expression | null | undefined): string | null {
  if (node?.type === "Literal" && typeof node.value === "string") return node.value;
  if (node?.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis[0]?.value.cooked ?? null;
  }
  return null;
}

/** What in `source` loads an estimator package at runtime; empty when the file is clean. */
function estimatorImports(source: string, fileName = "file.ts"): string[] {
  const { program, errors } = parseSync(fileName, source);
  if (errors.length > 0) throw new Error(`${fileName}: ${errors[0]?.message}`);

  const found: string[] = [];
  const text = (node: { start: number; end: number; }) => source.slice(node.start, node.end);
  const isEstimator = (specifier: string | null) => specifier?.startsWith(PACKAGE_PREFIX) === true;
  new Visitor({
    ImportDeclaration(node) {
      if (node.importKind !== "type" && isEstimator(node.source.value)) found.push(text(node));
    },
    ExportNamedDeclaration(node) {
      if (node.exportKind !== "type" && isEstimator(node.source?.value ?? null)) {
        found.push(text(node));
      }
    },
    ExportAllDeclaration(node) {
      if (node.exportKind !== "type" && isEstimator(node.source.value)) found.push(text(node));
    },
    ImportExpression(node) {
      if (isEstimator(stringValue(node.source))) found.push(text(node));
    },
  }).visit(program);
  return found;
}

describe("estimatorImports", () => {
  it("flags value imports, re-exports and dynamic imports", () => {
    expect(estimatorImports(`import { ZxcvbnFactory } from "@zxcvbn-ts/core";`)).toHaveLength(1);
    expect(estimatorImports(`import "@zxcvbn-ts/language-en";`)).toHaveLength(1);
    expect(estimatorImports(`import { type ZxcvbnFactory } from "@zxcvbn-ts/core";`)).toHaveLength(
      1,
    );
    expect(estimatorImports(`export * from "@zxcvbn-ts/core";`)).toHaveLength(1);
    expect(estimatorImports(`const core = await import("@zxcvbn-ts/core");`)).toHaveLength(1);
  });

  it("allows type-only imports and other packages", () => {
    expect(estimatorImports(`import type { ZxcvbnFactory } from "@zxcvbn-ts/core";`)).toEqual([]);
    expect(estimatorImports(`export type { ZxcvbnFactory } from "@zxcvbn-ts/core";`)).toEqual([]);
    expect(estimatorImports(`import { useState } from "react";`)).toEqual([]);
    expect(estimatorImports(`const lazy = import("./Other");`)).toEqual([]);
  });
});

describe("bundle split", () => {
  it("keeps @zxcvbn-ts/* out of every file except the engine loader", () => {
    const files = sourceFiles(srcDir);
    expect(files).toContain(ENGINE_FILE);

    const offenders = files
      .filter((file) => file !== ENGINE_FILE)
      .flatMap((file) =>
        estimatorImports(readFileSync(`${srcDir}${file}`, "utf8"), file).map((statement) =>
          `${file}: ${statement}`
        )
      );
    expect(
      offenders,
      "Do not import @zxcvbn-ts/* statically: it adds about 1.6 MB to the main bundle. "
        + "Load the estimator through PasswordStrengthEngine instead.",
    ).toEqual([]);
  });
});
