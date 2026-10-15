import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const SRC = import.meta.dirname;
const PAGES = join(SRC, "pages");

const SHARED_FOR_TAG: Record<string, string> = {
  textarea: "Textarea from @/components/ui/textarea",
  select: "SelectField from @/components/SelectField",
  input: "Input from @/components/ui/input (or Switch/FileDropzone for those controls)",
};
const FORBIDDEN_CONSTANTS: Record<string, string> = {
  INPUT_CLASS: "Input or Textarea from @/components/ui",
  LINK_CLASS: "INLINE_LINK from @/components/inlineLink",
  BUTTON_CLASS: "Button from @/components/ui/button",
};
/** Input types that have no shared component and are drawn by the browser. */
const NATIVE_INPUT_TYPES = new Set(["checkbox", "radio"]);

function pageFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return pageFiles(path);
    return path.endsWith(".tsx") && !path.endsWith(".test.tsx") ? [path] : [];
  });
}

/** The source text of a `className` attribute, or "" when the element has none. */
function classNameText(attributes: ts.JsxAttributes): string {
  for (const attribute of attributes.properties) {
    if (ts.isJsxAttribute(attribute) && attribute.name.getText() === "className") {
      return attribute.initializer?.getText() ?? "";
    }
  }
  return "";
}

/** A hand-built primary or outline button: the classes the shared Button already provides. */
function looksLikeButton(className: string): boolean {
  return className.includes("bg-primary")
    || (className.includes("rounded-md")
      && (className.includes("px-4") || className.includes("border-input")));
}

/** The literal value of a `type` attribute, or null when it is missing or computed. */
function typeAttribute(attributes: ts.JsxAttributes): string | null {
  for (const attribute of attributes.properties) {
    if (!ts.isJsxAttribute(attribute) || attribute.name.getText() !== "type") continue;
    const init = attribute.initializer;
    if (init && ts.isStringLiteral(init)) return init.text;
    if (init && ts.isJsxExpression(init) && init.expression) {
      const expression = init.expression;
      if (ts.isStringLiteralLike(expression)) return expression.text;
    }
    return null;
  }
  return null;
}

/** Every place a page bypasses the shared form controls or declares its own style constant. */
export function findViolations(fileName: string, text: string): string[] {
  const source = ts.createSourceFile(
    fileName,
    text,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );
  const found: string[] = [];
  const where = (node: ts.Node) =>
    `${relative(SRC, fileName)}:${source.getLineAndCharacterOfPosition(node.getStart()).line + 1}`;

  function visit(node: ts.Node) {
    if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
      const tag = node.tagName.getText();
      const shared = SHARED_FOR_TAG[tag];
      if (
        shared && !(tag === "input" && NATIVE_INPUT_TYPES.has(typeAttribute(node.attributes) ?? ""))
      ) {
        found.push(`${where(node)}: raw <${tag}>, use ${shared}`);
      }
    }
    if (
      (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node))
      && node.tagName.getText() === "button"
      && looksLikeButton(classNameText(node.attributes))
    ) {
      found.push(`${where(node)}: hand-built <button>, use Button from @/components/ui/button`);
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      const shared = FORBIDDEN_CONSTANTS[node.name.text];
      if (shared) found.push(`${where(node)}: constant ${node.name.text}, use ${shared}`);
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  return found;
}

describe("design system", () => {
  it("lists the page files it checks", () => {
    expect(pageFiles(PAGES).length).toBeGreaterThan(20);
  });

  it("finds a raw field, a style constant and a multi-line attribute list in a sample", () => {
    const sample = [
      "const INPUT_CLASS = \"x\";",
      "export const A = () => (",
      "  <div onClick={() => go()}>",
      "    <input",
      "      className={INPUT_CLASS}",
      "      type=\"text\"",
      "    />",
      "    <input type=\"checkbox\" />",
      "    <select />",
      "    <button className=\"bg-primary px-4\">Go</button>",
      "    <button className={`border-input rounded-md ${x}`}>Go</button>",
      "    <button className=\"rounded-full px-4\">Chip</button>",
      "    <textarea></textarea>",
      "  </div>",
      ");",
    ].join("\n");

    const found = findViolations(join(SRC, "pages/Sample.tsx"), sample);

    expect(found).toEqual([
      "pages/Sample.tsx:1: constant INPUT_CLASS, use Input or Textarea from @/components/ui",
      "pages/Sample.tsx:4: raw <input>, use Input from @/components/ui/input (or Switch/FileDropzone for those controls)",
      "pages/Sample.tsx:9: raw <select>, use SelectField from @/components/SelectField",
      "pages/Sample.tsx:10: hand-built <button>, use Button from @/components/ui/button",
      "pages/Sample.tsx:11: hand-built <button>, use Button from @/components/ui/button",
      "pages/Sample.tsx:13: raw <textarea>, use Textarea from @/components/ui/textarea",
    ]);
  });

  it("keeps pages on the shared form controls, links and buttons", () => {
    const violations = pageFiles(PAGES).flatMap((file) =>
      findViolations(file, readFileSync(file, "utf8"))
    );

    expect(violations, violations.join("\n")).toEqual([]);
  });
});
