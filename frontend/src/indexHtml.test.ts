import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * The head is hand-written HTML, so nothing else fails when a link names an
 * asset that was renamed or never copied into public/. These checks read the
 * real files from disk to keep the head, the manifest and the icons in sync.
 *
 * `import.meta.url` is bound to a variable first: Vite rewrites the literal
 * form `new URL("...", import.meta.url)` to a dev-server URL that node:fs
 * cannot read, and the indirection keeps the real file:// base.
 */
const moduleUrl = import.meta.url;
const publicDir = fileURLToPath(new URL("../public/", moduleUrl));
const srcDir = fileURLToPath(new URL("../src/", moduleUrl));
const html = readFileSync(new URL("../index.html", moduleUrl), "utf8");
const doc = new DOMParser().parseFromString(html, "text/html");
const head = doc.head;

interface ManifestIcon {
  readonly src: string;
  readonly sizes: string;
  readonly type: string;
  readonly purpose?: string;
}

interface WebManifest {
  readonly name: string;
  readonly short_name: string;
  readonly description: string;
  readonly start_url: string;
  readonly display: string;
  readonly theme_color: string;
  readonly background_color: string;
  readonly icons: readonly ManifestIcon[];
}

const manifest = JSON.parse(
  readFileSync(new URL("../public/site.webmanifest", moduleUrl), "utf8"),
) as WebManifest;

/** "/src/main.tsx" is served by Vite from src/; every other URL comes from public/. */
function resolveAsset(url: string): string | null {
  if (url === "/src/main.tsx") return `${srcDir}main.tsx`;
  if (!url.startsWith("/") || url.startsWith("//")) return null;
  return `${publicDir}${url.slice(1)}`;
}

/** Reads the dimensions straight out of the PNG IHDR chunk. */
function pngSize(path: string): { readonly width: number; readonly height: number; } {
  const bytes = readFileSync(path);
  expect(bytes.subarray(1, 4).toString("latin1")).toBe("PNG");
  expect(bytes.subarray(12, 16).toString("latin1")).toBe("IHDR");
  return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
}

describe("document head", () => {
  it("references only local assets, all of which exist on disk", () => {
    const urls = [
      ...Array.from(
        head.querySelectorAll("link[href], img[src]"),
        (element) => element.getAttribute("href") ?? element.getAttribute("src")!,
      ),
      // The module entry point is the only script outside the head; Vite serves
      // it from src/ instead of copying it from public/.
      ...Array.from(doc.querySelectorAll("script[src]"), (element) => element.getAttribute("src")!),
    ];

    expect(urls).toContain("/favicon.svg");
    expect(urls).toContain("/src/main.tsx");
    for (const url of urls) {
      const file = resolveAsset(url);
      expect(file, `"${url}" is not a locally served asset`).not.toBeNull();
      expect(existsSync(file!), `missing file for "${url}"`).toBe(true);
    }
  });

  it("links the favicon, the Apple touch icon and the web manifest", () => {
    expect(head.querySelector("link[rel=\"icon\"]")?.getAttribute("href")).toBe("/favicon.svg");
    expect(head.querySelector("link[rel=\"apple-touch-icon\"]")?.getAttribute("href")).toBe(
      "/apple-touch-icon.png",
    );
    expect(head.querySelector("link[rel=\"manifest\"]")?.getAttribute("href")).toBe(
      "/site.webmanifest",
    );
  });

  it("bootstraps the theme from the head, before the first paint", () => {
    const script = html.indexOf("src=\"/theme-init.js\"");
    expect(script).toBeGreaterThan(-1);
    expect(script).toBeLessThan(html.indexOf("</head>"));
  });

  it("ships the Apple touch icon at 180x180", () => {
    expect(pngSize(`${publicDir}apple-touch-icon.png`)).toEqual({ width: 180, height: 180 });
  });

  it("declares a theme colour for both colour schemes", () => {
    const themes = Object.fromEntries(
      Array.from(
        head.querySelectorAll("meta[name=\"theme-color\"]"),
        (meta) => [meta.getAttribute("media"), meta.getAttribute("content")],
      ),
    );

    expect(themes).toEqual({
      "(prefers-color-scheme: light)": "#fafafa",
      "(prefers-color-scheme: dark)": "#0a0a0a",
    });
  });
});

describe("web manifest", () => {
  it("describes the app", () => {
    expect(manifest.name).toBe("Specht");
    expect(manifest.short_name).toBe("Specht");
    expect(manifest.description).toBe("Vulnerability triage and deployment gate for your CI.");
    expect(manifest.start_url).toBe("/");
    expect(manifest.display).toBe("standalone");
    expect(manifest.theme_color).toBe("#0a0a0a");
    expect(manifest.background_color).toBe("#fafafa");
  });

  it("repeats the description in the document head", () => {
    expect(head.querySelector("meta[name=\"description\"]")?.getAttribute("content")).toBe(
      manifest.description,
    );
  });

  it("points every declared icon at a file on disk", () => {
    expect(manifest.icons.length).toBeGreaterThanOrEqual(3);
    for (const icon of manifest.icons) {
      const file = resolveAsset(icon.src);
      expect(file, `manifest icon "${icon.src}" is not served locally`).not.toBeNull();
      expect(existsSync(file!), `missing manifest icon "${icon.src}"`).toBe(true);
    }
  });

  it("ships PNG icons at the sizes they declare", () => {
    const pngIcons = manifest.icons.filter((icon) => icon.type === "image/png");
    expect(pngIcons.map((icon) => icon.sizes).sort()).toEqual(["192x192", "512x512"]);

    for (const icon of pngIcons) {
      expect(icon.purpose, `${icon.src} is not offered as a maskable icon`).toContain("maskable");
      const [width, height] = icon.sizes.split("x").map(Number);
      expect(pngSize(resolveAsset(icon.src)!)).toEqual({ width, height });
    }
  });
});
