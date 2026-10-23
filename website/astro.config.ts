import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

export default defineConfig({
  site: process.env.SITE_URL || undefined,
  base: process.env.SITE_BASE || "/",
  output: "static",
  trailingSlash: "always",
  integrations: [
    starlight({
      title: "Specht",
      description: "Self-hosted scanner reports, finding history and evidence-backed CI gates.",
      logo: { src: "./src/assets/mark.svg", alt: "", replacesTitle: false },
      customCss: ["./src/styles/docs.css"],
      expressiveCode: {
        defaultProps: { wrap: true },
        plugins: [
          {
            name: "keyboard-accessible-code",
            hooks: {
              postprocessRenderedBlock({ renderData }) {
                const elements = [renderData.blockAst];
                for (const element of elements) {
                  if (element.tagName === "pre") element.properties.tabIndex = 0;
                  elements.push(...element.children.filter((child) => child.type === "element"));
                }
              },
            },
          },
        ],
      },
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/minh-tg/specht" }],
      sidebar: [
        { label: "Product", link: "/" },
        { label: "Start here", items: ["docs/getting-started", "docs/scanners", "docs/ci-gates"] },
        { label: "Operate", items: ["docs/triage-and-waivers", "docs/self-hosting"] },
      ],
    }),
  ],
});
