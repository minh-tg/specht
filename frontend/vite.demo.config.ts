import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";

const sourceClient = fileURLToPath(new URL("./src/api/client.ts", import.meta.url));
const sampleClient = fileURLToPath(new URL("./src/demo/client.ts", import.meta.url));

function demoClient(): Plugin {
  return {
    name: "demo-only-client",
    enforce: "pre",
    async resolveId(source, importer, options) {
      if (!importer || source === sampleClient) return;
      const resolved = await this.resolve(source, importer, { ...options, skipSelf: true });
      if (resolved?.id === sourceClient) return sampleClient;
    },
  };
}

export default defineConfig({
  root: fileURLToPath(new URL("./demo", import.meta.url)),
  base: process.env.DEMO_BASE || "/demo/",
  publicDir: false,
  define: {
    __DEMO_SOURCE_URL__: JSON.stringify(
      `https://github.com/minh-tg/specht/tree/${
        execFileSync("git", ["rev-parse", "HEAD"], {
          cwd: fileURLToPath(new URL(".", import.meta.url)),
          encoding: "utf8",
        }).trim()
      }`,
    ),
  },
  plugins: [demoClient(), react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  build: {
    outDir: fileURLToPath(new URL("./demo-dist", import.meta.url)),
    emptyOutDir: true,
    assetsInlineLimit: (file) => /\.(woff2?|ttf|otf)$/i.test(file) ? false : undefined,
  },
});
