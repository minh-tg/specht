import { fileURLToPath } from "node:url"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from "vitest/config"

export default defineConfig({
  base: "/",
  plugins: [react(), tailwindcss()],
  test: {
    environment: "jsdom",
    // Worker threads start faster than the default forked processes; with 159
    // jsdom files that saves about 10% on a four-core runner.
    pool: "threads",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // Unit/component tests live under src/; browser specs under e2e/ are
    // Playwright's, not vitest's (vitest's default include would pick up
    // *.spec.ts and fail on the Playwright API).
    projects: [
      {
        extends: true,
        test: {
          name: "unit",
          include: ["src/**/*.test.{ts,tsx}", "src/**/*.spec.{ts,tsx}"],
          exclude: ["src/**/*.tz.test.{ts,tsx}"],
        },
      },
      // A worker thread keeps the time zone it started with, whatever the test sets
      // process.env.TZ to. Tests that switch zones run in forked processes, where it sticks.
      {
        extends: true,
        test: { name: "tz", pool: "forks", include: ["src/**/*.tz.test.{ts,tsx}"] },
      },
    ],
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/**/*.test.{ts,tsx}",
        "src/**/*.spec.{ts,tsx}",
        "src/**/__tests__/**",
        "src/test/**",
        "src/**/*.d.ts",
      ],
      reporter: ["text", "json", "json-summary"],
      reportsDirectory: "coverage",
    },
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  // A stable worker URL keeps old and new tabs on the same rotation owner
  // across deployments. The server serves this entry with revalidation.
  worker: {
    format: "es",
    rolldownOptions: { output: { entryFileNames: "session-refresh.js" } },
  },
  build: {
    outDir: "dist",
    // The server's Content-Security-Policy allows fonts only from its own origin, so a small font
    // file inlined as a data: URI is blocked and the page quietly falls back to another face.
    assetsInlineLimit: (file) => (/\.(woff2?|ttf|otf)$/i.test(file) ? false : undefined),
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
})
