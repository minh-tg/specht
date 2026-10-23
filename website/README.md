# Specht website

Static Astro and Starlight site with a separate read-only build of the real
frontend under `/demo/`. Neither calls a Specht API or ships inside the server
image. Screenshots and the interactive demo use synthetic data; documentation
describes the current evaluator build.

## Develop

Use Node 22.23.4 or newer and pnpm 11.

```bash
pnpm --dir frontend install --frozen-lockfile
pnpm --dir website install --frozen-lockfile
cd website
pnpm build
pnpm dev
```

## Verify

```bash
pnpm check
pnpm format:check
pnpm build
pnpm exec playwright install chromium
pnpm test
pnpm audit --audit-level=high
```

Set `CHROMIUM_BIN` to use an installed Chromium instead of Playwright's download.
Browser tests serve the static build and do not need Postgres or a running Specht
instance. The build compiles the isolated frontend demo, copies it to the ignored
`public/demo/` directory and builds the site. Rebuild after changing frontend demo
code. The frontend package also provides `pnpm test:demo` and the production
artifact isolation check described in `frontend/demo/README.md`. To disable Astro's build-tool telemetry, set
`ASTRO_TELEMETRY_DISABLED=1` in the build environment.

## Build for a static host

Set `SITE_URL` to the approved public origin, and `SITE_BASE` if the site lives
under a subdirectory. For example, these reserved example values exercise a
subdirectory build:

```bash
SITE_URL=https://docs.example.com SITE_BASE=/specht/ pnpm build
```

Serve the contents of `dist/`. Omit `SITE_BASE` for a root deployment. Without a
public URL, local builds omit the sitemap; set the URL before deploying. No
hosting provider or deployment workflow is configured.

Fonts are self-hosted. Their licenses are in `public/licenses/`. Site code and
product images use the repository's AGPL-3.0 license.
