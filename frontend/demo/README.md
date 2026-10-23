# Browser demo

The demo renders the application's actual findings, detail, report, gate and
waiver components with fixed synthetic snapshots. It runs on a static host.
There is no Go server, database, sign-in or scanner behind it.

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm build:demo
pnpm test:demo
```

The output is `frontend/demo-dist/`. `DEMO_BASE` defaults to `/demo/`; set it when
building for another path. Hash routes keep deep views reloadable on static
hosts. The product site can include this artifact under its demo directory.
`CHROMIUM_BIN` selects an installed browser for tests.

## Read-only boundary

The entry and Vite config are separate from the normal application build. Only
the demo config replaces the physical API client module, including relative
imports, with a local snapshot reader. Unknown requests and writes fail locally;
there is no fetch fallback. A Content Security Policy also denies connections,
workers and form submissions. No service worker or session token is created.

The observer has no management or mutation permissions. Live monitoring and
unsupported navigation have explicit unavailable states. The demo reads neither
an existing login nor its credentials. Changing a URL or local storage value
cannot activate the demo in a normal production build.

Snapshots were captured from an ephemeral test installation seeded with the
repository's synthetic SARIF fixtures. Authentication responses and API keys
are not part of the data. Do not replace this dataset with customer reports.
The sample is fixed, so dates and pending requests do not represent a live system.

After building both the normal app and the demo, verify artifact separation:

```bash
node scripts/check-demo-isolation.mjs
```

The demo includes AGPL-3.0 and font license notices. Its Source link identifies
the build's Git revision. Build deployable artifacts from a clean committed
checkout. Hosting and deployment are separate from this source change.
