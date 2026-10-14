# Specht frontend

The frontend is Specht's React and TypeScript web app. It helps teams review and manage security findings from SCA, SAST, and IaC scans.

## What it covers today

- **Projects:** a table of every project with its gate verdict (blocked, passing or never scanned), the number of blocking findings and the last scan. Admins can create projects.
- **Change view:** the page a CI link opens. It shows the verdict, which findings block, the smallest fix or waiver path, and the policy floor behind the answer.
- **Findings:** a filterable ledger with bulk triage and a "Blocks gate" answer taken from the gate's own `blocked_by` list. The detail page is ordered how to fix, where it occurs, decide (triage, reachability, waiver request), context, history.
- **Project settings:** CI setup with a one-time API key and copyable pipelines, policy and templates, waivers with a request and approval flow, insights and SLA aging, access (members, teams, invite links) and the CVE watcher.
- **Administration:** accounts, the retention preview and purge, and watcher health.
- **First run:** a setup screen creates the first administrator; invite pages let people join without open registration.
- **Profile:** the name other people see, and a password change that keeps this browser signed in while it ends every other session.
- **Command palette:** Ctrl+K or ⌘K jumps to project pages, other projects, admin places and two actions.
- **Accessibility and theming:** a skip link, focus moved to the content after navigation, live regions for outcomes, an error boundary, a not-found page, and a light, dark or system theme.

## Development

Run these from `frontend/`:

```bash
pnpm install
pnpm dev            # Vite dev server; start the API with `make dev-api` from the repository root
pnpm test           # unit tests (vitest)
pnpm exec tsc -b    # type check
pnpm lint           # oxlint
pnpm exec dprint check
```

`make e2e-ui` from the repository root runs the browser journeys against the real embedded build (it needs Docker, Go and a Chromium; set `CHROMIUM_BIN` when none is bundled). The script listens on `E2E_UI_PORT` (default 18081) and `E2E_UI_DB_PORT` (default 54331); change them if those ports are taken.

## Conventions

- Colours come from the tokens in `src/index.css`, not from raw palette classes. A `-fg` token is only used on its matching `-bg`, and severity and verdict are always shown as text as well as colour.
- The theme is applied before first paint by `public/theme-init.js`. It is an external file, not an inline script, so a strict `script-src 'self'` Content-Security-Policy keeps working. Keep it in step with `src/lib/theme.ts`.
- Add tests with every change. The accessibility baseline is an axe-core pass with no WCAG 2.2 AA violations in light and dark. `e2e/a11y.spec.ts` enforces it on every page (run it with `make e2e-ui`).

## Authentication and CSRF

The app sends session tokens in `Authorization: Bearer <token>` headers. Every request goes through `apiFetch` in `src/api/client.ts`. The API requires this header and does not use cookies for authentication.

This prevents cross-site requests from authenticating with a browser's automatically attached cookies.

If the backend starts using cookies for authentication, this protection no longer applies. Any such change must:

1. Add CSRF protection, such as a double-submit token, strict Origin or Referer checks, or `SameSite=Strict` with a same-origin check.
2. Keep sending the `Authorization` header on every mutation and keep requiring it on the server. Cookies must not become the only way to authenticate.
