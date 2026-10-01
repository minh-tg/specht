# Specht frontend

The frontend is Specht's React and TypeScript web app. It helps teams review and manage security findings from SCA, SAST, and IaC scans.

## What it covers today

- **Projects:** a table of every project with its gate verdict (blocked, passing or never scanned), the number of blocking findings and the last scan. Admins can create projects.
- **Project view:** a header with the verdict, the policy floor and where it comes from, the last scan and severity counts, above the Findings and Reports tabs. Reports are uploaded from the Reports tab.
- **CI setup:** after creating a project, a guided page creates an API key (shown once) and offers copyable GitHub Actions and GitLab CI pipelines.
- **Findings:** a filterable list with a "Blocks gate" answer taken from the gate's own `blocked_by` list, and a detail page ordered how to fix, where it occurs, decide (triage and reachability), context, history.
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
- Add tests with every change. The accessibility baseline is an axe-core pass with no WCAG 2.2 AA violations in light and dark.

## What is next

Show an honest "1-20 of N" pager and finding history with names (both need the list total and account directory the API now provides), add policy, waiver and evidence views, and support verifying fixes. This is a direction, not a promise or a schedule. See the [roadmap discussion](https://github.com/minh-tg/specht/discussions/1) for updates and to share feedback.

## Authentication and CSRF

The app sends session tokens in `Authorization: Bearer <token>` headers. Every request goes through `apiFetch` in `src/api/client.ts`. The API requires this header and does not use cookies for authentication.

This prevents cross-site requests from authenticating with a browser's automatically attached cookies.

If the backend starts using cookies for authentication, this protection no longer applies. Any such change must:

1. Add CSRF protection, such as a double-submit token, strict Origin or Referer checks, or `SameSite=Strict` with a same-origin check.
2. Keep sending the `Authorization` header on every mutation and keep requiring it on the server. Cookies must not become the only way to authenticate.
