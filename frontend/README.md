# Specht frontend

The frontend is Specht's React and TypeScript web app. It helps teams review and manage security findings from SCA, SAST, and IaC scans.

## Frontend roadmap

The focus is to make the main workflow clear and dependable:

- Connect the project overview, findings list, and finding details into one easy-to-follow flow.
- Keep shared controls and page layouts consistent.
- Improve filters, loading and error states, keyboard access, and smaller-screen layouts.
- Add tests for the main user flows as the interface grows.

After that, we want to improve the frontend for CI feedback, policy checks, and verifying fixes. This is a direction, not a promise or a schedule. See the [roadmap discussion](https://github.com/minh-tg/specht/discussions/1) for updates and to share feedback.

## Authentication and CSRF

The app sends session tokens in `Authorization: Bearer <token>` headers. Every request goes through `apiFetch` in `src/api/client.ts`. The API requires this header and does not use cookies for authentication.

This prevents cross-site requests from authenticating with a browser's automatically attached cookies.

If the backend starts using cookies for authentication, this protection no longer applies. Any such change must:

1. Add CSRF protection, such as a double-submit token, strict Origin or Referer checks, or `SameSite=Strict` with a same-origin check.
2. Keep sending the `Authorization` header on every mutation and keep requiring it on the server. Cookies must not become the only way to authenticate.
