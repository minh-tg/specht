# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some Oxlint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the Oxlint configuration

If you are developing a production application, we recommend enabling type-aware lint rules by installing `oxlint-tsgolint` and editing `.oxlintrc.json`:

```json
{
  "$schema": "./node_modules/oxlint/configuration_schema.json",
  "plugins": ["react", "typescript", "oxc"],
  "options": {
    "typeAware": true
  },
  "rules": {
    "react/rules-of-hooks": "error",
    "react/only-export-components": ["warn", { "allowConstantExport": true }]
  }
}
```

See the [Oxlint rules documentation](https://oxc.rs/docs/guide/usage/linter/rules) for the full list of rules and categories.

## Authentication and CSRF posture

The SPA authenticates exclusively with `Authorization: Bearer <token>` headers.
Every request goes through `apiFetch` (`src/api/client.ts`), which attaches the
session token explicitly to each request; the API rejects any request that
lacks the header, so no ambient (cookie) credential is ever used or trusted.

This is what keeps the API safe from CSRF: a cross-site request cannot attach
a Bearer header, so no forged state-changing request can authenticate.

**Cookie risk — read before adopting cookie-based sessions.** If the backend
ever starts authenticating via cookies (session cookie, `SameSite=None` for
cross-site, etc.), the CSRF protection above disappears: browsers attach
cookies automatically, so a malicious site could forge state-changing
requests. Any such change MUST:

1. add real CSRF defense (double-submit token, or strict Origin/Referer
   verification, or `SameSite=Strict` plus a same-origin check), and
2. keep sending the explicit `Authorization` header on every mutation and
   keep the server requiring it, so cookie adoption never becomes the sole
   credential path.
