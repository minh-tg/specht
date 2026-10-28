# Self-hosting Specht with Docker Compose

Specht is an early preview and is not production-ready. Docker Compose
(`deploy/docker-compose.yml`) is the documented single-node self-hosting path
for evaluation: Postgres 17 + the Specht server. Migrations run automatically
at startup (`DB_MIGRATE=true`). The `specht` and `specht-adapter` binaries are
attached to each GitHub Release. No Helm deployment is provided.

## 1. Secrets

```bash
cp deploy/.env.prod.example deploy/.env.prod
# Fill in POSTGRES_PASSWORD and JWT_SECRET (min 32 random bytes):
head -c 48 /dev/urandom | base64
```

`deploy/.env.prod` must never be committed. The server refuses to start with
a missing or short `JWT_SECRET`; Postgres refuses an empty password — both
fail fast instead of running insecure.

The bundled Postgres container has no TLS and the server reaches it over the
private Compose network, so `POSTGRES_SSLMODE` stays `disable` for it; setting
`require` makes the server fail to connect. If you replace the bundled database
with a remote, TLS-enabled one, set `POSTGRES_SSLMODE=require` (or
`verify-full` once the Postgres certificate and hostname are configured), and
never use the `disable` fallback for a database that is not on the same host.
Keep `DB_MIGRATE=true` for the simple deployment path, or set it to `false`
and run `specht migrate` as a separately controlled release step.

## 2. Start

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d
curl -fsS http://localhost:8080/api/v1/health   # liveness: the process is up
curl -fsS http://localhost:8080/api/v1/ready    # readiness: the database answers
curl -fsS http://localhost:8080/api/v1/version
```

The server service pulls `ghcr.io/minh-tg/specht:${SPECHT_VERSION}`. Set
`SPECHT_VERSION` in `deploy/.env.prod` to a release tag such as `v0.1.0` so a
restart never moves you to a new build. The default, `latest`, follows stable
releases only and does not exist until the first one, so a release candidate
(`v0.1.0-rc.1`) must be named in `deploy/.env.prod`. The GHCR package is
private after its first push: open the package settings on GitHub and change
its visibility to public once, or hosts cannot pull it without a login.

### Build from source

The override file replaces the pulled image with a local build from the
repository root. Run it from the checkout:

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.build.yml \
  --env-file deploy/.env.prod up -d --build
```

Without the override file, compose only pulls the image and never builds it.
Until the first release is published there is no image to pull, so use the
override for a first start.

With Podman, run the same commands through `podman compose`. Rootless Podman
needs subordinate ID ranges for your user before the build can unpack the base
images. [Rootless Podman](../README.md#rootless-podman) in the main README gives
the commands.

## 3. Configuration reference

The server reads its settings from the environment. Compose forwards every
variable below from `deploy/.env.prod`; for a bare-metal run, export them or
use your service manager. Defaults are the server's own, except where the
compose defaults differ, which is noted.

On/off switches take `true` or `false` (also `1`, `0`, `t`, `f` and their
capitalized forms); empty keeps the default and any other value stops the
server at startup. `SSO_ALLOW_USERINFO_ONLY`, `SSO_ALLOW_UNVERIFIED_EMAIL`
and `SSO_ALLOW_PRIVATE_ISSUER` accept only the exact words `true` and `false`.

### Core

| Variable | Default | Purpose |
|----------|---------|---------|
| `SERVER_ADDR` | `:8080` | HTTP listen address. |
| `DATABASE_URL` | *required* | Postgres DSN. Append `?sslmode=require` or `verify-full` for a remote database. |
| `JWT_SECRET` | *required* | HMAC signing key, at least 32 random bytes. Startup fails without it. |
| `DB_MIGRATE` | `true` | Run migrations at startup. Set `false` to run `specht migrate` as a separately controlled step. |
| `DB_CONNECT_TIMEOUT` | `30s` | How long startup waits for Postgres to answer, retrying with a growing delay, before the server exits. `0s` tries once. A rejected login fails at once. |
| `DB_MAX_CONNS` | `20` | The most database connections the server opens. Keep it below Postgres `max_connections` (100 by default), which every client of that database shares. Must be at least 2: an ingest holds two connections at once. |
| `DB_MIN_CONNS` | `2` | Connections kept open when idle. Capped at `DB_MAX_CONNS`. |
| `SHUTDOWN_TIMEOUT` | `150s` | How long a stop (SIGTERM) waits for in-flight requests before closing. Longer than the two minutes an ingest may run. If you run the container yourself, give it a stop grace period above this value; the Compose file sets 165s. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `CORS_ORIGINS` | *(empty)* | Comma/space-separated origins allowed to call the API from a browser. Empty allows none: the bundled UI is same-origin and needs no entry. Set it only when the UI is hosted elsewhere (use exact `https://` origins). |
| `ADMIN_EMAILS` | *(empty)* | Comma-separated emails promoted to global admin at startup. Idempotent; matching ignores case. Only an account that proved it owns the address is promoted: the one first-run setup created, or one that signed in through SSO while the identity provider reported the email as verified (an account linked under `SSO_ALLOW_UNVERIFIED_EMAIL` does not count). A password-registered account is never promoted, and neither is a deactivated one; the server logs one warning per such address. An address with no account is skipped silently, since its owner may still sign in through SSO. |
| `SETUP_TOKEN` | *(random)* | Proof of access for first-run setup. While the database has no global admin the server logs a random token at startup (`setup_token=...`); set this variable to choose it instead (at least 16 characters, never logged). Ignored once a global admin exists. |
| `REGISTRATION_ENABLED` | `false` | Allow self-service `POST /api/v1/auth/register`. Unset or empty is closed; set `true` only when open signup is intended. The endpoint answers `403 registration_disabled` while closed. First-run setup and invite links keep working, and invalid values fail startup. |
| `TRUSTED_PROXIES` | *(empty)* | Comma/space-separated CIDRs of proxy hops allowed to set `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto`. Empty trusts nobody. |
| `INVENTORY_TTL` | `2160h` | How long a scanned package stays in the watcher's active inventory. |
| `INGEST_MAX_CONCURRENCY` | `8` | Report ingests processed at once. Each parse holds several times the request body in memory (bodies are capped at 25 MiB), so this bounds the worst case. A request is authorized from the start of its body before it takes anything, and a slot is taken only after the whole body has arrived (the body has 30 s), so a slow upload holds no slot. One caller, a user or an API key, may hold at most half of the slots (at least one), and so may one project however many callers it has (a manager's session and any number of its keys together): at the default of 8, a project runs at most 4 ingests at once. A single-project install therefore uses at most half of the slots; raise this setting if its CI needs more at once. Further requests wait up to 15 s in their own queue and get `503 ingest_busy` with `Retry-After`, without delaying other callers. An ingest holds two database connections at once, so the server caps this at `DB_MAX_CONNS` minus one and logs a warning when it does: with `DB_MAX_CONNS=8`, at most 7 ingests run. An ingest may take up to two minutes once its body is in, and it finishes even if the client hangs up. Must be a positive integer. |
| `INGEST_MAX_FINDINGS` | `100000` | Findings and packages one report may produce. A report past it is refused with `422 too_many_findings`, and the parser stops at the limit instead of converting the whole file. A parsed finding holds about 1.4 KB in memory, so one report at the default holds about 140 MB of findings. `INGEST_MEMORY_BUDGET` bounds how many reports decode at once. Lower the limit on small hosts; raise it only with the memory to match. Before any parser decodes a report, the server also counts its JSON objects and the objects in the arrays that carry findings; a document with more than 16 objects, 64 JSON values of any kind, or 2 finding-array elements (objects, `null`, strings or numbers alike) per allowed finding is refused with the same error. Array names match the way the JSON decoder matches fields, ignoring case and JSON escapes. A document nested more than 64 levels deep is refused with the same error; the captured reports for the supported scanners nest at most 14 levels, so the cap refuses only hostile or malformed documents. Must be a positive integer. |
| `INGEST_MEMORY_BUDGET` | `2GiB` | Memory that all report ingests in flight may charge together. Before it decodes a report, an ingest charges 64 bytes per byte of the report's `raw_data` against this budget and gives the charge back when it ends, whatever way it ends. A 25 MiB report charges 1.56 GiB, so at the default one large report runs with at most 7 MiB of other reports beside it, and eight 4 MiB reports run together. A charge above the whole budget is capped to the budget, so a report of any size is admitted, alone. An ingest that cannot get its charge within 15 s, the wait a concurrency slot has, gets `503 ingest_busy` with `Retry-After`. One caller, and separately one project, also has an allowance of half the budget that its ingests in flight share, so a second 25 MiB report of the same project waits for its first. The allowance caps what one caller or project can queue; it does not lower a single ingest's charge against the whole budget. One 25 MiB report still charges 1.56 GiB there (78% of the default, and all of a 1 GiB budget), and an ingest of another project waits for it like any other. The factor 64 is 2.5 to 10 times what decoding costs: peaks measured at the default limit were 6 to 24 times the report (150 MB for a 14 MB Trivy report with 100000 findings). Decoding memory stays under 2 GiB as long as no report costs more than 64 times its size, which the document scan in `INGEST_MAX_FINDINGS` enforces for the padding shapes known today, and it is about 0.2 to 0.8 GiB for ordinary reports. The request bodies come on top: up to 25 MiB each, `INGEST_MAX_CONCURRENCY` of them (200 MiB at the defaults), each held about twice while it is read. Give the container at least the budget plus 1 GiB. Accepts bytes (`2147483648`) or a size such as `512MiB`, `2GiB` or `3GB` (`KiB`, `MiB`, `GiB`, `TiB` are powers of 1024; `KB`, `MB`, `GB`, `TB` of 1000). Must be positive; invalid values fail startup. |
| `SESSION_MAX_AGE` | `720h` | Absolute lifetime of a sign-in. Each refresh renews the token for a week, but never past this long after the original login; the next refresh then answers `401 refresh_failed` and the user signs in again. Must be a positive duration. |
| `RAW_RETENTION_DAYS` | `30` | Days a report keeps its `raw_data` payload. Each sweep on `LIFECYCLE_SWEEP_INTERVAL` clears the payload of every report older than this and keeps the report row, its findings and their summaries. Responses then carry `raw_data_expired: true` on the report and on the finding detail, with `raw_data_expires_at` as the date the window ended, and the finding detail page says when the raw evidence expired. `0` keeps every payload. Must be a whole number of days from 0 to 36500 (100 years); a negative, non-numeric or larger value fails startup. |
| `LIFECYCLE_SWEEP_INTERVAL` | `5m` | Period of the analysis-expiry, waiver-expiry, stale-report and dead-refresh-token sweeps; must be a positive duration. The stale-report sweep marks a report that has been `processing` for more than 10 minutes as `failed` and removes the findings it created that no occurrence supports (it archives ones that already had triage). The refresh token sweep deletes tokens that expired or were revoked more than 7 days ago, at most 50,000 rows per run. |
| `FINGERPRINT_KEY` | *(empty)* | Hex key, at least 16 bytes (for example `openssl rand -hex 32`), that Gitleaks secret identities are hashed with. Empty: the server makes a key on first use and stores it in the `instance_secrets` table. Set: the key stays out of the database. A value that is not hex or decodes to fewer than 16 bytes fails startup. See "Fingerprint key" below. |

### Fingerprint key

Gitleaks findings are identified by a keyed digest of the secret (HMAC-SHA-256), and the secret
itself is never stored. By default the key is a row in `instance_secrets`, next to the digests.
That row travels with every database backup, and anyone who can read it and the digests can test
a guessed secret against them. Set `FINGERPRINT_KEY` to keep the key outside the database.

Keep the key as long as the data: a different key gives every secret finding a new identity, so the
old ones stop matching and are not closed by a later scan. To move an instance that already has
a stored key, set `FINGERPRINT_KEY` to the stored value before the first restart, so the
identities stay the same:

```sh
psql "$DATABASE_URL" -Atc "SELECT encode(value, 'hex') FROM instance_secrets WHERE name = 'fingerprint-key'"
```

Once the server runs with that value, delete the row with
`DELETE FROM instance_secrets WHERE name = 'fingerprint-key'`. Back the key up with your other
secrets, because a restore of the database alone no longer carries it.

Registration does not verify email addresses: an account holds whatever address
its creator typed, so keep `REGISTRATION_ENABLED` closed unless you accept that.

Raw scanner output (`raw_data`) is redacted before it is stored. Trivy, Semgrep and Checkov
remove the matched secret and the source around it, at any depth: Trivy's `Match` and `Code`,
Semgrep's SARIF `snippet` and native `lines` and `metavars`, and its `fix` template, which Semgrep
fills with the matched values, and Checkov's `code_block` and `evaluations`. They also remove the content of any key named `secret`, `password`, `passwd`,
`token`, `api_key`, `apikey`, `access_key`, `private_key` or `client_secret`, at any depth and in
any case. A key whose lowercased name contains `password`, `passwd`, `secret`, `token`, `api_key`,
`apikey` or `authorization` loses its value at any depth, a scalar or an object, so `db_password`,
`auth_token` and `Authorization` are removed although the scanner did not name them. The match is by fragment,
so any key containing `token` is removed, `tokenizer_version` included (a known false positive). A list under such a key keeps its shape, so the
parser can still read it, but each of its scalar elements loses its value, and an object directly
under such a key is replaced whole. Only an object element with a neutral key inside that list
keeps its value. If redaction fails for a report, the stored payload is `{"redaction":"failed"}`,
and the report and its findings are still ingested. For these three scanners a payload over
64 KiB (65536 bytes) keeps only its first 64 KiB of redacted output, stored as
`{"truncated":true,"original_bytes":N,"prefix":"..."}`, where `N` is the size of the raw output
before redaction. Gitleaks and Nuclei already redacted their payloads and are not capped by this.
Findings, severities and fingerprints are computed from the full report, so redaction and the
cap change only the stored payload.

### Rate limiting

| Variable | Default | Purpose |
|----------|---------|---------|
| `RATE_LIMIT_ENABLED` | `false` (`true` in compose) | Token-bucket limiting on public and authenticated routes. |
| `RATE_LIMIT_RPS` | `10` | Per-IP rate for unauthenticated entry points. |
| `RATE_LIMIT_BURST` | `20` | Burst for the unauthenticated bucket. |
| `RATE_LIMIT_AUTH_RPS` | `1000` | Per-caller rate behind authentication. |
| `RATE_LIMIT_AUTH_BURST` | `2000` | Burst for the authenticated bucket. |
| `RATE_LIMIT_LOGIN_PER_MINUTE` | `5` | Per-client refill rate for the login tier: login, register, first-run setup, password reset, invite lookup and invite accept. `PUT /api/v1/me/password` has a separate bucket of the same size. |
| `RATE_LIMIT_LOGIN_BURST` | `5` | Burst for those buckets: attempts allowed before the per-minute refill applies. |

Several limiters stack. All of them count in memory, per server process, and
start empty after a restart.

| Tier | Routes | Counted per | Size | Active |
|------|--------|-------------|------|--------|
| Global | Every route except `/api/v1/health` and `/api/v1/version`. A request carrying an `Authorization` header skips it. On a route behind authentication the authenticated tier judges it when the token is valid, and this bucket judges it when the token is not (see below). | Client address | `RATE_LIMIT_RPS`, `RATE_LIMIT_BURST` | Only with `RATE_LIMIT_ENABLED=true`. |
| Anonymous auth routes | Token refresh, logout, the SSO exchange, and every route in the login tier below. Sending an `Authorization` header does not skip it. | Client address | `RATE_LIMIT_RPS`, `RATE_LIMIT_BURST` (10 per second, burst 20 when unset) | Always, also with `RATE_LIMIT_ENABLED=false`. |
| Login | Login, register, first-run setup, password reset, invite lookup and invite accept share one bucket. `PUT /api/v1/me/password` has a bucket of its own. | Client address | `RATE_LIMIT_LOGIN_PER_MINUTE`, `RATE_LIMIT_LOGIN_BURST` | Always. |
| Authenticated | Routes behind a session or API key. | The signed-in user for a session, and the key itself for an API key: a user's sessions and the keys they created do not share a budget | `RATE_LIMIT_AUTH_RPS`, `RATE_LIMIT_AUTH_BURST` | Only with `RATE_LIMIT_ENABLED=true`. |
| Account delay | `POST /api/v1/auth/login` and `PUT /api/v1/me/password` (the current-password check). | Normalized email (trimmed, lower-cased) | Fixed, see below | Always. |

**Invalid credentials.** The authenticated tier runs after the token is
checked. A request on a route behind authentication whose bearer token or API
key is invalid, expired, or not a bearer at all spends a token from the
per-address global bucket instead, and gets `429` once that bucket is empty, so
guessing keys is limited per address. A request whose credentials are valid
does not spend from the address bucket. The anonymous routes outside the
authentication group (`/api/v1/capabilities`, `/api/v1/ready`, SSO login and
callback) still skip every tier when they carry an `Authorization` header. The
cost of guessing a key is one database lookup per attempt. Keys and tokens
carry 256 bits of randomness, so this is load, not a way to guess one.

Member suggestions have one more fixed bucket of 30 requests a minute (burst
10) per caller, also always on.

With the global limiter enabled, the anonymous auth routes spend a token from
both buckets, which have the same size, so the limit you configure is the
limit you get. The anonymous auth bucket follows `RATE_LIMIT_RPS` and
`RATE_LIMIT_BURST`: raising them for a load test raises it too. A login request
also spends from the login bucket, so the login tier stays the tighter limit
for credentials.

A request over any bucket gets `429` with code `rate_limited` and a
`Retry-After` header in seconds.

**Client address.** An IPv6 client is counted by its /64 prefix, so rotating
through addresses in one network shares one budget. An IPv4 client is counted
per address, and an IPv4-mapped IPv6 address such as `::ffff:192.0.2.7`
counts as the IPv4 address. Behind a reverse proxy, set `TRUSTED_PROXIES` so
each client is counted by its own address instead of the proxy's; otherwise
every user shares one bucket.

**Account delay.** Failed password logins are counted per email, whichever
address they come from. Emails that do not exist are counted exactly like
registered ones, so the delay does not show which accounts exist. After three
failures in a row the account waits 1 second, then 2, 4, 8 and so on up to 60
seconds. A login attempt during the wait gets `429` with code
`too_many_attempts` and a `Retry-After` header, and it is not checked against
the password, so even the right password is refused until the wait ends. A
successful login resets the count, and the count drops to zero after 15
minutes without a failed login. There is no lockout: the wait never exceeds 60
seconds. Someone who keeps failing against an email can keep that account
waiting. Refused attempts are written to the audit log as failed logins.

`PUT /api/v1/me/password` draws on the same count, keyed by the signed-in
account's email, so sign-in failures and wrong current passwords add up
together. A wrong current password is charged before it is checked and a
correct one resets the count. During the wait the route answers `429` with code
`too_many_attempts` and a `Retry-After` header, and does not check the
password. A request rejected for its new password (too common, same as the
current one) never judged the current password and is not counted.

**Bucket cap.** Each limiter holds at most 100,000 buckets, and the account
delay holds at most 100,000 emails. When the per-IP limiter is full, expired
entries are dropped first. If it is still full, clients without an entry yet
share one overflow entry, which is limited as a group, and entries that already
exist are never evicted. While a flood keeps a per-IP store full, every
client without an entry in it shares that store's one overflow bucket. Login
requests also pass through the anonymous auth bucket, so the same flood fills
that store as well, and clients without a live entry there (for example a
browser refreshing its token) share a single bucket of 10 requests a second at
the defaults. To keep a store full an attacker needs about 100,000 distinct IPv4
addresses or IPv6 /64 prefixes, each seen again at least every 3 minutes (the
idle time after which a bucket expires), which is around 550 requests a second.
The effect ends within 3 minutes after the flood stops.

The account delay never shares a counter between emails. When its map is full,
entries whose count has expired are dropped first. If it is still full, the
stalest entry that has not reached a wait yet (fewer than three failures and not
waiting) makes room for the new email; the oldest of a sample of entries is
chosen, so the lookup stays cheap. If every entry is waiting, the new email is
not tracked at all and only the per-IP login bucket limits it. A flood of
made-up emails therefore cannot lock real users out: it can push out other
accounts' small failure counts, but never a wait that has started.

### SSO / OIDC

Off unless `SSO_ENABLE=true`, which then requires the client id, issuer, and
redirect URI, and a client secret unless `SSO_PUBLIC_CLIENT=true`. The server
checks these at startup and refuses to start when one is missing or malformed,
naming every problem at once. Issuer and redirect URI must be absolute URLs
that use `https`; `http` is accepted only for a loopback host (`localhost`,
`127.0.0.1`, `::1`), for a local identity provider. The redirect URI must not
carry a fragment.

The server finds the provider's endpoints through OpenID Connect Discovery: it
removes one trailing slash from `SSO_ISSUER_URL`, appends
`/.well-known/openid-configuration`, and takes the authorization, token,
UserInfo and JWKS endpoints from that document. Set `SSO_ISSUER_URL` to exactly
the `issuer` value from the identity provider's
`/.well-known/openid-configuration`, trailing slash included. Open that URL in
a browser and copy the field. When the two differ, the server logs and returns
`discovery document issuer "<document>" does not match configured
SSO_ISSUER_URL "<configured>"`, with both values quoted so a trailing slash or
a different scheme is visible. For
Keycloak that is `https://kc.example.com/realms/<realm>`, for Auth0
`https://<tenant>.auth0.com/` (with the slash), for Google
`https://accounts.google.com`, and for Entra ID
`https://login.microsoftonline.com/<tenant id>/v2.0`. A document whose `issuer`
differs in any character is refused, and the `iss` claim of every ID token must
match it byte for byte. Each endpoint must be an absolute `https` URL (`http`
only on a loopback host), and the provider must resolve to a public address:
connections to private and link-local addresses are refused. For an identity
provider inside your network, set `SSO_ALLOW_PRIVATE_ISSUER=true`: the host of
`SSO_ISSUER_URL`, and only that host, may then resolve to a private, loopback or
link-local address. An endpoint the discovery document names on any other host
is still refused, so a document cannot point the server at an internal service.

Discovery runs on the first sign-in, not at startup, so the server starts while
the provider is down. A fetch is tried up to three times; if all fail, the login
route answers `503` and logs the reason, and the next sign-in tries again. The
document is cached for an hour. When a refresh fails, the server keeps using
the last document it fetched.

| Variable | Default | Purpose |
|----------|---------|---------|
| `SSO_ENABLE` | `false` | Mounts the SSO login and callback routes. |
| `SSO_CLIENT_ID` | *(empty)* | OAuth client id. |
| `SSO_CLIENT_SECRET` | *(empty)* | **Secret.** OAuth client secret. Required unless `SSO_PUBLIC_CLIENT=true`. |
| `SSO_PUBLIC_CLIENT` | `false` | Allows an empty `SSO_CLIENT_SECRET`, for an identity provider client registered as public. PKCE protects the code exchange in that case. Leave it off for a confidential client: an empty secret then stops the server from starting instead of silently weakening the login. |
| `SSO_ISSUER_URL` | *(empty)* | Must be `https`; plain `http` is accepted only for a loopback host, for a local IdP. |
| `SSO_ALLOW_PRIVATE_ISSUER` | `false` | Lets the host of `SSO_ISSUER_URL` resolve to a private, loopback or link-local address, for an identity provider on an internal network. Any other host stays refused. Only the exact values `true` and `false` are accepted; anything else stops the server from starting. |
| `SSO_REDIRECT_URI` | *(empty)* | Must match the IdP's registered redirect URI. |
| `SSO_GROUPS_CLAIM` | `groups` | Claim carrying IdP group membership. |
| `SSO_ALLOWED_DOMAINS` | *(empty)* | Comma/space-separated email domains that may auto-provision. Empty refuses every unknown subject. |
| `SSO_ADMIN_GROUPS` | *(empty)* | IdP groups granting admin to a *newly provisioned* account. Existing accounts never change role from IdP groups. |
| `SSO_ALLOW_USERINFO_ONLY` | `false` | Insecure compatibility downgrade for an IdP that returns no ID token. |
| `SSO_ALLOW_UNVERIFIED_EMAIL` | `false` | Let a first SSO login link or provision by an email the IdP did not mark `email_verified`. Only for IdPs that never send the claim and whose emails administrators control. See "SSO account linking". |

### CVE feed watcher

| Variable | Default | Purpose |
|----------|---------|---------|
| `WATCHER_ENABLE` | `false` | Runs the OSV poll loop. |
| `WATCHER_POLL_INTERVAL` | `6h` | Time between polls. |
| `WATCHER_OSV_ENDPOINT` | `https://api.osv.dev/v1/querybatch` | Batch query endpoint. |
| `WATCHER_OSV_VULN_ENDPOINT` | `https://api.osv.dev/v1/vulns/{id}` | Full-advisory template; `{id}` is substituted. Keep it inside the same trust boundary as the batch endpoint. |
| `WATCHER_BATCH_SIZE` | `0` (unlimited; compose sets `100`) | Identifiers per batch. |
| `WATCHER_COLD_START_WINDOW` | `full` | `full` for full-history cold start, or a Go duration to backfill since. |
| `WATCHER_SLACK_URL` | *(empty)* | Slack webhook for new advisories. Empty disables the channel. |
| `WATCHER_SLACK_SIGNING_SECRET` | *(empty)* | **Secret.** Signs Slack deliveries. |
| `WATCHER_WEBHOOK_URL` | *(empty)* | Generic webhook for new advisories. |
| `WATCHER_WEBHOOK_SIGNING_SECRET` | *(empty)* | **Secret.** Signs both this webhook and tracker deliveries. |

### Tracker dispatch

Finding lifecycle events (created, verified fixed, regression) can be pushed to
an external issue tracker. Disabled by default.

| Variable | Default | Purpose |
|----------|---------|---------|
| `TRACKER_PROVIDER` | `noop` | `noop`, `inprocess`, or `webhook`. |
| `TRACKER_BASE_URL` | *(empty)* | Tracker API base URL. |
| `TRACKER_PROJECT_ID` | *(empty)* | Destination project. |
| `TRACKER_API_TOKEN` | *(empty)* | **Secret.** Tracker API token. |
| `WATCHER_WEBHOOK_URLS` | *(empty)* | Comma-separated endpoints fanned out to when `TRACKER_PROVIDER=webhook`. |

### Threat intel

| Variable | Default | Purpose |
|----------|---------|---------|
| `INTEL_ENABLED` | `true` | Set `false` to disable the EPSS and KEV feeds. No intelligence feed is built or called while disabled. |
| `INTEL_TTL` | `1h` | Cache lifetime for both feeds. A feed outage serves the last record, flagged stale. |
| `INTEL_EPSS_ENDPOINT` | `https://api.first.org/data/v1/epss` | EPSS feed. |
| `INTEL_KEV_ENDPOINT` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CISA KEV catalog. |

### Client (adapter, CLI and MCP bridge)

Read by `specht-adapter`, `specht` and `specht-mcp`, not by the server.

| Variable | Default | Purpose |
|----------|---------|---------|
| `API_URL` | `http://localhost:8080` | Specht base URL. |
| `API_KEY` | *required* | A project API key, or a session token for admin operations. |
| `SPECHT_PROJECT` | *(empty)* | Adapter only: project slug, used when the report and `-project` give none. |
| `SPECHT_API_URL`, `SPECHT_API_KEY` | *(empty)* | Aliases for `API_URL` and `API_KEY`, for runners where those names collide with other tools. Read only when the unprefixed name is empty. |
| `SPECHT_OWNER` | *(derived)* | Adapter only: repository owner recorded on the report. Defaults to the owner of `GITHUB_REPOSITORY` or `CI_PROJECT_PATH`. |
| `SPECHT_ENVIRONMENT` | *(empty)* | Adapter only: deployment environment (for example `production`) recorded on the report. |

The adapter also reads the CI provider's own variables when its flags are not
set: `GITHUB_REPOSITORY`, `GITHUB_SHA`, `GITHUB_REF_NAME`, `GITHUB_BASE_REF`,
`GITHUB_STEP_SUMMARY`, `GITHUB_EVENT_NAME` and `GITHUB_EVENT_PATH` on GitHub
Actions, and `CI_PROJECT_PATH`, `CI_COMMIT_SHA`, `CI_COMMIT_REF_NAME` and
`CI_MERGE_REQUEST_TARGET_BRANCH_NAME` on GitLab CI. On `pull_request` and
`pull_request_target` events the commit and branch come from the pull request
head in the event payload, not from `GITHUB_SHA` and `GITHUB_REF_NAME`, which
name the temporary merge commit there. The report and the check run then name
the commit the pull request lists. A pull request from a fork
has no secrets, so with an empty API key the adapter logs a notice and exits 0.

### CVE details from external providers

The finding page lists the CVE evaluation details: every CVSS vector, EPSS and
KEV, CWEs, dates and references. The scan report is the primary source. When a
report is incomplete for a CVE (no valid CVSS v3.0, v3.1 or v4.0 vector, or
neither a CWE nor a published date), the server can ask external providers for
the rest. Providers are off by default, so an air-gapped install makes no CVE
detail calls.

What leaves the server: the CVE identifier in the request (for example
`CVE-2024-3094`), the server's IP address, the `User-Agent: Specht` header and,
when configured, the provider's API key in a request header. No package name,
project, finding or report data is sent. Calls happen in the background when
someone opens a finding with an incomplete report, never during an ingest, and
answers are cached in PostgreSQL (`cve_detail_cache`) for `CVE_DETAIL_TTL`
(`CVE_DETAIL_NEGATIVE_TTL` for "not found"). Rows are deleted 30 days after they
expire. Requests use https only, follow no redirects, refuse private addresses
unless `CVE_DETAIL_ALLOW_PRIVATE_MIRROR=true`, and read at most 2 MiB.

Keys are read from the environment only. They are never logged, stored in the
database, or returned by the API. `GET /api/v1/admin/status` lists each
provider under `cve_providers` with whether it is on, whether a key is set (a
boolean), and its last success and last error category.

| Variable | Default | Purpose |
|----------|---------|---------|
| `CVE_DETAIL_PROVIDERS` | *(empty, off)* | Providers to ask, in order: `nvd`, `vulncheck`, `osv`, for example `nvd,osv`. The first that has the CVE answers. |
| `CVE_DETAIL_NVD_API_KEY` | *(empty)* | **Secret.** Optional NVD API key, sent in the `apiKey` header. Raises NVD's limit from 5 to 50 requests per 30 seconds. |
| `CVE_DETAIL_VULNCHECK_API_KEY` | *(empty)* | **Secret.** VulnCheck API token, sent as a bearer token. Required when `vulncheck` is listed; startup fails without it. |
| `CVE_DETAIL_NVD_BASE_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Override for a mirror or tests. Must be https. |
| `CVE_DETAIL_VULNCHECK_BASE_URL` | `https://api.vulncheck.com/v3/index/nist-nvd2` | Override for a mirror or tests. Must be https. |
| `CVE_DETAIL_OSV_BASE_URL` | `https://api.osv.dev/v1/vulns` | Override for a mirror or tests. Must be https; the CVE identifier is appended as the last path segment. |
| `CVE_DETAIL_ALLOW_PRIVATE_MIRROR` | `false` | Let a base URL resolve to a private address, for a mirror inside your network. |
| `CVE_DETAIL_TTL` | `24h` | How long a found record is reused. |
| `CVE_DETAIL_NEGATIVE_TTL` | `6h` | How long a "not found" answer is reused. |
| `CVE_DETAIL_TIMEOUT` | `10s` | Per-request timeout. |
| `CVE_DETAIL_NVD_RPS` | `0.16` without a key, `1.6` with one | Requests per second to NVD, per server replica. |
| `CVE_DETAIL_VULNCHECK_RPS` | `1` | Requests per second to VulnCheck, per server replica. |
| `CVE_DETAIL_OSV_RPS` | `1` | Requests per second to OSV, per server replica. |

The rates apply per replica. Replicas share one fetch per CVE through a lease in
PostgreSQL and share a provider's backoff after a rate limit, so with several
replicas divide the rate by their count if you need to stay under a provider's
published limit.

### Compose-only

| Variable | Default | Purpose |
|----------|---------|---------|
| `POSTGRES_PASSWORD` | *required* | Postgres password. |
| `POSTGRES_SSLMODE` | `disable` | Appended to the generated `DATABASE_URL`. |
| `SERVER_PORT` | `8080` | Host port published for the server. |

See `.env.example` for a commented starting point.

## 4. Verify release images

Published images are signed with keyless Sigstore signing from the tagged
release workflow. Install `cosign`, then verify an image before deployment:

```bash
IMAGE=ghcr.io/minh-tg/specht:v0.1.0
cosign verify \
  --certificate-identity-regexp 'https://github.com/minh-tg/specht/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE"
```

The command verifies the certificate issuer and that the signing workflow ran
from this repository's release tag; replace the image with the exact version
you intend to deploy.

## 5. First admin

Self-service registration is closed by default. Use first-run setup to create
an administrator; setup remains available while registration is closed.
Tenant isolation is enforced: every project needs members, and project
administration needs a global admin.

1. On the first start, read the setup token from the server log
   (`docker compose logs server | grep setup_token`), open the app and create
   the first administrator with it. Or set `SETUP_TOKEN` in `deploy/.env.prod`
   and use that value. Setup stays open until a global admin exists, so a
   stranger who registers before you does not close it; setup closes as soon
   as the first admin is created. If the address you enter already belongs to
   an account, setup answers `409 email_in_use`; use another address. An
   existing server that has accounts but no admin offers a new token in the
   log at the next start.
2. To make more admins, change an account's role in the Admin area, or
   add the email to `ADMIN_EMAILS` in `deploy/.env.prod` and restart (`up -d`
   again; promotion is idempotent). `ADMIN_EMAILS` promotes only an account
   that proved the address: the setup account, or one that signed in through
   SSO with a verified email. A password-registered account stays a normal
   user and the server logs a warning naming the masked address. If you relied
   on registering a listed address and restarting, create the admin with
   first-run setup or sign in with SSO instead, or run `specht grant-admin`.
3. Create projects in the UI, then add members from the project's Access page
   (or `POST /projects/:slug/members`).
4. Bring teammates in with invite links (Access page, or
   `POST /projects/:slug/invites`; valid 1 to 30 days, single use). The link
   works while `REGISTRATION_ENABLED` is `false`, so registration can stay
   closed.

### Recovering access

If the only administrator has forgotten a password, or an account has to be
promoted while no admin can sign in, run one of these inside the server
container. They act on the database directly, so access to the host is the
credential:

```bash
docker compose -f deploy/docker-compose.yml exec server specht reset-password ada@example.com
docker compose -f deploy/docker-compose.yml exec server specht grant-admin ada@example.com
```

`reset-password` prints a generated 24-character password once and ends every
session of the account. Add `--password-stdin` to set a password you chose
instead; it is read from standard input and never printed. A deactivated
account stays deactivated, and the command says so. `grant-admin` makes the
account a global admin; a session the person already has picks the role up at
the next sign-in. Neither command touches the seeded `system@specht.local`
account. Anyone signed in can change their own password, and the name others
see, on the Profile page (the API is `PUT /api/v1/me/password`).

When another administrator can still sign in, they do not need shell access.
On the Admin page, "Reset password" next to a person issues a one-time link
(`/reset/<token>`) that is shown once and works for 24 hours. The person opens it,
chooses a password, and every session the account had ends. A newer link retires
the older ones. Accounts that sign in through SSO, deactivated accounts and the
system account get no link. With no mail server, you hand the link over yourself,
so send it over a channel you trust.

### Changing or deactivating an account

Global admins manage accounts from the admin area or the API:

- `PUT /api/v1/users/{id}/role` changes the global role. The account's token
  generation advances, so its open sessions stop working and the person signs
  in again to get the new role.
- `POST /api/v1/users/{id}/deactivate` ends access without deleting history or
  memberships: open sessions stop at their next request, refresh tokens are
  revoked, and sign-in is refused until `POST /api/v1/users/{id}/reactivate`.

The last active admin, the signed-in admin themselves (for deactivation) and
the seeded `system@specht.local` account cannot be demoted or deactivated;
those requests answer 409. A deactivated account does not count as a project
admin. Deactivating the only admin who can sign in on a project answers 409
`sole_project_admin` and lists the project slugs; send `{"force": true}` (or
`specht users deactivate --force`) to do it anyway. Specht has no endpoint that deletes an account.
Removing someone from a project or a team takes effect on their next request.

### Who sees which teams

A team is visible to a person who belongs to it and to anyone who can reach a
project it is linked to, directly or through a team of their own. `GET
/api/v1/teams` lists only those teams, and a team outside that set answers 404
on `GET /api/v1/teams/{id}/members` and on the roster writes, the same as a team
that does not exist. Global admins see every team. Plan for this when several
organizations share one instance: a project manager picks teams to link from
the teams they can see, so a global admin links a team that is new to their
project, or adds the manager to it first.

## 6. Reverse proxy

Terminate TLS at the proxy and forward plain HTTP. Set `TRUSTED_PROXIES` to
only the proxy-hop CIDRs. `CORS_ORIGINS` stays empty unless the UI is served
from a different origin than the API.

Duplicated browser tabs coordinate refresh through a same-origin SharedWorker.
Browsers without SharedWorker use Web Locks and BroadcastChannel instead; this
fallback requires HTTPS (localhost also qualifies as a secure context). Browsers
with neither mechanism support single-tab sessions only. Credentials remain in
sessionStorage and browser memory. The fallback stores only spent-token SHA-256
digests and expiry times in localStorage; a missing peer response never causes a
spent token to be submitted again. Server-side replay rejection is unchanged.

The server reads `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto` only
when the direct peer is inside `TRUSTED_PROXIES`. A request from any other peer
keeps its connection address and its forwarding headers are never read. For a
trusted peer the client address is resolved like this:

1. Every `X-Forwarded-For` line is joined into one comma-separated list, so a
   proxy that adds its own line next to the client's line (HAProxy
   `option forwardfor`) is read the same as one that appends to a single line.
2. The list is walked from the right. Entries inside `TRUSTED_PROXIES` are
   skipped, and the first entry outside them is the client. Entries to its
   left are client-supplied and ignored.
3. An entry that is not an IP address (including a bracketed or zoned IPv6
   address) stops the walk with no answer. Nothing to its left is used.
4. `X-Real-IP` is read only when step 2 found no client, for example when the
   header is absent, holds only trusted hops, or was stopped by a malformed
   entry. A value that is not an IP address or is itself a trusted proxy is
   ignored.
5. With no answer from either header the client is counted under the proxy's
   address.

So the nearest proxy has to append the address it saw to `X-Forwarded-For`
(its own line or the end of the existing one). A proxy that only sets
`X-Real-IP` and passes the client's `X-Forwarded-For` through unchanged lets the
client choose its address, because a well-formed client-supplied entry wins over
`X-Real-IP`. Setting `X-Forwarded-Proto` makes the server mark the connection
secure; the proxy must overwrite it. A peer outside `TRUSTED_PROXIES` never
makes the connection secure, so with `TRUSTED_PROXIES` empty behind a proxy the
SSO sign-in state cookies are sent without the `Secure` attribute and no
`Strict-Transport-Security` header is set, even on an HTTPS site.

nginx:

```nginx
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
```

HAProxy (frontend or `defaults`):

```haproxy
option forwardfor
http-request set-header X-Real-IP %[src]
http-request set-header X-Forwarded-Proto https if { ssl_fc }
http-request set-header X-Forwarded-Proto http  if !{ ssl_fc }
```

In both cases `TRUSTED_PROXIES` lists the proxy's address (or the network that
holds it), not the clients' networks. With a proxy chain, list every hop.

## SSO ID-token requirement

The SSO authorization-code callback requires a signed ID token by default and
verifies its signature and claims before accepting identity. For an IdP that
cannot return an ID token, `SSO_ALLOW_USERINFO_ONLY=true` explicitly enables
an insecure compatibility downgrade: identity then comes from the UserInfo
endpoint without a signed subject to verify. Prefer configuring the IdP to
return ID tokens; enable this only after assessing the reduced assurance.
This option never bypasses validation when an ID token is present.

## SSO login protections

Each SSO login sends the provider a random state, an OIDC `nonce` and a PKCE
`code_challenge` (S256). PKCE is always on, including for a public client
(`SSO_PUBLIC_CLIENT=true`), and the token request proves possession of the
verifier. The state is public: it comes back in the callback URL next to the
code. The login is therefore bound to the browser that started it by a
signed, `HttpOnly`, `SameSite=Lax` cookie named `sso_state_<id>`, which holds
a random per-login secret and the return path. The verifier and the nonce are
derived from that secret, and the callback refuses a request whose cookie is
missing, expired, altered or issued for another state, before the code is sent
anywhere. Someone who obtains a callback URL (from a log, a browser extension
or a shared device) cannot finish the login without that browser's cookie.

The cookie is signed with a key derived from `JWT_SECRET`, so every replica
that shares the secret can finish a login another one started. Changing
`JWT_SECRET` fails the logins in flight. Each login has its own cookie, so
several tabs can sign in at once. A browser keeps at most four pending logins;
starting a fifth drops the oldest, and that tab answers "start sign-in again".
A login cookie lives 10 minutes. The return path is limited to 1024 bytes.
Logins that were already in flight when you upgrade fail once and succeed on
retry. Providers that do not support PKCE ignore the extra parameters.

After a successful login the SPA receives a single-use code in the URL
fragment, valid for 60 seconds, and trades it for an access and a refresh token
at `POST /api/v1/auth/sso/exchange`. The fragment is never sent to the server
or in a `Referer` header, and a replayed or expired code answers 401.

The code is bound to the browser that started the login. The callback leaves
the `sso_state_<id>` cookie in place, and the exchange spends the code only
from a request that carries that cookie. The code stores a hash of the
cookie's secret. Anyone who holds the code without the cookie, from a shared
link, a copied URL or a log, gets `403` with `sso_browser_mismatch`, and the
code stays valid for the rest of its 60 seconds. A missing or expired cookie
gets the same answer. A successful exchange deletes the cookie.

A login must finish on the device that started it. If the callback link opens
on another device, the login page says "Start sign-in again from this browser."
and its button starts a new login there. Codes issued before this version carry
no binding and are refused the same way, so a login still waiting at the upgrade
starts again. Upgrade every server to this version in one step: stop the old
version, then start the new one, and do not run old and new servers side by
side.

## SSO account linking

An SSO login is matched to an account by the provider's stable identity, the
pair of issuer and subject (`sub`), which is stored in `user_identities` after
the first login. Later logins use only that pair, so a changed or unverified
`email` claim cannot redirect them to a different account.

The first login of a new subject needs a verified email: the ID token or
UserInfo response must carry `email_verified: true`. That email then either
links the existing account with the same address or, when its domain is in
`SSO_ALLOWED_DOMAINS`, provisions a new one. An account that is already linked
to a different subject at the same provider is never re-linked by email.

Linking an existing account removes its password, revokes all of its
refresh tokens and revokes every API key the account created before the link,
because whoever registered that address first may not be the person the
provider vouches for. The user signs in through the provider from then on.
Accounts created by SSO never had a password.

Existing SSO users have no link yet; their next login creates it, which needs
the verified email above. If your provider never sends `email_verified` (Azure
AD v2 does not by default) and its emails are controlled by your
administrators, set `SSO_ALLOW_UNVERIFIED_EMAIL=true` for that first login. The
server logs a warning at startup while it is on.

## 7. Backup and restore

Postgres holds all state; the server keeps nothing on disk. That includes a
random key the server makes the first time it reads a Gitleaks report. Gitleaks
findings are identified by a keyed hash of each credential, so the key keeps a
finding the same finding from one scan to the next without storing the
credential. It is in the dump, so a restore keeps every finding's identity.
Restoring only part of the database, or starting from an empty one, makes a new
key, and the next Gitleaks scan then opens new findings for secrets that are
still there. Dump in custom
format (`-Fc`): `pg_restore` can read it selectively and restores faster than
plain SQL. The `-T` flag turns off the TTY so the redirect gets clean binary:

```bash
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_dump -U specht -Fc specht > specht-$(date +%F).dump
```

A nightly cron entry that keeps 14 days of dumps. In a crontab, `%` must be
escaped as `\%`. Create the directory first with `mkdir -p /var/backups/specht`.

```cron
30 2 * * * cd /opt/specht && docker compose -f deploy/docker-compose.yml exec -T db pg_dump -U specht -Fc specht > /var/backups/specht/specht-$(date +\%F).dump && find /var/backups/specht -name 'specht-*.dump' -mtime +14 -delete
```

A dump on the same disk as the database protects against a bad migration or
a deleted row, not against losing the host. Copy each dump off the host in the
same job (for example `rsync` to another machine or `aws s3 cp` to a bucket),
and check that the copy arrived.

### Restore into an empty database

Restore with migrations off, so the server cannot touch the schema while the
dump loads. Set `DB_MIGRATE=false` in `deploy/.env.prod`, then start only the
database:

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d db
docker compose -f deploy/docker-compose.yml cp specht-YYYY-MM-DD.dump db:/tmp/specht.dump
docker compose -f deploy/docker-compose.yml exec db \
  pg_restore -U specht -d specht --no-owner /tmp/specht.dump
docker compose -f deploy/docker-compose.yml exec db rm /tmp/specht.dump
```

Read the `pg_restore` output for errors before you continue. Then remove
`DB_MIGRATE=false` (or set it back to `true`) and start the server normally.
Any migrations newer than the dump run at that start:

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d
curl -fsS http://localhost:8080/api/v1/ready
```

## 8. Upgrades

Migrations are forward-only and run when the server starts. A rollback
therefore depends on a backup taken before the upgrade, so take one first
(section 7).

1. Set `SPECHT_VERSION` in `deploy/.env.prod` to the new tag.
2. Pull the new image and recreate the server:

   ```bash
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod pull server
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env.prod up -d
   curl -fsS http://localhost:8080/api/v1/ready
   ```

   Pending migrations run before the new server takes traffic. Check
   `docker compose -f deploy/docker-compose.yml logs server` if `ready` does
   not answer 200.

   From a source checkout, add the override and `--build` instead of `pull`:
   `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.build.yml --env-file deploy/.env.prod up -d --build`.

Migration 54 (`users_email_proven`) adds a column to `users` and backfills it
for every account with an SSO identity, and it holds a lock on `users` until the
backfill ends. With 100,000 linked accounts that stalled reads for about 1.8
seconds in a test, and the pause grows with the number of SSO users, so operators
with many SSO accounts should expect a short pause on the first start of this
version or later.

Migration 58 (`finding_scope_severities`) adds a table that holds the severity each
scan scope last reported for a finding. It backfills the table in one pass over
`finding_occurrences`, so the first start after this version takes longer on installs
with many occurrences. The migration also rebuilds the check on `finding_events` to
allow the `severity_changed` event, which locks `finding_events` while the existing
rows are re-checked. It does not rewrite `findings.current_severity`. A finding that a
scan from another branch or scanner lowered before the upgrade keeps the lower value
until the next scan reports it again. That scan sets the highest severity across
scopes, so the gate can start blocking on the finding at that point.

Migration 59 (`sso_exchange_codes.browser_binding`) adds a column with a
constant default. PostgreSQL 11 and later add such a column without rewriting
the table, and the table holds only codes that expire within 60 seconds, so
there is nothing to back up. The down migration drops that column.

Every change is checked in CI by letting an earlier build fill a database through
its own API and starting the current build on it (`scripts/upgrade-smoke.sh`):
the account, project, scan, triage decision and API key must survive the
migrations. One thing the migrations cannot fix: an API key made by an early
preview build carries only the `ingest` scope and cannot read the gate. Create
a new key for those pipelines.

### Rolling back

An older server cannot read a schema that a newer migration changed, so a
rollback restores the pre-upgrade dump:

1. Stop the server and drop the database: `docker compose -f deploy/docker-compose.yml stop server`, then
   `docker compose -f deploy/docker-compose.yml exec db dropdb -U specht specht`
   and `... exec db createdb -U specht specht`.
2. Set `SPECHT_VERSION` back to the previous tag.
3. Follow the restore steps above with the pre-upgrade dump, then start the
   previous version.

## 9. Hardening checklist

- `RATE_LIMIT_ENABLED=true` (compose default) — strict per-IP buckets on
  unauthenticated routes, generous per-caller budgets behind auth. Login and
  register always get their own 5-per-minute per-client bucket, and repeated
  failed logins for one email slow that account down (see Rate limiting).
- Request bodies are size-capped; ingest rejects oversized scans with 413.
- `GET /api/v1/ready` answers 200 while the database is reachable and 503
  when it is not, with no detail in the body. The image's HEALTHCHECK uses it,
  and so should a load balancer or uptime monitor. `GET /api/v1/health` only
  says the process is up. Both are public, and readiness reuses its answer for
  one second so probing it cannot load the database.
- `LOG_LEVEL=info` (or `warn`); audit events go to structured logs. Every
  response carries an `X-Request-Id` header, and the access log line and any
  audit line for that request carry the same `request_id`, so a report that
  quotes the header leads straight to the log. The access log names the route
  pattern (`/api/v1/invites/{token}`), never the raw path or query, so tokens
  stay out of it; the health and readiness probes log at `debug`.
- Keep the image updated; rebuilds pull a fresh Alpine + `go mod` pins.
- Watcher (`WATCHER_ENABLE`) and SSO stay off unless configured.
- Database TLS: the compose default `POSTGRES_SSLMODE=disable` is for a
  database on the same host. For anything else set `require` or `verify-full`;
  at startup the server logs a warning when `DATABASE_URL` reaches a non-local
  host with `sslmode` of `disable`, `allow`, `prefer`, or unset.
