# ott — OAuth Test Tool

A small axum web app that exercises the `oath` crate end-to-end. It
serves a "Sign in" page, walks you through an OIDC provider, and
shows the resulting user record on a profile page.

```
  ┌─────────┐    GET /          ┌──────────┐    GET /auth/login    ┌──────────┐
  │ Browser │ ───────────────►  │   ott    │ ────────────────────► │ Provider │
  │         │ ◄────────────────  │          │ ◄──── callback ────── │          │
  └─────────┘    /profile        └──────────┘                       └──────────┘
                                       │
                                       └── writes users/<sub>.json (LocalDriver)
```

## Quick start (Google, discovery mode)

ott can discover the provider's endpoints from its
`.well-known/openid-configuration` document — set `OAUTH_ISSUER` and
the explicit URLs go away.

1. Visit https://console.cloud.google.com/apis/credentials, create an
   OAuth 2.0 Client ID of type **Web application**.
2. Add an authorized redirect URI:
   `http://127.0.0.1:3000/auth/callback`.
3. Copy the client id and secret.
4. Generate a cookie key:
   ```sh
   openssl rand -base64 64 | tr -d '\n'
   ```
5. Run ott:
   ```sh
   export OAUTH_CLIENT_ID="<your client id>"
   export OAUTH_CLIENT_SECRET="<your client secret>"
   export OAUTH_ISSUER="https://accounts.google.com"
   export COOKIE_KEY="<the openssl output>"
   export SECURE_COOKIES=false           # http://localhost is not https
   export PROVIDER_NAME="Google"
   cargo run -p ott
   ```
6. Open http://127.0.0.1:3000 in a browser, click **Sign in with
   Google**, complete the consent screen. ott will redirect to
   `/profile` and show the JSON record it persisted.

The discovery fetch happens once, at startup; the resolved
`token_endpoint` and `authorization_endpoint` are logged. If a
provider doesn't publish a discovery document, pin the URLs by hand:
set `OAUTH_AUTH_URI` and `OAUTH_TOKEN_URI` instead of `OAUTH_ISSUER`.

## Quick start (Okta)

1. Sign up for a free developer org at
   https://developer.okta.com/signup/.
2. Create a new **Web** application. Set the **Sign-in redirect URI**
   to `http://127.0.0.1:3000/auth/callback`.
3. Note the **Client ID** and **Client secret**. Either set
   `OAUTH_ISSUER=https://<org>.okta.com/oauth2/default` (discovery
   mode, recommended) or pin the URLs directly:
   - `OAUTH_AUTH_URI`  = `https://<org>.okta.com/oauth2/default/v1/authorize`
   - `OAUTH_TOKEN_URI` = `https://<org>.okta.com/oauth2/default/v1/token`
4. Run ott with those env vars and a fresh `COOKIE_KEY`.

## Manual test plan

After signing in once, you should see:

- `users/<sub>.json` exists under `DATA_DIR` (defaults to `./data/`).
- The profile page shows `Subject`, `Email`, `verified` badge, the
  timestamps, and a pretty-printed JSON of the stored record.
- Clicking **Sign out** redirects to `/`, deletes the in-memory
  session, and clears the `oath_session` cookie.
- Signing in again updates `last_login_at` (and currently
  `created_at` — see "Known issues" below).

## Configuration

ott reads its config from one of two sources, in priority order:

1. **A TOML file**, when either `--config <path>` (or `-c <path>`) is
   passed on the CLI, or `OTT_CONFIG=<path>` is set in the environment.
   See [`ott.toml.example`](ott.toml.example) for the schema; unknown
   keys are rejected so typos surface at startup.
2. **Process environment variables** when no TOML path is provided.
   See [`.env.example`](.env.example) for the variable list.

The two sources are not mixed — either you point ott at a TOML file and
everything comes from there, or you set env vars and nothing else. Pick
based on your deployment style.

### Environment variables

| Var                   | Required | Default                       |
|-----------------------|----------|-------------------------------|
| `OAUTH_CLIENT_ID`     | yes      | —                             |
| `OAUTH_CLIENT_SECRET` | yes      | —                             |
| `OAUTH_ISSUER`        | one of   | —                             |
| `OAUTH_AUTH_URI`      | one of   | —                             |
| `OAUTH_TOKEN_URI`     | one of   | —                             |
| `COOKIE_KEY`          | yes      | — (base64, ≥64 bytes)         |
| `OAUTH_SCOPES`        | no       | `openid email profile`        |
| `PROVIDER_NAME`       | no       | `OAuth`                       |
| `EXTERNAL_ORIGIN`     | no       | `http://127.0.0.1:3000`       |
| `BIND_ADDR`           | no       | `127.0.0.1:3000`              |
| `DATA_DIR`            | no       | `./data`                      |
| `SECURE_COOKIES`      | no       | `true`                        |
| `RUST_LOG`            | no       | `info,ott=debug,tower_http=info` |

**Endpoint resolution.** Set *either* `OAUTH_ISSUER` (discovery —
ott fetches `<issuer>/.well-known/openid-configuration` at startup
and uses the `authorization_endpoint`, `token_endpoint`, and any
`device_authorization_endpoint` it finds), *or* both
`OAUTH_AUTH_URI` and `OAUTH_TOKEN_URI` explicitly. If both are set,
`OAUTH_ISSUER` wins.

The redirect URI registered with the provider must exactly match
`{EXTERNAL_ORIGIN}/auth/callback`. ott prints both the configured
provider and the resolved callback URL on startup; cross-check those
against the provider console if a callback comes back with
`redirect_uri_mismatch`.

## Architecture

- `src/config.rs` — env loader for everything above.
- `src/user.rs` — `AppUser` schema + the default identity resolver
  (parses the OIDC `id_token` claims, no signature verification).
- `src/templates.rs` — minijinja environment with three templates
  baked in via `include_str!`.
- `src/state.rs` — `AppState` cloned into every handler.
- `src/auth.rs` — `CurrentUser` / `OptionalCurrentUser` axum
  extractors. They read the signed `oath_session` cookie, hit the
  session store, then the user store; missing/invalid → `Redirect::to("/")`.
- `src/handlers.rs` — three handlers (home, profile, healthz).
- `src/main.rs` — assembles the `OAuth2Router` from `oath::server`,
  merges it with ott's own routes, applies `TraceLayer`, and serves.
- `templates/` — Jinja templates extending one Bootstrap-themed base.

The OAuth flow itself lives in `oath::server` — see `oath/README.md`
for the per-grant breakdown.

## Known issues / limitations

- **`created_at` is overwritten on every login.** The identity
  resolver doesn't (yet) look up the existing user before writing.
  Planned Phase C polish.
- **Sessions evaporate on restart.** `InMemorySessionStore` is exactly
  what it says on the tin. Swap in a durable `SessionStore`
  implementation for any real deployment.
- **Templates are baked into the binary.** During development, swap
  the `include_str!`s for `minijinja::path_loader` to hot-reload
  changes.
- **Only OIDC providers are supported.** The default identity resolver
  parses the `id_token`, which non-OIDC providers like GitHub don't
  issue. Adding a `/userinfo`-based resolver is straightforward; see
  `ott/PLAN.md` open question #3.

## Development

```sh
cargo test  -p ott    # 13 unit tests covering config parse + template render
cargo clippy -p ott --all-targets -- -D warnings
cargo run   -p ott    # with env vars set as above
```
