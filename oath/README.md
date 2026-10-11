# oath

An OAuth2 client built on top of the workspace `api-client` crate.

`oath` focuses on consuming OAuth2-protected APIs. It is not an
authorization server or an OIDC provider. The core crate provides the
protocol primitives and a refresh-aware HTTP wrapper that fit between
the user-agent redirect and the bearer header on the outgoing API
request; the optional `server` feature adds an `axum` router that runs
the browser login flow against one or more providers.

## Layout

| Layer       | Type                                  | What it does                                                   |
|-------------|---------------------------------------|----------------------------------------------------------------|
| Protocol    | [`TokenEndpoint`]                     | POST grants to `/token`, parse the response                    |
| Discovery   | `ProviderMetadata`                    | Fetch `.well-known/openid-configuration`, configure an endpoint |
| URL builder | [`AuthorizationUrl`] / [`PendingAuthorization`] | Build the auth redirect, persist + verify on callback |
| HTTP        | [`OAuth2Client`]                      | API client that refreshes the bearer proactively               |
| Config      | `provider::OAuthProviderConfig`       | Serde-friendly provider description for app config files       |
| Login flow  | `server::OAuth2Router` (`server`)     | `axum` routes for login / callback / logout, multi-provider    |

## Supported grants

| Grant                                           | Builder                          | RFC          |
|-------------------------------------------------|----------------------------------|--------------|
| Client Credentials                              | `ClientCredentialsRequest`       | 6749 §4.4    |
| Authorization Code + PKCE                       | `AuthorizationCodeRequest`       | 6749, 7636   |
| Refresh Token                                   | `RefreshRequest`                 | 6749 §6      |
| Device Authorization                            | `DeviceCodeRequest`              | 8628         |

## Installation

```toml
[dependencies]
oath = { path = "../oath" }
```

Enable a TLS backend that matches the rest of your workspace:

```toml
[features]
tls-ring   = ["oath/tls-ring"]    # rustls + ring
tls-aws-lc = ["oath/tls-aws-lc"]  # rustls + aws-lc-rs
```

| Feature                | Adds                                                                 |
|------------------------|----------------------------------------------------------------------|
| `tls-ring` / `tls-aws-lc` | TLS backend for the default HTTP transport                        |
| `server`               | `oath::server`: the `axum` login-flow router, sessions, user stores |
| `json-file-user-store` | `server::JsonFileUserStore`, backed by a `storage` driver (use with `server`) |

## Examples

### Client Credentials (machine-to-machine)

```rust
use oath::{ClientCredentialsRequest, ScopeSet, TokenEndpoint};
use secret::Secret;

let endpoint = TokenEndpoint::builder()
    .client_id("svc-account")
    .client_secret(Secret::from(std::env::var("OAUTH_CLIENT_SECRET")?))
    .token_uri("https://provider.example.com/oauth/token".parse()?)
    .build()?;

let scope: ScopeSet = "read:things write:things".parse()?;
let response = endpoint
    .exchange(ClientCredentialsRequest::new().scope(scope))
    .await?;
```

### Authorization Code with PKCE

```rust
use oath::{AuthorizationUrl, PendingAuthorization, ScopeSet, TokenEndpoint};
use secret::Secret;

let endpoint = TokenEndpoint::builder()
    .client_id("my-app")
    .client_secret(Secret::from(std::env::var("OAUTH_CLIENT_SECRET")?))
    .auth_uri("https://provider.example.com/oauth/authorize".parse()?)
    .token_uri("https://provider.example.com/oauth/token".parse()?)
    .redirect_uri("https://app.example.com/auth/callback".parse()?)
    .build()?;

// /auth/login: build the redirect URL plus the bundle to persist.
let scopes: ScopeSet = "openid profile email".parse()?;
let (url, pending) = AuthorizationUrl::new(&endpoint)
    .scopes(scopes)
    .begin()?;

// Stash `pending` in your session store keyed by a short-lived cookie:
let stashed = serde_json::to_string(&pending)?;
// ... redirect the user to `url` ...

// /auth/callback: load `pending`, verify state, exchange the code.
let pending: PendingAuthorization = serde_json::from_str(&stashed)?;
let token_set = pending
    .complete(&endpoint, returned_state, returned_code)
    .await?;
```

`PendingAuthorization::complete` verifies the state token **before** any
network call. State mismatches return `CallbackError::StateMismatch`
without contacting the token endpoint.

### OIDC discovery

```rust
use oath::{ProviderMetadata, TokenEndpoint};

let issuer: http::Uri = "https://accounts.google.com".parse()?;
let metadata = ProviderMetadata::discover(&issuer).await?;

let endpoint = TokenEndpoint::builder()
    .from_metadata(&metadata)?          // endpoints, issuer, RFC 9207 support
    .client_id("my-app")
    .redirect_uri("https://app.example.com/auth/callback".parse()?)
    .build()?;
```

`from_metadata` records the issuer exactly as published (for `iss`
checks) and whether the provider advertises
`authorization_response_iss_parameter_supported`.
`provider::OAuthProviderConfig::provider(callback_path)` does all of this
from a config-file description of the provider.

### Refresh-aware API client

For long-lived consumers, wrap the endpoint and an initial `TokenSet` in
an `OAuth2Client`. The wrapper checks `expires_at` before every send
and refreshes if needed:

```rust
use oath::{OAuth2Client, TokenEndpoint, TokenSet};

let oauth = OAuth2Client::from_authorization_code(
    endpoint,
    "https://api.example.com/".parse()?,
    token_set,
)?;

// Reads like normal api-client code; refresh is automatic.
let widgets: Vec<Widget> = oauth
    .get("/widgets")
    .send()
    .await?
    .json()
    .await?;
```

Refresh state is single-mutex protected, so N concurrent calls on a
near-expired token collapse to one `/token` round-trip; the remaining
N-1 callers reuse the freshly-installed bearer.

### Device Authorization (CLI / headless)

```rust
use oath::{ScopeSet, TokenEndpoint};
use secret::Secret;

let endpoint = TokenEndpoint::builder()
    .client_id("my-cli")
    .token_uri("https://provider.example.com/oauth/token".parse()?)
    .device_uri("https://provider.example.com/oauth/device_authorization".parse()?)
    .build()?;

let scope: ScopeSet = "openid email".parse()?;
let auth = endpoint.start_device_flow(Some(scope)).await?;
println!("Visit {} and enter {}", auth.verification_uri, auth.user_code);

// Polls `interval` seconds apart, handling authorization_pending and
// slow_down per RFC 8628 §3.5. Returns when the user authorizes,
// rejects, or `expires_in` elapses.
let response = endpoint.poll_device_token(&auth).await?;
```

## Browser login flow (`server` feature)

`oath::server::OAuth2Router` assembles the protocol pieces into `axum`
routes, with signed cookies, a pluggable `SessionStore` and `UserStore`,
and an `IdentityResolver` that turns tokens into your user type.

```rust
use std::sync::Arc;

use oath::server::{
    IdentityResolver, Identity, InMemorySessionStore, OAuth2Router, OAuth2RouterConfig,
    Provider, ProviderId, XForwardedHeaders, parse_id_token,
};

let google: ProviderId = "google".parse()?;
let okta: ProviderId = "okta".parse()?;

// Each endpoint's redirect URI must point at its provider's callback,
// e.g. config.provider_callback_path(&google) == "/auth/google/callback".
let config = OAuth2RouterConfig::default();

let identity = IdentityResolver::new(|tokens| async move {
    let claims = parse_id_token(&tokens)?;
    Ok(Identity { username: claims.sub, data: MyUser { email: claims.email } })
});

let router: axum::Router = OAuth2Router::multi_provider(
    InMemorySessionStore::default(),
    my_user_store,                       // impl UserStore<Data = MyUser>
    identity,
    cookie::Key::generate(),
)
.config(config)
.provider(Provider::new(google.clone(), google_endpoint).with_display_name("Google"))
.provider(Provider::new(okta, okta_endpoint).with_scopes("openid groups".parse()?))
.default_provider(google)                // serves /auth/login
.redirect(Arc::new(XForwardedHeaders::new())) // optional: per-host redirect URIs
.into_router();
```

### Routes

| Route                              | Purpose                                                        |
|------------------------------------|----------------------------------------------------------------|
| `GET  {prefix}/{id}/login`         | Start a login with provider `id` (`?return_to=/path` optional) |
| `GET  {prefix}/{id}/callback`      | That provider's redirect URI                                   |
| `GET  {prefix}/login`              | Login with the default provider, if any (else unrouted)        |
| `POST {prefix}/logout`             | End the session                                                |

`{prefix}` defaults to `/auth`. A provider registered with
`OAuth2Router::new(endpoint, ...)` (or `Provider::root`) is mounted at
`{prefix}/login` and `{prefix}/callback` instead, so single-provider
apps keep their registered redirect URI and can add more providers
alongside it.

### Redirect URIs behind a proxy

To serve several hostnames, `.redirect(...)` takes an `ExtractRedirect`
that derives the public origin per request; the router appends the
provider's callback path and repeats the exact value at the code
exchange.

| Extractor            | Reads                                                     |
|----------------------|-----------------------------------------------------------|
| `http::Uri`          | A fixed origin                                            |
| `TrustedHeader`      | A custom header set by your proxy                         |
| `ForwardedHeader`    | RFC 7239 `Forwarded` (rightmost element)                  |
| `XForwardedHeaders`  | `X-Forwarded-Proto` / `-Host` / `-Port` (rightmost value) |

The header-based extractors trust the request, so only use them when the
server is reachable exclusively through a proxy that sets those headers.

### Callback checks

Before a session is created, the callback verifies, in order:

1. the RFC 9207 `iss` parameter, per the provider's `IssParameter`
   policy: `Auto` (checked when present, required when discovery
   advertises support), `Required`, or `Ignored` to opt out;
2. the single-use pre-auth session from the signed cookie;
3. that the callback arrived on the route of the provider the login
   started with (IdP mix-up defense);
4. the CSRF state, then the PKCE code exchange;
5. the ID token, if any: `aud` includes the client id, `azp` (if
   present) equals it, and `iss` equals the discovered issuer (opt out
   with `Provider::skip_issuer_validation`, e.g. for Entra's
   multi-tenant `common` endpoint);
6. the resolved username (no path separators, control characters, or
   `..`).

Users and sessions are keyed by `(provider, username)`, so the same
`sub` at two providers is two users. `JsonFileUserStore` stores the
root provider's users at `users/<username>.json` and other providers'
at `users/<provider>/<username>.json`.

`return_to` values must be same-origin paths outside the auth routes;
backslashes, whitespace, control characters, and dot segments are
rejected. Anything else falls back to the configured login landing
page. `OAuth2RouterConfig::with_return_to` builds links using the same
rules.

See the `oath::server` module docs for details, and `ott` for a
complete reference app.

## Security

- All token-bearing types wrap [`secret::Secret`]: they never appear in
  `Debug` output and are zeroed on drop.
- Authorization-code flows use PKCE (`S256` by default) with verifiers
  drawn from `SysRng`. `Plain` is exposed only for providers that demand
  it.
- `StateToken::verify` uses a constant-time compare to dodge timing
  oracles, even though state tokens are short-lived.
- `OAuth2Client` refreshes proactively: the `expires_at` check runs
  before each request, with a 60-second clock-drift offset built in.
- The `server` login flow binds each callback to the provider it was
  started with, checks the RFC 9207 `iss` parameter and the ID token's
  `iss` / `aud` / `azp`, and only follows same-origin `return_to`
  paths. See [Callback checks](#callback-checks).

## What's not in scope

`oath` v1 deliberately stops at the protocol boundary. The following
are explicit non-goals or punted features:

- **`id_token` signature verification.** `server::parse_id_token`
  decodes claims without checking the signature, and
  `server::validate_id_token` checks `iss` / `aud` / `azp` but not the
  signature, `exp`, or `nonce`. Tokens are trusted because they come
  straight from the token endpoint over TLS; JWKS-based verification can
  land when a concrete consumer needs it.
- **Durable sessions.** `server::InMemorySessionStore` is the only
  bundled `SessionStore`; sessions are lost on restart.
- **RP-initiated logout.** `POST {prefix}/logout` ends the local session
  only; it doesn't sign the user out at the provider.
- **Automatic 401 retry layer.** The proactive refresh wrapper handles
  normal expiry. Server-side revocation (admin actions, password
  changes) still surfaces as a 401; the caller can recover by invoking
  `OAuth2Client::refresh` and retrying. A tower layer that does this
  transparently has to grapple with non-replayable bodies (streaming
  uploads) and is deferred until that trade-off matters to a real
  consumer.
- **Persistent token storage.** The `ArcSwap<AccessToken>` inside
  `ApiClient` is in-memory only. Apps that want cross-restart
  persistence can wrap `OAuth2Client::refresh` and write the new
  `AccessToken` through to durable storage. A `refresh_hook` callback
  is a candidate v1.1 addition if two consumers want the same plumbing.
- **Auth-style auto-detection.** `ClientAuthStyle` is set explicitly on
  the builder. Most providers document which style they accept.
- **Clock-drift offset configuration.** The 60-second offset is
  hard-coded. Configurability is straightforward to add if a consumer
  has a high-latency token endpoint that needs more headroom.

## Layered design rationale

A few decisions worth surfacing:

- **`AccessToken` itself implements `api_client::Authentication`.** That
  way the existing `ArcSwap<A>` inside `ApiClient` is the only place
  the current bearer lives. Refresh is just an
  `ApiClient::refresh_auth` call from outside. This mirrors how
  `services/b2-client` handles its short-lived `B2Authorization`.
- **Refresh is proactive, not reactive.** OAuth2 servers tell us
  `expires_in` on every issuance. Checking it costs nothing; sending a
  request that we already know will 401 costs an extra round-trip
  *and* a body-streaming problem. So `OAuth2Client::send` calls
  `ensure_fresh().await?` before each request and skips the retry
  dance.
- **The strategy lives behind a `tokio::sync::Mutex`.** Refresh tokens
  can rotate on each exchange (RFC 6749 §6); the mutex both protects
  the mutable state and serializes refresh attempts so concurrent
  callers collapse to one `/token` round-trip.

[`TokenEndpoint`]: https://docs.rs/oath/latest/oath/struct.TokenEndpoint.html
[`AuthorizationUrl`]: https://docs.rs/oath/latest/oath/struct.AuthorizationUrl.html
[`PendingAuthorization`]: https://docs.rs/oath/latest/oath/struct.PendingAuthorization.html
[`OAuth2Client`]: https://docs.rs/oath/latest/oath/struct.OAuth2Client.html
[`secret::Secret`]: https://docs.rs/secret/latest/secret/struct.Secret.html
