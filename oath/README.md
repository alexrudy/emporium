# oath

An OAuth2 client built on top of the workspace `api-client` crate.

`oath` focuses on consuming OAuth2-protected APIs. It is not an
authorization server, an OIDC provider, or a session library — it
provides the protocol primitives and a refresh-aware HTTP wrapper that
fit between the user-agent redirect and the bearer header on the
outgoing API request.

## Layout

| Layer       | Type                                  | What it does                                                   |
|-------------|---------------------------------------|----------------------------------------------------------------|
| Protocol    | [`TokenEndpoint`]                     | POST grants to `/token`, parse the response                    |
| URL builder | [`AuthorizationUrl`] / [`PendingAuthorization`] | Build the auth redirect, persist + verify on callback |
| HTTP        | [`OAuth2Client`]                      | API client that refreshes the bearer proactively               |

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

## Security

- All token-bearing types wrap [`secret::Secret`]: they never appear in
  `Debug` output and are zeroed on drop.
- Authorization-code flows use PKCE (`S256` by default) with verifiers
  drawn from `OsRng`. `Plain` is exposed only for providers that demand
  it.
- `StateToken::verify` uses a constant-time compare to dodge timing
  oracles, even though state tokens are short-lived.
- `OAuth2Client` refreshes proactively: the `expires_at` check runs
  before each request, with a 60-second clock-drift offset built in.

## What's not in scope

`oath` v1 deliberately stops at the protocol boundary. The following
are explicit non-goals or punted features:

- **`id_token` signature verification.** `TokenResponse::id_token` is
  returned as a raw string. Consumers either trust the issuer through
  TLS or parse claims unverified; signed verification can land when a
  concrete consumer needs it.
- **OIDC discovery.** No `.well-known/openid-configuration` parsing yet
  — configure the URIs explicitly on the builder.
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
