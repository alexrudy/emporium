# otool

Shared plumbing for small `axum` apps that sign users in with OAuth2 /
OIDC via [`oath::server`](../oath). It's what `ogateway` and `otunnel`
are built on: configuration types, app state, router assembly with
multi-provider support, a provider chooser page, and extractors for the
signed-in user.

## What's in it

| Item                                   | Purpose                                                              |
|----------------------------------------|----------------------------------------------------------------------|
| `config::ProvidersConfig`              | `[provider]` / `[providers.<id>]` / `default_provider` config        |
| `config::SessionsConfig`               | Cookie signing key and session TTL                                   |
| `state::AppState`                      | Router config, providers, in-memory session store                    |
| `build_router`                         | Resolve every provider (OIDC discovery) into an `OAuth2Router`       |
| `router_with_chooser`                  | `OAuth2Router` → `axum::Router`, plus a chooser at `{prefix}/login` |
| `auth::CurrentUser` / `OptionalCurrentUser` | Extractors for the signed-in `AppUser`                          |
| `user::AppUser`                        | `provider` + `username` (the OIDC `sub`); displays as `provider:sub` |

## Usage

Flatten the config types into your app's config:

```rust
#[derive(serde::Deserialize)]
struct Config {
    #[serde(default)]
    oath: oath::server::OAuth2RouterConfig,
    #[serde(flatten)]
    providers: otool::config::ProvidersConfig,
    #[serde(default)]
    sessions: otool::config::SessionsConfig,
}
```

Then build the state and router:

```rust
let state = otool::state::AppState::new(config.oath, config.providers, config.sessions);

let oauth = otool::build_router::<http::Uri>(&state).await?;
// Optionally: oauth = oauth.redirect(Arc::new(oath::server::XForwardedHeaders::new()));

let app = otool::router_with_chooser(oauth)
    .route("/", axum::routing::get(home))
    .with_state(state);

async fn home(otool::auth::OptionalCurrentUser(user): otool::auth::OptionalCurrentUser) -> String {
    match user {
        Some(user) => format!("hello, {user}"),
        None => "not signed in".into(),
    }
}
```

`CurrentUser` rejects with `401` when there's no valid session;
`OptionalCurrentUser` never rejects. To send unauthenticated users to
sign in and back, redirect them to
`state.oauth_router.with_return_to(&state.oauth_router.login_path(), Some(original_path))`.

## Configuration

```toml
[oath]
scopes = "openid email profile"   # default scopes for every provider
secure_cookies = true             # false only for http://localhost

# A single provider at /auth/login + /auth/callback.
[provider]
client_id = "my-app"
client_secret = "..."
provider_name = "Bastion"
external_origin = "https://app.example.com"
[provider.endpoints]
issuer = "https://idp.example.com"          # OIDC discovery
# or: auth_uri = "...", token_uri = "..."

# Additional providers at /auth/<id>/login + /auth/<id>/callback.
[providers.google]
client_id = "..."
client_secret = "..."
provider_name = "Google"
external_origin = "https://app.example.com"
scopes = "openid email"                      # optional override
[providers.google.endpoints]
issuer = "https://accounts.google.com"

# Which provider serves /auth/login (only without [provider], which
# always does). Without one, /auth/login lists every provider.
# default_provider = "google"

[sessions]
key = "<base64, at least 64 bytes>"          # openssl rand -base64 64
```

Every provider table accepts the same fields:

| Field                    | Default | Meaning                                                            |
|--------------------------|---------|--------------------------------------------------------------------|
| `client_id`              | —       | Required                                                           |
| `client_secret`          | none    | Omit for public clients                                            |
| `provider_name`          | —       | Display name on the chooser page                                   |
| `external_origin`        | none    | Public origin for the redirect URI (ignored if the app derives it per request) |
| `endpoints`              | —       | `issuer` for discovery, or `auth_uri` + `token_uri`                |
| `scopes`                 | `[oath] scopes` | Per-provider scope override                                |
| `skip_issuer_validation` | `false` | Don't check the ID token's `iss` (`aud` is still checked)          |
| `iss_parameter`          | `auto`  | RFC 9207 callback `iss`: `auto`, `required`, or `ignored`           |

Register `<origin>/auth/callback` with the `[provider]` provider and
`<origin>/auth/<id>/callback` with each `[providers.<id>]`. Provider ids
may contain ASCII letters, digits, `-`, and `_`.

Startup fails if no provider is configured, if `[providers.default]` is
combined with `[provider]` (they share the id `default`), if
`default_provider` names an unknown provider, or if it's combined with
`[provider]`.

## Limitations

- Sessions and users live in memory and are lost on restart.
- `AppUser` carries only the provider and `sub`; other claims aren't
  kept.
