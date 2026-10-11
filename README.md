# Emporium

Rust clients for various services and APIs

## OAuth2 / OIDC

| Crate                    | What it is                                                                 |
|--------------------------|----------------------------------------------------------------------------|
| [`oath`](oath)           | OAuth2 client library; the `server` feature adds a multi-provider `axum` login flow |
| [`otool`](otool)         | Shared config, state, and extractors for small apps built on `oath::server` |
| [`ogateway`](ogateway)   | Authentication gateway for proxy auth sub-requests (Caddy `forward_auth`, nginx `auth_request`) |
| [`otunnel`](otunnel)     | Reverse proxy that requires sign-in before forwarding to an upstream       |
| [`ott`](ott)             | OAuth Test Tool: a reference app for `oath::server`                        |
