# otunnel

A reverse proxy that requires an OAuth2 / OIDC sign-in before forwarding
requests to an upstream HTTP server. Useful for putting a login in front
of an internal service that has no authentication of its own.

Built on [`otool`](../otool) and [`oath::server`](../oath).

## How it works

- **`/auth/*`** is handled by otunnel itself: `/auth/login` (default
  provider or a provider chooser), `/auth/<id>/login`, the callbacks,
  and `POST /auth/logout`.
- **Everything else**, when the request carries a valid session, is
  forwarded to the upstream over HTTP/1.1, with:
  - hop-by-hop headers stripped and a `Via: otunnel` header added;
  - an `x-proxy-request-id` header (a fresh UUID);
  - connection upgrades (e.g. WebSockets) passed through.
- **Unauthenticated requests** are redirected to
  `/auth/login?return_to=<original path and query>`, so users come back
  where they started after signing in.

## Running

```sh
otunnel --config config.toml 127.0.0.1:8000
```

The positional argument is the upstream authority (`host:port`); requests
are sent to it over plain HTTP.

Configuration comes from the `--config` file (if given), overridden by
`OTUNNEL_*` environment variables, with `__` separating nested keys,
e.g. `OTUNNEL_PROVIDERS__GOOGLE__CLIENT_ID` or
`OTUNNEL_SERVER__BIND_ADDR`. See
[otool's README](../otool/README.md#environment-variables) for the
details.

## Configuration

See [`config.toml`](config.toml) for an annotated example. Provider,
`[oath]`, and `[sessions]` settings are the shared `otool` ones, see
[otool's README](../otool/README.md#configuration) for every field.
otunnel adds:

```toml
[server]
bind_addr = "127.0.0.1:3030"   # default 127.0.0.1:0 (a random port)
```

Redirect URIs come from each provider's `external_origin`, which should
be otunnel's public origin: register `<origin>/auth/callback` for
`[provider]` and `<origin>/auth/<id>/callback` for each
`[providers.<id>]`.

## Limitations

- Sessions are in memory: restarting otunnel signs everyone out.
- The user's identity isn't passed to the upstream, and any signed-in
  user from any configured provider is let through.
- The upstream is reached over plain HTTP only.
