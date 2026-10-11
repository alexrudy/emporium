# ogateway

An OAuth2 / OIDC authentication gateway for reverse proxies that support
"auth request" style sub-requests: Caddy's `forward_auth`, nginx's
`auth_request`, Traefik's `forwardAuth`, and similar. The proxy asks
ogateway whether each request is signed in; ogateway also serves the
login flow (`/auth/*`) itself. One gateway can protect several
hostnames and offer several identity providers.

Built on [`otool`](../otool) and [`oath::server`](../oath).

## How it works

```
Browser ──► proxy ──(GET /proxy/verify, original cookies)──► ogateway
               │   204 → serve the request
               │   403 → redirect to /auth/login?return_to=…
               └── /auth/* ───────────────────────────────► ogateway
```

- **`GET <verify_route>`** returns `204 No Content` if the request
  carries a valid session cookie, `403 Forbidden` otherwise. That's the
  contract nginx's `auth_request` expects (it only understands 2xx, 401,
  and 403).
- **`/auth/*`** is the login flow: `/auth/login` (default provider or a
  provider chooser), `/auth/<id>/login`, the callbacks, and
  `POST /auth/logout`. The proxy must route these to ogateway on every
  protected host.
- Session cookies are per host, so users sign in separately on each
  hostname.

## Running

```sh
ogateway --config config.toml            # listen on server.bind_addr
ogateway --config config.toml --systemd  # use a systemd-activated socket
```

Without `--config`, configuration is read from `OGATEWAY_*` environment
variables, which can only express top-level keys; anything with a
provider table needs a config file. With `--systemd`, ogateway serves
HTTP/1.1 on the first socket passed by systemd socket activation (e.g.
a Unix socket) instead of binding `server.bind_addr`.

## Configuration

See [`config.toml`](config.toml) for an annotated example. Provider,
`[oath]`, and `[sessions]` settings are the shared `otool` ones, see
[otool's README](../otool/README.md#configuration) for every field.
ogateway adds `[server]`:

```toml
[server]
bind_addr = "127.0.0.1:3030"   # default 127.0.0.1:0 (a random port)
verify_route = "/proxy/verify" # default "/verify"

# Where every provider's redirect URI origin comes from.
[server.origin]
kind = "x-forwarded"           # or "forwarded", "trusted-header", "fixed"
# default_scheme = "https"     # when no proto is forwarded
# header = "X-Gateway-Callback"  # trusted-header only
# origin = "https://gw.example.com"  # fixed only
```

| `kind`           | Reads                                                                |
|------------------|----------------------------------------------------------------------|
| `fixed`          | Nothing: one `origin` for every request, for a single-host gateway   |
| `x-forwarded`    | `X-Forwarded-Proto` / `-Host` / `-Port`, falling back to `Host` (what Caddy's `reverse_proxy` sends by default) |
| `forwarded`      | RFC 7239 `Forwarded`                                                 |
| `trusted-header` | A custom header holding `scheme://host` (a full URL works too; only scheme and host are used) |

`trusted_header = "X-Gateway-Callback"` under `[server]` is shorthand
for `kind = "trusted-header"`.

Each provider's origin has exactly one source, checked at startup:

- with `[server.origin]`, it applies to every provider, and any
  provider's `external_origin` is ignored (with a warning);
- without it, every provider must set `external_origin`, or startup
  fails.

Only use a header-based kind when ogateway is reachable exclusively
through the proxy, since those headers come from the request. With one
configured, register `https://<host>/auth/callback` (for `[provider]`)
or `https://<host>/auth/<id>/callback` (for `[providers.<id>]`) with
each provider for **every** host.

A provider whose setup fails at startup (e.g. OIDC discovery times out)
is logged and left out; the others keep working. See
[otool's README](../otool/README.md#provider-setup-failures).

## Proxy setup

### Caddy

[`Caddyfile`](Caddyfile) has a working local example and a reusable
`(gateway)` snippet:

```caddyfile
app.example.com {
    handle /auth/* {
        reverse_proxy unix//run/gateway/gateway.sock
    }

    handle {
        forward_auth unix//run/gateway/gateway.sock {
            uri /proxy/verify
            @error status 403
            handle_response @error {
                redir * {scheme}://{host}/auth/login?return_to={%uri}
            }
        }
        reverse_proxy localhost:8000   # the protected app
    }
}
```

The `handle` blocks matter: Caddy orders `forward_auth` before
`reverse_proxy`, so without them `/auth/*` would itself require a
session and nobody could sign in. `{%uri}` (Caddy 2.11+) is the
query-escaped request URI, so users land back where they started. With
`kind = "x-forwarded"`, no extra headers are needed.

### nginx

A sketch (not tested in this repo):

```nginx
location /auth/ {
    proxy_pass http://127.0.0.1:3030;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location = /_ogateway_verify {
    internal;
    proxy_pass http://127.0.0.1:3030/proxy/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host $host;
}

location / {
    auth_request /_ogateway_verify;
    error_page 403 = @login;
    proxy_pass http://127.0.0.1:8000;
}

location @login {
    return 302 $scheme://$host/auth/login;
}
```

nginx has no built-in way to URL-encode the original URI, so this
example doesn't pass `return_to`; users land on the login landing page
(`[oath] login_landing`, default `/`).

## Limitations

- Sessions are in memory: restarting ogateway signs everyone out.
- The verify endpoint only answers "signed in or not". It doesn't pass
  the user's identity to the upstream (e.g. as a header), and doesn't
  restrict which users or providers may access a host.
