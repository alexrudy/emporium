//! Environment-driven configuration.
//!
//! Loads everything needed to bring up the OAuth2 flow, the HTTP
//! listener, and the file-backed user store. Required vars produce a
//! clear error when absent; optional vars carry sensible defaults.

use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use camino::Utf8PathBuf;
use cookie::Key;
use eyre::{Context as _, eyre};
use http::Uri;
use oath::ScopeSet;
use secret::Secret;
use serde::Deserialize;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_DATA_DIR: &str = "./data";
const DEFAULT_SCOPES: &str = "openid email profile";
const DEFAULT_PROVIDER_NAME: &str = "OAuth";
const DEFAULT_EXTERNAL_ORIGIN: &str = "http://127.0.0.1:3000";

/// Resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP listener binds to.
    pub bind_addr: SocketAddr,
    /// Directory the [`storage::LocalDriver`] backing the
    /// `JsonFileUserStore` writes into.
    pub data_dir: Utf8PathBuf,
    /// Public origin the provider's redirect URI lives under.
    /// Combined with `/auth/callback` to form the redirect URI sent in
    /// the authorization request.
    pub external_origin: Uri,
    /// Display name shown on the "Sign in with X" button.
    pub provider_name: String,
    /// OAuth2 client id issued by the provider.
    pub client_id: String,
    /// OAuth2 client secret issued by the provider.
    pub client_secret: Secret,
    /// How to discover (or hard-code) the provider's endpoints.
    pub endpoints: ProviderEndpoints,
    /// Scopes requested at the authorization endpoint.
    pub scopes: ScopeSet,
    /// Key used to sign the pre-auth and session cookies.
    pub cookie_key: Key,
    /// Whether to set `Secure` on outgoing cookies. Turn `false` only
    /// for `http://localhost` development.
    pub secure_cookies: bool,
}

/// How ott resolves the provider's authorization, token, and (optional)
/// device endpoints. Either the operator supplies an `OAUTH_ISSUER`
/// (a discovery URL is derived from it and fetched at startup) or
/// they wire `OAUTH_AUTH_URI` and `OAUTH_TOKEN_URI` explicitly.
#[derive(Debug, Clone)]
pub enum ProviderEndpoints {
    /// Endpoints will be discovered from
    /// `<issuer>/.well-known/openid-configuration` at startup.
    Discover { issuer: Uri },
    /// Endpoints are pinned at config-load time.
    Explicit {
        /// `authorization_endpoint`.
        auth_uri: Uri,
        /// `token_endpoint`.
        token_uri: Uri,
    },
}

impl Config {
    /// Read configuration from process environment variables.
    pub fn from_env() -> eyre::Result<Self> {
        Self::from_provider(|key| env::var(key).ok())
    }

    /// Read configuration from a caller-supplied env provider.
    ///
    /// The provider returns `Some(value)` for set vars and `None` for
    /// unset ones. Tests use this to inject specific environments
    /// without touching the global env.
    pub fn from_provider<F>(get: F) -> eyre::Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let bind_addr = parse_env(&get, "BIND_ADDR", Some(DEFAULT_BIND_ADDR))?;
        let data_dir = get("DATA_DIR")
            .map(Utf8PathBuf::from)
            .unwrap_or_else(|| Utf8PathBuf::from(DEFAULT_DATA_DIR));

        let external_origin = parse_env(&get, "EXTERNAL_ORIGIN", Some(DEFAULT_EXTERNAL_ORIGIN))?;
        let provider_name = get("PROVIDER_NAME").unwrap_or_else(|| DEFAULT_PROVIDER_NAME.into());

        let client_id = require(&get, "OAUTH_CLIENT_ID")?;
        let client_secret = Secret::from(require(&get, "OAUTH_CLIENT_SECRET")?);
        let endpoints = ProviderEndpoints::from_provider(&get)?;

        let scopes_raw = get("OAUTH_SCOPES").unwrap_or_else(|| DEFAULT_SCOPES.into());
        let scopes: ScopeSet = scopes_raw
            .parse::<ScopeSet>()
            .map_err(|e| eyre!("{e}"))
            .with_context(|| format!("parsing env var OAUTH_SCOPES={scopes_raw:?}"))?;

        let cookie_key = load_cookie_key(&get)?;
        let secure_cookies = parse_env(&get, "SECURE_COOKIES", Some("true"))?;

        Ok(Self {
            bind_addr,
            data_dir,
            external_origin,
            provider_name,
            client_id,
            client_secret,
            endpoints,
            scopes,
            cookie_key,
            secure_cookies,
        })
    }
}

impl ProviderEndpoints {
    fn from_provider<F>(get: &F) -> eyre::Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let issuer = get("OAUTH_ISSUER");
        let auth = get("OAUTH_AUTH_URI");
        let token = get("OAUTH_TOKEN_URI");
        match (issuer, auth, token) {
            (Some(raw), _, _) => {
                let uri = parse_uri(&raw, "OAUTH_ISSUER")?;
                Ok(ProviderEndpoints::Discover { issuer: uri })
            }
            (None, Some(auth_raw), Some(token_raw)) => {
                let auth_uri = parse_uri(&auth_raw, "OAUTH_AUTH_URI")?;
                let token_uri = parse_uri(&token_raw, "OAUTH_TOKEN_URI")?;
                Ok(ProviderEndpoints::Explicit {
                    auth_uri,
                    token_uri,
                })
            }
            _ => Err(eyre!(
                "set OAUTH_ISSUER for `.well-known` discovery, \
                 or set both OAUTH_AUTH_URI and OAUTH_TOKEN_URI explicitly"
            )),
        }
    }
}

fn parse_uri(raw: &str, name: &str) -> eyre::Result<Uri> {
    raw.parse::<Uri>()
        .map_err(|source| eyre!("{source}"))
        .with_context(|| format!("parsing env var {name}={raw:?}"))
}

impl Config {
    /// Public redirect URI sent in the authorization request: the
    /// configured `external_origin` joined to `/auth/callback`.
    pub fn redirect_uri(&self) -> Uri {
        let base = self.external_origin.to_string();
        let trimmed = base.trim_end_matches('/');
        format!("{trimmed}/auth/callback")
            .parse()
            .expect("validated external_origin + known path is a valid Uri")
    }
}

fn require<F>(get: &F, key: &str) -> eyre::Result<String>
where
    F: Fn(&str) -> Option<String>,
{
    get(key).ok_or_else(|| eyre!("required env var {key} is not set"))
}

fn parse_env<F, T>(get: &F, key: &str, default: Option<&str>) -> eyre::Result<T>
where
    F: Fn(&str) -> Option<String>,
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let raw = match (get(key), default) {
        (Some(value), _) => value,
        (None, Some(d)) => d.to_owned(),
        (None, None) => return Err(eyre!("required env var {key} is not set")),
    };
    raw.parse::<T>()
        .map_err(|e| eyre!(e))
        .with_context(|| format!("parsing env var {key}={raw:?}"))
}

fn load_cookie_key<F>(get: &F) -> eyre::Result<Key>
where
    F: Fn(&str) -> Option<String>,
{
    let raw = require(get, "COOKIE_KEY")?;
    cookie_key_from_base64(&raw, "COOKIE_KEY")
}

fn cookie_key_from_base64(raw: &str, name: &str) -> eyre::Result<Key> {
    let bytes = BASE64_STANDARD
        .decode(raw.trim())
        .with_context(|| format!("{name} is not valid base64"))?;
    if bytes.len() < 64 {
        return Err(eyre!(
            "{name} decodes to {} bytes; need at least 64 (try `openssl rand -base64 64`)",
            bytes.len()
        ));
    }
    Ok(Key::from(&bytes))
}

// ─── TOML configuration ────────────────────────────────────────────────

/// Wire shape of the TOML file. Optional everywhere so the parser can
/// surface clear "missing field X" errors with the TOML path inline.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    oauth: RawOauth,
    #[serde(default)]
    cookies: RawCookies,
    #[serde(default)]
    server: RawServer,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOauth {
    client_id: Option<String>,
    client_secret: Option<String>,
    provider_name: Option<String>,
    scopes: Option<String>,
    issuer: Option<String>,
    auth_uri: Option<String>,
    token_uri: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCookies {
    key: Option<String>,
    secure: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    bind_addr: Option<String>,
    external_origin: Option<String>,
    data_dir: Option<String>,
}

impl Config {
    /// Load configuration from a TOML file at `path`.
    pub fn from_toml_path(path: &Path) -> eyre::Result<Self> {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        Self::from_toml_str(&body)
            .with_context(|| format!("parsing config file {}", path.display()))
    }

    /// Load configuration from an in-memory TOML string. The shape
    /// matches [`ott.toml.example`](../ott.toml.example).
    pub fn from_toml_str(input: &str) -> eyre::Result<Self> {
        let raw: RawConfig = toml::from_str(input).wrap_err("TOML syntax")?;
        raw.into_config()
    }
}

impl RawConfig {
    fn into_config(self) -> eyre::Result<Config> {
        let RawConfig {
            oauth,
            cookies,
            server,
        } = self;

        let client_id = oauth
            .client_id
            .ok_or_else(|| eyre!("missing required field `oauth.client_id`"))?;
        let client_secret = Secret::from(
            oauth
                .client_secret
                .ok_or_else(|| eyre!("missing required field `oauth.client_secret`"))?,
        );

        let endpoints = match (oauth.issuer, oauth.auth_uri, oauth.token_uri) {
            (Some(raw), _, _) => ProviderEndpoints::Discover {
                issuer: parse_uri(&raw, "oauth.issuer")?,
            },
            (None, Some(auth_raw), Some(token_raw)) => ProviderEndpoints::Explicit {
                auth_uri: parse_uri(&auth_raw, "oauth.auth_uri")?,
                token_uri: parse_uri(&token_raw, "oauth.token_uri")?,
            },
            _ => {
                return Err(eyre!(
                    "set `oauth.issuer` for `.well-known` discovery, \
                     or set both `oauth.auth_uri` and `oauth.token_uri` explicitly"
                ));
            }
        };

        let provider_name = oauth
            .provider_name
            .unwrap_or_else(|| DEFAULT_PROVIDER_NAME.into());
        let scopes_raw = oauth.scopes.unwrap_or_else(|| DEFAULT_SCOPES.into());
        let scopes: ScopeSet = scopes_raw
            .parse::<ScopeSet>()
            .map_err(|e| eyre!("{e}"))
            .with_context(|| format!("parsing field `oauth.scopes`={scopes_raw:?}"))?;

        let cookie_key_raw = cookies
            .key
            .ok_or_else(|| eyre!("missing required field `cookies.key`"))?;
        let cookie_key = cookie_key_from_base64(&cookie_key_raw, "cookies.key")?;
        let secure_cookies = cookies.secure.unwrap_or(true);

        let bind_addr: SocketAddr = parse_or_default(
            server.bind_addr.as_deref(),
            DEFAULT_BIND_ADDR,
            "server.bind_addr",
        )?;
        let external_origin: Uri = parse_or_default(
            server.external_origin.as_deref(),
            DEFAULT_EXTERNAL_ORIGIN,
            "server.external_origin",
        )?;
        let data_dir = server
            .data_dir
            .map(Utf8PathBuf::from)
            .unwrap_or_else(|| Utf8PathBuf::from(DEFAULT_DATA_DIR));

        Ok(Config {
            bind_addr,
            data_dir,
            external_origin,
            provider_name,
            client_id,
            client_secret,
            endpoints,
            scopes,
            cookie_key,
            secure_cookies,
        })
    }
}

fn parse_or_default<T>(value: Option<&str>, default: &str, name: &str) -> eyre::Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let raw = value.unwrap_or(default);
    raw.parse::<T>()
        .map_err(|e| eyre!(e))
        .with_context(|| format!("parsing field `{name}`={raw:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn provider(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key| map.get(key).cloned()
    }

    /// 64 random-ish bytes, base64-encoded — enough to satisfy
    /// `cookie::Key::from`. Don't reuse outside tests.
    fn test_cookie_key() -> String {
        BASE64_STANDARD.encode([0x42u8; 64])
    }

    fn minimal_env() -> Vec<(&'static str, String)> {
        vec![
            ("OAUTH_CLIENT_ID", "client".to_owned()),
            ("OAUTH_CLIENT_SECRET", "secret".to_owned()),
            (
                "OAUTH_AUTH_URI",
                "https://accounts.example.com/authorize".to_owned(),
            ),
            (
                "OAUTH_TOKEN_URI",
                "https://accounts.example.com/token".to_owned(),
            ),
            ("COOKIE_KEY", test_cookie_key()),
        ]
    }

    fn with_env(extra: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
        let mut env = minimal_env();
        for (k, v) in extra {
            // Replace if already present.
            if let Some(slot) = env.iter_mut().find(|(name, _)| name == k) {
                slot.1 = (*v).to_owned();
            } else {
                env.push((k, (*v).to_owned()));
            }
        }
        env
    }

    fn build(env: Vec<(&'static str, String)>) -> eyre::Result<Config> {
        let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        Config::from_provider(provider(&pairs))
    }

    #[test]
    fn loads_minimal_required_env() {
        let cfg = build(minimal_env()).expect("minimal env should load");
        assert_eq!(cfg.client_id, "client");
        assert_eq!(cfg.client_secret.revealed(), "secret");
        match cfg.endpoints {
            ProviderEndpoints::Explicit {
                auth_uri,
                token_uri,
            } => {
                assert_eq!(
                    auth_uri.to_string(),
                    "https://accounts.example.com/authorize"
                );
                assert_eq!(token_uri.to_string(), "https://accounts.example.com/token");
            }
            ProviderEndpoints::Discover { .. } => panic!("expected Explicit endpoints"),
        }
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:3000");
        assert_eq!(cfg.data_dir, Utf8PathBuf::from("./data"));
        assert_eq!(cfg.provider_name, "OAuth");
        assert_eq!(cfg.scopes.to_string(), "openid email profile");
        assert!(cfg.secure_cookies);
    }

    #[test]
    fn oauth_issuer_selects_discovery_mode() {
        // OAUTH_ISSUER alone is enough; explicit URIs aren't required.
        let mut env: Vec<(&'static str, String)> = vec![
            ("OAUTH_CLIENT_ID", "client".to_owned()),
            ("OAUTH_CLIENT_SECRET", "secret".to_owned()),
            ("OAUTH_ISSUER", "https://accounts.example.com".to_owned()),
            ("COOKIE_KEY", test_cookie_key()),
        ];
        let pairs: Vec<(&str, &str)> = env.iter_mut().map(|(k, v)| (*k, v.as_str())).collect();
        let cfg = Config::from_provider(provider(&pairs)).expect("issuer mode loads");
        match cfg.endpoints {
            ProviderEndpoints::Discover { issuer } => {
                // http::Uri normalizes by adding a trailing slash to
                // the authority — accept either form.
                let s = issuer.to_string();
                assert!(
                    s == "https://accounts.example.com" || s == "https://accounts.example.com/",
                    "unexpected issuer normalization: {s}",
                );
            }
            ProviderEndpoints::Explicit { .. } => panic!("expected Discover endpoints"),
        }
    }

    #[test]
    fn oauth_issuer_wins_over_explicit_uris() {
        // If both are set, OAUTH_ISSUER takes precedence.
        let env = with_env(&[("OAUTH_ISSUER", "https://accounts.example.com")]);
        let cfg = build(env).unwrap();
        assert!(matches!(cfg.endpoints, ProviderEndpoints::Discover { .. }));
    }

    #[test]
    fn no_endpoints_at_all_errors() {
        let env: Vec<(&'static str, String)> = vec![
            ("OAUTH_CLIENT_ID", "client".to_owned()),
            ("OAUTH_CLIENT_SECRET", "secret".to_owned()),
            ("COOKIE_KEY", test_cookie_key()),
        ];
        let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let err = Config::from_provider(provider(&pairs)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("OAUTH_ISSUER") && msg.contains("OAUTH_AUTH_URI"),
            "error must point at both options: {msg}",
        );
    }

    #[test]
    fn only_auth_uri_without_token_uri_errors() {
        let mut env = minimal_env();
        env.retain(|(k, _)| *k != "OAUTH_TOKEN_URI");
        let err = build(env).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("OAUTH_ISSUER") || msg.contains("OAUTH_TOKEN_URI"));
    }

    #[test]
    fn missing_client_id_errors() {
        let mut env = minimal_env();
        env.retain(|(k, _)| *k != "OAUTH_CLIENT_ID");
        let err = build(env).unwrap_err();
        assert!(
            format!("{err:#}").contains("OAUTH_CLIENT_ID"),
            "error must name the missing var",
        );
    }

    #[test]
    fn missing_cookie_key_errors() {
        let mut env = minimal_env();
        env.retain(|(k, _)| *k != "COOKIE_KEY");
        let err = build(env).unwrap_err();
        assert!(format!("{err:#}").contains("COOKIE_KEY"));
    }

    #[test]
    fn malformed_auth_uri_errors() {
        let env = with_env(&[("OAUTH_AUTH_URI", "not a uri")]);
        let err = build(env).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("OAUTH_AUTH_URI"), "msg: {msg}");
    }

    #[test]
    fn malformed_bind_addr_errors() {
        let env = with_env(&[("BIND_ADDR", "not-a-socket")]);
        let err = build(env).unwrap_err();
        assert!(format!("{err:#}").contains("BIND_ADDR"));
    }

    #[test]
    fn cookie_key_not_base64_errors() {
        let env = with_env(&[("COOKIE_KEY", "*** not base64 ***")]);
        let err = build(env).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("COOKIE_KEY"), "msg: {msg}");
    }

    #[test]
    fn cookie_key_too_short_errors() {
        let short = BASE64_STANDARD.encode([0u8; 32]);
        let env = with_env(&[("COOKIE_KEY", &short)]);
        let err = build(env).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("64"),
            "error must mention the 64-byte minimum: {msg}",
        );
    }

    #[test]
    fn redirect_uri_uses_external_origin() {
        let env = with_env(&[("EXTERNAL_ORIGIN", "https://app.example.com")]);
        let cfg = build(env).unwrap();
        assert_eq!(
            cfg.redirect_uri().to_string(),
            "https://app.example.com/auth/callback",
        );
    }

    #[test]
    fn redirect_uri_strips_trailing_slash() {
        let env = with_env(&[("EXTERNAL_ORIGIN", "https://app.example.com/")]);
        let cfg = build(env).unwrap();
        assert_eq!(
            cfg.redirect_uri().to_string(),
            "https://app.example.com/auth/callback",
        );
    }

    #[test]
    fn scopes_parse_from_env() {
        let env = with_env(&[("OAUTH_SCOPES", "openid email")]);
        let cfg = build(env).unwrap();
        assert_eq!(cfg.scopes.to_string(), "openid email");
    }

    #[test]
    fn secure_cookies_overridable() {
        let env = with_env(&[("SECURE_COOKIES", "false")]);
        let cfg = build(env).unwrap();
        assert!(!cfg.secure_cookies);
    }

    // ─── TOML loader tests ─────────────────────────────────────────

    fn minimal_toml() -> String {
        let key = test_cookie_key();
        format!(
            r#"
                [oauth]
                client_id = "client"
                client_secret = "secret"
                issuer = "https://accounts.example.com"

                [cookies]
                key = "{key}"
            "#,
        )
    }

    #[test]
    fn toml_loads_minimal_config() {
        let cfg = Config::from_toml_str(&minimal_toml()).expect("minimal TOML loads");
        assert_eq!(cfg.client_id, "client");
        assert_eq!(cfg.client_secret.revealed(), "secret");
        assert!(matches!(cfg.endpoints, ProviderEndpoints::Discover { .. }));
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:3000");
        assert_eq!(cfg.data_dir, Utf8PathBuf::from("./data"));
        assert_eq!(cfg.provider_name, "OAuth");
        assert_eq!(cfg.scopes.to_string(), "openid email profile");
        assert!(cfg.secure_cookies);
    }

    #[test]
    fn toml_supports_explicit_endpoints() {
        let key = test_cookie_key();
        let body = format!(
            r#"
                [oauth]
                client_id = "client"
                client_secret = "secret"
                auth_uri = "https://accounts.example.com/authorize"
                token_uri = "https://accounts.example.com/token"

                [cookies]
                key = "{key}"
            "#,
        );
        let cfg = Config::from_toml_str(&body).unwrap();
        match cfg.endpoints {
            ProviderEndpoints::Explicit {
                auth_uri,
                token_uri,
            } => {
                assert_eq!(
                    auth_uri.to_string(),
                    "https://accounts.example.com/authorize"
                );
                assert_eq!(token_uri.to_string(), "https://accounts.example.com/token");
            }
            ProviderEndpoints::Discover { .. } => panic!("expected Explicit endpoints"),
        }
    }

    #[test]
    fn toml_missing_client_id_errors() {
        let key = test_cookie_key();
        let body = format!(
            r#"
                [oauth]
                client_secret = "secret"
                issuer = "https://accounts.example.com"

                [cookies]
                key = "{key}"
            "#,
        );
        let err = Config::from_toml_str(&body).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("oauth.client_id"), "msg: {msg}");
    }

    #[test]
    fn toml_missing_endpoints_errors() {
        let key = test_cookie_key();
        let body = format!(
            r#"
                [oauth]
                client_id = "client"
                client_secret = "secret"

                [cookies]
                key = "{key}"
            "#,
        );
        let err = Config::from_toml_str(&body).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("oauth.issuer"), "msg: {msg}");
        assert!(msg.contains("oauth.auth_uri"), "msg: {msg}");
    }

    #[test]
    fn toml_cookie_key_too_short_errors() {
        let short = BASE64_STANDARD.encode([0u8; 32]);
        let body = format!(
            r#"
                [oauth]
                client_id = "client"
                client_secret = "secret"
                issuer = "https://accounts.example.com"

                [cookies]
                key = "{short}"
            "#,
        );
        let err = Config::from_toml_str(&body).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cookies.key"), "msg: {msg}");
        assert!(msg.contains("64"), "msg: {msg}");
    }

    #[test]
    fn toml_rejects_unknown_field() {
        let body = r#"
            [oauth]
            client_id = "c"
            client_secret = "s"
            issuer = "https://x"
            nonsense = "stranger"

            [cookies]
            key = "irrelevant"
        "#;
        let err = Config::from_toml_str(body).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nonsense"), "msg: {msg}");
    }

    #[test]
    fn toml_invalid_syntax_errors() {
        let err = Config::from_toml_str("not = valid = toml").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("TOML"), "msg: {msg}");
    }

    #[test]
    fn toml_optional_fields_honored() {
        let key = test_cookie_key();
        let body = format!(
            r#"
                [oauth]
                client_id = "c"
                client_secret = "s"
                provider_name = "Acme"
                scopes = "openid"
                issuer = "https://x"

                [cookies]
                key = "{key}"
                secure = false

                [server]
                bind_addr = "0.0.0.0:9000"
                external_origin = "https://app.example.com"
                data_dir = "/var/lib/ott"
            "#,
        );
        let cfg = Config::from_toml_str(&body).unwrap();
        assert_eq!(cfg.provider_name, "Acme");
        assert_eq!(cfg.scopes.to_string(), "openid");
        assert_eq!(cfg.bind_addr.to_string(), "0.0.0.0:9000");
        assert_eq!(cfg.external_origin.to_string(), "https://app.example.com/",);
        assert_eq!(cfg.data_dir, Utf8PathBuf::from("/var/lib/ott"));
        assert!(!cfg.secure_cookies);
    }
}
