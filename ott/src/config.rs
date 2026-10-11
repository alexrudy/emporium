//! Environment- or TOML-driven configuration.
//!
//! Loads everything needed to bring up the OAuth2 flow, the HTTP
//! listener, and the file-backed user store. Required vars produce a
//! clear error when absent; optional vars carry sensible defaults.
//!
//! Providers come in two flavours:
//!
//! - the original single provider (`[oauth]` / `OAUTH_*`), mounted at
//!   `/auth/login` and `/auth/callback` so existing redirect URIs keep
//!   working;
//! - any number of named providers (`[providers.<id>]` /
//!   `OAUTH_PROVIDERS` + `OAUTH_<ID>_*`), mounted at `/auth/<id>/login`
//!   and `/auth/<id>/callback`.

use std::collections::BTreeMap;
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
use oath::server::ProviderId;
use oath::{
    ScopeSet,
    provider::{IssParameter, OAuthProviderConfig, ProviderEndpoints, parse_configured_uri},
};
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
    /// Public origin the providers' redirect URIs live under.
    pub external_origin: Uri,
    /// Scopes requested from every provider that doesn't override them.
    pub scopes: ScopeSet,
    /// The original single provider, mounted at `/auth/login` and
    /// `/auth/callback`.
    pub root_provider: Option<OAuthProviderConfig>,
    /// Named providers, mounted at `/auth/<id>/login` and
    /// `/auth/<id>/callback`.
    pub providers: BTreeMap<ProviderId, OAuthProviderConfig>,
    /// Which named provider serves `/auth/login` when there's no root
    /// provider.
    pub default_provider: Option<ProviderId>,
    /// Key used to sign the pre-auth and session cookies.
    pub cookie_key: Key,
    /// Whether to set `Secure` on outgoing cookies. Turn `false` only
    /// for `http://localhost` development.
    pub secure_cookies: bool,
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

        let external_origin: Uri =
            parse_env(&get, "EXTERNAL_ORIGIN", Some(DEFAULT_EXTERNAL_ORIGIN))?;

        let scopes_raw = get("OAUTH_SCOPES").unwrap_or_else(|| DEFAULT_SCOPES.into());
        let scopes = parse_scopes(&scopes_raw, "env var OAUTH_SCOPES")?;

        let provider_ids = match get("OAUTH_PROVIDERS") {
            Some(raw) => parse_provider_list(&raw)?,
            None => Vec::new(),
        };

        // The root provider is configured by the unprefixed OAUTH_* vars.
        // It's required when no named providers are listed, so a bare
        // environment still reports the missing OAUTH_CLIENT_ID.
        let root_provider = if get("OAUTH_CLIENT_ID").is_some() || provider_ids.is_empty() {
            Some(env_provider(&get, None, &external_origin)?)
        } else {
            None
        };

        let mut providers = BTreeMap::new();
        for id in provider_ids {
            let provider = env_provider(&get, Some(&id), &external_origin)?;
            providers.insert(id, provider);
        }

        let default_provider = get("OAUTH_DEFAULT_PROVIDER")
            .map(|raw| {
                ProviderId::new(raw.trim()).wrap_err("parsing env var OAUTH_DEFAULT_PROVIDER")
            })
            .transpose()?;

        let cookie_key = load_cookie_key(&get)?;
        let secure_cookies = parse_env(&get, "SECURE_COOKIES", Some("true"))?;

        let config = Self {
            bind_addr,
            data_dir,
            external_origin,
            scopes,
            root_provider,
            providers,
            default_provider,
            cookie_key,
            secure_cookies,
        };
        config.validate()?;
        Ok(config)
    }
}

impl Config {
    /// Public URL for a route path, e.g. a provider's callback.
    pub fn public_uri(&self, path: &str) -> Uri {
        let base = self.external_origin.to_string();
        let trimmed = base.trim_end_matches('/');
        format!("{trimmed}{path}")
            .parse()
            .expect("validated external_origin + route path is a valid Uri")
    }

    fn validate(&self) -> eyre::Result<()> {
        if self.root_provider.is_none() && self.providers.is_empty() {
            return Err(eyre!("no OAuth providers configured"));
        }
        let root = ProviderId::default();
        if self.root_provider.is_some() && self.providers.contains_key(&root) {
            return Err(eyre!(
                "provider id {root:?} is reserved for the single [oauth] / OAUTH_* provider"
            ));
        }
        if let Some(default) = &self.default_provider {
            if self.root_provider.is_some() {
                return Err(eyre!(
                    "default provider {default:?} conflicts with the single [oauth] / OAUTH_* \
                     provider, which always serves /auth/login"
                ));
            }
            if !self.providers.contains_key(default) {
                return Err(eyre!(
                    "default provider {default:?} is not a configured provider"
                ));
            }
        }
        Ok(())
    }
}

/// Parse `OAUTH_PROVIDERS`, a comma-separated list of provider ids.
fn parse_provider_list(raw: &str) -> eyre::Result<Vec<ProviderId>> {
    let mut ids: Vec<ProviderId> = Vec::new();
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let id = ProviderId::new(item).wrap_err("parsing env var OAUTH_PROVIDERS")?;
        if let Some(clash) = ids
            .iter()
            .find(|other| env_segment(other) == env_segment(&id))
        {
            return Err(eyre!(
                "OAUTH_PROVIDERS: providers {clash:?} and {id:?} would share OAUTH_{}_* env vars",
                env_segment(&id)
            ));
        }
        ids.push(id);
    }
    Ok(ids)
}

/// `my-idp` → `MY_IDP`, for `OAUTH_MY_IDP_CLIENT_ID` etc.
fn env_segment(id: &ProviderId) -> String {
    id.as_str().to_ascii_uppercase().replace('-', "_")
}

/// Read one provider's env vars: `OAUTH_<SUFFIX>` for the root provider,
/// `OAUTH_<ID>_<SUFFIX>` for a named one.
fn env_provider<F>(
    get: &F,
    id: Option<&ProviderId>,
    external_origin: &Uri,
) -> eyre::Result<OAuthProviderConfig>
where
    F: Fn(&str) -> Option<String>,
{
    let var = |suffix: &str| match id {
        None => format!("OAUTH_{suffix}"),
        Some(id) => format!("OAUTH_{}_{suffix}", env_segment(id)),
    };

    let client_id = require(get, &var("CLIENT_ID"))?;
    let client_secret = Secret::from(require(get, &var("CLIENT_SECRET"))?);

    let endpoints = match id {
        None => ProviderEndpoints::from_provider(get)?,
        Some(_) => {
            let prefixed = |key: &str| get(&var(key.trim_start_matches("OAUTH_")));
            ProviderEndpoints::from_provider(&prefixed).wrap_err_with(|| {
                format!(
                    "set {} for discovery, or both {} and {}",
                    var("ISSUER"),
                    var("AUTH_URI"),
                    var("TOKEN_URI")
                )
            })?
        }
    };

    // The root provider's name and scopes predate named providers:
    // `PROVIDER_NAME`, and `OAUTH_SCOPES` (now the default for everyone).
    let (provider_name, scopes) = match id {
        None => (
            get("PROVIDER_NAME").unwrap_or_else(|| DEFAULT_PROVIDER_NAME.into()),
            None,
        ),
        Some(id) => {
            let scopes = get(&var("SCOPES"))
                .map(|raw| parse_scopes(&raw, &format!("env var {}", var("SCOPES"))))
                .transpose()?;
            (
                get(&var("PROVIDER_NAME")).unwrap_or_else(|| id.to_string()),
                scopes,
            )
        }
    };

    let skip_issuer_validation = parse_env(get, &var("SKIP_ISSUER_VALIDATION"), Some("false"))?;
    let iss_parameter: IssParameter = parse_env(get, &var("ISS_PARAMETER"), Some("auto"))?;

    Ok(OAuthProviderConfig {
        external_origin: Some(external_origin.clone()),
        provider_name,
        client_id,
        client_secret: Some(client_secret),
        endpoints,
        scopes,
        skip_issuer_validation,
        iss_parameter,
    })
}

fn parse_scopes(raw: &str, source: &str) -> eyre::Result<ScopeSet> {
    raw.parse::<ScopeSet>()
        .map_err(|e| eyre!("{e}"))
        .with_context(|| format!("parsing {source}={raw:?}"))
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
    providers: BTreeMap<String, RawProvider>,
    #[serde(default)]
    cookies: RawCookies,
    #[serde(default)]
    server: RawServer,
}

/// `[oauth]`: global OAuth settings, plus (optionally) the single root
/// provider's fields.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOauth {
    scopes: Option<String>,
    default_provider: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    provider_name: Option<String>,
    issuer: Option<String>,
    auth_uri: Option<String>,
    token_uri: Option<String>,
    skip_issuer_validation: Option<bool>,
    iss_parameter: Option<IssParameter>,
}

/// `[providers.<id>]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProvider {
    client_id: Option<String>,
    client_secret: Option<String>,
    provider_name: Option<String>,
    scopes: Option<String>,
    issuer: Option<String>,
    auth_uri: Option<String>,
    token_uri: Option<String>,
    skip_issuer_validation: Option<bool>,
    iss_parameter: Option<IssParameter>,
}

impl RawProvider {
    fn is_empty(&self) -> bool {
        self.client_id.is_none()
            && self.client_secret.is_none()
            && self.provider_name.is_none()
            && self.scopes.is_none()
            && self.issuer.is_none()
            && self.auth_uri.is_none()
            && self.token_uri.is_none()
            && self.skip_issuer_validation.is_none()
            && self.iss_parameter.is_none()
    }

    /// Resolve into an [`OAuthProviderConfig`]. `path` is the TOML table
    /// name used in error messages, e.g. `oauth` or `providers.google`.
    fn into_provider(
        self,
        path: &str,
        default_name: &str,
        external_origin: &Uri,
    ) -> eyre::Result<OAuthProviderConfig> {
        let client_id = self
            .client_id
            .ok_or_else(|| eyre!("missing required field `{path}.client_id`"))?;
        let client_secret = Secret::from(
            self.client_secret
                .ok_or_else(|| eyre!("missing required field `{path}.client_secret`"))?,
        );

        let endpoints = match (self.issuer, self.auth_uri, self.token_uri) {
            (Some(raw), _, _) => ProviderEndpoints::Discover {
                issuer: parse_configured_uri(&raw, &format!("{path}.issuer"))?,
            },
            (None, Some(auth_raw), Some(token_raw)) => ProviderEndpoints::Explicit {
                auth_uri: parse_configured_uri(&auth_raw, &format!("{path}.auth_uri"))?,
                token_uri: parse_configured_uri(&token_raw, &format!("{path}.token_uri"))?,
            },
            _ => {
                return Err(eyre!(
                    "set `{path}.issuer` for `.well-known` discovery, \
                     or set both `{path}.auth_uri` and `{path}.token_uri` explicitly"
                ));
            }
        };

        let scopes = self
            .scopes
            .map(|raw| parse_scopes(&raw, &format!("field `{path}.scopes`")))
            .transpose()?;

        Ok(OAuthProviderConfig {
            external_origin: Some(external_origin.clone()),
            provider_name: self.provider_name.unwrap_or_else(|| default_name.into()),
            client_id,
            client_secret: Some(client_secret),
            endpoints,
            scopes,
            skip_issuer_validation: self.skip_issuer_validation.unwrap_or(false),
            iss_parameter: self.iss_parameter.unwrap_or_default(),
        })
    }
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
            providers: raw_providers,
            cookies,
            server,
        } = self;

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

        let scopes_raw = oauth.scopes.unwrap_or_else(|| DEFAULT_SCOPES.into());
        let scopes = parse_scopes(&scopes_raw, "field `oauth.scopes`")?;

        let default_provider = oauth
            .default_provider
            .map(|raw| ProviderId::new(raw).wrap_err("parsing field `oauth.default_provider`"))
            .transpose()?;

        // `[oauth]`'s provider fields define the root provider. It's
        // required when there are no `[providers.*]`, so an empty config
        // still reports the missing `oauth.client_id`.
        let root = RawProvider {
            client_id: oauth.client_id,
            client_secret: oauth.client_secret,
            provider_name: oauth.provider_name,
            scopes: None,
            issuer: oauth.issuer,
            auth_uri: oauth.auth_uri,
            token_uri: oauth.token_uri,
            skip_issuer_validation: oauth.skip_issuer_validation,
            iss_parameter: oauth.iss_parameter,
        };
        let root_provider = if !root.is_empty() || raw_providers.is_empty() {
            Some(root.into_provider("oauth", DEFAULT_PROVIDER_NAME, &external_origin)?)
        } else {
            None
        };

        let mut providers = BTreeMap::new();
        for (key, raw) in raw_providers {
            let path = format!("providers.{key}");
            let id = ProviderId::new(key.as_str()).wrap_err_with(|| format!("table `[{path}]`"))?;
            let provider = raw.into_provider(&path, id.as_str(), &external_origin)?;
            providers.insert(id, provider);
        }

        let cookie_key_raw = cookies
            .key
            .ok_or_else(|| eyre!("missing required field `cookies.key`"))?;
        let cookie_key = cookie_key_from_base64(&cookie_key_raw, "cookies.key")?;
        let secure_cookies = cookies.secure.unwrap_or(true);

        let config = Config {
            bind_addr,
            data_dir,
            external_origin,
            scopes,
            root_provider,
            providers,
            default_provider,
            cookie_key,
            secure_cookies,
        };
        config.validate()?;
        Ok(config)
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

    fn root(cfg: &Config) -> &OAuthProviderConfig {
        cfg.root_provider.as_ref().expect("root provider")
    }

    fn id(s: &str) -> ProviderId {
        ProviderId::new(s).unwrap()
    }

    #[test]
    fn loads_minimal_required_env() {
        let cfg = build(minimal_env()).expect("minimal env should load");
        let root = root(&cfg);
        assert_eq!(root.client_id, "client");
        assert_eq!(root.client_secret.as_ref().unwrap().revealed(), "secret");
        match &root.endpoints {
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
        assert_eq!(root.provider_name, "OAuth");
        assert!(root.scopes.is_none());
        assert!(cfg.providers.is_empty());
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:3000");
        assert_eq!(cfg.data_dir, Utf8PathBuf::from("./data"));
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
        match &root(&cfg).endpoints {
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
        assert!(matches!(
            root(&cfg).endpoints,
            ProviderEndpoints::Discover { .. }
        ));
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
    fn public_uri_uses_external_origin() {
        let env = with_env(&[("EXTERNAL_ORIGIN", "https://app.example.com")]);
        let cfg = build(env).unwrap();
        assert_eq!(
            cfg.public_uri("/auth/callback").to_string(),
            "https://app.example.com/auth/callback",
        );
        assert_eq!(
            root(&cfg)
                .redirect_uri("/auth/callback")
                .unwrap()
                .to_string(),
            "https://app.example.com/auth/callback",
        );
    }

    #[test]
    fn public_uri_strips_trailing_slash() {
        let env = with_env(&[("EXTERNAL_ORIGIN", "https://app.example.com/")]);
        let cfg = build(env).unwrap();
        assert_eq!(
            cfg.public_uri("/auth/callback").to_string(),
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

    // ─── Named providers from env ──────────────────────────────────

    fn named_env() -> Vec<(&'static str, String)> {
        vec![
            ("OAUTH_PROVIDERS", "google, my-idp".to_owned()),
            ("OAUTH_GOOGLE_CLIENT_ID", "g".to_owned()),
            ("OAUTH_GOOGLE_CLIENT_SECRET", "gs".to_owned()),
            (
                "OAUTH_GOOGLE_ISSUER",
                "https://accounts.google.com".to_owned(),
            ),
            ("OAUTH_GOOGLE_PROVIDER_NAME", "Google".to_owned()),
            ("OAUTH_MY_IDP_CLIENT_ID", "m".to_owned()),
            ("OAUTH_MY_IDP_CLIENT_SECRET", "ms".to_owned()),
            (
                "OAUTH_MY_IDP_AUTH_URI",
                "https://idp.example.com/authorize".to_owned(),
            ),
            (
                "OAUTH_MY_IDP_TOKEN_URI",
                "https://idp.example.com/token".to_owned(),
            ),
            ("OAUTH_MY_IDP_SCOPES", "openid groups".to_owned()),
            ("COOKIE_KEY", test_cookie_key()),
        ]
    }

    #[test]
    fn named_providers_from_env() {
        let cfg = build(named_env()).unwrap();
        assert!(cfg.root_provider.is_none());

        let google = &cfg.providers[&id("google")];
        assert_eq!(google.client_id, "g");
        assert_eq!(google.provider_name, "Google");
        assert!(matches!(
            google.endpoints,
            ProviderEndpoints::Discover { .. }
        ));

        let idp = &cfg.providers[&id("my-idp")];
        assert_eq!(idp.client_id, "m");
        assert_eq!(idp.provider_name, "my-idp");
        assert_eq!(idp.scopes.as_ref().unwrap().to_string(), "openid groups");
        assert!(matches!(idp.endpoints, ProviderEndpoints::Explicit { .. }));
    }

    #[test]
    fn named_providers_alongside_root() {
        let mut env = named_env();
        env.extend(
            minimal_env()
                .into_iter()
                .filter(|(k, _)| *k != "COOKIE_KEY"),
        );
        let cfg = build(env).unwrap();
        assert_eq!(root(&cfg).client_id, "client");
        assert_eq!(cfg.providers.len(), 2);
    }

    #[test]
    fn named_provider_missing_endpoints_names_its_vars() {
        let mut env = named_env();
        env.retain(|(k, _)| *k != "OAUTH_GOOGLE_ISSUER");
        let msg = format!("{:#}", build(env).unwrap_err());
        assert!(
            msg.contains("OAUTH_GOOGLE_ISSUER") && msg.contains("OAUTH_GOOGLE_AUTH_URI"),
            "msg: {msg}"
        );
    }

    #[test]
    fn named_provider_missing_client_id_names_its_var() {
        let mut env = named_env();
        env.retain(|(k, _)| *k != "OAUTH_MY_IDP_CLIENT_ID");
        let msg = format!("{:#}", build(env).unwrap_err());
        assert!(msg.contains("OAUTH_MY_IDP_CLIENT_ID"), "msg: {msg}");
    }

    #[test]
    fn default_provider_from_env() {
        let mut env = named_env();
        env.push(("OAUTH_DEFAULT_PROVIDER", "google".to_owned()));
        assert_eq!(build(env).unwrap().default_provider, Some(id("google")));

        let mut env = named_env();
        env.push(("OAUTH_DEFAULT_PROVIDER", "okta".to_owned()));
        assert!(build(env).is_err());
    }

    #[test]
    fn skip_issuer_validation_from_env() {
        let cfg = build(minimal_env()).unwrap();
        assert!(!root(&cfg).skip_issuer_validation);

        let cfg = build(with_env(&[("OAUTH_SKIP_ISSUER_VALIDATION", "true")])).unwrap();
        assert!(root(&cfg).skip_issuer_validation);

        let mut env = named_env();
        env.push(("OAUTH_MY_IDP_SKIP_ISSUER_VALIDATION", "true".to_owned()));
        let cfg = build(env).unwrap();
        assert!(cfg.providers[&id("my-idp")].skip_issuer_validation);
        assert!(!cfg.providers[&id("google")].skip_issuer_validation);

        let err = build(with_env(&[("OAUTH_SKIP_ISSUER_VALIDATION", "maybe")])).unwrap_err();
        assert!(format!("{err:#}").contains("OAUTH_SKIP_ISSUER_VALIDATION"));
    }

    #[test]
    fn iss_parameter_from_env() {
        let cfg = build(minimal_env()).unwrap();
        assert_eq!(root(&cfg).iss_parameter, IssParameter::Auto);

        let cfg = build(with_env(&[("OAUTH_ISS_PARAMETER", "ignored")])).unwrap();
        assert_eq!(root(&cfg).iss_parameter, IssParameter::Ignored);

        let mut env = named_env();
        env.push(("OAUTH_GOOGLE_ISS_PARAMETER", "Required".to_owned()));
        let cfg = build(env).unwrap();
        assert_eq!(
            cfg.providers[&id("google")].iss_parameter,
            IssParameter::Required
        );
        assert_eq!(
            cfg.providers[&id("my-idp")].iss_parameter,
            IssParameter::Auto
        );

        let err = build(with_env(&[("OAUTH_ISS_PARAMETER", "sometimes")])).unwrap_err();
        assert!(format!("{err:#}").contains("OAUTH_ISS_PARAMETER"));
    }

    #[test]
    fn provider_list_rejects_env_clashes() {
        assert!(parse_provider_list("my-idp, my_idp").is_err());
        assert!(parse_provider_list("bad/id").is_err());
    }

    #[test]
    fn provider_ids_must_be_lowercase() {
        let msg = format!("{:#}", parse_provider_list("google, Okta").unwrap_err());
        assert!(
            msg.contains("OAUTH_PROVIDERS") && msg.contains("lowercase"),
            "{msg}"
        );

        let key = test_cookie_key();
        let body = format!(
            r#"
                [providers.Okta]
                client_id = "o"
                client_secret = "os"
                issuer = "https://okta.example.com"

                [cookies]
                key = "{key}"
            "#,
        );
        let msg = format!("{:#}", Config::from_toml_str(&body).unwrap_err());
        assert!(
            msg.contains("providers.Okta") && msg.contains("lowercase"),
            "{msg}"
        );
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
        let root = root(&cfg);
        assert_eq!(root.client_id, "client");
        assert_eq!(root.client_secret.as_ref().unwrap().revealed(), "secret");
        assert!(matches!(root.endpoints, ProviderEndpoints::Discover { .. }));
        assert_eq!(root.provider_name, "OAuth");
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:3000");
        assert_eq!(cfg.data_dir, Utf8PathBuf::from("./data"));
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
        match &root(&cfg).endpoints {
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
        assert_eq!(root(&cfg).provider_name, "Acme");
        assert_eq!(cfg.scopes.to_string(), "openid");
        assert_eq!(cfg.bind_addr.to_string(), "0.0.0.0:9000");
        assert_eq!(cfg.external_origin.to_string(), "https://app.example.com/",);
        assert_eq!(cfg.data_dir, Utf8PathBuf::from("/var/lib/ott"));
        assert!(!cfg.secure_cookies);
    }

    fn named_toml(extra_oauth: &str) -> String {
        let key = test_cookie_key();
        format!(
            r#"
                [oauth]
                scopes = "openid email"
                {extra_oauth}

                [providers.google]
                client_id = "g"
                client_secret = "gs"
                provider_name = "Google"
                issuer = "https://accounts.google.com"

                [providers.okta]
                client_id = "o"
                client_secret = "os"
                scopes = "openid groups"
                auth_uri = "https://okta.example.com/authorize"
                token_uri = "https://okta.example.com/token"

                [cookies]
                key = "{key}"
            "#,
        )
    }

    #[test]
    fn toml_named_providers() {
        let cfg = Config::from_toml_str(&named_toml("")).unwrap();
        assert!(cfg.root_provider.is_none());
        assert_eq!(cfg.scopes.to_string(), "openid email");
        assert_eq!(cfg.providers[&id("google")].provider_name, "Google");
        let okta = &cfg.providers[&id("okta")];
        assert_eq!(okta.provider_name, "okta");
        assert_eq!(okta.scopes.as_ref().unwrap().to_string(), "openid groups");
        assert_eq!(
            okta.redirect_uri("/auth/okta/callback")
                .unwrap()
                .to_string(),
            "http://127.0.0.1:3000/auth/okta/callback"
        );
    }

    #[test]
    fn toml_skip_issuer_validation() {
        let cfg = Config::from_toml_str(&named_toml("")).unwrap();
        assert!(!cfg.providers[&id("okta")].skip_issuer_validation);

        let key = test_cookie_key();
        let body = format!(
            r#"
                [oauth]
                client_id = "c"
                client_secret = "s"
                issuer = "https://login.microsoftonline.com/common/v2.0"
                skip_issuer_validation = true

                [providers.entra]
                client_id = "e"
                client_secret = "es"
                issuer = "https://login.microsoftonline.com/common/v2.0"
                skip_issuer_validation = true

                [cookies]
                key = "{key}"
            "#,
        );
        let cfg = Config::from_toml_str(&body).unwrap();
        assert!(root(&cfg).skip_issuer_validation);
        assert!(cfg.providers[&id("entra")].skip_issuer_validation);
    }

    #[test]
    fn toml_iss_parameter() {
        let key = test_cookie_key();
        let body = format!(
            r#"
                [oauth]
                client_id = "c"
                client_secret = "s"
                issuer = "https://x"
                iss_parameter = "ignored"

                [providers.okta]
                client_id = "o"
                client_secret = "os"
                issuer = "https://okta.example.com"
                iss_parameter = "required"

                [providers.google]
                client_id = "g"
                client_secret = "gs"
                issuer = "https://accounts.google.com"

                [cookies]
                key = "{key}"
            "#,
        );
        let cfg = Config::from_toml_str(&body).unwrap();
        assert_eq!(root(&cfg).iss_parameter, IssParameter::Ignored);
        assert_eq!(
            cfg.providers[&id("okta")].iss_parameter,
            IssParameter::Required
        );
        assert_eq!(
            cfg.providers[&id("google")].iss_parameter,
            IssParameter::Auto
        );

        let err = Config::from_toml_str(&body.replace(r#""ignored""#, r#""nope""#)).unwrap_err();
        assert!(format!("{err:#}").contains("nope"), "{err:#}");
    }

    #[test]
    fn toml_default_provider() {
        let cfg = Config::from_toml_str(&named_toml(r#"default_provider = "okta""#)).unwrap();
        assert_eq!(cfg.default_provider, Some(id("okta")));

        let err = Config::from_toml_str(&named_toml(r#"default_provider = "github""#)).unwrap_err();
        assert!(format!("{err:#}").contains("github"));
    }

    #[test]
    fn toml_root_and_named_providers() {
        let cfg = Config::from_toml_str(&named_toml(
            r#"
            client_id = "c"
            client_secret = "s"
            issuer = "https://x"
            "#,
        ))
        .unwrap();
        assert_eq!(root(&cfg).client_id, "c");
        assert_eq!(cfg.providers.len(), 2);

        let err = Config::from_toml_str(&named_toml(
            r#"
            client_id = "c"
            client_secret = "s"
            issuer = "https://x"
            default_provider = "google"
            "#,
        ))
        .unwrap_err();
        assert!(format!("{err:#}").contains("conflicts"));
    }

    #[test]
    fn toml_named_provider_errors_name_the_table() {
        let key = test_cookie_key();
        let body = format!(
            r#"
                [providers.google]
                client_secret = "gs"
                issuer = "https://accounts.google.com"

                [cookies]
                key = "{key}"
            "#,
        );
        let msg = format!("{:#}", Config::from_toml_str(&body).unwrap_err());
        assert!(msg.contains("providers.google.client_id"), "msg: {msg}");

        let body = format!(
            r#"
                [providers."bad id"]
                client_id = "x"

                [cookies]
                key = "{key}"
            "#,
        );
        let msg = format!("{:#}", Config::from_toml_str(&body).unwrap_err());
        assert!(msg.contains("providers.bad id"), "msg: {msg}");
    }
}
