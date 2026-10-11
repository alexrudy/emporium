use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use config::ConfigError;
use oath::server::OAuth2RouterConfig;
use otool::config::{ProvidersConfig, SessionsConfig};
use serde::{Deserialize, Serialize};

use crate::origin::OriginConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub oath: OAuth2RouterConfig,

    /// `[provider]`, `[providers.<id>]`, and `default_provider`.
    #[serde(flatten)]
    pub providers: ProvidersConfig,

    #[serde(default)]
    pub sessions: SessionsConfig,
    #[serde(default)]
    pub server: ServerConfig,
}

impl Config {
    /// Load configuration from a file, overridden by `OGATEWAY_*`
    /// environment variables (see [`env_source`]).
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        let settings = config::Config::builder()
            .add_source(config::File::from(path))
            .add_source(env_source())
            .build()?;
        settings.try_deserialize()
    }

    /// Load configuration from `OGATEWAY_*` environment variables only
    /// (see [`env_source`]).
    pub fn from_env() -> Result<Self, ConfigError> {
        let settings = config::Config::builder().add_source(env_source()).build()?;

        settings.try_deserialize()
    }
}

/// `OGATEWAY_*` environment variables, with `__` separating nested keys:
/// `OGATEWAY_SERVER__BIND_ADDR` is `server.bind_addr`, and
/// `OGATEWAY_PROVIDERS__GOOGLE__CLIENT_ID` is
/// `providers.google.client_id`.
///
/// Values stay strings (no type guessing), so numeric client ids aren't
/// turned into integers. Keys are lowercased, which matches provider ids
/// (always lowercase): `…__GOOGLE__…` configures `[providers.google]`.
fn env_source() -> config::Environment {
    config::Environment::with_prefix("OGATEWAY")
        .prefix_separator("_")
        .separator("__")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// The address to bind the server to.
    pub bind_addr: SocketAddr,

    /// Where to read the request's public origin from. Each provider's
    /// redirect URI is that origin joined to its callback path, which
    /// lets one gateway authenticate several hostnames. When unset, the
    /// provider's configured `external_origin` is used.
    #[serde(default)]
    pub origin: Option<OriginConfig>,

    /// Shorthand for `origin = { kind = "trusted-header", header = ... }`:
    /// a header, set by the reverse proxy, carrying the request's public
    /// origin (e.g. `https://app.example.com`). Only the header's scheme
    /// and host are used. Can't be combined with `origin`.
    #[serde(default)]
    pub trusted_header: Option<String>,

    #[serde(default)]
    pub verify_route: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            origin: None,
            trusted_header: None,
            verify_route: "/verify".into(),
        }
    }
}

impl Config {
    /// Check that each provider's redirect URI has exactly one source.
    ///
    /// With `[server.origin]`, the origin comes from there and providers'
    /// `external_origin` is ignored: those providers are returned so the
    /// caller can warn. Without it, every provider needs an
    /// `external_origin`, or its redirect URI would be a bare path that
    /// providers reject.
    pub fn check_origins(&self) -> eyre::Result<Vec<String>> {
        let providers = self
            .providers
            .provider
            .iter()
            .map(|p| ("[provider]".to_owned(), p))
            .chain(
                self.providers
                    .providers
                    .iter()
                    .map(|(id, p)| (format!("[providers.{id}]"), p)),
            );

        if self.server.origin()?.is_some() {
            return Ok(providers
                .filter(|(_, p)| p.external_origin.is_some())
                .map(|(name, _)| name)
                .collect());
        }

        let missing: Vec<_> = providers
            .filter(|(_, p)| p.external_origin.is_none())
            .map(|(name, _)| name)
            .collect();
        if !missing.is_empty() {
            eyre::bail!(
                "{} need an external_origin, or set [server.origin] \
                 (e.g. kind = \"fixed\", origin = \"https://gw.example.com\") for all providers",
                missing.join(", ")
            );
        }
        Ok(Vec::new())
    }
}

impl ServerConfig {
    /// The configured origin source, resolving the `trusted_header`
    /// shorthand.
    pub fn origin(&self) -> eyre::Result<Option<OriginConfig>> {
        match (&self.origin, &self.trusted_header) {
            (Some(_), Some(_)) => Err(eyre::eyre!(
                "server.origin and server.trusted_header are mutually exclusive"
            )),
            (Some(origin), None) => Ok(Some(origin.clone())),
            (None, Some(header)) => Ok(Some(OriginConfig::TrustedHeader {
                header: header.clone(),
            })),
            (None, None) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::DefaultScheme;
    use oath::provider::IssParameter;

    fn server(toml: &str) -> ServerConfig {
        config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap()
    }

    #[test]
    fn origin_table_variants() {
        let cfg = server(
            r#"
            [origin]
            kind = "x-forwarded"
            default_scheme = "https"
            "#,
        );
        assert_eq!(
            cfg.origin().unwrap(),
            Some(OriginConfig::XForwarded {
                default_scheme: Some(DefaultScheme::Https)
            })
        );

        let cfg = server(
            r#"
            [origin]
            kind = "forwarded"
            "#,
        );
        assert_eq!(
            cfg.origin().unwrap(),
            Some(OriginConfig::Forwarded {
                default_scheme: None
            })
        );

        let cfg = server(
            r#"
            [origin]
            kind = "trusted-header"
            header = "X-Gateway-Callback"
            "#,
        );
        assert_eq!(
            cfg.origin().unwrap(),
            Some(OriginConfig::TrustedHeader {
                header: "X-Gateway-Callback".into()
            })
        );
    }

    #[test]
    fn trusted_header_shorthand() {
        let cfg = server(r#"trusted_header = "X-Gateway-Callback""#);
        assert_eq!(
            cfg.origin().unwrap(),
            Some(OriginConfig::TrustedHeader {
                header: "X-Gateway-Callback".into()
            })
        );
    }

    #[test]
    fn origin_and_trusted_header_conflict() {
        let cfg = server(
            r#"
            trusted_header = "X-Gateway-Callback"
            [origin]
            kind = "forwarded"
            "#,
        );
        assert!(cfg.origin().is_err());
    }

    fn env(vars: &[(&str, &str)]) -> config::Environment {
        env_source().source(Some(
            vars.iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        ))
    }

    fn from_env_vars(vars: &[(&str, &str)]) -> Config {
        config::Config::builder()
            .add_source(env(vars))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap()
    }

    #[test]
    fn multi_provider_config_from_env_only() {
        let cfg = from_env_vars(&[
            ("OGATEWAY_DEFAULT_PROVIDER", "google"),
            ("OGATEWAY_PROVIDERS__GOOGLE__CLIENT_ID", "123456789"),
            ("OGATEWAY_PROVIDERS__GOOGLE__CLIENT_SECRET", "g-secret"),
            ("OGATEWAY_PROVIDERS__GOOGLE__PROVIDER_NAME", "Google"),
            ("OGATEWAY_PROVIDERS__GOOGLE__SCOPES", "openid email"),
            ("OGATEWAY_PROVIDERS__GOOGLE__SKIP_ISSUER_VALIDATION", "true"),
            ("OGATEWAY_PROVIDERS__GOOGLE__ISS_PARAMETER", "ignored"),
            (
                "OGATEWAY_PROVIDERS__GOOGLE__ENDPOINTS__ISSUER",
                "https://accounts.google.com",
            ),
            ("OGATEWAY_PROVIDERS__MY_IDP__CLIENT_ID", "m"),
            ("OGATEWAY_PROVIDERS__MY_IDP__PROVIDER_NAME", "Mine"),
            (
                "OGATEWAY_PROVIDERS__MY_IDP__EXTERNAL_ORIGIN",
                "https://gw.example.com",
            ),
            (
                "OGATEWAY_PROVIDERS__MY_IDP__ENDPOINTS__AUTH_URI",
                "https://idp.example.com/authorize",
            ),
            (
                "OGATEWAY_PROVIDERS__MY_IDP__ENDPOINTS__TOKEN_URI",
                "https://idp.example.com/token",
            ),
            ("OGATEWAY_OATH__SECURE_COOKIES", "false"),
            ("OGATEWAY_OATH__SCOPES", "openid"),
            ("OGATEWAY_SESSIONS__KEY", "session-key"),
            ("OGATEWAY_SERVER__BIND_ADDR", "127.0.0.1:3030"),
            ("OGATEWAY_SERVER__VERIFY_ROUTE", "/proxy/verify"),
            ("OGATEWAY_SERVER__ORIGIN__KIND", "x-forwarded"),
            ("OGATEWAY_SERVER__ORIGIN__DEFAULT_SCHEME", "https"),
        ]);

        let providers = &cfg.providers;
        assert!(providers.provider.is_none());
        assert_eq!(
            providers.default_provider.as_ref().unwrap().as_str(),
            "google"
        );

        let google = &providers.providers[&"google".parse().unwrap()];
        // Numeric-looking values stay strings.
        assert_eq!(google.client_id, "123456789");
        assert_eq!(
            google.client_secret.as_ref().unwrap().revealed(),
            "g-secret"
        );
        assert_eq!(google.scopes.as_ref().unwrap().to_string(), "openid email");
        assert!(google.skip_issuer_validation);
        assert_eq!(google.iss_parameter, IssParameter::Ignored);

        let idp = &providers.providers[&"my_idp".parse().unwrap()];
        assert_eq!(idp.client_id, "m");
        assert!(!idp.skip_issuer_validation);
        assert_eq!(
            idp.external_origin.as_ref().unwrap().to_string(),
            "https://gw.example.com/"
        );

        assert!(!cfg.oath.secure_cookies);
        assert_eq!(cfg.oath.scopes.to_string(), "openid");
        assert_eq!(cfg.sessions.key.revealed(), "session-key");
        assert_eq!(cfg.server.bind_addr.to_string(), "127.0.0.1:3030");
        assert_eq!(cfg.server.verify_route, "/proxy/verify");
        assert_eq!(
            cfg.server.origin().unwrap(),
            Some(OriginConfig::XForwarded {
                default_scheme: Some(DefaultScheme::Https)
            })
        );
        assert!(cfg.providers.validate().is_ok());
    }

    #[test]
    fn env_overrides_file_values() {
        let cfg: Config = config::Config::builder()
            .add_source(config::File::from_str(
                r#"
                [provider]
                client_id = "from-file"
                client_secret = "file-secret"
                provider_name = "Bastion"
                [provider.endpoints]
                issuer = "https://idp.example.com"
                "#,
                config::FileFormat::Toml,
            ))
            .add_source(env(&[
                ("OGATEWAY_PROVIDER__CLIENT_SECRET", "env-secret"),
                ("OGATEWAY_PROVIDER__SKIP_ISSUER_VALIDATION", "yes"),
            ]))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        let provider = cfg.providers.provider.unwrap();
        assert_eq!(provider.client_id, "from-file");
        assert_eq!(provider.client_secret.unwrap().revealed(), "env-secret");
        assert!(provider.skip_issuer_validation);
    }

    #[test]
    fn legacy_top_level_env_var_still_works() {
        let cfg = from_env_vars(&[
            ("OGATEWAY_DEFAULT_PROVIDER", "okta"),
            ("OGATEWAY_PROVIDERS__OKTA__CLIENT_ID", "o"),
            ("OGATEWAY_PROVIDERS__OKTA__PROVIDER_NAME", "Okta"),
            (
                "OGATEWAY_PROVIDERS__OKTA__ENDPOINTS__ISSUER",
                "https://okta.example.com",
            ),
        ]);
        assert_eq!(cfg.providers.default_provider.unwrap().as_str(), "okta");
    }

    fn full(toml: &str) -> Config {
        config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap()
    }

    #[test]
    fn uppercase_provider_id_is_rejected() {
        let result = config::Config::builder()
            .add_source(config::File::from_str(
                r#"
                [providers.Google]
                client_id = "g"
                provider_name = "Google"
                [providers.Google.endpoints]
                issuer = "https://accounts.google.com"
                "#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap()
            .try_deserialize::<Config>();
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Google") && err.contains("lowercase"), "{err}");
    }

    #[test]
    fn legacy_single_provider() {
        let cfg = full(
            r#"
            [provider]
            client_id = "ogateway"
            provider_name = "Bastion"
            [provider.endpoints]
            issuer = "https://bastion.example.com"
            "#,
        );
        assert_eq!(cfg.providers.provider.unwrap().client_id, "ogateway");
        assert!(cfg.providers.providers.is_empty());
    }

    #[test]
    fn multiple_providers() {
        let cfg = full(
            r#"
            default_provider = "google"

            [providers.google]
            client_id = "g"
            provider_name = "Google"
            scopes = "openid email"
            [providers.google.endpoints]
            issuer = "https://accounts.google.com"

            [providers.okta]
            client_id = "o"
            provider_name = "Okta"
            skip_issuer_validation = true
            iss_parameter = "ignored"
            [providers.okta.endpoints]
            auth_uri = "https://okta.example.com/authorize"
            token_uri = "https://okta.example.com/token"
            "#,
        );
        let ids: Vec<_> = cfg
            .providers
            .providers
            .keys()
            .map(|id| id.as_str().to_owned())
            .collect();
        assert_eq!(ids, ["google", "okta"]);
        assert_eq!(cfg.providers.default_provider.unwrap().as_str(), "google");
        assert_eq!(
            cfg.providers.providers.values().next().unwrap().scopes,
            Some("openid email".parse().unwrap())
        );
        assert!(cfg.providers.provider.is_none());

        let skips: Vec<_> = cfg
            .providers
            .providers
            .values()
            .map(|p| p.skip_issuer_validation)
            .collect();
        assert_eq!(skips, [false, true]);

        let iss: Vec<_> = cfg
            .providers
            .providers
            .values()
            .map(|p| p.iss_parameter)
            .collect();
        assert_eq!(iss, [IssParameter::Auto, IssParameter::Ignored]);
    }

    const PROVIDERS: &str = r#"
        [provider]
        client_id = "r"
        provider_name = "Root"
        {root_origin}
        [provider.endpoints]
        issuer = "https://idp.example.com"

        [providers.google]
        client_id = "g"
        provider_name = "Google"
        [providers.google.endpoints]
        issuer = "https://accounts.google.com"
    "#;

    fn with_root_origin(root_origin: &str, server: &str) -> Config {
        full(&format!(
            "{}\n{server}",
            PROVIDERS.replace("{root_origin}", root_origin)
        ))
    }

    #[test]
    fn origins_need_a_source() {
        let cfg = with_root_origin(r#"external_origin = "https://gw.example.com""#, "");
        let err = cfg.check_origins().unwrap_err().to_string();
        assert!(err.contains("[providers.google]"), "{err}");
        assert!(!err.contains("[provider]"), "{err}");
    }

    #[test]
    fn server_origin_makes_external_origin_redundant() {
        let cfg = with_root_origin(
            r#"external_origin = "https://gw.example.com""#,
            "[server.origin]\nkind = \"fixed\"\norigin = \"https://gw.example.com\"",
        );
        assert_eq!(cfg.check_origins().unwrap(), ["[provider]"]);

        let cfg = with_root_origin("", "[server.origin]\nkind = \"x-forwarded\"");
        assert!(cfg.check_origins().unwrap().is_empty());
    }

    #[test]
    fn every_provider_with_external_origin_is_fine() {
        let cfg = full(
            r#"
            [providers.google]
            client_id = "g"
            provider_name = "Google"
            external_origin = "https://gw.example.com"
            [providers.google.endpoints]
            issuer = "https://accounts.google.com"
            "#,
        );
        assert!(cfg.check_origins().unwrap().is_empty());
    }

    #[test]
    fn fixed_origin_parses() {
        let cfg = server(
            r#"
            [origin]
            kind = "fixed"
            origin = "https://gw.example.com"
            "#,
        );
        assert_eq!(
            cfg.origin().unwrap(),
            Some(OriginConfig::Fixed {
                origin: "https://gw.example.com".into()
            })
        );
    }

    #[test]
    fn no_origin_by_default() {
        assert_eq!(server("").origin().unwrap(), None);
    }
}
