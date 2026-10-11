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
    /// Load configuration from a file
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        let settings = config::Config::builder()
            .add_source(config::File::from(path))
            .add_source(config::Environment::with_prefix("OGATEWAY"))
            .build()?;
        settings.try_deserialize()
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::Environment::with_prefix("OGATEWAY"))
            .build()?;

        settings.try_deserialize()
    }
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

    fn full(toml: &str) -> Config {
        config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap()
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
            default_provider = "Google"

            [providers.Google]
            client_id = "g"
            provider_name = "Google"
            scopes = "openid email"
            [providers.Google.endpoints]
            issuer = "https://accounts.google.com"

            [providers.okta]
            client_id = "o"
            provider_name = "Okta"
            skip_issuer_validation = true
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
        assert_eq!(ids, ["Google", "okta"]);
        assert_eq!(cfg.providers.default_provider.unwrap().as_str(), "Google");
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
    }

    #[test]
    fn no_origin_by_default() {
        assert_eq!(server("").origin().unwrap(), None);
    }
}
