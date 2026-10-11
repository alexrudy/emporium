use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use config::ConfigError;
use hyperdriver::client::conn::transport::tcp::TcpTransportConfig;
use oath::server::OAuth2RouterConfig;
use otool::config::{ProvidersConfig, SessionsConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub oath: OAuth2RouterConfig,

    /// `[provider]`, `[providers.<id>]`, and `default_provider`.
    #[serde(flatten)]
    pub providers: ProvidersConfig,

    #[serde(skip, default)]
    pub tcp: TcpTransportConfig,

    #[serde(default)]
    pub sessions: SessionsConfig,
    #[serde(default)]
    pub server: ServerConfig,
}

impl Config {
    /// Load configuration from a file, overridden by `OTUNNEL_*`
    /// environment variables (see [`env_source`]).
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        let settings = config::Config::builder()
            .add_source(config::File::from(path))
            .add_source(env_source())
            .build()?;
        settings.try_deserialize()
    }

    /// Load configuration from `OTUNNEL_*` environment variables only (see
    /// [`env_source`]).
    pub fn from_env() -> Result<Self, ConfigError> {
        let settings = config::Config::builder().add_source(env_source()).build()?;

        settings.try_deserialize()
    }
}

/// `OTUNNEL_*` environment variables, with `__` separating nested keys:
/// `OTUNNEL_SERVER__BIND_ADDR` is `server.bind_addr`, and
/// `OTUNNEL_PROVIDERS__GOOGLE__CLIENT_ID` is `providers.google.client_id`.
///
/// Values stay strings (no type guessing), so numeric client ids aren't
/// turned into integers. Keys are lowercased, which matches provider ids
/// (always lowercase): `…__GOOGLE__…` configures `[providers.google]`.
fn env_source() -> config::Environment {
    config::Environment::with_prefix("OTUNNEL")
        .prefix_separator("_")
        .separator("__")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// The address to bind the server to.
    pub bind_addr: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The config is logged at startup with `{:?}`; secrets must not appear.
    #[test]
    fn debug_output_redacts_secrets() {
        let config: Config = config::Config::builder()
            .add_source(config::File::from_str(
                r#"
                [provider]
                client_id = "otunnel"
                client_secret = "root-client-secret"
                provider_name = "Bastion"
                [provider.endpoints]
                issuer = "https://idp.example.com"

                [providers.google]
                client_id = "g"
                client_secret = "google-client-secret"
                provider_name = "Google"
                [providers.google.endpoints]
                issuer = "https://accounts.google.com"

                [sessions]
                key = "session-signing-key"
                "#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        let debug = format!("{config:?}");
        for secret in [
            "root-client-secret",
            "google-client-secret",
            "session-signing-key",
        ] {
            assert!(!debug.contains(secret), "{secret} leaked: {debug}");
        }
        assert!(debug.contains("otunnel"), "non-secret fields still shown");
    }

    #[test]
    fn multi_provider_config_from_env_only() {
        let vars = [
            ("OTUNNEL_PROVIDER__CLIENT_ID", "42"),
            ("OTUNNEL_PROVIDER__PROVIDER_NAME", "Bastion"),
            (
                "OTUNNEL_PROVIDER__EXTERNAL_ORIGIN",
                "https://tunnel.example.com",
            ),
            (
                "OTUNNEL_PROVIDER__ENDPOINTS__ISSUER",
                "https://idp.example.com",
            ),
            ("OTUNNEL_PROVIDERS__GOOGLE__CLIENT_ID", "g"),
            ("OTUNNEL_PROVIDERS__GOOGLE__PROVIDER_NAME", "Google"),
            (
                "OTUNNEL_PROVIDERS__GOOGLE__EXTERNAL_ORIGIN",
                "https://tunnel.example.com",
            ),
            ("OTUNNEL_PROVIDERS__GOOGLE__SKIP_ISSUER_VALIDATION", "true"),
            (
                "OTUNNEL_PROVIDERS__GOOGLE__ENDPOINTS__ISSUER",
                "https://accounts.google.com",
            ),
            ("OTUNNEL_SERVER__BIND_ADDR", "127.0.0.1:3030"),
            ("OTUNNEL_SESSIONS__KEY", "session-key"),
        ];
        let config: Config = config::Config::builder()
            .add_source(
                env_source().source(Some(
                    vars.iter()
                        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                        .collect(),
                )),
            )
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        let root = config.providers.provider.as_ref().unwrap();
        assert_eq!(root.client_id, "42");
        let google = &config.providers.providers[&"google".parse().unwrap()];
        assert!(google.skip_issuer_validation);
        assert_eq!(config.server.bind_addr.to_string(), "127.0.0.1:3030");
        assert!(config.providers.validate().is_ok());
    }
}
