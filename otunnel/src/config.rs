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
    /// Load configuration from a file
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        let settings = config::Config::builder()
            .add_source(config::File::from(path))
            .add_source(config::Environment::with_prefix("OTUNNEL"))
            .build()?;
        settings.try_deserialize()
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::Environment::with_prefix("OTUNNEL"))
            .build()?;

        settings.try_deserialize()
    }
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
}
