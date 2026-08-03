use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use config::ConfigError;
use oath::{provider::OAuthProviderConfig, server::OAuth2RouterConfig};
use otool::config::SessionsConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub oath: OAuth2RouterConfig,
    pub provider: OAuthProviderConfig,

    #[serde(default)]
    pub sessions: SessionsConfig,
    #[serde(default)]
    pub server: ServerConfig,

    pub verify_route: String,
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        }
    }
}
