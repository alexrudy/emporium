//! Environment-driven configuration.
//!
//! Phase A only knows how to read [`Config::bind_addr`] and
//! [`Config::data_dir`]. Phase B will extend [`Config`] with the
//! OAuth2 fields.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use eyre::{Context as _, eyre};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_DATA_DIR: &str = "./data";

/// Resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP listener binds to.
    pub bind_addr: SocketAddr,
    /// Directory the user store writes JSON records into.
    pub data_dir: PathBuf,
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
        let bind_addr = parse_env(&get, "BIND_ADDR", DEFAULT_BIND_ADDR)?;
        let data_dir = get("DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));

        Ok(Self {
            bind_addr,
            data_dir,
        })
    }
}

fn parse_env<F, T>(get: &F, key: &str, default: &str) -> eyre::Result<T>
where
    F: Fn(&str) -> Option<String>,
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let raw = get(key).unwrap_or_else(|| default.to_owned());
    raw.parse::<T>()
        .map_err(|e| eyre!(e))
        .with_context(|| format!("parsing env var {key}={raw:?}"))
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

    #[test]
    fn defaults_when_no_env() {
        let cfg = Config::from_provider(provider(&[])).expect("defaults parse");
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:3000");
        assert_eq!(cfg.data_dir, PathBuf::from("./data"));
    }

    #[test]
    fn honors_explicit_bind_addr() {
        let cfg = Config::from_provider(provider(&[("BIND_ADDR", "0.0.0.0:8080")])).unwrap();
        assert_eq!(cfg.bind_addr.to_string(), "0.0.0.0:8080");
    }

    #[test]
    fn honors_explicit_data_dir() {
        let cfg = Config::from_provider(provider(&[("DATA_DIR", "/var/lib/ott")])).unwrap();
        assert_eq!(cfg.data_dir, PathBuf::from("/var/lib/ott"));
    }

    #[test]
    fn rejects_malformed_bind_addr() {
        let err = Config::from_provider(provider(&[("BIND_ADDR", "not-a-socket")])).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("BIND_ADDR"),
            "error should name the offending var: {msg}",
        );
    }
}
