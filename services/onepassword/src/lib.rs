//! Access 1Password secrets via the 1Password Connect API
//!
//! This requires a running instance of 1Passowrd Connect, which can be set up via docker.

mod client;
pub mod models;
mod secrets;

use api_client::Secret;
pub use client::{OnePassword, OnePasswordError};
use http::Uri;
pub use secrets::{SecretManager, SecretsError};
use serde::Deserialize;

/// Configuration for a 1Password Connect client
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// The secret token used to authenticate
    pub token: Secret,

    /// The host URI for 1Password connect
    #[serde(with = "api_client::uri::serde")]
    pub host: Uri,
}

/// Configuration for 1Password secrets management
#[derive(Debug, Clone, Deserialize)]
pub struct OnePasswordConfig {
    /// Configuration of the 1Password Client
    #[serde(flatten)]
    pub client: Option<ClientConfig>,

    /// The name of the primary vault to search for secrets
    pub vault: String,
}

/// Create a new secret manager from the configuration.
pub async fn secret_manager(config: &OnePasswordConfig) -> Result<SecretManager, OnePasswordError> {
    if let Some(client) = config.client.as_ref() {
        Ok(SecretManager::new(client.host.clone(), client.token.clone(), &config.vault).await?)
    } else {
        Ok(SecretManager::new_from_environmnet().await?)
    }
}
