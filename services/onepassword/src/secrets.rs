use api_client::Secret;
use url::Url;

use crate::{OnePassword, client::OnePasswordError, models::vaults::Vault};

const HOST: &str = "OP_CONNECT_HOST";
const TOKEN: &str = "OP_CONNECT_TOKEN";
const VAULT: &str = "OP_CONNECT_VAULT";

/// A manager for accessing 1Password connect items by URI
#[derive(Debug, Clone)]
pub struct SecretManager {
    client: Vault,
}

fn read_env_var(name: &str) -> Result<String, OnePasswordError> {
    let value = std::env::var(name).map_err(|_| {
        OnePasswordError::Configuration(format!("Environment variable {name} not found!"))
    })?;

    if value.is_empty() {
        return Err(OnePasswordError::Configuration(format!(
            "Environment variable {name} is empty!"
        )));
    }

    Ok(value)
}

impl SecretManager {
    /// Construct and connect a new 1Password Secrets manager
    pub async fn new(
        host: http::Uri,
        token: Secret,
        vault: &str,
    ) -> Result<Self, OnePasswordError> {
        let client = OnePassword::new(host, token);

        let vault = client.get_vault(vault).await?;

        Ok(Self { client: vault })
    }

    /// Construct a 1Password Secrets Manager from environment variables
    pub async fn new_from_environmnet() -> Result<Self, OnePasswordError> {
        let host: http::Uri = read_env_var(HOST)?.parse().map_err(|_| {
            OnePasswordError::Configuration(format!("Environment variable {HOST} not a URL!"))
        })?;

        let token = read_env_var(TOKEN)?;
        let vault = read_env_var(VAULT)?;

        Self::new(host, token.into(), &vault).await
    }

    /// Get a 1password secret by looking it up by URI (in the same formate the command line uses)
    pub async fn get<U: Into<Url>>(&self, address: U) -> Result<Secret, SecretsError> {
        let url: Url = address.into();

        if url.scheme() != "op" {
            return Err(SecretsError::InvalidUrl(url.clone()));
        }

        if url.path_segments().map(|c| c.count()).unwrap_or(0) < 2 {
            return Err(SecretsError::InvalidUrl(url.clone()));
        }

        if url.host_str() != Some(self.client.name()) {
            return Err(SecretsError::InvalidUrl(url.clone()));
        }

        let mut segments = url
            .path_segments()
            .ok_or_else(|| SecretsError::InvalidUrl(url.clone()))?;

        let name = segments.next().unwrap();
        let field = segments.next_back().unwrap();
        let section = segments.next();

        if let Some(section) = section {
            self.get_by_section_field(name, section, field).await
        } else {
            self.get_by_field(name, field).await
        }
    }

    /// Get a 1password secret by item name. Will take the first concealed, non-empty field
    /// in the item.
    pub async fn get_by_name(&self, name: &str) -> Result<Secret, SecretsError> {
        let item = self.client.get_item_by_name(name).await?;

        let field = item
            .fields()
            .find(|f| f.r#type.concealed() && f.value.is_some())
            .ok_or_else(|| SecretsError::NotFound(name.into()))?;

        Ok(field.value.clone().unwrap())
    }

    /// Get a specific field from a 1Password item.
    pub async fn get_by_field(&self, name: &str, field: &str) -> Result<Secret, SecretsError> {
        let item = self.client.get_item_by_name(name).await?;

        let field = item
            .fields()
            .find(|f| {
                f.label.as_deref().map(|s| s.to_ascii_lowercase())
                    == Some(field.to_ascii_lowercase())
            })
            .ok_or_else(|| SecretsError::NotFound(name.into()))?;

        field
            .value
            .clone()
            .ok_or_else(|| SecretsError::NotFound(name.into()))
    }

    /// Get a specific field in a specifci section of a 1password item.
    pub async fn get_by_section_field(
        &self,
        name: &str,
        section: &str,
        field: &str,
    ) -> Result<Secret, SecretsError> {
        let item = self.client.get_item_by_name(name).await?;

        let section = item
            .sections()
            .find(|s| s.title().eq_ignore_ascii_case(section))
            .ok_or_else(|| SecretsError::NotFound(name.into()))?;

        let field = section
            .fields()
            .find(|f| {
                f.label.as_deref().map(|s| s.to_ascii_lowercase())
                    == Some(field.to_ascii_lowercase())
            })
            .ok_or_else(|| SecretsError::NotFound(name.into()))?;

        field
            .value
            .clone()
            .ok_or_else(|| SecretsError::NotFound(name.into()))
    }
}

/// An error while processing a secret
#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    /// The secret could not be found
    #[error("Secret {0} not found")]
    NotFound(String),

    /// The secret URL was not valid for the format 1Password expected
    #[error("Invalid URL {0}")]
    InvalidUrl(Url),

    /// There was an error from the 1Passwort Client
    #[error(transparent)]
    OnePassword(#[from] OnePasswordError),
}
