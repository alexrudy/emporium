use std::{borrow::Cow, str::Utf8Error};

use api_client::Secret;
use thiserror::Error;
use url::Url;

use crate::{
    OnePassword,
    client::{Kind, OnePasswordError},
    models::{items::Item, vaults::Vault},
};

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

fn percent_decode(text: &str) -> Result<Cow<'_, str>, Utf8Error> {
    percent_encoding::percent_decode(text.as_bytes()).decode_utf8()
}

impl crate::OnePasswordConfig {
    /// Create a new 1Password configuration from environment variables.
    pub fn from_environment() -> Result<Self, OnePasswordError> {
        let client = crate::ClientConfig::from_environment()?;
        let vault = read_env_var(VAULT)?;

        Ok(Self {
            client: Some(client),
            vault,
        })
    }
}

impl crate::ClientConfig {
    /// Construct a client config from the cannonical environment variables.
    pub fn from_environment() -> Result<Self, OnePasswordError> {
        let host: http::Uri = read_env_var(HOST)?.parse().map_err(|_| {
            OnePasswordError::Configuration(format!("Environment variable {HOST} not a URL!"))
        })?;

        let token = read_env_var(TOKEN)?;

        Ok(Self {
            token: token.into(),
            host,
        })
    }
}

#[derive(Debug, Error)]
pub enum InvalidSecretUrl {
    #[error("Unexpected URL scheme, expected op://")]
    UnexpectedScheme,

    #[error("Missing path segments (must have at least op://<vault>/<item>/<field>")]
    MissingPathSegments,

    #[error("The URL host component is missing (it should be the name of the 1Password vault)")]
    MissingVault,

    #[error("The percent decoding of {field} yeilded non-utf-8 characters")]
    Utf8Error { field: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretReference<'s> {
    vault: Cow<'s, str>,
    item: Cow<'s, str>,
    section: Option<Cow<'s, str>>,
    field: Cow<'s, str>,
}

impl<'s> SecretReference<'s> {
    pub fn parse(url: &'s Url) -> Result<SecretReference<'s>, InvalidSecretUrl> {
        if url.scheme() != "op" {
            return Err(InvalidSecretUrl::UnexpectedScheme);
        }

        if url.path_segments().map(|c| c.count()).unwrap_or(0) < 2 {
            return Err(InvalidSecretUrl::MissingPathSegments);
        }

        let vault = url.host_str().ok_or(InvalidSecretUrl::MissingVault)?;

        let mut segments = url
            .path_segments()
            .ok_or(InvalidSecretUrl::MissingPathSegments)?;

        let item = percent_decode(segments.next().unwrap())
            .map_err(|_| InvalidSecretUrl::Utf8Error { field: "name" })?;
        let field = percent_decode(segments.next_back().unwrap())
            .map_err(|_| InvalidSecretUrl::Utf8Error { field: "field" })?;
        let section = segments
            .next()
            .map(percent_decode)
            .transpose()
            .map_err(|_| InvalidSecretUrl::Utf8Error { field: "section" })?;

        Ok(Self {
            vault: vault.into(),
            item,
            section,
            field,
        })
    }
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

    /// Access the inner API Client
    pub fn api_client(
        &self,
    ) -> &api_client::ApiClient<crate::client::OnePasswordApiAuthentication> {
        self.client.api_client()
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

        let reference = SecretReference::parse(&url).map_err(|error| SecretsError {
            kind: SecretsErrorKind::InvalidUrl(error),
            url: url.clone(),
        })?;

        self.get_reference(&reference, &url).await
    }

    async fn get_reference(
        &self,
        reference: &SecretReference<'_>,
        url: &Url,
    ) -> Result<Secret, SecretsError> {
        if let Some(section) = &reference.section {
            self.get_by_section_field(&reference.item, section, &reference.field)
                .await
        } else {
            self.get_by_field(&reference.item, &reference.field).await
        }
        .map_err(|error| SecretsError {
            kind: error,
            url: url.clone(),
        })
    }

    async fn get_item(&self, name: &str) -> Result<Item, OnePasswordError> {
        let mut items = self.client.get_items_by_name(name).await?;
        items.retain(|item| item.category.is_secret());
        let summary = items
            .pop()
            .ok_or_else(|| OnePasswordError::NotFound(Kind::Item, format!("{name} as secret")))?;

        self.client.get_item(&summary.id).await
    }

    /// Get a 1password secret by item name. Will take the first concealed, non-empty field
    /// in the item.
    pub async fn get_by_name(&self, name: &str) -> Result<Secret, OnePasswordError> {
        let item = self.get_item(name).await?;

        let field = item
            .concealed()
            .find(|f| f.value.is_some())
            .ok_or_else(|| OnePasswordError::NotFound(crate::client::Kind::Item, name.into()))?;

        Ok(field.value.clone().unwrap())
    }

    /// Get a specific field from a 1Password item.
    async fn get_by_field(&self, name: &str, field: &str) -> Result<Secret, SecretsErrorKind> {
        let item = self.get_item(name).await?;

        let field = item
            .fields()
            .find(|f| {
                f.label.as_deref().map(|s| s.to_ascii_lowercase())
                    == Some(field.to_ascii_lowercase())
            })
            .ok_or_else(|| SecretsErrorKind::NotFound(name.into()))?;

        field
            .value
            .clone()
            .ok_or_else(|| SecretsErrorKind::NotFound(name.into()))
    }

    /// Get a specific field in a specifci section of a 1password item.
    async fn get_by_section_field(
        &self,
        name: &str,
        section: &str,
        field: &str,
    ) -> Result<Secret, SecretsErrorKind> {
        let item = self.get_item(name).await?;

        let section = item
            .sections()
            .find(|s| {
                s.title()
                    .is_some_and(|title| title.eq_ignore_ascii_case(section))
            })
            .ok_or_else(|| SecretsErrorKind::NotFound(name.into()))?;

        let field = section
            .fields()
            .find(|f| {
                f.label.as_deref().map(|s| s.to_ascii_lowercase())
                    == Some(field.to_ascii_lowercase())
            })
            .ok_or_else(|| SecretsErrorKind::NotFound(name.into()))?;

        field
            .value
            .clone()
            .ok_or_else(|| SecretsErrorKind::NotFound(name.into()))
    }
}

impl From<Vault> for SecretManager {
    fn from(vault: Vault) -> Self {
        SecretManager { client: vault }
    }
}

/// An error while processing a secret
#[derive(Debug, thiserror::Error)]
pub enum SecretsErrorKind {
    /// The secret could not be found
    #[error("Secret {0} not found")]
    NotFound(String),

    /// The secret URL was not valid for the format 1Password expected
    #[error("Invalid URL {0}")]
    InvalidUrl(InvalidSecretUrl),

    /// There was an error from the 1Passwort Client
    #[error(transparent)]
    OnePassword(#[from] OnePasswordError),
}

/// An error returned while processing a secret.
#[derive(Debug, thiserror::Error)]
#[error("Secret '{url}' error: {kind}")]
pub struct SecretsError {
    #[source]
    kind: SecretsErrorKind,
    url: Url,
}

impl SecretsError {
    /// Inner error type
    pub fn kind(&self) -> &SecretsErrorKind {
        &self.kind
    }

    /// URL of this secret
    pub fn url(&self) -> &Url {
        &self.url
    }
}
