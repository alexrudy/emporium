use std::fmt;
use std::ops::Deref;

use api_client::{
    ApiClient, Authentication, Secret,
    response::{ResponseBodyExt as _, ResponseExt as _},
};
use serde::de::DeserializeOwned;

use crate::models::vaults::{Vault, VaultSummary};

#[derive(Debug, Clone)]
pub struct OnePasswordApiAuthentication {
    token: Secret,
}

impl OnePasswordApiAuthentication {
    pub fn new(token: Secret) -> Self {
        Self { token }
    }
}

impl Authentication for OnePasswordApiAuthentication {
    fn authenticate<B>(&self, mut req: http::Request<B>) -> http::Request<B> {
        let hdrs = req.headers_mut();

        hdrs.append(
            http::header::CONTENT_TYPE,
            http::header::HeaderValue::from_static("application/json"),
        );

        let mut value = http::HeaderValue::from_str(&format!("Bearer {}", self.token.revealed()))
            .expect("authorization should be a valid http header value");
        value.set_sensitive(true);

        hdrs.append(http::header::AUTHORIZATION, value);

        req
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Vault,
    Item,
    File,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Kind::Vault => write!(f, "Vault"),
            Kind::Item => write!(f, "Item"),
            Kind::File => write!(f, "File"),
        }
    }
}

/// Error when working with 1Password vaults
#[derive(Debug, thiserror::Error)]
pub enum OnePasswordError {
    /// Some entity was not found
    #[error("{0} {1} not found")]
    NotFound(Kind, String),

    /// More than 1 entity was found, but a unique entity was requested.
    #[error("Multiple {0}s named {1} found")]
    MultipleFound(Kind, String),

    /// Some configuration error for 1password
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// An API request encountered an error.
    #[error(transparent)]
    Request(#[from] api_client::Error),

    /// An API response returned an error.
    #[error("Response error: {status} {message}")]
    Response {
        /// The HTTP status code
        status: http::StatusCode,
        /// The HTTP body returned with the status code.
        message: String,
    },
}

impl From<http::Error> for OnePasswordError {
    fn from(value: http::Error) -> Self {
        Self::Request(value.into())
    }
}

impl From<hyperdriver::client::Error> for OnePasswordError {
    fn from(value: hyperdriver::client::Error) -> Self {
        Self::Request(value.into())
    }
}

/// A client for accessing 1Password secrets
#[derive(Debug, Clone)]
pub struct OnePassword {
    pub(crate) client: ApiClient<OnePasswordApiAuthentication>,
}

impl OnePassword {
    /// Create a new 1Password client.
    pub fn new<S: Into<Secret>>(host: http::Uri, token: S) -> Self {
        let client = ApiClient::new(host, OnePasswordApiAuthentication::new(token.into()));
        Self { client }
    }

    /// Access the inner API Client
    pub fn api_client(&self) -> &ApiClient<OnePasswordApiAuthentication> {
        &self.client
    }
}

impl From<ApiClient<OnePasswordApiAuthentication>> for OnePassword {
    fn from(client: ApiClient<OnePasswordApiAuthentication>) -> Self {
        Self { client }
    }
}

impl OnePassword {
    /// Get a vault by name
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn get_vault(&self, name: &str) -> Result<Vault, OnePasswordError> {
        let query = format!("name eq \"{name}\"");
        tracing::trace!("Searching for vaults with query: {query}");
        let response = self
            .client
            .get("v1/vaults")
            .query(&[&("filter", query)])?
            .send()
            .await?;

        let mut vaults: Vec<VaultSummary> = response.deserialize().await?;

        tracing::trace!("Found {} vaults", vaults.len());
        match vaults.deref() {
            [] => Err(OnePasswordError::NotFound(Kind::Vault, name.into())),
            [_] => Ok(()),
            _ => Err(OnePasswordError::MultipleFound(Kind::Vault, name.into())),
        }?;

        let vault = vaults.pop().unwrap();
        tracing::debug!(vault = ?vault.id, "Found vault");
        Ok(Vault::new(vault, self.client.clone()))
    }
}

pub(crate) trait OnePassowrdResponse: Sized {
    async fn deserialize<T>(self) -> Result<T, OnePasswordError>
    where
        T: DeserializeOwned;
}

impl OnePassowrdResponse for api_client::response::Response {
    async fn deserialize<T>(self) -> Result<T, OnePasswordError>
    where
        T: DeserializeOwned,
    {
        if !self.status().is_success() {
            if self.status().is_client_error() || self.status().is_server_error() {
                tracing::error!("Error response from onepassword: {:?}", self.status());
            }

            let status = self.status();
            let message = self.text().await.unwrap_or_else(|_| "No message".into());
            return Err(OnePasswordError::Response { status, message });
        }

        self.json()
            .await
            .map_err(|err| OnePasswordError::Request(api_client::Error::ResponseBody(err)))
    }
}
