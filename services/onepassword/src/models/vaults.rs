//! Models for working with 1Password Vaults

use std::ops::Deref;

use api_client::{
    ApiClient,
    response::{ResponseBodyExt as _, ResponseExt as _},
};
use serde::Deserialize;

use crate::client::{Kind, OnePasswordApiAuthentication, OnePasswordError};

use super::items::{Item, ItemID, ItemInfo};

crate::newtype!(pub VaultID);

/// The API object returned when looking for vaults
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VaultSummary {
    pub(crate) id: VaultID,
    pub(crate) name: String,
}

/// A Vault contains a collection of 1password items
#[derive(Debug, Clone)]
pub struct Vault {
    /// Identifier of the vault
    pub id: VaultID,
    name: String,
    client: ApiClient<OnePasswordApiAuthentication>,
}

#[derive(Debug, Clone, Deserialize)]
struct ItemSummary {
    id: ItemID,
}

impl Vault {
    pub(crate) fn new(
        summary: VaultSummary,
        client: ApiClient<OnePasswordApiAuthentication>,
    ) -> Self {
        Self {
            id: summary.id,
            name: summary.name,
            client,
        }
    }

    /// Get the name of the vault.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Look for an item in the vault by name.
    pub async fn get_item_by_name(&self, name: &str) -> Result<Item, OnePasswordError> {
        let query = format!("title eq \"{name}\"");

        let response = self
            .client
            .get(&format!("/v1/vaults/{vault}/items", vault = self.id))
            .query(&[&("filter", query)])
            .map_err(OnePasswordError::Request)?
            .send()
            .await
            .map_err(|err| OnePasswordError::Request(api_client::Error::Request(err)))?;

        if !response.status().is_success() {
            if response.status().is_client_error() || response.status().is_server_error() {
                tracing::error!("Error response from onepassword: {:?}", response.status());
            }

            let status = response.status();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "No message".into());
            return Err(OnePasswordError::Response { status, message });
        }

        let mut items: Vec<ItemSummary> = response
            .json()
            .await
            .map_err(|err| OnePasswordError::Request(api_client::Error::ResponseBody(err)))?;

        match items.deref() {
            [] => Err(OnePasswordError::NotFound(Kind::Item, name.into())),
            [_] => Ok(()),
            _ => Err(OnePasswordError::MultipleFound(Kind::Item, name.into())),
        }?;

        let info = items.pop().unwrap();

        self.get_item(&info.id).await
    }

    /// Look for an item in the vault by ID
    pub async fn get_item(&self, id: &ItemID) -> Result<Item, OnePasswordError> {
        let response = self
            .client
            .get(&format!(
                "/v1/vaults/{vault}/items/{id}",
                vault = self.id,
                id = id
            ))
            .send()
            .await
            .map_err(|err| OnePasswordError::Request(api_client::Error::Request(err)))?;

        if !response.status().is_success() {
            if response.status().is_client_error() || response.status().is_server_error() {
                tracing::error!("Error response from onepassword: {:?}", response.status());
            }

            let status = response.status();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "No message".into());
            return Err(OnePasswordError::Response { status, message });
        }
        let info: ItemInfo = response
            .json()
            .await
            .map_err(|err| OnePasswordError::Request(api_client::Error::ResponseBody(err)))?;

        Ok(Item::new(info, self.client.clone()))
    }
}
