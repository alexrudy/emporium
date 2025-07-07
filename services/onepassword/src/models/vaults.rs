//! Models for working with 1Password Vaults

use std::ops::Deref;

use api_client::ApiClient;
use serde::Deserialize;

use crate::client::{Kind, OnePassowrdResponse, OnePasswordApiAuthentication, OnePasswordError};

use super::items::{Category, Item, ItemID, ItemInfo};

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

/// The summary returned when items are queried.
#[derive(Debug, Clone, Deserialize)]
pub struct ItemSummary {
    /// Identifier of the item
    pub id: ItemID,

    /// Title of the item
    pub title: String,

    /// OnePassword Category of the item
    pub category: Category,
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

    /// Access the inner API Client
    pub fn api_client(&self) -> &ApiClient<OnePasswordApiAuthentication> {
        &self.client
    }

    /// Get the name of the vault.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get all items with the given name.
    pub async fn get_items_by_name(
        &self,
        name: &str,
    ) -> Result<Vec<ItemSummary>, OnePasswordError> {
        let query = format!("title eq \"{name}\"");

        let response = self
            .client
            .get(&format!("/v1/vaults/{vault}/items", vault = self.id))
            .query(&[&("filter", query)])?
            .send()
            .await?;

        response.deserialize().await
    }

    /// Look for an item in the vault by name.
    pub async fn get_item_by_name(&self, name: &str) -> Result<Item, OnePasswordError> {
        let query = format!("title eq \"{name}\"");

        let response = self
            .client
            .get(&format!("/v1/vaults/{vault}/items", vault = self.id))
            .query(&[&("filter", query)])?
            .send()
            .await?;

        let mut items: Vec<ItemSummary> = response.deserialize().await?;

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
            .await?;

        let info: ItemInfo = response.deserialize().await?;

        Ok(Item::new(info, self.client.clone()))
    }
}
