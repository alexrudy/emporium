//! 1Password Items

use api_client::{Secret, response::ResponseBodyExt as _};
use camino::Utf8PathBuf;
use serde::Deserialize;

use super::vaults::VaultID;

type Client = api_client::ApiClient<crate::client::OnePasswordApiAuthentication>;

crate::newtype!(pub ItemID);

/// Information about a Vault.
#[derive(Debug, Clone, Deserialize)]
pub struct VaultInfo {
    /// The 1password identifier for this vault.
    pub id: VaultID,
}

/// Information about an item in 1Password
#[derive(Debug, Clone, Deserialize)]
pub struct ItemInfo {
    /// The 1password identifier for this item.
    pub id: ItemID,

    /// The title of this item.
    pub title: String,

    /// The vault this item belongs to.
    pub vault: VaultInfo,

    /// The set of tags for this item.
    pub tags: Option<Vec<String>>,

    /// The set of fields for this item
    pub fields: Option<Vec<Field>>,

    /// Subsections included in this item
    sections: Option<Vec<Section>>,

    /// Information about attachments
    files: Option<Vec<FileInfo>>,
}

/// API Object representing a 1password item
#[derive(Debug, Clone)]
pub struct Item {
    info: ItemInfo,
    pub(crate) client: Client,
}

impl Item {
    pub(crate) fn new(info: ItemInfo, client: Client) -> Self {
        Self { info, client }
    }

    /// Access the inner API Client
    pub fn api_client(&self) -> &Client {
        &self.client
    }

    /// Get the identifier for this item.
    pub fn id(&self) -> &ItemID {
        &self.info.id
    }

    /// Get the title for this item.
    pub fn title(&self) -> &str {
        &self.info.title
    }

    /// Iterates over the tags for this item.
    pub fn tags(&self) -> impl Iterator<Item = &'_ str> + '_ {
        self.info.tags.iter().flatten().map(|s| s.as_str())
    }

    /// Get the vault identifier for this item.
    pub fn vault(&self) -> &VaultID {
        &self.info.vault.id
    }

    /// Iterates over the sections for this item.
    pub fn sections(&self) -> impl Iterator<Item = SectionRef<'_>> + '_ {
        self.info.sections.iter().flatten().map(|s| SectionRef {
            item: self,
            section: s,
        })
    }

    /// Iterates over the files for this item.
    pub fn files(&self) -> impl Iterator<Item = File<'_>> + '_ {
        let client = &self.client;
        self.info.files.iter().flatten().map(move |f| File {
            info: f,
            client: client.clone(),
        })
    }

    /// Iterates over the fields for this item.
    pub fn fields(&self) -> impl Iterator<Item = &'_ Field> + '_ {
        self.info.fields.iter().flatten()
    }

    /// Get a section by title.
    pub fn get_section(&self, title: &str) -> Option<SectionRef<'_>> {
        self.info
            .sections
            .iter()
            .flatten()
            .find(|s| s.label.eq_ignore_ascii_case(title))
            .map(|s| SectionRef {
                item: self,
                section: s,
            })
    }

    /// Get a file by attachment name.
    pub fn get_file(&self, name: &str) -> Option<File<'_>> {
        self.info
            .files
            .iter()
            .flatten()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| File {
                info: f,
                client: self.client.clone(),
            })
    }
}

/// A reference to a section in a 1password item.
#[derive(Debug, Clone)]
pub struct SectionRef<'i> {
    item: &'i Item,
    section: &'i Section,
}

impl<'i> SectionRef<'i> {
    /// Get the title of the section
    pub fn title(&self) -> &str {
        &self.section.label
    }

    /// Get the ID of the section
    pub fn id(&self) -> &SectionID {
        &self.section.id
    }

    /// Get the fields in the section
    pub fn fields(&self) -> impl Iterator<Item = &'i Field> + 'i {
        let section = self.section;
        self.item.info.fields.iter().flatten().filter(move |f| {
            f.section
                .as_ref()
                .map(|s| s.id == section.id)
                .unwrap_or(false)
        })
    }

    /// Get the files in the section
    pub fn files(&self) -> impl Iterator<Item = File<'i>> + 'i {
        let section = self.section;
        let client = &self.item.client;
        self.item
            .info
            .files
            .iter()
            .flatten()
            .filter(move |f| f.section.id == section.id)
            .map(|f| File {
                info: f,
                client: client.clone(),
            })
    }
}

crate::newtype!(pub SectionID);

/// Information about a section in an item.
#[derive(Debug, Clone, Deserialize)]
pub struct SectionInfo {
    /// The ID of the section.
    pub id: SectionID,
}

crate::newtype!(pub FieldID);

/// Different typed fields in a 1password item
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FieldType {
    /// A string field.
    String,
    /// An email field.
    Email,
    /// A concealed field.
    Concealed,
    /// A URL field.
    Url,
    /// An OTP field.
    Otp,
    /// A date field.
    Date,
    /// A month-year field.
    MonthYear,
    /// A menu field.
    Menu,
}

impl FieldType {
    /// Returns true if the field type is concealed.
    pub fn concealed(&self) -> bool {
        matches!(self, Self::Concealed)
    }
}

/// Represents a field in a 1password item.
#[derive(Debug, Clone, Deserialize)]
pub struct Field {
    /// The ID of the field.
    pub id: FieldID,
    /// The type of the field.
    pub r#type: FieldType,
    /// The label of the field.
    pub label: Option<String>,
    /// The value of the field.
    pub value: Option<Secret>,
    /// The section of the field.
    pub section: Option<SectionInfo>,
}

crate::newtype!(pub FileID);

/// A file object attached to the item.
#[derive(Debug, Clone, Deserialize)]
pub struct FileInfo {
    /// The ID of the file.
    pub id: FileID,
    /// The name of the file.
    pub name: String,
    /// The size of the file in bytes.
    pub size: u64,
    /// The path to the file content.
    pub content_path: Utf8PathBuf,
    /// The section of the file.
    pub section: SectionInfo,
}

/// A file object with the client available.
#[derive(Debug, Clone)]
pub struct File<'i> {
    info: &'i FileInfo,
    client: Client,
}

impl<'i> File<'i> {
    /// The size of the file in bytes.
    pub fn filesize(&self) -> u64 {
        self.info.size
    }

    /// Download the contents of the file and collect it in a Vec<u8> of bytes.
    pub async fn content(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        self.client
            .get(self.info.content_path.as_str())
            .send()
            .await?
            .bytes()
            .await
            .map(|b| b.to_vec())
    }
}

/// A section in a 1password item
#[derive(Debug, Clone, Deserialize)]
pub struct Section {
    /// Id of the section
    pub id: SectionID,

    /// User-facing label of the section
    pub label: String,
}
