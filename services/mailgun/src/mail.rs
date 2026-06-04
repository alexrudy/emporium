//! Provides types for working with email addresses and email messages.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// Represents an email address with an optional name and email address.
#[derive(Debug, Clone)]
pub struct EmailAddress {
    /// Friendly name for the email address.
    pub name: Option<String>,

    /// Email address.
    pub email: String,
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = &self.name {
            write!(f, "{} <{}>", name, self.email)
        } else {
            write!(f, "{}", self.email)
        }
    }
}

impl Serialize for EmailAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Error parsing an email address
#[derive(Debug, thiserror::Error)]
pub enum ParseEmailError {}

impl FromStr for EmailAddress {
    type Err = ParseEmailError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((name, address)) = s.rsplit_once(' ') {
            Ok(Self {
                name: Some(name.to_string()),
                email: address
                    .strip_prefix('<')
                    .and_then(|s| s.strip_suffix('>'))
                    .unwrap_or(address)
                    .to_string(),
            })
        } else {
            Ok(Self {
                name: None,
                email: s.to_string(),
            })
        }
    }
}

impl<'de> Deserialize<'de> for EmailAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EmailVisitor;

        impl<'de> serde::de::Visitor<'de> for EmailVisitor {
            type Value = EmailAddress;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an email address")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                EmailAddress::from_str(v).map_err(|e| serde::de::Error::custom(e))
            }
        }

        deserializer.deserialize_str(EmailVisitor)
    }
}

/// Represents an email message to be sent via Mailgun.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The sender of the email.
    pub from: EmailAddress,

    /// The recipients of the email.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<EmailAddress>,

    /// The CC recipients of the email.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<EmailAddress>,

    /// The BCC recipients of the email.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bcc: Vec<EmailAddress>,

    /// The subject of the email.
    pub subject: String,

    /// The body of the email.
    #[serde(flatten)]
    pub body: Body,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            from: EmailAddress {
                name: None,
                email: "dev@example.com".into(),
            },
            to: Default::default(),
            cc: Default::default(),
            bcc: Default::default(),
            subject: Default::default(),
            body: Default::default(),
        }
    }
}

/// Represents the body of an email message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Body {
    /// The HTML body of the email.
    pub html: Option<Html>,

    /// The text body of the email.
    pub text: Option<Text>,
}

/// Represents the HTML body of an email message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Html(pub String);

impl From<Html> for Body {
    fn from(html: Html) -> Self {
        Self {
            html: Some(html),
            text: None,
        }
    }
}

/// Represents the text body of an email message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Text(pub String);

impl From<Text> for Body {
    fn from(text: Text) -> Self {
        Self {
            html: None,
            text: Some(text),
        }
    }
}

/// Represents the response from the MailGun API after sending an email.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageResponse {
    /// The unique identifier of the email message.
    pub id: String,

    /// A human-readable message indicating the result of the email send operation.
    pub message: String,
}
