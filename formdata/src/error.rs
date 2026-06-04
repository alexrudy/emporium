//! Error type for form-data serialization.

use std::fmt::Display;

/// Errors that can occur while serializing a value into multipart form data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A custom error message produced by [`serde`] during serialization.
    #[error("{0}")]
    Custom(String),

    /// The top-level value was not a struct or map.
    ///
    /// Multipart form data is a collection of named fields, so the value passed
    /// to [`to_form`](crate::to_form) must serialize as a struct or a map. The
    /// payload describes what was found instead.
    #[error("form data must be a struct or map, found {0}")]
    TopLevel(&'static str),

    /// A field value could not be represented as a form field.
    ///
    /// Nested structs, maps and similar compound values have no unambiguous
    /// representation as flat form fields and are rejected. The payload
    /// describes the offending value.
    #[error("cannot serialize {0} as a form field value")]
    UnsupportedValue(&'static str),

    /// A map key could not be represented as a field name.
    ///
    /// Field names must be strings (or values that serialize as strings). The
    /// payload describes the offending key.
    #[error("form field names must be strings, found {0}")]
    UnsupportedKey(&'static str),
}

impl serde::ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Custom(msg.to_string())
    }
}
