//! Serialize Rust values into `multipart/form-data` request bodies.
//!
//! This crate turns any [`serde::Serialize`] value whose top level is a struct
//! or map into a [`Form`]: a collection of named text parts, one per field,
//! that renders into a `multipart/form-data` body.
//!
//! File attachments and other per-part content types are not supported; every
//! field is serialized as a plain text part. Sequence-valued fields (such as
//! `Vec<T>`) emit one part per element, all sharing the field name, and `None`
//! or unit values are omitted.
//!
//! # Examples
//!
//! ```
//! use serde::Serialize;
//!
//! #[derive(Serialize)]
//! struct Message {
//!     subject: String,
//!     to: Vec<String>,
//! }
//!
//! let form = formdata::to_form(&Message {
//!     subject: "Hello".into(),
//!     to: vec!["a@example.com".into(), "b@example.com".into()],
//! })
//! .unwrap();
//!
//! // Three parts: `subject`, and one `to` per recipient.
//! assert_eq!(form.len(), 3);
//!
//! // Use the boundary-aware content type alongside the rendered body.
//! let content_type = form.content_type();
//! let body = form.into_bytes();
//! # let _ = (content_type, body);
//! ```

mod error;
mod ser;

use std::borrow::Cow;
use std::fmt;

use rand::{Rng as _, rng};
use serde::Serialize;

pub use self::error::Error;

/// Serialize a value into a [`Form`].
///
/// The value's top level must serialize as a struct or map; each field becomes
/// a separate part. Sequence-valued fields produce one part per element, all
/// sharing the field name, while `None` and unit values are omitted.
///
/// # Errors
///
/// Returns an [`Error`] if the value is not a struct or map at the top level,
/// or if a field value cannot be represented as form data (for example a nested
/// struct or map, which has no flat form-field representation).
///
/// # Examples
///
/// ```
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Login<'a> {
///     user: &'a str,
///     remember: bool,
/// }
///
/// let form = formdata::to_form(&Login {
///     user: "alice",
///     remember: true,
/// })
/// .unwrap();
/// assert_eq!(form.len(), 2);
/// ```
pub fn to_form<T>(value: &T) -> Result<Form, Error>
where
    T: ?Sized + Serialize,
{
    Ok(Form {
        boundary: generate_boundary(),
        parts: ser::to_parts(value)?,
    })
}

/// A `multipart/form-data` form: a boundary and an ordered list of parts.
///
/// Render the body with [`Form::into_bytes`] or the [`fmt::Display`]
/// implementation, and pair it with the matching [`Form::content_type`].
#[derive(Debug, Clone)]
pub struct Form {
    boundary: String,
    parts: Vec<FormPart>,
}

impl Form {
    /// Create a new, empty form with a freshly generated boundary.
    pub fn new() -> Self {
        Self {
            boundary: generate_boundary(),
            parts: Vec::new(),
        }
    }

    /// Append a part to the form.
    pub fn add_part(&mut self, part: FormPart) {
        self.parts.push(part);
    }

    /// The multipart boundary used to separate parts.
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// The value for the `Content-Type` header, including the boundary.
    ///
    /// ```
    /// let form = formdata::Form::new();
    /// assert!(form.content_type().starts_with("multipart/form-data; boundary="));
    /// ```
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// The parts of the form, in insertion order.
    pub fn parts(&self) -> &[FormPart] {
        &self.parts
    }

    /// The number of parts in the form.
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Whether the form has no parts.
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Render the form into its `multipart/form-data` body as bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.to_string().into_bytes()
    }
}

impl Default for Form {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Form {
    /// Render the multipart body, including the closing boundary delimiter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for part in &self.parts {
            part.render(f, &self.boundary)?;
        }
        f.write_str("--")?;
        f.write_str(&self.boundary)?;
        f.write_str("--\r\n")
    }
}

/// A single named field within a [`Form`].
#[derive(Debug, Clone)]
pub struct FormPart {
    name: Cow<'static, str>,
    data: Cow<'static, str>,
}

impl FormPart {
    /// Create a part with the given field name and value.
    pub fn new(name: impl Into<Cow<'static, str>>, data: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            data: data.into(),
        }
    }

    /// The field name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The field value.
    pub fn data(&self) -> &str {
        &self.data
    }

    /// Write this part, prefixed by its boundary delimiter, to `f`.
    fn render(&self, f: &mut fmt::Formatter<'_>, boundary: &str) -> fmt::Result {
        f.write_str("--")?;
        f.write_str(boundary)?;
        f.write_str("\r\nContent-Disposition: form-data; name=\"")?;
        f.write_str(&escape_field_name(&self.name))?;
        f.write_str("\"\r\n\r\n")?;
        f.write_str(&self.data)?;
        f.write_str("\r\n")
    }
}

/// Escape a field name for use inside a quoted `Content-Disposition` value.
///
/// Quotes, backslashes and line breaks would otherwise break the header, so
/// they are percent-encoded. Field names are usually simple identifiers, in
/// which case the input is returned borrowed and unchanged.
fn escape_field_name(name: &str) -> Cow<'_, str> {
    if name
        .bytes()
        .any(|b| matches!(b, b'"' | b'\\' | b'\r' | b'\n'))
    {
        let mut escaped = String::with_capacity(name.len() + 8);
        for ch in name.chars() {
            match ch {
                '"' => escaped.push_str("%22"),
                '\\' => escaped.push_str("%5C"),
                '\r' => escaped.push_str("%0D"),
                '\n' => escaped.push_str("%0A"),
                other => escaped.push(other),
            }
        }
        Cow::Owned(escaped)
    } else {
        Cow::Borrowed(name)
    }
}

/// Generate a random boundary that is exceedingly unlikely to appear in any
/// part's content.
fn generate_boundary() -> String {
    let mut rng = rng();
    let value: u128 = rng.random();
    format!("FormDataBoundary{value:032x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[test]
    fn simple_struct_produces_one_part_per_field() {
        #[derive(Serialize)]
        struct Login<'a> {
            user: &'a str,
            attempts: u32,
            remember: bool,
        }

        let form = to_form(&Login {
            user: "alice",
            attempts: 3,
            remember: true,
        })
        .unwrap();

        let parts: Vec<_> = form.parts().iter().map(|p| (p.name(), p.data())).collect();
        assert_eq!(
            parts,
            vec![("user", "alice"), ("attempts", "3"), ("remember", "true")]
        );
    }

    #[test]
    fn sequences_repeat_the_field_name() {
        #[derive(Serialize)]
        struct Form {
            to: Vec<&'static str>,
        }

        let form = to_form(&Form {
            to: vec!["a@example.com", "b@example.com"],
        })
        .unwrap();

        let parts: Vec<_> = form.parts().iter().map(|p| (p.name(), p.data())).collect();
        assert_eq!(
            parts,
            vec![("to", "a@example.com"), ("to", "b@example.com")]
        );
    }

    #[test]
    fn none_and_unit_values_are_skipped() {
        #[derive(Serialize)]
        struct Form {
            present: Option<&'static str>,
            absent: Option<&'static str>,
            empty: Vec<&'static str>,
        }

        let form = to_form(&Form {
            present: Some("yes"),
            absent: None,
            empty: vec![],
        })
        .unwrap();

        let parts: Vec<_> = form.parts().iter().map(|p| (p.name(), p.data())).collect();
        assert_eq!(parts, vec![("present", "yes")]);
    }

    #[test]
    fn flattened_fields_are_merged() {
        #[derive(Serialize)]
        struct Outer {
            id: u32,
            #[serde(flatten)]
            inner: Inner,
        }

        #[derive(Serialize)]
        struct Inner {
            kind: &'static str,
            note: Option<&'static str>,
        }

        let form = to_form(&Outer {
            id: 7,
            inner: Inner {
                kind: "alert",
                note: None,
            },
        })
        .unwrap();

        let parts: Vec<_> = form.parts().iter().map(|p| (p.name(), p.data())).collect();
        assert_eq!(parts, vec![("id", "7"), ("kind", "alert")]);
    }

    #[test]
    fn unit_enum_variants_serialize_as_their_name() {
        #[derive(Serialize)]
        #[serde(rename_all = "lowercase")]
        enum Priority {
            Low,
            High,
        }

        #[derive(Serialize)]
        struct Form {
            priority: Priority,
            fallback: Priority,
        }

        let form = to_form(&Form {
            priority: Priority::High,
            fallback: Priority::Low,
        })
        .unwrap();
        assert_eq!(form.parts()[0].data(), "high");
        assert_eq!(form.parts()[1].data(), "low");
    }

    #[test]
    fn custom_string_serialization_is_used() {
        // A type that serializes via `serialize_str`, like an email address.
        struct Email(&'static str);

        impl Serialize for Email {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.0)
            }
        }

        #[derive(Serialize)]
        struct Form {
            from: Email,
        }

        let form = to_form(&Form {
            from: Email("dev@example.com"),
        })
        .unwrap();
        assert_eq!(form.parts()[0].data(), "dev@example.com");
    }

    #[test]
    fn maps_are_supported_as_the_top_level() {
        use std::collections::BTreeMap;

        let mut map = BTreeMap::new();
        map.insert("b", "2");
        map.insert("a", "1");

        let form = to_form(&map).unwrap();
        let parts: Vec<_> = form.parts().iter().map(|p| (p.name(), p.data())).collect();
        // BTreeMap iterates in sorted key order.
        assert_eq!(parts, vec![("a", "1"), ("b", "2")]);
    }

    #[test]
    fn rendering_matches_the_multipart_grammar() {
        let mut form = Form::new();
        form.add_part(FormPart::new("a", "1"));
        form.add_part(FormPart::new("b", "two"));

        let boundary = form.boundary().to_owned();
        let expected = format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"a\"\r\n\r\n\
             1\r\n\
             --{boundary}\r\n\
             Content-Disposition: form-data; name=\"b\"\r\n\r\n\
             two\r\n\
             --{boundary}--\r\n"
        );
        assert_eq!(form.to_string(), expected);
    }

    #[test]
    fn field_names_with_quotes_are_escaped() {
        let mut form = Form::new();
        form.add_part(FormPart::new("we\"ird", "v"));
        assert!(
            form.to_string()
                .contains("Content-Disposition: form-data; name=\"we%22ird\"")
        );
    }

    #[test]
    fn empty_form_renders_only_the_closing_boundary() {
        let form = Form::new();
        let boundary = form.boundary().to_owned();
        assert_eq!(form.to_string(), format!("--{boundary}--\r\n"));
        assert!(form.is_empty());
    }

    #[test]
    fn non_map_top_level_is_rejected() {
        let err = to_form(&42_u32).unwrap_err();
        assert!(matches!(err, Error::TopLevel(_)));
    }

    #[test]
    fn nested_struct_value_is_rejected() {
        #[derive(Serialize)]
        struct Outer {
            inner: Inner,
        }

        #[derive(Serialize)]
        struct Inner {
            x: u32,
        }

        let err = to_form(&Outer {
            inner: Inner { x: 1 },
        })
        .unwrap_err();
        assert!(matches!(err, Error::UnsupportedValue(_)));
    }

    #[test]
    fn boundaries_are_unique_per_form() {
        assert_ne!(Form::new().boundary(), Form::new().boundary());
    }
}
