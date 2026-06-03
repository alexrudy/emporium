//! OAuth2 scope types.
//!
//! Per RFC 6749 §3.3, a scope is a list of space-separated tokens drawn
//! from a restricted ASCII charset. [`Scope`] represents a single token;
//! [`ScopeSet`] represents the wire-level list.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Reasons a scope token may be rejected.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ScopeError {
    /// The scope token was empty.
    #[error("scope token must contain at least one character")]
    Empty,
    /// The scope token contained a character outside the RFC 6749 §3.3 charset.
    #[error("scope token contained invalid character: {0:?}")]
    InvalidChar(char),
}

/// A single OAuth2 scope token (RFC 6749 §3.3).
///
/// Valid characters are `%x21`, `%x23-5B`, and `%x5D-7E` — printable ASCII
/// excluding space (`0x20`), double-quote (`0x22`), and backslash (`0x5C`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Scope(Cow<'static, str>);

impl Scope {
    /// Construct a [`Scope`] from any string-like value, validating
    /// against the RFC 6749 §3.3 charset.
    pub fn new(value: impl Into<Cow<'static, str>>) -> Result<Self, ScopeError> {
        let value = value.into();
        validate(&value)?;
        Ok(Self(value))
    }

    /// Construct a [`Scope`] from a static string, panicking on invalid
    /// input. Intended for compile-time-known literals where the input is
    /// trusted.
    ///
    /// # Panics
    ///
    /// Panics if `value` contains characters outside the RFC 6749 §3.3 charset.
    pub fn from_static(value: &'static str) -> Self {
        match Self::new(Cow::Borrowed(value)) {
            Ok(scope) => scope,
            Err(err) => panic!("invalid scope {value:?}: {err}"),
        }
    }

    /// The underlying scope-token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate(s: &str) -> Result<(), ScopeError> {
    if s.is_empty() {
        return Err(ScopeError::Empty);
    }
    for c in s.chars() {
        let valid = matches!(c as u32, 0x21 | 0x23..=0x5B | 0x5D..=0x7E);
        if !valid {
            return Err(ScopeError::InvalidChar(c));
        }
    }
    Ok(())
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Scope {
    type Err = ScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl TryFrom<&str> for Scope {
    type Error = ScopeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_owned())
    }
}

impl TryFrom<String> for Scope {
    type Error = ScopeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A space-separated set of OAuth2 scope tokens (RFC 6749 §3.3).
///
/// The wire representation is a single string with scope tokens separated
/// by spaces. `ScopeSet` round-trips through this format via
/// [`Display`](fmt::Display) / [`FromStr`] and via serde.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSet(Vec<Scope>);

impl ScopeSet {
    /// Create an empty set.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Append a scope to the set.
    pub fn push(&mut self, scope: Scope) {
        self.0.push(scope);
    }

    /// Iterate the scopes in insertion order.
    pub fn iter(&self) -> std::slice::Iter<'_, Scope> {
        self.0.iter()
    }

    /// Number of scopes in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set contains no scopes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for scope in &self.0 {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            fmt::Display::fmt(scope, f)?;
        }
        Ok(())
    }
}

impl FromStr for ScopeSet {
    type Err = ScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split(' ')
            .filter(|tok| !tok.is_empty())
            .map(Scope::from_str)
            .collect()
    }
}

impl FromIterator<Scope> for ScopeSet {
    fn from_iter<I: IntoIterator<Item = Scope>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a ScopeSet {
    type Item = &'a Scope;
    type IntoIter = std::slice::Iter<'a, Scope>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl Serialize for ScopeSet {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = ScopeSet;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a space-separated OAuth2 scope string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                value.parse().map_err(de::Error::custom)
            }
        }
        de.deserialize_str(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scope_rejected() {
        assert_eq!(Scope::new("".to_owned()).unwrap_err(), ScopeError::Empty);
    }

    #[test]
    fn scope_rejects_space_quote_backslash() {
        for bad in [" ", "a b", "with\"quote", "back\\slash"] {
            assert!(matches!(
                Scope::new(bad.to_owned()),
                Err(ScopeError::InvalidChar(_))
            ));
        }
    }

    #[test]
    fn scope_accepts_typical_tokens() {
        for ok in [
            "read",
            "write",
            "read:things",
            "openid",
            "user.read",
            "api://x/y",
        ] {
            Scope::new(ok.to_owned()).unwrap_or_else(|e| panic!("{ok:?} should be valid: {e}"));
        }
    }

    #[test]
    fn from_static_panics_on_invalid() {
        let result = std::panic::catch_unwind(|| Scope::from_static("has space"));
        assert!(result.is_err());
    }

    #[test]
    fn scopeset_display_roundtrips() {
        let set: ScopeSet = "openid profile email".parse().unwrap();
        assert_eq!(set.to_string(), "openid profile email");
    }

    #[test]
    fn scopeset_skips_empty_tokens() {
        let set: ScopeSet = "  openid   profile  ".parse().unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(set.to_string(), "openid profile");
    }

    #[test]
    fn scopeset_serde_roundtrip() {
        let original: ScopeSet = "read write admin".parse().unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"read write admin\"");
        let parsed: ScopeSet = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn scopeset_empty_serializes_to_empty_string() {
        let empty = ScopeSet::new();
        let json = serde_json::to_string(&empty).unwrap();
        assert_eq!(json, "\"\"");
    }
}
