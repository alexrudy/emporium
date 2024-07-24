//! URI utilities.

use ::serde::Serialize;
use camino::Utf8Path;
use http::Uri;
use thiserror::Error;
use url::Url;

/// The provided URL cannot be a base URL,
/// and so is not valid as the base part of an API URL.
#[derive(Debug, Error)]
#[error("cannot be a base URL: {0}")]
pub struct CannotBeABase(url::Url);

/// Errors that can occur when parsing a URI.
#[derive(Debug, Error)]
pub enum ParseUriError {
    /// An error occurred while parsing the URI.
    #[error(transparent)]
    Url(#[from] url::ParseError),

    /// The provided URL cannot be a base URL,
    #[error(transparent)]
    CannotBeABase(#[from] CannotBeABase),

    /// The URI is invalid, but URL parsing succeded.
    #[error("invalid URI: {0}")]
    Invalid(http::uri::InvalidUri),
}

/// Error appending query parameters to a URI.
#[derive(Debug, Error)]
pub enum QueryError {
    /// The new query parameters could not be serialized.
    #[error("failed to serialize query parameters: {0}")]
    Serialize(#[from] serde_urlencoded::ser::Error),

    /// The URI is invalid with new query parameters.
    #[error("uri is not valid: {0}")]
    InvalidUriParts(#[from] http::uri::InvalidUriParts),

    /// The query parameters are invalid
    #[error("uri is not valid: {0}")]
    InvalidUri(#[from] http::uri::InvalidUri),
}

/// Convert a value into a URI.
pub trait IntoUri {
    /// Convert the value into a URI.
    fn into_uri(self) -> Result<Uri, ParseUriError>;
}

impl IntoUri for Url {
    fn into_uri(self) -> Result<Uri, ParseUriError> {
        if self.cannot_be_a_base() {
            return Err(CannotBeABase(self).into());
        }

        match self.as_str().parse() {
            Ok(uri) => Ok(uri),
            Err(e) => Err(ParseUriError::Invalid(e)),
        }
    }
}

impl IntoUri for Uri {
    fn into_uri(self) -> Result<Uri, ParseUriError> {
        Ok(self)
    }
}

impl IntoUri for &str {
    fn into_uri(self) -> Result<Uri, ParseUriError> {
        let url: Url = self.parse()?;
        url.into_uri()
    }
}

/// Serialize and Deserialize a URI to and from a string.
pub mod serde {
    use http::Uri;
    use serde::{Deserialize as _, Deserializer};

    /// Serialize and Deserialize a URI to and from a string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Uri, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }

    /// Serialize a URI as a string
    pub fn serialize<S>(uri: &Uri, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(uri)
    }
}

/// Extension trait for URIs.
pub trait UriExtension {
    /// Join a path to a URI.
    fn join<P: AsRef<str>>(self, path: P) -> Uri;

    /// Replace a query parameter in a URI.
    fn replace_query(self, key: &str, value: &str) -> Uri;

    /// Append query parameters to a URI.
    fn append_query<T: Serialize + ?Sized>(self, query: &T) -> Result<Uri, QueryError>;

    /// Remove all query parameters from a URI.
    fn clear_query(self) -> Uri;
}

impl UriExtension for Uri {
    fn join<P: AsRef<str>>(self, path: P) -> Uri {
        let mut parts = self.into_parts();

        parts.path_and_query = parts.path_and_query.as_ref().map(|pq| {
            let joined = Utf8Path::new(pq.path()).join(path.as_ref());
            http::uri::PathAndQuery::from_maybe_shared(joined.to_string()).unwrap()
        });
        Uri::from_parts(parts).unwrap()
    }

    fn replace_query(self, key: &str, value: &str) -> Uri {
        let mut url = Url::parse(&self.to_string()).expect("valid url");

        // Get a copy of the current query pairs without the target key.
        let current = url
            .query_pairs()
            .filter(|(k, _)| k != key)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>();

        {
            let mut query = url.query_pairs_mut();
            query.clear().extend_pairs(current).append_pair(key, value);
        }

        url.to_string().parse().expect("valid uri")
    }

    fn append_query<T: Serialize + ?Sized>(self, query: &T) -> Result<Uri, QueryError> {
        let qs = serde_urlencoded::to_string(query)?;
        let mut parts = self.into_parts();

        let mut query = String::new();
        let mut path = String::new();

        if let Some(pq) = parts.path_and_query {
            path.push_str(pq.path());
            if let Some(q) = pq.query() {
                query.push_str(q);
                if !(qs.is_empty() && q.is_empty()) {
                    query.push('&');
                }
            }
        }
        query.push_str(&qs);

        let pq = format!("{}?{}", path, query);
        parts.path_and_query = Some(http::uri::PathAndQuery::from_maybe_shared(pq)?);

        Ok(http::Uri::from_parts(parts)?)
    }

    #[allow(clippy::unnecessary_to_owned)]
    fn clear_query(self) -> Uri {
        let mut parts = self.into_parts();
        parts.path_and_query = parts
            .path_and_query
            .as_ref()
            .map(|pq| http::uri::PathAndQuery::from_maybe_shared(pq.path().to_owned()).unwrap());
        Uri::from_parts(parts).unwrap()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_uri_join() {
        let uri = "http://example.com".parse::<Uri>().unwrap();
        let joined = uri.join("foo");
        assert_eq!(joined.to_string(), "http://example.com/foo");

        let uri = "http://example.com/".parse::<Uri>().unwrap();
        let joined = uri.join("foo");
        assert_eq!(joined.to_string(), "http://example.com/foo");

        let uri = "http://example.com/bar".parse::<Uri>().unwrap();
        let joined = uri.join("foo");
        assert_eq!(joined.to_string(), "http://example.com/bar/foo");

        let uri = "http://example.com/bar/".parse::<Uri>().unwrap();
        let joined = uri.join("foo");
        assert_eq!(joined.to_string(), "http://example.com/bar/foo");

        let uri = "http://example.com/bar".parse::<Uri>().unwrap();
        let joined = uri.join("/foo");
        assert_eq!(joined.to_string(), "http://example.com/foo");

        let uri = "http://example.com/bar/".parse::<Uri>().unwrap();
        let joined = uri.join("/foo");
        assert_eq!(joined.to_string(), "http://example.com/foo");
    }

    #[test]
    fn test_uri_join_empty() {
        let uri = "http://example.com".parse::<Uri>().unwrap();
        let joined = uri.join("");
        assert_eq!(joined.to_string(), "http://example.com/");

        let uri = "http://example.com/".parse::<Uri>().unwrap();
        let joined = uri.join("");
        assert_eq!(joined.to_string(), "http://example.com/");

        let uri = "http://example.com/bar".parse::<Uri>().unwrap();
        let joined = uri.join("");
        assert_eq!(joined.to_string(), "http://example.com/bar/");

        let uri = "http://example.com/bar/".parse::<Uri>().unwrap();
        let joined = uri.join("");
        assert_eq!(joined.to_string(), "http://example.com/bar/");
    }

    #[test]
    fn test_append_query() {
        let uri = "http://example.com".parse::<Uri>().unwrap();
        let appended = uri.append_query(&[("foo", "bar")]).unwrap();
        assert_eq!(appended.to_string(), "http://example.com/?foo=bar");

        let uri = "http://example.com/?baz=qux".parse::<Uri>().unwrap();
        let appended = uri.append_query(&[("foo", "bar")]).unwrap();
        assert_eq!(appended.to_string(), "http://example.com/?baz=qux&foo=bar");

        let uri = "http://example.com/?baz=qux".parse::<Uri>().unwrap();
        let appended = uri.append_query(&[("foo", "bar"), ("foo", "baz")]).unwrap();
        assert_eq!(
            appended.to_string(),
            "http://example.com/?baz=qux&foo=bar&foo=baz"
        );
    }

    #[test]
    fn test_clear_query() {
        let uri = "http://example.com".parse::<Uri>().unwrap();
        let cleared = uri.clear_query();
        assert_eq!(cleared.to_string(), "http://example.com/");

        let uri = "http://example.com/?foo=bar".parse::<Uri>().unwrap();
        let cleared = uri.clear_query();
        assert_eq!(cleared.to_string(), "http://example.com/");

        let uri = "http://example.com/?foo=bar&baz=qux"
            .parse::<Uri>()
            .unwrap();
        let cleared = uri.clear_query();
        assert_eq!(cleared.to_string(), "http://example.com/");
    }

    #[test]
    fn test_replace_query() {
        let uri = "http://example.com".parse::<Uri>().unwrap();
        let replaced = uri.replace_query("foo", "bar");
        assert_eq!(replaced.to_string(), "http://example.com/?foo=bar");

        let uri = "http://example.com?foo=baz".parse::<Uri>().unwrap();
        let replaced = uri.replace_query("foo", "bar");
        assert_eq!(replaced.to_string(), "http://example.com/?foo=bar");

        let uri = "http://example.com?foo=baz&baz=qux".parse::<Uri>().unwrap();
        let replaced = uri.replace_query("foo", "bar");
        assert_eq!(replaced.to_string(), "http://example.com/?baz=qux&foo=bar");

        let uri = "http://example.com?foo=baz&baz=qux".parse::<Uri>().unwrap();
        let replaced = uri.replace_query("baz", "bar");
        assert_eq!(replaced.to_string(), "http://example.com/?foo=baz&baz=bar");
    }
}
