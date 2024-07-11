//! URI utilities.

use camino::Utf8Path;
use http::Uri;

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
}
