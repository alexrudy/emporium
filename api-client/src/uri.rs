use http::Uri;

pub mod serde {
    use http::Uri;
    use serde::{Deserialize as _, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Uri, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }

    pub fn serialize<S>(uri: &Uri, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(uri)
    }
}

pub trait UriExtension {
    fn join<P: AsRef<str>>(self, path: P) -> Uri;
}

impl UriExtension for Uri {
    fn join<P: AsRef<str>>(self, path: P) -> Uri {
        let mut parts = self.into_parts();
        parts.path_and_query = parts.path_and_query.as_ref().map(|pq| {
            let path = format!("{}/{}", pq.path(), path.as_ref());
            http::uri::PathAndQuery::from_maybe_shared(path).unwrap()
        });
        Uri::from_parts(parts).unwrap()
    }
}
