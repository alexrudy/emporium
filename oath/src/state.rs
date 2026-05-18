//! Authorization-code CSRF state tokens.
//!
//! A [`StateToken`] is a high-entropy nonce the client embeds in an
//! authorization request via the `state` parameter, then validates when
//! the authorization server redirects back. RFC 6749 §10.12 requires
//! this to prevent CSRF attacks against the redirect URI.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use secret::Secret;

/// A CSRF state token.
///
/// Stash a freshly generated token alongside the authorization request,
/// then call [`StateToken::verify`] with the value returned in the
/// redirect.
#[derive(Debug, Clone)]
pub struct StateToken(Secret);

impl StateToken {
    /// Generate a fresh state token from 32 random bytes drawn from
    /// [`OsRng`], encoded as 43 base64url characters (no padding).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng must provide random bytes");
        Self(Secret::from(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// Wrap an existing string as a state token. The string is treated as
    /// opaque; no validation is performed.
    pub fn from_secret(secret: impl Into<Secret>) -> Self {
        Self(secret.into())
    }

    /// Reveal the underlying token text so it can be placed in an
    /// authorization request URL.
    pub fn revealed(&self) -> &str {
        self.0.revealed()
    }

    /// Constant-time compare against a value returned by the
    /// authorization server. Returns `true` if they match.
    pub fn verify(&self, returned: &str) -> bool {
        ct_eq(self.0.revealed().as_bytes(), returned.as_bytes())
    }
}

/// Constant-time byte-slice equality.
///
/// Length differences are revealed (and they're typically observable
/// anyway in HTTP frames). Beyond that, the comparison is constant-time
/// to avoid leaking partial matches via timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_43_char_token() {
        let s = StateToken::generate();
        assert_eq!(s.revealed().len(), 43);
    }

    #[test]
    fn generate_yields_distinct_values() {
        let a = StateToken::generate();
        let b = StateToken::generate();
        assert_ne!(a.revealed(), b.revealed());
    }

    #[test]
    fn verify_accepts_matching_value() {
        let s = StateToken::from_secret("abc123".to_owned());
        assert!(s.verify("abc123"));
    }

    #[test]
    fn verify_rejects_different_value() {
        let s = StateToken::from_secret("abc123".to_owned());
        assert!(!s.verify("abc124"));
    }

    #[test]
    fn verify_rejects_different_length() {
        let s = StateToken::from_secret("abc123".to_owned());
        assert!(!s.verify("abc"));
        assert!(!s.verify("abc12345"));
    }

    #[test]
    fn verify_rejects_empty() {
        let s = StateToken::generate();
        assert!(!s.verify(""));
    }

    #[test]
    fn ct_eq_basic_cases() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abc"));
    }
}
