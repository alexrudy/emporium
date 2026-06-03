//! Proof Key for Code Exchange (PKCE) — RFC 7636.
//!
//! [`PkceVerifier`] is the client-side secret a caller stashes during the
//! authorization-code flow. [`PkceChallenge`] is the value embedded in the
//! authorization URL; it derives deterministically from the verifier.
//!
//! ```
//! use oath::pkce::{PkceMethod, PkceVerifier};
//!
//! let verifier = PkceVerifier::generate();
//! let challenge = verifier.challenge();
//! assert_eq!(challenge.method, PkceMethod::S256);
//! ```

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use secret::Secret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Minimum verifier length per RFC 7636 §4.1.
pub const VERIFIER_MIN_LEN: usize = 43;
/// Maximum verifier length per RFC 7636 §4.1.
pub const VERIFIER_MAX_LEN: usize = 128;

/// Reasons a PKCE verifier may be rejected.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PkceError {
    /// Verifier is shorter than [`VERIFIER_MIN_LEN`].
    #[error("PKCE verifier must be at least {VERIFIER_MIN_LEN} characters")]
    TooShort,
    /// Verifier is longer than [`VERIFIER_MAX_LEN`].
    #[error("PKCE verifier must be at most {VERIFIER_MAX_LEN} characters")]
    TooLong,
    /// Verifier contains a character outside the unreserved set
    /// (RFC 3986 §2.3): `[A-Za-z0-9-._~]`.
    #[error("PKCE verifier contained invalid character: {0:?}")]
    InvalidChar(char),
}

/// The `code_challenge_method` parameter of an OAuth2 authorization
/// request (RFC 7636 §4.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PkceMethod {
    /// `plain`: challenge equals verifier. Use only when the server does
    /// not support `S256`.
    Plain,
    /// `S256`: challenge is BASE64URL(SHA256(ASCII(verifier))).
    #[default]
    S256,
}

impl fmt::Display for PkceMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Plain => "plain",
            Self::S256 => "S256",
        })
    }
}

/// A high-entropy random string the client retains during the
/// authorization-code flow and submits when exchanging the code.
///
/// `Serialize`/`Deserialize` are derived so the verifier can be stashed
/// in a pre-auth session store between the `/auth/login` and
/// `/auth/callback` requests. The wire format is the raw verifier string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkceVerifier(Secret);

impl PkceVerifier {
    /// Generate a fresh verifier from 32 random bytes drawn from
    /// [`OsRng`], encoded as 43 base64url characters (no padding).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng must provide random bytes");
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        // 32 bytes always encodes to 43 chars in base64url (no pad), within range.
        Self(Secret::from(encoded))
    }

    /// Construct a verifier from existing material, validating the
    /// length and character set required by RFC 7636 §4.1.
    pub fn new(verifier: impl Into<Secret>) -> Result<Self, PkceError> {
        let secret = verifier.into();
        validate(secret.revealed())?;
        Ok(Self(secret))
    }

    /// Compute the corresponding [`PkceChallenge`] using the default
    /// method ([`PkceMethod::S256`]).
    pub fn challenge(&self) -> PkceChallenge {
        self.challenge_with(PkceMethod::S256)
    }

    /// Compute the [`PkceChallenge`] using a specific method.
    pub fn challenge_with(&self, method: PkceMethod) -> PkceChallenge {
        let value = match method {
            PkceMethod::Plain => self.0.revealed().to_owned(),
            PkceMethod::S256 => {
                let hash = Sha256::digest(self.0.revealed().as_bytes());
                URL_SAFE_NO_PAD.encode(hash)
            }
        };
        PkceChallenge { method, value }
    }

    /// Reveal the underlying verifier text. Use only when emitting the
    /// value as part of the code exchange request.
    pub fn revealed(&self) -> &str {
        self.0.revealed()
    }
}

fn validate(s: &str) -> Result<(), PkceError> {
    if s.len() < VERIFIER_MIN_LEN {
        return Err(PkceError::TooShort);
    }
    if s.len() > VERIFIER_MAX_LEN {
        return Err(PkceError::TooLong);
    }
    for c in s.chars() {
        let valid = c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~');
        if !valid {
            return Err(PkceError::InvalidChar(c));
        }
    }
    Ok(())
}

/// The `code_challenge` and `code_challenge_method` derived from a
/// [`PkceVerifier`], suitable for embedding in an authorization URL.
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    /// The method used to derive `value`.
    pub method: PkceMethod,
    /// The challenge string itself. Not a secret — it appears in URLs.
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B test vector.
    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_S256_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn generate_produces_43_char_verifier() {
        let v = PkceVerifier::generate();
        assert_eq!(v.revealed().len(), 43);
        validate(v.revealed()).expect("generated verifier should be valid");
    }

    #[test]
    fn generate_yields_distinct_values() {
        let a = PkceVerifier::generate();
        let b = PkceVerifier::generate();
        assert_ne!(a.revealed(), b.revealed());
    }

    #[test]
    fn rfc7636_s256_test_vector() {
        let v = PkceVerifier::new(RFC_VERIFIER.to_owned()).unwrap();
        let challenge = v.challenge();
        assert_eq!(challenge.method, PkceMethod::S256);
        assert_eq!(challenge.value, RFC_S256_CHALLENGE);
    }

    #[test]
    fn plain_method_returns_verifier_unchanged() {
        let v = PkceVerifier::new(RFC_VERIFIER.to_owned()).unwrap();
        let challenge = v.challenge_with(PkceMethod::Plain);
        assert_eq!(challenge.method, PkceMethod::Plain);
        assert_eq!(challenge.value, RFC_VERIFIER);
    }

    #[test]
    fn too_short_rejected() {
        let short = "a".repeat(42);
        assert_eq!(PkceVerifier::new(short).unwrap_err(), PkceError::TooShort);
    }

    #[test]
    fn too_long_rejected() {
        let long = "a".repeat(129);
        assert_eq!(PkceVerifier::new(long).unwrap_err(), PkceError::TooLong);
    }

    #[test]
    fn invalid_chars_rejected() {
        // 43 chars but with a space at the end — outside the unreserved set.
        let bad = format!("{}{}", "a".repeat(42), ' ');
        assert!(matches!(
            PkceVerifier::new(bad),
            Err(PkceError::InvalidChar(' '))
        ));
    }

    #[test]
    fn unreserved_charset_accepted() {
        let v = "a".repeat(20) + "Z" + "0" + "-" + "." + "_" + "~" + &"a".repeat(18);
        assert_eq!(v.len(), 44);
        PkceVerifier::new(v).expect("unreserved chars should validate");
    }

    #[test]
    fn pkce_method_default_is_s256() {
        assert_eq!(PkceMethod::default(), PkceMethod::S256);
    }

    #[test]
    fn pkce_method_display() {
        assert_eq!(PkceMethod::S256.to_string(), "S256");
        assert_eq!(PkceMethod::Plain.to_string(), "plain");
    }
}
