// SPDX-License-Identifier: GPL-2.0-only

//! Restart-stable opaque browser-session token material.

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::secret_text::{SECRET_BYTES, decode, derive, encode};
use crate::{ApiKeyBundle, OperationId, SessionId};

const PREFIX: &str = "meshspan-session-v1.";
const CSRF_PREFIX: &str = "meshspan-csrf-v1.";

/// Exact byte length of one canonical encoded session token.
pub const ENCODED_SESSION_TOKEN_LENGTH: usize = PREFIX.len() + 97;
/// Exact byte length of one canonical encoded CSRF presentation token.
pub const ENCODED_CSRF_TOKEN_LENGTH: usize = CSRF_PREFIX.len() + 97;

/// Secret-bearing opaque session token whose plaintext is never persisted.
///
/// The type deliberately implements neither `Debug` nor `Display`.
pub struct SessionTokenBundle {
    session_id: SessionId,
    secret: Zeroizing<[u8; SECRET_BYTES]>,
}

impl SessionTokenBundle {
    /// Derives an exact-retry-stable session from one accepted API key and operation.
    ///
    /// The token and identity use separate domain labels. Losing an HTTP response therefore
    /// does not require storing plaintext or creating a second authoritative session.
    ///
    /// # Errors
    ///
    /// Rejects the cryptographically negligible nil identity or zero-secret output.
    pub fn derive(
        api_key: &ApiKeyBundle,
        operation_id: OperationId,
    ) -> Result<Self, SessionTokenBundleError> {
        let mut session_id = derive(
            b"meshspan.authentication.session-id.v1",
            api_key.secret_bytes(),
            operation_id,
        );
        session_id[6] = (session_id[6] & 0x0f) | 0x40;
        session_id[8] = (session_id[8] & 0x3f) | 0x80;
        let secret = Zeroizing::new(derive(
            b"meshspan.authentication.session-secret.v1",
            api_key.secret_bytes(),
            operation_id,
        ));
        Self::from_parts(
            session_id[..16]
                .try_into()
                .map_err(|_| SessionTokenBundleError::Invalid)?,
            secret,
        )
    }

    /// Parses one exact lowercase canonical session token.
    ///
    /// # Errors
    ///
    /// Rejects another version, whitespace, uppercase/non-hex material or zero values.
    pub fn parse(value: &str) -> Result<Self, SessionTokenBundleError> {
        let (session_id, secret) =
            decode(value, PREFIX).ok_or(SessionTokenBundleError::InvalidEncoding)?;
        Self::from_parts(session_id, Zeroizing::new(secret))
    }

    /// Returns the public session identity embedded in this token.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the verifier stored in replicated authentication metadata.
    #[must_use]
    pub fn token_digest(&self) -> [u8; 32] {
        Sha256::digest(self.secret.as_ref()).into()
    }

    /// Explicitly exposes the token only to the secure-cookie response boundary.
    #[must_use]
    pub fn expose_encoded(&self) -> Zeroizing<String> {
        encode(PREFIX, &self.session_id.as_bytes(), &self.secret)
    }

    fn from_parts(
        session_id: [u8; 16],
        secret: Zeroizing<[u8; SECRET_BYTES]>,
    ) -> Result<Self, SessionTokenBundleError> {
        let session_id =
            SessionId::from_bytes(session_id).map_err(|_| SessionTokenBundleError::Invalid)?;
        if secret.as_ref() == [0; SECRET_BYTES] {
            return Err(SessionTokenBundleError::Invalid);
        }
        Ok(Self { session_id, secret })
    }
}

/// Secret-bearing CSRF token independently presented by browser code.
///
/// The type deliberately implements neither `Debug` nor `Display`.
pub struct SessionCsrfBundle {
    session_id: SessionId,
    secret: Zeroizing<[u8; SECRET_BYTES]>,
}

impl SessionCsrfBundle {
    /// Derives exact-retry-stable CSRF material independently of the bearer token.
    ///
    /// # Errors
    ///
    /// Rejects the cryptographically negligible nil identity or zero-secret output.
    pub fn derive(
        api_key: &ApiKeyBundle,
        operation_id: OperationId,
    ) -> Result<Self, SessionTokenBundleError> {
        let session = SessionTokenBundle::derive(api_key, operation_id)?;
        let secret = Zeroizing::new(derive(
            b"meshspan.authentication.csrf-secret.v1",
            api_key.secret_bytes(),
            operation_id,
        ));
        Self::from_parts(session.session_id.as_bytes(), secret)
    }

    /// Parses one exact lowercase canonical CSRF token.
    ///
    /// # Errors
    ///
    /// Rejects another version, whitespace, uppercase/non-hex material or zero values.
    pub fn parse(value: &str) -> Result<Self, SessionTokenBundleError> {
        let (session_id, secret) =
            decode(value, CSRF_PREFIX).ok_or(SessionTokenBundleError::InvalidEncoding)?;
        Self::from_parts(session_id, Zeroizing::new(secret))
    }

    /// Returns the session identity to which this CSRF token is bound.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the verifier stored beside the authoritative session.
    #[must_use]
    pub fn token_digest(&self) -> [u8; 32] {
        Sha256::digest(self.secret.as_ref()).into()
    }

    /// Explicitly exposes the token only to the browser response boundary.
    #[must_use]
    pub fn expose_encoded(&self) -> Zeroizing<String> {
        encode(CSRF_PREFIX, &self.session_id.as_bytes(), &self.secret)
    }

    fn from_parts(
        session_id: [u8; 16],
        secret: Zeroizing<[u8; SECRET_BYTES]>,
    ) -> Result<Self, SessionTokenBundleError> {
        let session_id =
            SessionId::from_bytes(session_id).map_err(|_| SessionTokenBundleError::Invalid)?;
        if secret.as_ref() == [0; SECRET_BYTES] {
            return Err(SessionTokenBundleError::Invalid);
        }
        Ok(Self { session_id, secret })
    }
}

/// Failure to derive or parse opaque session-token material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionTokenBundleError {
    /// Derived or decoded values violated the non-zero contract.
    #[error("session token material is invalid")]
    Invalid,
    /// Presented text was not the exact canonical session-token encoding.
    #[error("session token encoding is invalid")]
    InvalidEncoding,
}

#[cfg(test)]
mod tests {
    use super::{
        ENCODED_CSRF_TOKEN_LENGTH, ENCODED_SESSION_TOKEN_LENGTH, SessionCsrfBundle,
        SessionTokenBundle, SessionTokenBundleError,
    };
    use crate::{ApiKeyBundle, EntropyError, OperationId, RandomSource};

    #[test]
    fn derivation_is_exact_retry_stable_and_round_trips() -> Result<(), Box<dyn std::error::Error>>
    {
        let api_key = ApiKeyBundle::generate(&mut SequentialRandom(1))?;
        let operation_id = OperationId::from_bytes([9; 16])?;
        let first = SessionTokenBundle::derive(&api_key, operation_id)?;
        let retry = SessionTokenBundle::derive(&api_key, operation_id)?;
        assert_eq!(first.session_id(), retry.session_id());
        assert_eq!(first.token_digest(), retry.token_digest());
        let encoded = first.expose_encoded();
        assert_eq!(encoded.len(), ENCODED_SESSION_TOKEN_LENGTH);
        let parsed = SessionTokenBundle::parse(&encoded)?;
        assert_eq!(parsed.session_id(), first.session_id());
        assert_eq!(parsed.token_digest(), first.token_digest());
        let csrf = SessionCsrfBundle::derive(&api_key, operation_id)?;
        assert_eq!(csrf.session_id(), first.session_id());
        assert_ne!(csrf.token_digest(), first.token_digest());
        let csrf_encoded = csrf.expose_encoded();
        assert_eq!(csrf_encoded.len(), ENCODED_CSRF_TOKEN_LENGTH);
        let parsed_csrf = SessionCsrfBundle::parse(&csrf_encoded)?;
        assert_eq!(parsed_csrf.session_id(), first.session_id());
        assert_eq!(parsed_csrf.token_digest(), csrf.token_digest());
        Ok(())
    }

    #[test]
    fn parser_rejects_changed_family_and_zero_material() {
        for value in [
            "",
            "meshspan-session-v2.00000000000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000",
            "meshspan-session-v1.00000000000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(matches!(
                SessionTokenBundle::parse(value),
                Err(SessionTokenBundleError::Invalid | SessionTokenBundleError::InvalidEncoding)
            ));
        }
    }

    struct SequentialRandom(u8);

    impl RandomSource for SequentialRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            for byte in destination {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }
}
