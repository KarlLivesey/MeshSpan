// SPDX-License-Identifier: GPL-2.0-only

//! Canonical high-entropy API-key material shared by every compatible service.

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::secret_text::{SECRET_BYTES, decode, derive, encode};
use crate::{ApiKeyId, ClaimBundle, OperationId, RandomSource};

const PREFIX: &str = "meshspan-key-v1.";

/// Exact byte length of one canonical encoded API key.
pub const ENCODED_API_KEY_LENGTH: usize = PREFIX.len() + 97;

/// Secret-bearing ordinary `MeshSpan` API key.
///
/// The type deliberately implements neither `Debug` nor `Display`.
pub struct ApiKeyBundle {
    key_id: ApiKeyId,
    secret: Zeroizing<[u8; SECRET_BYTES]>,
}

impl ApiKeyBundle {
    /// Generates an independent API key from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Rejects unavailable, nil-identity or all-zero secret output.
    pub fn generate(random: &mut impl RandomSource) -> Result<Self, ApiKeyBundleError> {
        let mut key_id = [0_u8; 16];
        let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
        random
            .fill_bytes(&mut key_id)
            .map_err(|_| ApiKeyBundleError::EntropyUnavailable)?;
        random
            .fill_bytes(secret.as_mut())
            .map_err(|_| ApiKeyBundleError::EntropyUnavailable)?;
        Self::from_parts(key_id, secret)
    }

    /// Derives a restart-stable initial key from a first-boot secret and operation.
    ///
    /// Each output is domain-separated and no claim or plaintext key is persisted.
    ///
    /// # Errors
    ///
    /// Rejects the cryptographically negligible nil identifier or zero-secret output.
    pub fn derive_initial(
        claim: &ClaimBundle,
        operation_id: OperationId,
    ) -> Result<Self, ApiKeyBundleError> {
        let mut key_id = derive(
            b"meshspan.setup.initial-key-id.v1",
            claim.secret_bytes(),
            operation_id,
        );
        key_id[6] = (key_id[6] & 0x0f) | 0x40;
        key_id[8] = (key_id[8] & 0x3f) | 0x80;
        let secret = Zeroizing::new(derive(
            b"meshspan.setup.initial-key-secret.v1",
            claim.secret_bytes(),
            operation_id,
        ));
        Self::from_parts(
            key_id[..16]
                .try_into()
                .map_err(|_| ApiKeyBundleError::Invalid)?,
            secret,
        )
    }

    /// Parses one exact lowercase canonical key.
    ///
    /// # Errors
    ///
    /// Rejects another version, whitespace, uppercase/non-hex material or zero values.
    pub fn parse(value: &str) -> Result<Self, ApiKeyBundleError> {
        let (key_id, secret) = decode(value, PREFIX).ok_or(ApiKeyBundleError::InvalidEncoding)?;
        Self::from_parts(key_id, Zeroizing::new(secret))
    }

    /// Returns the public identity included in the key text.
    #[must_use]
    pub const fn key_id(&self) -> ApiKeyId {
        self.key_id
    }

    /// Returns the verifier persisted in replicated authentication metadata.
    #[must_use]
    pub fn secret_digest(&self) -> [u8; 32] {
        Sha256::digest(self.secret.as_ref()).into()
    }

    /// Explicitly exposes the secret-bearing text for its one-time response boundary.
    #[must_use]
    pub fn expose_encoded(&self) -> Zeroizing<String> {
        encode(PREFIX, &self.key_id.as_bytes(), &self.secret)
    }

    /// Exposes fixed secret bytes only to sibling domain-separated credential derivations.
    #[must_use]
    pub(crate) fn secret_bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.secret
    }

    fn from_parts(
        key_id: [u8; 16],
        secret: Zeroizing<[u8; SECRET_BYTES]>,
    ) -> Result<Self, ApiKeyBundleError> {
        let key_id = ApiKeyId::from_bytes(key_id).map_err(|_| ApiKeyBundleError::Invalid)?;
        if secret.as_ref() == [0; SECRET_BYTES] {
            return Err(ApiKeyBundleError::Invalid);
        }
        Ok(Self { key_id, secret })
    }
}

/// Failure to create or parse API-key material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ApiKeyBundleError {
    /// Operating-system entropy was unavailable.
    #[error("API-key entropy is unavailable")]
    EntropyUnavailable,
    /// Generated or derived values violated the non-zero contract.
    #[error("API-key material is invalid")]
    Invalid,
    /// Presented text was not the exact canonical API-key encoding.
    #[error("API-key encoding is invalid")]
    InvalidEncoding,
}

#[cfg(test)]
mod tests {
    use super::{ApiKeyBundle, ApiKeyBundleError, ENCODED_API_KEY_LENGTH};
    use crate::{ClaimBundle, EntropyError, OperationId, RandomSource};

    #[test]
    fn generated_and_derived_keys_round_trip_without_debug_exposure()
    -> Result<(), Box<dyn std::error::Error>> {
        let generated = ApiKeyBundle::generate(&mut SequentialRandom(1))?;
        let encoded = generated.expose_encoded();
        assert_eq!(encoded.len(), ENCODED_API_KEY_LENGTH);
        let parsed = ApiKeyBundle::parse(&encoded)?;
        assert_eq!(parsed.key_id(), generated.key_id());
        assert_eq!(parsed.secret_digest(), generated.secret_digest());

        let claim = ClaimBundle::generate(&mut SequentialRandom(8))?;
        let operation_id = OperationId::from_bytes([9; 16])?;
        let first = ApiKeyBundle::derive_initial(&claim, operation_id)?;
        let replay = ApiKeyBundle::derive_initial(&claim, operation_id)?;
        assert_eq!(first.expose_encoded(), replay.expose_encoded());
        assert_eq!(first.expose_encoded().len(), 113);
        Ok(())
    }

    #[test]
    fn parser_rejects_changed_families_and_noncanonical_text() {
        for value in [
            "",
            "meshspan-key-v2.00000000000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000",
            "meshspan-key-v1.00000000000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(matches!(
                ApiKeyBundle::parse(value),
                Err(ApiKeyBundleError::Invalid | ApiKeyBundleError::InvalidEncoding)
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
