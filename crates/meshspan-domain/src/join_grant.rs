// SPDX-License-Identifier: GPL-2.0-only

//! Canonical high-entropy node join-grant material.

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::secret_text::{SECRET_BYTES, decode, encode};
use crate::{JoinGrantId, RandomSource};

const PREFIX: &str = "meshspan-join-v1.";
/// Exact byte length of one canonical encoded join grant.
pub const ENCODED_JOIN_GRANT_LENGTH: usize = PREFIX.len() + 97;

/// Secret-bearing administrator-issued node join grant.
///
/// The type deliberately implements neither `Debug` nor `Display`. Callers must explicitly
/// request a zeroising encoded value at the one-time presentation boundary.
pub struct JoinGrantBundle {
    join_grant_id: JoinGrantId,
    secret: Zeroizing<[u8; SECRET_BYTES]>,
}

impl JoinGrantBundle {
    /// Generates an independent join grant from cryptographic entropy.
    ///
    /// # Errors
    ///
    /// Rejects unavailable entropy, a nil identifier or an all-zero secret.
    pub fn generate(random: &mut impl RandomSource) -> Result<Self, JoinGrantBundleError> {
        let mut join_grant_id = [0_u8; 16];
        let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
        random
            .fill_bytes(&mut join_grant_id)
            .map_err(|_| JoinGrantBundleError::EntropyUnavailable)?;
        random
            .fill_bytes(secret.as_mut())
            .map_err(|_| JoinGrantBundleError::EntropyUnavailable)?;
        Self::from_parts(join_grant_id, secret)
    }

    /// Parses one exact lowercase canonical join grant.
    ///
    /// # Errors
    ///
    /// Rejects another version, whitespace, uppercase/non-hex bytes, zero values, extra fields
    /// and an incorrect exact length.
    pub fn parse(value: &str) -> Result<Self, JoinGrantBundleError> {
        let (join_grant_id, secret) =
            decode(value, PREFIX).ok_or(JoinGrantBundleError::InvalidEncoding)?;
        Self::from_parts(join_grant_id, Zeroizing::new(secret))
    }

    /// Returns the stable public grant identity included in the encoded value.
    #[must_use]
    pub const fn join_grant_id(&self) -> JoinGrantId {
        self.join_grant_id
    }

    /// Returns the verifier persisted in replicated join-grant metadata.
    #[must_use]
    pub fn secret_digest(&self) -> [u8; 32] {
        Sha256::digest(self.secret.as_ref()).into()
    }

    /// Explicitly exposes the secret-bearing text for its one-time output or enrolment boundary.
    ///
    /// The returned allocation is zeroed on drop. It must never be logged or persisted in
    /// replicated metadata.
    #[must_use]
    pub fn expose_encoded(&self) -> Zeroizing<String> {
        encode(PREFIX, &self.join_grant_id.as_bytes(), &self.secret)
    }

    fn from_parts(
        join_grant_id: [u8; 16],
        secret: Zeroizing<[u8; SECRET_BYTES]>,
    ) -> Result<Self, JoinGrantBundleError> {
        let join_grant_id = JoinGrantId::from_bytes(join_grant_id)
            .map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        if secret.as_ref() == [0; SECRET_BYTES] {
            return Err(JoinGrantBundleError::InvalidEncoding);
        }
        Ok(Self {
            join_grant_id,
            secret,
        })
    }
}

/// Failure to generate or parse node join-grant material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JoinGrantBundleError {
    /// The configured cryptographic entropy source failed.
    #[error("join-grant entropy is unavailable")]
    EntropyUnavailable,
    /// The supplied value is not the exact supported canonical encoding.
    #[error("join-grant encoding is invalid")]
    InvalidEncoding,
}

#[cfg(test)]
mod tests {
    use super::{ENCODED_JOIN_GRANT_LENGTH, JoinGrantBundle, JoinGrantBundleError};
    use crate::{EntropyError, RandomSource};

    const EXPECTED: &str = concat!(
        "meshspan-join-v1.",
        "0102030405060708090a0b0c0d0e0f10.",
        "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"
    );

    #[test]
    fn generation_parsing_and_verifier_are_canonical() -> Result<(), JoinGrantBundleError> {
        let generated = JoinGrantBundle::generate(&mut SequentialRandom(1))?;
        let encoded = generated.expose_encoded();
        assert_eq!(encoded.len(), ENCODED_JOIN_GRANT_LENGTH);
        assert_eq!(encoded.as_str(), EXPECTED);

        let parsed = JoinGrantBundle::parse(&encoded)?;
        assert_eq!(parsed.join_grant_id(), generated.join_grant_id());
        assert_eq!(parsed.secret_digest(), generated.secret_digest());
        assert_eq!(parsed.expose_encoded().as_str(), EXPECTED);
        Ok(())
    }

    #[test]
    fn parser_rejects_noncanonical_or_zero_material() {
        for value in [
            "",
            "meshspan-join-v2.0102030405060708090a0b0c0d0e0f10.1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
            "meshspan-join-v1.0102030405060708090A0b0c0d0e0f10.1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
            "meshspan-join-v1.0102030405060708090a0b0c0d0e0f10.1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3z",
            "meshspan-join-v1.0102030405060708090a0b0c0d0e0f10.1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30\n",
            "meshspan-join-v1.00000000000000000000000000000000.1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
            "meshspan-join-v1.0102030405060708090a0b0c0d0e0f10.0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert_eq!(
                JoinGrantBundle::parse(value).err(),
                Some(JoinGrantBundleError::InvalidEncoding),
                "unexpected parse result for {value:?}"
            );
        }
    }

    #[test]
    fn generation_rejects_failed_or_zero_entropy() {
        assert_eq!(
            JoinGrantBundle::generate(&mut FailingRandom).err(),
            Some(JoinGrantBundleError::EntropyUnavailable)
        );
        assert_eq!(
            JoinGrantBundle::generate(&mut ZeroRandom).err(),
            Some(JoinGrantBundleError::InvalidEncoding)
        );
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

    struct FailingRandom;

    impl RandomSource for FailingRandom {
        fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError)
        }
    }

    struct ZeroRandom;

    impl RandomSource for ZeroRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(0);
            Ok(())
        }
    }
}
