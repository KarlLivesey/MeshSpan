// SPDX-License-Identifier: GPL-2.0-only

//! Canonical high-entropy first-boot claim material.

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{ClaimId, RandomSource};

const PREFIX: &str = "meshspan-claim-v1.";
const SECRET_BYTES: usize = 32;
const SECRET_HEX_LENGTH: usize = SECRET_BYTES * 2;
const IDENTIFIER_HEX_LENGTH: usize = 32;

/// Exact byte length of one canonical encoded claim bundle.
pub const ENCODED_CLAIM_BUNDLE_LENGTH: usize =
    PREFIX.len() + IDENTIFIER_HEX_LENGTH + 1 + SECRET_HEX_LENGTH;

/// Secret-bearing single-use claim material.
///
/// The type deliberately implements neither `Debug` nor `Display`. Callers must
/// explicitly request a zeroising encoded value at the local presentation boundary.
pub struct ClaimBundle {
    claim_id: ClaimId,
    secret: Zeroizing<[u8; SECRET_BYTES]>,
}

impl ClaimBundle {
    /// Generates a claim from the caller's cryptographically secure random source.
    ///
    /// # Errors
    ///
    /// Rejects unavailable entropy and all-zero identifier or secret output instead
    /// of silently weakening the claim.
    pub fn generate(random: &mut impl RandomSource) -> Result<Self, ClaimBundleError> {
        let mut claim_id_bytes = [0_u8; 16];
        let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
        random
            .fill_bytes(&mut claim_id_bytes)
            .map_err(|_| ClaimBundleError::EntropyUnavailable)?;
        random
            .fill_bytes(secret.as_mut())
            .map_err(|_| ClaimBundleError::EntropyUnavailable)?;
        let claim_id =
            ClaimId::from_bytes(claim_id_bytes).map_err(|_| ClaimBundleError::InvalidEntropy)?;
        if secret.as_ref() == [0; SECRET_BYTES] {
            return Err(ClaimBundleError::InvalidEntropy);
        }
        Ok(Self { claim_id, secret })
    }

    /// Parses one exact lowercase canonical claim bundle.
    ///
    /// # Errors
    ///
    /// Rejects another version, whitespace, uppercase/non-hex bytes, nil identity,
    /// zero secret, extra fields or an incorrect exact length.
    pub fn parse(value: &str) -> Result<Self, ClaimBundleError> {
        if value.len() != ENCODED_CLAIM_BUNDLE_LENGTH {
            return Err(ClaimBundleError::InvalidEncoding);
        }
        let body = value
            .strip_prefix(PREFIX)
            .ok_or(ClaimBundleError::InvalidEncoding)?;
        let (claim_id, secret) = body
            .split_once('.')
            .ok_or(ClaimBundleError::InvalidEncoding)?;
        if claim_id.len() != IDENTIFIER_HEX_LENGTH || secret.len() != SECRET_HEX_LENGTH {
            return Err(ClaimBundleError::InvalidEncoding);
        }
        let claim_id = ClaimId::parse(claim_id).map_err(|_| ClaimBundleError::InvalidEncoding)?;
        let secret = Zeroizing::new(decode_secret(secret)?);
        if secret.as_ref() == [0; SECRET_BYTES] {
            return Err(ClaimBundleError::InvalidEncoding);
        }
        Ok(Self { claim_id, secret })
    }

    /// Returns the stable non-secret identity included in the encoded bundle.
    #[must_use]
    pub const fn claim_id(&self) -> ClaimId {
        self.claim_id
    }

    /// Returns the verifier persisted by the node-local claim state machine.
    #[must_use]
    pub fn secret_digest(&self) -> [u8; 32] {
        Sha256::digest(self.secret.as_ref()).into()
    }

    /// Explicitly exposes the canonical secret-bearing representation for local output.
    ///
    /// The returned allocation is zeroed on drop. It must never be logged, included in
    /// an error, stored in metadata or sent through an unauthenticated discovery response.
    #[must_use]
    pub fn expose_encoded(&self) -> Zeroizing<String> {
        let mut encoded = Zeroizing::new(String::with_capacity(ENCODED_CLAIM_BUNDLE_LENGTH));
        encoded.push_str(PREFIX);
        append_hex(&mut encoded, &self.claim_id.as_bytes());
        encoded.push('.');
        append_hex(&mut encoded, self.secret.as_ref());
        encoded
    }
}

/// Failure to generate or parse first-boot claim material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClaimBundleError {
    /// The configured operating-system entropy source failed.
    #[error("claim entropy is unavailable")]
    EntropyUnavailable,
    /// The entropy source returned a forbidden all-zero identity or secret.
    #[error("claim entropy output is invalid")]
    InvalidEntropy,
    /// The supplied claim is not the exact supported canonical encoding.
    #[error("claim bundle encoding is invalid")]
    InvalidEncoding,
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

fn decode_secret(value: &str) -> Result<[u8; SECRET_BYTES], ClaimBundleError> {
    let mut decoded = [0_u8; SECRET_BYTES];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() || pairs.len() != SECRET_BYTES {
        return Err(ClaimBundleError::InvalidEncoding);
    }
    for (destination, pair) in decoded.iter_mut().zip(pairs) {
        let high = decode_hex(pair[0]).ok_or(ClaimBundleError::InvalidEncoding)?;
        let low = decode_hex(pair[1]).ok_or(ClaimBundleError::InvalidEncoding)?;
        *destination = (high << 4) | low;
    }
    Ok(decoded)
}

const fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{ClaimBundle, ClaimBundleError, ENCODED_CLAIM_BUNDLE_LENGTH};
    use crate::{EntropyError, RandomSource};

    const EXPECTED: &str = concat!(
        "meshspan-claim-v1.",
        "0102030405060708090a0b0c0d0e0f10.",
        "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"
    );

    #[test]
    fn generation_encoding_parsing_and_verifier_are_canonical() -> Result<(), ClaimBundleError> {
        let mut random = SequentialRandom(1);
        let generated = ClaimBundle::generate(&mut random)?;
        let encoded = generated.expose_encoded();
        assert_eq!(encoded.len(), ENCODED_CLAIM_BUNDLE_LENGTH);
        assert_eq!(encoded.as_str(), EXPECTED);

        let parsed = ClaimBundle::parse(&encoded)?;
        assert_eq!(parsed.claim_id(), generated.claim_id());
        assert_eq!(parsed.secret_digest(), generated.secret_digest());
        assert_eq!(parsed.expose_encoded().as_str(), EXPECTED);
        Ok(())
    }

    #[test]
    fn parser_rejects_every_noncanonical_family() {
        let cases = [
            "",
            "meshspan-claim-v2.0102030405060708090a0b0c0d0e0f10.1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
            "meshspan-claim-v1.0102030405060708090A0b0c0d0e0f10.1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
            "meshspan-claim-v1.0102030405060708090a0b0c0d0e0f10.1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3z",
            "meshspan-claim-v1.0102030405060708090a0b0c0d0e0f10.1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30\n",
            "meshspan-claim-v1.00000000000000000000000000000000.1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
            "meshspan-claim-v1.0102030405060708090a0b0c0d0e0f10.0000000000000000000000000000000000000000000000000000000000000000",
        ];
        for value in cases {
            assert_eq!(
                ClaimBundle::parse(value).err(),
                Some(ClaimBundleError::InvalidEncoding),
                "unexpected parse result for {value:?}"
            );
        }
    }

    #[test]
    fn generation_rejects_failed_or_structurally_broken_entropy() {
        assert_eq!(
            ClaimBundle::generate(&mut FailingRandom).err(),
            Some(ClaimBundleError::EntropyUnavailable)
        );
        assert_eq!(
            ClaimBundle::generate(&mut ZeroRandom).err(),
            Some(ClaimBundleError::InvalidEntropy)
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
