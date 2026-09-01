// SPDX-License-Identifier: GPL-2.0-only

//! One-time printable recovery code and short save-verification challenge.

use meshspan_domain::RandomSource;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::RecoveryBundleError;

const CODE_BYTES: usize = 32;
const CODE_PREFIX: &str = "meshspan-offline-v1.";
const CODE_TEXT_BYTES: usize = CODE_PREFIX.len() + (CODE_BYTES * 2);
const CHALLENGE_BYTES: usize = 8;
const CHALLENGE_PREFIX: &str = "meshspan-check-v1.";
const CHALLENGE_TEXT_BYTES: usize = CHALLENGE_PREFIX.len() + (CHALLENGE_BYTES * 2);
const CHALLENGE_DOMAIN: &[u8] = b"meshspan.recovery-bundle.challenge.v1\0";
const CHALLENGE_COMMITMENT_DOMAIN: &[u8] = b"meshspan.recovery-bundle.challenge-commitment.v1\0";

/// High-entropy recovery code displayed once and stored separately from the bundle file.
///
/// The type implements neither `Clone`, `Debug` nor `Display`; explicit presentation is limited
/// to the initial delivery boundary and owned bytes are zeroized on drop.
pub struct RecoveryBundleCode(Zeroizing<[u8; CODE_BYTES]>);

impl RecoveryBundleCode {
    /// Generates a uniformly random recovery code.
    ///
    /// # Errors
    ///
    /// Rejects unavailable or all-zero entropy.
    pub fn generate(random: &mut impl RandomSource) -> Result<Self, RecoveryBundleError> {
        let mut bytes = [0_u8; CODE_BYTES];
        random
            .fill_bytes(&mut bytes)
            .map_err(|_| RecoveryBundleError::Entropy)?;
        if bytes == [0; CODE_BYTES] {
            Err(RecoveryBundleError::Entropy)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }

    /// Accepts a protected uniformly random 256-bit seed from a domain-separated bootstrap KDF.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero value.
    pub fn from_high_entropy_seed(
        bytes: Zeroizing<[u8; CODE_BYTES]>,
    ) -> Result<Self, RecoveryBundleError> {
        if *bytes == [0; CODE_BYTES] {
            Err(RecoveryBundleError::InvalidInput)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Parses the exact canonical lowercase presentation.
    ///
    /// # Errors
    ///
    /// Rejects wrong prefixes, lengths, case, characters or the reserved all-zero code.
    pub fn parse(value: &str) -> Result<Self, RecoveryBundleError> {
        if value.len() != CODE_TEXT_BYTES || !value.starts_with(CODE_PREFIX) {
            return Err(RecoveryBundleError::InvalidInput);
        }
        let mut bytes = [0_u8; CODE_BYTES];
        decode_hex(&value.as_bytes()[CODE_PREFIX.len()..], &mut bytes)?;
        if bytes == [0; CODE_BYTES] {
            Err(RecoveryBundleError::InvalidInput)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }

    /// Produces the one-time printable form for immediate delivery to the administrator.
    #[must_use]
    pub fn expose_once(&self) -> String {
        let mut output = String::with_capacity(CODE_TEXT_BYTES);
        output.push_str(CODE_PREFIX);
        append_hex(&mut output, self.0.as_ref());
        output
    }

    pub(crate) fn key_bytes(&self) -> &[u8; CODE_BYTES] {
        &self.0
    }

    pub(crate) fn challenge(&self, bundle_digest: [u8; 32]) -> RecoveryChallenge {
        let mut digest = Sha256::new();
        digest.update(CHALLENGE_DOMAIN);
        digest.update(self.0.as_ref());
        digest.update(bundle_digest);
        let full: [u8; 32] = digest.finalize().into();
        let mut bytes = [0; CHALLENGE_BYTES];
        bytes.copy_from_slice(&full[..CHALLENGE_BYTES]);
        RecoveryChallenge(bytes)
    }
}

/// Short proof derived from both the separately stored code and exact downloaded bundle.
#[derive(Clone, Copy, Debug, Eq)]
pub struct RecoveryChallenge([u8; CHALLENGE_BYTES]);

impl RecoveryChallenge {
    /// Parses the exact canonical lowercase challenge.
    ///
    /// # Errors
    ///
    /// Rejects wrong prefixes, lengths, case or characters.
    pub fn parse(value: &str) -> Result<Self, RecoveryBundleError> {
        if value.len() != CHALLENGE_TEXT_BYTES || !value.starts_with(CHALLENGE_PREFIX) {
            return Err(RecoveryBundleError::InvalidInput);
        }
        let mut bytes = [0; CHALLENGE_BYTES];
        decode_hex(&value.as_bytes()[CHALLENGE_PREFIX.len()..], &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Returns the short canonical text intended for the save-verification ceremony.
    #[must_use]
    pub fn expose_for_verification(self) -> String {
        let mut output = String::with_capacity(CHALLENGE_TEXT_BYTES);
        output.push_str(CHALLENGE_PREFIX);
        append_hex(&mut output, &self.0);
        output
    }

    /// Returns the non-reversible commitment stored by authoritative metadata until verification.
    #[must_use]
    pub fn commitment(self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(CHALLENGE_COMMITMENT_DOMAIN);
        digest.update(self.0);
        digest.finalize().into()
    }
}

impl PartialEq for RecoveryChallenge {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

fn decode_hex(source: &[u8], destination: &mut [u8]) -> Result<(), RecoveryBundleError> {
    if source.len() != destination.len() * 2 {
        return Err(RecoveryBundleError::InvalidInput);
    }
    for (pair, byte) in source.as_chunks::<2>().0.iter().zip(destination) {
        let high = decode_nibble(pair[0]).ok_or(RecoveryBundleError::InvalidInput)?;
        let low = decode_nibble(pair[1]).ok_or(RecoveryBundleError::InvalidInput)?;
        *byte = (high << 4) | low;
    }
    Ok(())
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
