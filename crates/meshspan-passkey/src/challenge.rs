// SPDX-License-Identifier: GPL-2.0-only

//! Exact `WebAuthn` challenge representation and canonical base64url transport.

use crate::base64url;
use crate::{PasskeyError, PasskeyErrorKind};

/// Cryptographic bytes in one `MeshSpan` `WebAuthn` challenge.
pub const PASSKEY_CHALLENGE_BYTES: usize = 32;

/// One non-zero 256-bit challenge, deliberately without `Debug` or `Display`.
#[derive(Clone, Eq, PartialEq)]
pub struct PasskeyChallenge([u8; PASSKEY_CHALLENGE_BYTES]);

impl PasskeyChallenge {
    /// Constructs a challenge from exact cryptographic random bytes.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero value.
    pub fn from_bytes(bytes: [u8; PASSKEY_CHALLENGE_BYTES]) -> Result<Self, PasskeyError> {
        if bytes == [0; PASSKEY_CHALLENGE_BYTES] {
            Err(PasskeyError::new(PasskeyErrorKind::Malformed))
        } else {
            Ok(Self(bytes))
        }
    }

    /// Parses the exact canonical unpadded base64url representation.
    ///
    /// # Errors
    ///
    /// Rejects padding, a non-base64url alphabet, non-canonical tail bits, a wrong length or zero.
    pub fn parse_base64url(value: &str) -> Result<Self, PasskeyError> {
        let decoded = base64url::decode(value, PASSKEY_CHALLENGE_BYTES)?;
        let bytes = decoded
            .try_into()
            .map_err(|_| PasskeyError::new(PasskeyErrorKind::Malformed))?;
        Self::from_bytes(bytes)
    }

    /// Borrows the exact challenge bytes used by `WebAuthn` verification.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PASSKEY_CHALLENGE_BYTES] {
        &self.0
    }

    /// Encodes the canonical 43-character unpadded base64url representation.
    #[must_use]
    pub fn to_base64url(&self) -> String {
        base64url::encode(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::{PASSKEY_CHALLENGE_BYTES, PasskeyChallenge, PasskeyErrorKind};

    #[test]
    fn challenge_round_trips_through_exact_unpadded_base64url()
    -> Result<(), Box<dyn std::error::Error>> {
        let challenge = PasskeyChallenge::from_bytes([0x11; PASSKEY_CHALLENGE_BYTES])?;
        let encoded = challenge.to_base64url();
        assert_eq!(encoded, "ERERERERERERERERERERERERERERERERERERERERERE");
        assert!(PasskeyChallenge::parse_base64url(&encoded)? == challenge);
        Ok(())
    }

    #[test]
    fn challenge_rejects_zero_wrong_length_padding_and_noncanonical_tail_bits() {
        assert_kind(
            PasskeyChallenge::from_bytes([0; 32]),
            PasskeyErrorKind::Malformed,
        );
        for value in [
            "",
            "AA",
            "ERERERERERERERERERERERERERERERERERERERERERE=",
            "ERERERERERERERERERERERERERERERERERERERERERF",
        ] {
            assert_kind(
                PasskeyChallenge::parse_base64url(value),
                PasskeyErrorKind::Malformed,
            );
        }
    }

    fn assert_kind<T>(result: Result<T, crate::PasskeyError>, expected: PasskeyErrorKind) {
        assert_eq!(result.err().map(crate::PasskeyError::kind), Some(expected));
    }
}
